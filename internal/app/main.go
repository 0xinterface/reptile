package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

const defaultConfigPath = "/etc/reptile/config.json"

var daemonRestartKeys = map[string]bool{
	"interface":   true,
	"socket_path": true,
	"log_file":    true,
}

var firewallReloadKeys = map[string]bool{
	"interface":    true,
	"wg_conf":      true,
	"extra_accept": true,
}

func configureLogging() {
	// Under journald stderr is a pipe and the journal timestamps every line,
	// so the handler omits its own clock; interactively it adds short time.
	slog.SetDefault(slog.New(NewConsoleHandler(os.Stderr, stderrIsTTY())))
}

func Run() {
	var (
		configPath = flag.String("config", defaultConfigPath, "path to config.json")
		ifaceFlag  = flag.String("interface", "", "override the WireGuard interface from config")
	)
	flag.Parse()

	configureLogging()

	// install and version must run WITHOUT a config file: install creates
	// the one every other subcommand needs, version is metadata-only.
	sub := flag.Args()
	subCmd, subArgs := "", []string(nil)
	if len(sub) > 0 {
		subCmd, subArgs = sub[0], sub[1:]
	}
	switch subCmd {
	case "install":
		os.Exit(runInstall(subArgs))
	case "version":
		os.Exit(runVersion())
	}

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		fatal("load config: %v", err)
	}
	if *ifaceFlag != "" {
		cfg.Interface = *ifaceFlag
	}

	switch subCmd {
	case "standby", "daemon":
		mustValidate(cfg)
		runDaemon(cfg, *configPath)
	case "check":
		mustValidate(cfg)
		os.Exit(runCheck(cfg))
	case "status":
		os.Exit(runStatus(cfg, subArgs))
	case "history":
		os.Exit(runHistory(cfg, subArgs))
	case "config":
		os.Exit(runConfig(*configPath, subArgs))
	case "firewall":
		runFirewall(cfg, flag.Arg(1))
	default:
		fatal("usage: reptile [-config path] [-interface wg0] standby|status|history|config [set]|check|install|version|firewall up|down")
	}
}

func stderrIsTTY() bool {
	fi, err := os.Stderr.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func stdoutIsTTY() bool {
	fi, err := os.Stdout.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func fatal(format string, args ...any) {
	slog.Error(fmt.Sprintf(format, args...))
	os.Exit(1)
}

func mustValidate(cfg Config) {
	if err := cfg.Validate(); err != nil {
		fatal("config: %v", err)
	}
}

func mustRe(pattern string) *regexp.Regexp {
	re, err := regexp.Compile(pattern)
	if err != nil {
		fatal("bad regex %q: %v", pattern, err)
	}
	return re
}

func buildCheckers(cfg Config) (*TunnelChecker, *EgressChecker) {
	d, err := cfg.Durations()
	if err != nil {
		fatal("config: %v", err)
	}
	tc := &TunnelChecker{
		Iface:      cfg.Interface,
		MaxAge:     d.maxHandshakeAge,
		PingTarget: cfg.PingTarget,
		Runner:     ExecRunner{},
	}
	eg := &EgressChecker{
		Iface:           cfg.Interface,
		URL:             cfg.ProbeURL,
		CountryRe:       mustRe(cfg.CountryPattern),
		IPRe:            mustRe(cfg.IPPattern),
		Timeout:         d.probeTimeout,
		TTL:             d.probeInterval,
		ExpectedCountry: cfg.ExpectedCountry,
		ExpectedIP:      cfg.ExpectedIP,
		Zones:           cfg.DNSBLZones,
		Logf:            func(format string, args ...any) { slog.Warn(fmt.Sprintf(format, args...)) },
	}
	return tc, eg
}

// openLogFile tees logging into the file sink in addition to the console
// handler installed by Run. The file sink always timestamps: history needs
// the times that journald otherwise provides for the console sink.
func openLogFile(path string) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		fatal("log dir: %v", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		fatal("log file: %v", err)
	}
	slog.SetDefault(slog.New(NewFanoutHandler(slog.Default().Handler(), NewConsoleHandler(f, true))))
}

func runDaemon(cfg Config, configPath string) {
	d, err := cfg.Durations()
	if err != nil {
		fatal("config: %v", err)
	}
	if cfg.LogFile != "" {
		openLogFile(cfg.LogFile)
	}
	live := NewLive(cfg)
	tc, eg := buildCheckers(cfg)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	store := NewStore()
	if cfg.SocketPath != "" {
		srv := NewServer(cfg.SocketPath, store, func() Status {
			return probeNow(live, tc, eg, ctx, store)
		})
		srv.Reloader = makeReloader(configPath, live, tc, eg)
		ln, err := srv.Listen()
		if err != nil {
			fatal("agent socket: %v", err)
		}
		defer srv.Close()
		go func() {
			if serr := srv.Serve(ln); serr != nil {
				slog.Warn("agent server stopped", "err", serr.Error())
			}
		}()
	}

	killLog := func(event string, pid int, comm string, err error) {
		switch {
		case err == nil:
			slog.Warn("sent "+event, "comm", comm, "pid", pid)
		case errors.Is(err, syscall.ESRCH):
			slog.Info("process exited before "+event, "comm", comm, "pid", pid)
		default:
			slog.Error("failed "+event, "comm", comm, "pid", pid, "err", err)
		}
	}
	killer := func() {
		c := live.Get()
		gd, err := c.Durations()
		if err != nil {
			gd = d
		}
		_, err = killTargets(ctx, c.Targets, killOptions{
			Lister: procLister{},
			Grace:  gd.killGrace,
			Log:    killLog,
		})
		if err != nil {
			slog.Error("target enforcement incomplete", "err", err)
		}
	}
	tunnel := func() (bool, string) {
		ok, reason := tc.Check(ctx)
		if !ok {
			eg.Invalidate()
		}
		return ok, reason
	}
	egress := func() (bool, string) {
		result := eg.evaluate(ctx, false)
		if result.Probed {
			if result.OK {
				slog.Info("egress verified", "country", result.Country, "ip", result.IP)
			} else {
				slog.Warn("egress check failed", "reason", result.Reason,
					"observed_country", result.Country, "observed_ip", result.IP)
			}
		}
		return result.OK, result.Reason
	}
	proof := func() (string, string) {
		ip, country, _ := eg.Proof()
		return ip, country
	}
	logf := func(format string, args ...any) { slog.Info(fmt.Sprintf(format, args...)) }

	if err := runWatchdog(ctx, live,
		tunnel,
		egress,
		proof,
		killer,
		store,
		logf,
	); err != nil && ctx.Err() == nil {
		fatal("watchdog: %v", err)
	}
}

// makeReloader hot-applies safe settings and reports service-specific
// lifecycle work for settings wired at startup.
func makeReloader(configPath string, live *Live, tc *TunnelChecker, eg *EgressChecker) func() (reloadResult, error) {
	return func() (reloadResult, error) {
		newCfg, err := LoadConfig(configPath)
		if err != nil {
			return reloadResult{}, err
		}
		if err := newCfg.Validate(); err != nil {
			return reloadResult{}, err
		}
		old := live.Get()
		changed := diffKeys(old, newCfg)
		result := classifyReload(changed)

		effective := newCfg
		effective.Interface = old.Interface
		effective.SocketPath = old.SocketPath
		effective.LogFile = old.LogFile
		if err := eg.Apply(effective); err != nil {
			return reloadResult{}, err
		}
		if err := tc.Apply(effective); err != nil {
			return reloadResult{}, err
		}
		live.Set(effective)
		slog.Info("config reloaded", "changed", strings.Join(changed, ","))
		return result, nil
	}
}

func classifyReload(changed []string) reloadResult {
	result := reloadResult{}
	for _, key := range changed {
		if daemonRestartKeys[key] {
			result.DaemonRestartRequired = append(result.DaemonRestartRequired, key)
		}
		if firewallReloadKeys[key] {
			result.FirewallReloadRequired = append(result.FirewallReloadRequired, key)
		}
		if !daemonRestartKeys[key] && !firewallReloadKeys[key] {
			result.Applied = append(result.Applied, key)
		}
	}
	return result
}

// probeNow runs a full fresh evaluation for the agent "probe" command and
// publishes the result without touching the poll loop's debounce streak.
func probeNow(live *Live, tc *TunnelChecker, eg *EgressChecker, ctx context.Context, store *Store) Status {
	c := live.Get()
	tOK, tReason := tc.Check(ctx)
	result := egressResult{}
	reason := tReason
	if !tOK {
		eg.Invalidate()
	} else if c.VerifyEgress {
		result = eg.evaluate(ctx, true)
		reason = result.Reason
	}
	state := "up"
	if !(tOK && (!c.VerifyEgress || result.OK)) {
		state = "down"
	}
	store.SetProbe(state, reason, result.IP, result.Country)
	return store.Snapshot()
}

// runStatus queries the running daemon's agent socket. With -probe it asks
// for a fresh egress evaluation instead of the cached verdict.
func runStatus(cfg Config, args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	probe := fs.Bool("probe", false, "force a fresh egress evaluation")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if cfg.SocketPath == "" {
		slog.Error("agent socket disabled (socket_path is empty in config)")
		return 1
	}
	cmd := "status"
	if *probe {
		cmd = "probe"
	}
	st, err := Query(cfg.SocketPath, cmd)
	if err != nil {
		slog.Error("agent unavailable", "socket", cfg.SocketPath, "err", err)
		return 1
	}
	fmt.Printf("state=%s streak=%d exit_ip=%s country=%s updated=%s\n",
		st.State, st.Streak, st.ExitIP, st.Country, st.UpdatedAt)
	if st.Reason != "" {
		fmt.Printf("reason=%s\n", st.Reason)
	}
	if st.State != "up" {
		return 1
	}
	return 0
}

// runHistory prints recent events from the log file sink with level
// highlighting (ANSI color on a TTY, plain otherwise).
func runHistory(cfg Config, args []string) int {
	fs := flag.NewFlagSet("history", flag.ContinueOnError)
	n := fs.Int("n", 100, "show the last N entries")
	level := fs.String("level", "info", "minimum level: info|warn|error")
	noColor := fs.Bool("no-color", false, "disable ANSI colors")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if cfg.LogFile == "" {
		slog.Error("log file disabled (log_file is empty in config)")
		return 1
	}
	if *n < 0 || *n > maxHistoryEntries {
		slog.Error(fmt.Sprintf("invalid -n %d (want 0..%d)", *n, maxHistoryEntries))
		return 2
	}
	min, ok := map[string]int{"info": RankInfo, "warn": RankWarn, "error": RankError}[*level]
	if !ok {
		slog.Error(fmt.Sprintf("invalid -level %q (want info|warn|error)", *level))
		return 2
	}
	f, err := os.Open(cfg.LogFile)
	if err != nil {
		slog.Error("cannot read log file", "file", cfg.LogFile, "err", err)
		return 1
	}
	defer f.Close()
	entries, err := ReadRecentEvents(f, min, *n)
	if err != nil {
		slog.Error("cannot parse log file", "file", cfg.LogFile, "err", err)
		return 1
	}
	if err := RenderEntries(os.Stdout, entries, !*noColor && stdoutIsTTY()); err != nil {
		slog.Error(fmt.Sprintf("render: %v", err))
		return 1
	}
	return 0
}

// runConfig implements `reptile config` (display the effective config as a
// table) and `reptile config set key value ...` (validate + persist, then
// hot-reload the running daemon via its agent socket).
func runConfig(configPath string, args []string) int {
	if len(args) == 0 || args[0] != "set" {
		if len(args) > 0 {
			slog.Error(fmt.Sprintf("unknown config command %q (want: set)", args[0]))
			return 2
		}
		cfg, err := LoadConfig(configPath)
		if err != nil {
			slog.Error(fmt.Sprintf("load config: %v", err))
			return 1
		}
		if err := RenderConfigTable(os.Stdout, cfg); err != nil {
			slog.Error(fmt.Sprintf("render: %v", err))
			return 1
		}
		return 0
	}

	pairs := args[1:]
	if len(pairs) == 0 {
		slog.Error("usage: reptile config set key value [key value ...]")
		return 2
	}
	current, err := LoadConfig(configPath)
	if err != nil {
		slog.Error(fmt.Sprintf("load current config: %v", err))
		return 1
	}
	fresh, err := SetConfigFileKeys(configPath, pairs)
	if err != nil {
		slog.Error(fmt.Sprintf("config set: %v", err))
		return 1
	}
	required := classifyReload(diffKeys(current, fresh))
	if current.SocketPath == "" {
		slog.Info("saved; agent socket disabled, daemon changes apply on next start")
		if len(required.FirewallReloadRequired) > 0 {
			slog.Warn("firewall reload required",
				"keys", strings.Join(required.FirewallReloadRequired, ","),
				"command", "systemctl reload reptile-firewall")
		}
		return 0
	}
	resp, err := QueryResponse(current.SocketPath, "reload")
	if err != nil {
		slog.Warn("daemon not reloaded live", "err", err.Error())
		slog.Info("daemon changes apply on next start", "command", "systemctl restart reptile")
		if len(required.FirewallReloadRequired) > 0 {
			slog.Warn("firewall reload required",
				"keys", strings.Join(required.FirewallReloadRequired, ","),
				"command", "systemctl reload reptile-firewall")
		}
		return 0
	}
	if len(resp.Applied) > 0 {
		slog.Info("applied live", "keys", strings.Join(resp.Applied, ","))
	}
	if len(resp.DaemonRestartRequired) > 0 {
		slog.Warn("daemon restart required",
			"keys", strings.Join(resp.DaemonRestartRequired, ","),
			"command", "systemctl restart reptile")
	}
	if len(resp.FirewallReloadRequired) > 0 {
		slog.Warn("firewall reload required",
			"keys", strings.Join(resp.FirewallReloadRequired, ","),
			"command", "systemctl reload reptile-firewall")
	}
	if len(resp.Applied) == 0 &&
		len(resp.DaemonRestartRequired) == 0 &&
		len(resp.FirewallReloadRequired) == 0 {
		slog.Info("daemon reports no effective changes")
	}
	return 0
}

// runCheck performs one full evaluation; exit 0 means every configured
// condition holds right now. Intended for post-install verification.
func runCheck(cfg Config) int {
	tc, eg := buildCheckers(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	up, reason := tc.Check(ctx)
	if !up {
		slog.Error("tunnel: DOWN", "interface", cfg.Interface, "reason", reason)
		return 1
	}
	slog.Info("tunnel: UP", "interface", cfg.Interface)
	if !cfg.VerifyEgress {
		return 0
	}
	result := eg.evaluate(ctx, false)
	if !result.OK {
		slog.Error("egress: FAILED", "reason", result.Reason)
		return 1
	}
	slog.Info("egress: OK",
		"expected_country", cfg.ExpectedCountry,
		"ip", result.IP,
		"country", result.Country,
	)
	return 0
}

func runFirewall(cfg Config, action string) {
	switch action {
	case "up":
		endpoints, err := parseEndpoints(cfg.WGConf)
		if err != nil {
			fatal("firewall: %v", err)
		}
		if err := ApplyRuleset(buildRuleset(cfg.Interface, endpoints, cfg.ExtraAccept)); err != nil {
			fatal("firewall: %v", err)
		}
		slog.Info("kill-switch firewall engaged", "interface", cfg.Interface, "transport_endpoints", endpoints)
	case "down":
		if err := ApplyDown(); err != nil {
			fatal("firewall: %v", err)
		}
		slog.Info("kill-switch firewall removed")
	default:
		fatal("usage: reptile firewall up|down")
	}
}

package app

import (
	"context"
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

// restartRequiredKeys are settings that only take effect when the daemon
// restarts (they wire up listeners, log sinks or runners at startup).
var restartRequiredKeys = map[string]bool{
	"interface":          true,
	"socket_path":        true,
	"log_file":           true,
	"wg_conf":            true,
	"extra_accept":       true,
	"heartbeat_interval": true,
}

func Run() {
	var (
		configPath = flag.String("config", defaultConfigPath, "path to config.json")
		ifaceFlag  = flag.String("interface", "", "override the WireGuard interface from config")
	)
	flag.Parse()

	// Under journald stderr is a pipe and the journal timestamps every line,
	// so the handler omits its own clock; interactively it adds short time.
	slog.SetDefault(slog.New(NewConsoleHandler(os.Stderr, stderrIsTTY())))

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

	killLog := func(event string, pid int, comm string) {
		if event == "list_failed" {
			slog.Warn("process listing failed - cannot scan for target processes")
			return
		}
		slog.Warn("sent "+event, "comm", comm, "pid", pid)
	}
	killer := func() {
		c := live.Get()
		gd, err := c.Durations()
		if err != nil {
			gd = d
		}
		KillTargets(ctx, procLister{}, c.Targets, gd.killGrace, killLog)
	}
	egress := func() (bool, string) {
		ok, reason := eg.Check(ctx)
		if eg.Probed {
			if ok {
				slog.Info("egress verified", "country", eg.LastCountry, "ip", eg.LastIP)
			} else {
				slog.Warn("egress check failed", "reason", reason,
					"observed_country", eg.LastCountry, "observed_ip", eg.LastIP)
			}
		}
		return ok, reason
	}
	proof := func() (string, string) {
		st := store.Snapshot()
		return st.ExitIP, st.Country
	}
	logf := func(format string, args ...any) { slog.Info(fmt.Sprintf(format, args...)) }

	if err := runWatchdog(ctx, live,
		func() (bool, string) { return tc.Check(ctx) },
		egress,
		proof,
		killer,
		store,
		logf,
	); err != nil && ctx.Err() == nil {
		fatal("watchdog: %v", err)
	}
}

// makeReloader returns the agent "reload" implementation: re-read the config
// file, hot-apply everything that can change safely on a running daemon
// (checkers, thresholds, targets, probe settings), and report which changed
// keys need a restart instead.
func makeReloader(configPath string, live *Live, tc *TunnelChecker, eg *EgressChecker) func() ([]string, []string, error) {
	return func() ([]string, []string, error) {
		newCfg, err := LoadConfig(configPath)
		if err != nil {
			return nil, nil, err
		}
		if err := newCfg.Validate(); err != nil {
			return nil, nil, err
		}
		if err := eg.Apply(newCfg); err != nil {
			return nil, nil, err
		}
		if err := tc.Apply(newCfg); err != nil {
			return nil, nil, err
		}
		old := live.Get()
		live.Set(newCfg)
		changed := diffKeys(old, newCfg)
		var restart []string
		for _, k := range changed {
			if restartRequiredKeys[k] {
				restart = append(restart, k)
			}
		}
		slog.Info("config reloaded", "changed", strings.Join(changed, ","))
		return changed, restart, nil
	}
}

// probeNow runs a full fresh evaluation for the agent "probe" command and
// publishes the result without touching the poll loop's debounce streak.
func probeNow(live *Live, tc *TunnelChecker, eg *EgressChecker, ctx context.Context, store *Store) Status {
	c := live.Get()
	tOK, tReason := tc.Check(ctx)
	eOK := false
	reason := tReason
	if c.VerifyEgress && tOK {
		eOK, reason = eg.CheckFresh(ctx)
	}
	state := "up"
	if !(tOK && (!c.VerifyEgress || eOK)) {
		state = "down"
	}
	store.Set(state, store.Snapshot().Streak, reason, eg.LastIP, eg.LastCountry)
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
	data, err := os.ReadFile(cfg.LogFile)
	if err != nil {
		slog.Error("cannot read log file", "file", cfg.LogFile, "err", err)
		return 1
	}
	min, ok := map[string]int{"info": RankInfo, "warn": RankWarn, "error": RankError}[*level]
	if !ok {
		slog.Error(fmt.Sprintf("invalid -level %q (want info|warn|error)", *level))
		return 2
	}
	entries := ParseEvents(strings.Split(string(data), "\n"))
	entries = FilterMin(entries, min)
	if len(entries) > *n {
		entries = entries[len(entries)-*n:]
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
	if _, err := SetConfigFileKeys(configPath, pairs); err != nil {
		slog.Error(fmt.Sprintf("config set: %v", err))
		return 1
	}

	fresh, err := LoadConfig(configPath)
	if err != nil {
		slog.Error(fmt.Sprintf("reload config: %v", err))
		return 1
	}
	if fresh.SocketPath == "" {
		slog.Info("saved; agent socket disabled, changes apply on next start")
		return 0
	}
	resp, err := QueryResponse(fresh.SocketPath, "reload")
	switch {
	case err == nil:
		if len(resp.Applied) > 0 {
			slog.Info("applied live", "keys", strings.Join(resp.Applied, ","))
		} else {
			slog.Info("daemon reports no effective changes")
		}
		if len(resp.RestartRequired) > 0 {
			slog.Warn("restart required for these keys", "keys", strings.Join(resp.RestartRequired, ","))
		}
	default:
		slog.Warn("daemon not reloaded live", "err", err.Error())
		slog.Info("changes apply on next start: systemctl restart reptile")
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
	ok, ereason := eg.Check(ctx)
	if !ok {
		slog.Error("egress: FAILED", "reason", ereason)
		return 1
	}
	slog.Info("egress: OK", "expected_country", cfg.ExpectedCountry, "ip", eg.LastIP, "country", eg.LastCountry)
	return 0
}

func runFirewall(cfg Config, action string) {
	switch action {
	case "up":
		ports, err := EndpointPorts(cfg.WGConf)
		if err != nil {
			fatal("firewall: %v", err)
		}
		if err := ApplyRuleset(BuildRuleset(cfg.Interface, ports, cfg.ExtraAccept)); err != nil {
			fatal("firewall: %v", err)
		}
		slog.Info("kill-switch firewall engaged", "interface", cfg.Interface, "transport_ports", ports)
	case "down":
		if err := ApplyDown(); err != nil {
			fatal("firewall: %v", err)
		}
		slog.Info("kill-switch firewall removed")
	default:
		fatal("usage: reptile firewall up|down")
	}
}

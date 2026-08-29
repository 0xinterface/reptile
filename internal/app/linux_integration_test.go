//go:build integration && linux

package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const integrationRequiredEnv = "REPTILE_REQUIRE_INTEGRATION"

func requireIntegration(t *testing.T, commands ...string) {
	t.Helper()
	missing := ""
	if os.Geteuid() != 0 {
		missing = "root privileges"
	}
	for _, command := range commands {
		if _, err := exec.LookPath(command); err != nil {
			missing = command
			break
		}
	}
	if missing == "" {
		return
	}
	if os.Getenv(integrationRequiredEnv) == "1" {
		t.Fatalf("required integration prerequisite unavailable: %s", missing)
	}
	t.Skipf("integration prerequisite unavailable: %s", missing)
}

func runCommand(t *testing.T, name string, args ...string) string {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

func netnsName(prefix string) string {
	name := prefix + strconv.Itoa(os.Getpid())
	if len(name) > 15 {
		name = name[:15]
	}
	return name
}

func TestFirewallNamespace(t *testing.T) {
	switch os.Getenv("REPTILE_NETNS_HELPER") {
	case "server":
		runUDPEchoServer()
		return
	case "client":
		runUDPClient(os.Getenv("REPTILE_NETNS_ADDRESS"))
		return
	}

	requireIntegration(t, "ip", "nft")
	clientNS := netnsName("rptc")
	serverNS := netnsName("rpts")
	clientLink := netnsName("rvc")
	serverLink := netnsName("rvs")
	for _, namespace := range []string{clientNS, serverNS} {
		_ = exec.Command("ip", "netns", "del", namespace).Run()
	}
	t.Cleanup(func() {
		_ = exec.Command("ip", "netns", "del", clientNS).Run()
		_ = exec.Command("ip", "netns", "del", serverNS).Run()
	})

	runCommand(t, "ip", "netns", "add", clientNS)
	runCommand(t, "ip", "netns", "add", serverNS)
	runCommand(t, "ip", "link", "add", clientLink, "type", "veth", "peer", "name", serverLink)
	runCommand(t, "ip", "link", "set", clientLink, "netns", clientNS)
	runCommand(t, "ip", "link", "set", serverLink, "netns", serverNS)
	runCommand(t, "ip", "-n", clientNS, "addr", "add", "10.203.0.2/24", "dev", clientLink)
	runCommand(t, "ip", "-n", serverNS, "addr", "add", "10.203.0.1/24", "dev", serverLink)
	runCommand(t, "ip", "-n", serverNS, "addr", "add", "10.203.0.3/24", "dev", serverLink)
	for _, pair := range [][2]string{{clientNS, clientLink}, {serverNS, serverLink}} {
		runCommand(t, "ip", "-n", pair[0], "link", "set", "lo", "up")
		runCommand(t, "ip", "-n", pair[0], "link", "set", pair[1], "up")
	}

	rules := buildRuleset(
		"wg0",
		[]endpoint{{IP: net.ParseIP("10.203.0.1"), Port: "51820"}},
		nil,
	)
	rulesPath := filepath.Join(t.TempDir(), "reptile.nft")
	if err := os.WriteFile(rulesPath, []byte(rules), 0o600); err != nil {
		t.Fatal(err)
	}
	runCommand(t, "ip", "netns", "exec", clientNS, "nft", "-f", rulesPath)

	server := exec.Command(
		"ip", "netns", "exec", serverNS,
		os.Args[0], "-test.run=^TestFirewallNamespace$",
	)
	server.Env = append(os.Environ(), "REPTILE_NETNS_HELPER=server")
	serverOutput := &strings.Builder{}
	server.Stdout, server.Stderr = serverOutput, serverOutput
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = server.Process.Kill()
		_ = server.Wait()
	})

	deadline := time.Now().Add(3 * time.Second)
	var allowedErr error
	for time.Now().Before(deadline) {
		allowedErr = runNetnsUDPClient(clientNS, "10.203.0.1:51820")
		if allowedErr == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if allowedErr != nil {
		t.Fatalf("configured endpoint was blocked: %v\nserver: %s", allowedErr, serverOutput)
	}

	err := runNetnsUDPClient(clientNS, "10.203.0.3:51820")
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 3 {
		t.Fatalf("same port on an unconfigured address was not dropped: %v", err)
	}
}

func runUDPEchoServer() {
	conn, err := net.ListenPacket("udp4", "0.0.0.0:51820")
	if err != nil {
		os.Exit(2)
	}
	defer conn.Close()
	buf := make([]byte, 64)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			os.Exit(2)
		}
		if _, err := conn.WriteTo(buf[:n], addr); err != nil {
			os.Exit(2)
		}
	}
}

func runUDPClient(address string) {
	remote, err := net.ResolveUDPAddr("udp4", address)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	conn, err := net.DialUDP("udp4", nil, remote)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := conn.Write([]byte("proof")); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
	if string(buf[:n]) != "proof" {
		fmt.Fprintf(os.Stderr, "unexpected echo %q\n", buf[:n])
		os.Exit(4)
	}
}

func runNetnsUDPClient(namespace, address string) error {
	cmd := exec.Command(
		"ip", "netns", "exec", namespace,
		os.Args[0], "-test.run=^TestFirewallNamespace$",
	)
	cmd.Env = append(os.Environ(),
		"REPTILE_NETNS_HELPER=client",
		"REPTILE_NETNS_ADDRESS="+address,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func TestInstalledSystemdSandbox(t *testing.T) {
	if os.Getenv("REPTILE_SYSTEMD_HELPER") == "1" {
		cfg, err := LoadConfig(os.Getenv("REPTILE_SYSTEMD_CONFIG"))
		if err != nil {
			t.Fatal(err)
		}
		if err := cfg.Validate(); err != nil {
			t.Fatal(err)
		}
		configureLogging()
		runDaemon(cfg, os.Getenv("REPTILE_SYSTEMD_CONFIG"))
		return
	}

	requireIntegration(t, "systemctl", "systemd-run")
	state, err := exec.Command("systemctl", "is-system-running").CombinedOutput()
	stateName := strings.TrimSpace(string(state))
	if err != nil && stateName != "degraded" {
		if os.Getenv(integrationRequiredEnv) == "1" {
			t.Fatalf("systemd is not running: %s (%v)", stateName, err)
		}
		t.Skipf("systemd is not running: %s", stateName)
	}

	suffix := strconv.Itoa(os.Getpid())
	unit := "reptile-integration-" + suffix
	directoryName := unit
	stateDir := filepath.Join("/var/lib", directoryName)
	runtimeDir := filepath.Join("/run", directoryName)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(stateDir)
		_ = os.RemoveAll(runtimeDir)
	})
	binaryPath := filepath.Join(stateDir, "integration-test-"+suffix)
	configPath := filepath.Join(stateDir, "integration-config-"+suffix+".json")
	logPath := filepath.Join(stateDir, "integration-events-"+suffix+".log")
	socketPath := filepath.Join(runtimeDir, "integration-agent-"+suffix+".sock")
	for _, path := range []string{binaryPath, configPath, logPath, socketPath} {
		path := path
		t.Cleanup(func() { _ = os.Remove(path) })
	}
	if err := copyFile(os.Args[0], binaryPath, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := Defaults()
	cfg.Interface = "wg-test"
	cfg.PollInterval = "20ms"
	cfg.MaxHandshakeAge = "1s"
	cfg.DownCyclesToKill = 1
	cfg.KillGrace = "0s"
	cfg.HeartbeatInterval = "0s"
	cfg.VerifyEgress = false
	cfg.ExpectedCountry = ""
	cfg.Targets = []string{"no-such-process"}
	cfg.SocketPath = socketPath
	cfg.LogFile = logPath
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	args := []string{
		"--unit=" + unit,
		"--property=Type=simple",
		"--property=RemainAfterExit=yes",
		"--property=TimeoutStopSec=5s",
		"--property=NoNewPrivileges=yes",
		"--property=ProtectSystem=strict",
		"--property=ProtectHome=yes",
		"--property=PrivateTmp=yes",
		"--property=RuntimeDirectory=" + directoryName,
		"--property=RuntimeDirectoryMode=0700",
		"--property=StateDirectory=" + directoryName,
		"--property=StateDirectoryMode=0700",
		"--property=UMask=0077",
		"--property=CapabilityBoundingSet=CAP_KILL CAP_NET_ADMIN CAP_NET_RAW",
		"--property=RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK",
		"--setenv=REPTILE_SYSTEMD_HELPER=1",
		"--setenv=REPTILE_SYSTEMD_CONFIG=" + configPath,
		binaryPath,
		"-test.run=^TestInstalledSystemdSandbox$",
	}
	if out, err := exec.Command("systemd-run", args...).CombinedOutput(); err != nil {
		t.Fatalf("systemd-run: %v\n%s", err, out)
	}
	stopped := false
	t.Cleanup(func() {
		if !stopped {
			_ = exec.Command("systemctl", "stop", unit).Run()
		}
		_ = exec.Command("systemctl", "reset-failed", unit).Run()
	})

	deadline := time.Now().Add(5 * time.Second)
	queryErr := errors.New("agent socket was not created")
	for time.Now().Before(deadline) {
		if _, err := os.Stat(socketPath); err == nil {
			_, queryErr = Query(socketPath, "status")
			if queryErr == nil {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if queryErr != nil {
		journal, _ := exec.Command("journalctl", "-u", unit, "--no-pager", "-n", "50").CombinedOutput()
		t.Fatalf("sandboxed daemon did not serve its socket: %v\n%s", queryErr, journal)
	}
	var logBody []byte
	logDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(logDeadline) {
		logBody, err = os.ReadFile(logPath)
		if err == nil && strings.Contains(string(logBody), "watchdog started") {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("sandboxed daemon did not create its state log: %v", err)
	}
	if !strings.Contains(string(logBody), "watchdog started") {
		t.Fatalf("state log lacks startup event after readiness wait: %s", logBody)
	}
	if info, err := os.Stat(socketPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %v, err=%v; want 0600", info, err)
	}
	if output := runCommand(t, "systemctl", "is-active", unit); strings.TrimSpace(output) != "active" {
		t.Fatalf("unit state = %q, want active", output)
	}
	if out, err := exec.Command("systemctl", "stop", unit).CombinedOutput(); err != nil {
		t.Fatalf("sandboxed daemon did not stop cleanly: %v\n%s", err, out)
	}
	stopped = true
	result := runCommand(
		t,
		"systemctl",
		"show",
		"--property=Result",
		"--property=ExecMainCode",
		"--property=ExecMainStatus",
		unit,
	)
	for _, want := range []string{"Result=success", "ExecMainStatus=0"} {
		if !strings.Contains(result, want) {
			t.Fatalf("unclean daemon shutdown (%s missing):\n%s", want, result)
		}
	}
}

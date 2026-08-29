package app

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

const nftTable = "inet reptile"

var endpointRe = regexp.MustCompile(`(?i)^\s*Endpoint\s*=\s*(.+)$`)

// EndpointPorts extracts the unique transport ports of every Endpoint in a
// wg-quick config. Hostname endpoints and [v6]:port forms are handled.
// Without these ports allowed in the kill-switch firewall, the tunnel could
// never re-establish, so a missing port is a hard error.
func EndpointPorts(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := map[string]bool{}
	var ports []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		m := endpointRe.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		host := strings.TrimSpace(m[1])
		i := strings.LastIndex(host, ":")
		if i < 0 {
			continue
		}
		p := host[i+1:]
		if !isPort(p) {
			continue
		}
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("no numeric Endpoint port found in %s: the kill-switch firewall would block the tunnel from ever reconnecting", path)
	}
	return ports, nil
}

func isPort(s string) bool {
	if len(s) == 0 || len(s) > 5 {
		return false
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
		n = n*10 + int(r-'0')
	}
	return n >= 1 && n <= 65535
}

// BuildRuleset renders the always-on egress kill switch: everything leaving
// the host is dropped except loopback, the tunnel itself, the WireGuard
// transport ports (so the tunnel can reconnect), DHCP renewal, and any
// user-supplied extra accepts.
func BuildRuleset(iface string, ports, extra []string) string {
	var b strings.Builder
	b.WriteString("table " + nftTable + " {\n")
	b.WriteString("  chain out {\n")
	b.WriteString("    type filter hook output priority filter; policy drop;\n")
	b.WriteString("    oifname \"lo\" accept\n")
	fmt.Fprintf(&b, "    oifname %q accept\n", iface)
	b.WriteString("    ct state established,related accept\n")
	for _, p := range ports {
		fmt.Fprintf(&b, "    udp dport %s accept\n", p)
	}
	b.WriteString("    udp sport 68 udp dport 67 accept\n")
	b.WriteString("    udp sport 546 udp dport 547 accept\n")
	for _, e := range extra {
		fmt.Fprintf(&b, "    %s\n", strings.TrimSpace(e))
	}
	b.WriteString("  }\n")
	b.WriteString("}\n")
	return b.String()
}

func nftRun(args ...string) error {
	cmd := exec.Command("nft", args...)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// ApplyRuleset atomically hands the ruleset to nft on stdin, then verifies
// the table exists.
func ApplyRuleset(rs string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rs)
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("nft -f -: %w", err)
	}
	if err := nftRun("list", "table", "inet", "reptile"); err != nil {
		return fmt.Errorf("post-load verification failed: %w", err)
	}
	return nil
}

// ApplyDown removes the table. A missing table (fresh host, already removed)
// is not an error; a missing nft binary is.
func ApplyDown() error {
	err := nftRun("delete", "table", "inet", "reptile")
	if _, isExit := err.(*exec.ExitError); isExit {
		return nil
	}
	return err
}

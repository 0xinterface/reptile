package app

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

const nftTable = "inet reptile"

var endpointRe = regexp.MustCompile(`(?i)^\s*Endpoint\s*=\s*(.+)$`)

type endpoint struct {
	IP   net.IP
	Port string
}

// parseEndpoints extracts literal endpoint address-and-port tuples from a
// wg-quick config. Hostnames are rejected: permitting a port without its
// resolved address would create a general-purpose non-tunnel UDP bypass.
func parseEndpoints(path string) ([]endpoint, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := map[string]bool{}
	endpoints := []endpoint{}
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		m := endpointRe.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		raw := strings.TrimSpace(m[1])
		host, port, err := net.SplitHostPort(raw)
		if err != nil || !isPort(port) {
			return nil, fmt.Errorf("%s:%d: invalid Endpoint %q", path, line, raw)
		}
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, fmt.Errorf("%s:%d: Endpoint %q uses a hostname; the fail-closed firewall requires a literal IP address", path, line, raw)
		}
		key := ip.String() + ":" + port
		if !seen[key] {
			seen[key] = true
			endpoints = append(endpoints, endpoint{IP: ip, Port: port})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(endpoints) == 0 {
		return nil, fmt.Errorf("no valid Endpoint found in %s: the kill-switch firewall would block the tunnel from reconnecting", path)
	}
	return endpoints, nil
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

// buildRuleset renders the always-on egress kill switch. Physical-interface
// traffic is limited to exact WireGuard endpoints, DHCP, and the IPv6 control
// packets needed to discover an on-link router or endpoint.
func buildRuleset(iface string, endpoints []endpoint, extra []string) string {
	var b strings.Builder
	b.WriteString("table " + nftTable + " {\n")
	b.WriteString("  chain out {\n")
	b.WriteString("    type filter hook output priority filter; policy drop;\n")
	b.WriteString("    oifname \"lo\" accept\n")
	fmt.Fprintf(&b, "    oifname %q accept\n", iface)
	for _, ep := range endpoints {
		if ep.IP.To4() != nil {
			fmt.Fprintf(&b, "    ip daddr %s udp dport %s accept\n", ep.IP.String(), ep.Port)
		} else {
			fmt.Fprintf(&b, "    ip6 daddr %s udp dport %s accept\n", ep.IP.String(), ep.Port)
		}
	}
	b.WriteString("    udp sport 68 udp dport 67 accept\n")
	b.WriteString("    udp sport 546 udp dport 547 accept\n")
	b.WriteString("    icmpv6 type { nd-router-solicit, nd-neighbor-solicit } accept\n")
	for _, e := range extra {
		fmt.Fprintf(&b, "    %s\n", strings.TrimSpace(e))
	}
	b.WriteString("  }\n")
	b.WriteString("}\n")
	return b.String()
}

func nftTablePresent() (bool, error) {
	out, err := exec.Command("nft", "list", "tables").CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("nft list tables: %w: %s", err, strings.TrimSpace(string(out)))
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && f[0] == "table" && f[1] == "inet" && f[2] == "reptile" {
			return true, nil
		}
	}
	return false, nil
}

// ApplyRuleset replaces the table in one nft transaction, then verifies it.
func ApplyRuleset(rs string) error {
	present, err := nftTablePresent()
	if err != nil {
		return err
	}
	if present {
		rs = "delete table " + nftTable + "\n" + rs
	}
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rs)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft -f -: %w: %s", err, strings.TrimSpace(string(out)))
	}
	present, err = nftTablePresent()
	if err != nil {
		return fmt.Errorf("post-load verification failed: %w", err)
	}
	if !present {
		return fmt.Errorf("post-load verification failed: table %s is absent", nftTable)
	}
	return nil
}

// ApplyDown removes the table. An already absent table is successful; every
// actual nft failure is returned.
func ApplyDown() error {
	present, err := nftTablePresent()
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	out, err := exec.Command("nft", "delete", "table", "inet", "reptile").CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft delete table %s: %w: %s", nftTable, err, strings.TrimSpace(string(out)))
	}
	return nil
}

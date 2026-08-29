package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeWgConf(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "wg0.conf")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEndpointPortsSingle(t *testing.T) {
	p := writeWgConf(t, `
[Interface]
PrivateKey = xxx

[Peer]
PublicKey = yyy
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0
`)
	ports, err := EndpointPorts(p)
	if err != nil {
		t.Fatalf("EndpointPorts: %v", err)
	}
	if len(ports) != 1 || ports[0] != "51820" {
		t.Errorf("ports = %v, want [51820]", ports)
	}
}

func TestEndpointPortsMultiplePeersV6(t *testing.T) {
	p := writeWgConf(t, `
[Peer]
Endpoint = 203.0.113.7:51820

[Peer]
Endpoint = [2001:db8::1]:47111

[Peer]
AllowedIPs = 10.0.0.0/8
`)
	ports, err := EndpointPorts(p)
	if err != nil {
		t.Fatalf("EndpointPorts: %v", err)
	}
	if len(ports) != 2 || ports[0] != "51820" || ports[1] != "47111" {
		t.Errorf("ports = %v, want [51820 47111]", ports)
	}
}

func TestEndpointPortsNoneIsError(t *testing.T) {
	p := writeWgConf(t, "[Peer]\nAllowedIPs = 0.0.0.0/0\n")
	if _, err := EndpointPorts(p); err == nil {
		t.Fatal("missing endpoints must error: tunnel could never reconnect")
	}
	p2 := writeWgConf(t, "Endpoint = host:notaport\n")
	if _, err := EndpointPorts(p2); err == nil {
		t.Fatal("non-numeric endpoint port must error")
	}
}

func TestBuildRuleset(t *testing.T) {
	rs := BuildRuleset("wg0", []string{"51820", "47111"},
		[]string{"ip daddr 10.0.0.0/8 accept", "udp dport 53 accept"})
	for _, want := range []string{
		"table inet reptile {",
		"type filter hook output priority filter; policy drop;",
		`oifname "lo" accept`,
		`oifname "wg0" accept`,
		"ct state established,related accept",
		"udp dport 51820 accept",
		"udp dport 47111 accept",
		"udp sport 68 udp dport 67 accept",
		"udp sport 546 udp dport 547 accept",
		"ip daddr 10.0.0.0/8 accept",
		"udp dport 53 accept",
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset missing %q\nruleset:\n%s", want, rs)
		}
	}
	if open, close := strings.Count(rs, "{"), strings.Count(rs, "}"); open != close {
		t.Errorf("unbalanced braces: %d open vs %d close\n%s", open, close, rs)
	}
}

// ApplyRuleset/ApplyDown must exec the real `nft` binary; here a stub on PATH
// captures stdin so we can assert exactly what would be handed to nft.
func TestApplyRulesetAndDown(t *testing.T) {
	bin := t.TempDir()
	nft := filepath.Join(bin, "nft")
	script := `#!/bin/sh
case "$1 $2" in
  "-f -") cat > "$NFT_OUT"; exit 0 ;;
  "list table") echo "table inet reptile {}"; exit 0 ;;
  "delete table") echo delete > "$NFT_MODE"; exit 0 ;;
esac
exit 1
`
	if err := os.WriteFile(nft, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("NFT_OUT", filepath.Join(t.TempDir(), "rules"))
	t.Setenv("NFT_MODE", filepath.Join(t.TempDir(), "mode"))

	rs := BuildRuleset("wg0", []string{"51820"}, nil)
	if err := ApplyRuleset(rs); err != nil {
		t.Fatalf("ApplyRuleset: %v", err)
	}
	got, err := os.ReadFile(os.Getenv("NFT_OUT"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != rs {
		t.Error("nft did not receive ruleset verbatim")
	}
	if err := ApplyDown(); err != nil {
		t.Fatalf("ApplyDown: %v", err)
	}
	mode, _ := os.ReadFile(os.Getenv("NFT_MODE"))
	if strings.TrimSpace(string(mode)) != "delete" {
		t.Errorf("ApplyDown mode = %q, want delete", mode)
	}
}

func TestApplyRulesetNftFailure(t *testing.T) {
	bin := t.TempDir()
	nft := filepath.Join(bin, "nft")
	if err := os.WriteFile(nft, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := ApplyRuleset("table inet reptile {}\n"); err == nil {
		t.Fatal("nft failure must propagate as error")
	}
}

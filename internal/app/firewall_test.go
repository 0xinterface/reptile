package app

import (
	"net"
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

func TestParseEndpointsLiteralAddresses(t *testing.T) {
	p := writeWgConf(t, `
[Peer]
Endpoint = 203.0.113.7:51820

[Peer]
Endpoint = [2001:db8::1]:47111
`)
	endpoints, err := parseEndpoints(p)
	if err != nil {
		t.Fatalf("parseEndpoints: %v", err)
	}
	if len(endpoints) != 2 {
		t.Fatalf("endpoints = %v, want two", endpoints)
	}
	if got := endpoints[0].IP.String() + ":" + endpoints[0].Port; got != "203.0.113.7:51820" {
		t.Errorf("IPv4 endpoint = %q", got)
	}
	if got := "[" + endpoints[1].IP.String() + "]:" + endpoints[1].Port; got != "[2001:db8::1]:47111" {
		t.Errorf("IPv6 endpoint = %q", got)
	}
}

func TestParseEndpointsRejectsUnsafeValues(t *testing.T) {
	cases := map[string]string{
		"missing":  "[Peer]\nAllowedIPs = 0.0.0.0/0\n",
		"bad port": "Endpoint = 203.0.113.7:notaport\n",
		"hostname": "Endpoint = vpn.example.com:51820\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseEndpoints(writeWgConf(t, body)); err == nil {
				t.Fatalf("%s endpoint accepted", name)
			}
		})
	}
}

func TestBuildRulesetIsEndpointConstrained(t *testing.T) {
	rs := buildRuleset(
		"wg0",
		[]endpoint{
			{IP: net.ParseIP("203.0.113.7"), Port: "51820"},
			{IP: net.ParseIP("2001:db8::1"), Port: "47111"},
		},
		[]string{"ip daddr 10.0.0.0/8 accept"},
	)
	for _, want := range []string{
		"table inet reptile {",
		"type filter hook output priority filter; policy drop;",
		`oifname "lo" accept`,
		`oifname "wg0" accept`,
		"ip daddr 203.0.113.7 udp dport 51820 accept",
		"ip6 daddr 2001:db8::1 udp dport 47111 accept",
		"udp sport 68 udp dport 67 accept",
		"udp sport 546 udp dport 547 accept",
		"icmpv6 type { nd-router-solicit, nd-neighbor-solicit } accept",
		"ip daddr 10.0.0.0/8 accept",
	} {
		if !strings.Contains(rs, want) {
			t.Errorf("ruleset missing %q\nruleset:\n%s", want, rs)
		}
	}
	for _, unsafe := range []string{
		"ct state established,related accept",
		"\n    udp dport 51820 accept\n",
	} {
		if strings.Contains(rs, unsafe) {
			t.Errorf("ruleset contains unconstrained rule %q\n%s", unsafe, rs)
		}
	}
}

func installNftStub(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	script := `#!/bin/sh
case "$1 $2" in
  "list tables")
    if [ -f "$NFT_MODE" ] && [ "$(cat "$NFT_MODE")" = present ]; then
      echo "table inet reptile"
    fi
    exit 0
    ;;
  "-f -")
    cat > "$NFT_OUT"
    echo present > "$NFT_MODE"
    exit 0
    ;;
  "delete table")
    if [ "$NFT_DELETE_FAIL" = 1 ]; then
      echo "permission denied" >&2
      exit 1
    fi
    echo absent > "$NFT_MODE"
    exit 0
    ;;
esac
exit 1
`
	if err := os.WriteFile(filepath.Join(bin, "nft"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("NFT_OUT", filepath.Join(t.TempDir(), "rules"))
	t.Setenv("NFT_MODE", filepath.Join(t.TempDir(), "mode"))
}

func TestApplyRulesetAndDown(t *testing.T) {
	installNftStub(t)
	rs := buildRuleset(
		"wg0",
		[]endpoint{{IP: net.ParseIP("203.0.113.7"), Port: "51820"}},
		nil,
	)
	if err := ApplyRuleset(rs); err != nil {
		t.Fatalf("ApplyRuleset: %v", err)
	}
	got, err := os.ReadFile(os.Getenv("NFT_OUT"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != rs {
		t.Errorf("nft input differs\n got: %s\nwant: %s", got, rs)
	}
	if err := ApplyDown(); err != nil {
		t.Fatalf("ApplyDown: %v", err)
	}
	mode, err := os.ReadFile(os.Getenv("NFT_MODE"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(mode)) != "absent" {
		t.Errorf("ApplyDown mode = %q, want absent", mode)
	}
}

func TestApplyRulesetAtomicallyReplacesExistingTable(t *testing.T) {
	installNftStub(t)
	if err := os.WriteFile(os.Getenv("NFT_MODE"), []byte("present\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rs := "table inet reptile {}\n"
	if err := ApplyRuleset(rs); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(os.Getenv("NFT_OUT"))
	if err != nil {
		t.Fatal(err)
	}
	if want := "delete table inet reptile\n" + rs; string(got) != want {
		t.Errorf("replacement batch = %q, want %q", got, want)
	}
}

func TestApplyDownPropagatesDeleteFailure(t *testing.T) {
	installNftStub(t)
	if err := os.WriteFile(os.Getenv("NFT_MODE"), []byte("present\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NFT_DELETE_FAIL", "1")
	if err := ApplyDown(); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("ApplyDown error = %v, want permission failure", err)
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

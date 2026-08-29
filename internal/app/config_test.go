package app

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConfigDefaults(t *testing.T) {
	c, err := LoadConfig("")
	if err != nil {
		t.Fatalf(`LoadConfig("") returned error: %v`, err)
	}
	if c.Interface != "wg0" {
		t.Errorf("Interface default = %q, want wg0", c.Interface)
	}
	if c.PollInterval != "10s" {
		t.Errorf("PollInterval default = %q, want 10s", c.PollInterval)
	}
	if c.MaxHandshakeAge != "180s" {
		t.Errorf("MaxHandshakeAge default = %q, want 180s", c.MaxHandshakeAge)
	}
	if c.DownCyclesToKill != 2 {
		t.Errorf("DownCyclesToKill default = %d, want 2", c.DownCyclesToKill)
	}
	if c.KillGrace != "3s" {
		t.Errorf("KillGrace default = %q, want 3s", c.KillGrace)
	}
	if c.HeartbeatInterval != "10m" {
		t.Errorf("HeartbeatInterval default = %q, want 10m", c.HeartbeatInterval)
	}
	if c.SocketPath != "/run/reptile/agent.sock" {
		t.Errorf("SocketPath default = %q, want /run/reptile/agent.sock", c.SocketPath)
	}
	if c.LogFile != "/var/lib/reptile/events.log" {
		t.Errorf("LogFile default = %q, want /var/lib/reptile/events.log", c.LogFile)
	}
	if c.ProbeURL != "https://1.1.1.1/cdn-cgi/trace" {
		t.Errorf("ProbeURL default = %q, want cloudflare trace literal IP", c.ProbeURL)
	}
	if c.CountryPattern == "" || c.IPPattern == "" {
		t.Errorf("default probe patterns must be non-empty, got %q / %q", c.CountryPattern, c.IPPattern)
	}
	if c.WGConf != "/etc/wireguard/wg0.conf" {
		t.Errorf("WGConf default = %q, want /etc/wireguard/wg0.conf", c.WGConf)
	}
	if len(c.DNSBLZones) == 0 {
		t.Error("DNSBLZones default must be non-empty (user asked for blacklist assurance)")
	}
	if !c.VerifyEgress {
		t.Error("VerifyEgress default must be true")
	}
}

func TestLoadConfigFileOverrides(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	body := `{
		"interface": "wg9",
		"targets": ["torrentd", "syncd"],
		"expected_country": "ch",
		"poll_interval": "5s"
	}`
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := LoadConfig(p)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if c.Interface != "wg9" {
		t.Errorf("Interface = %q, want wg9", c.Interface)
	}
	if len(c.Targets) != 2 || c.Targets[0] != "torrentd" {
		t.Errorf("Targets = %v, want [torrentd syncd]", c.Targets)
	}
	if c.ExpectedCountry != "CH" {
		t.Errorf("ExpectedCountry = %q, want normalized CH", c.ExpectedCountry)
	}
	if c.PollInterval != "5s" {
		t.Errorf("PollInterval = %q, want 5s", c.PollInterval)
	}
	if c.MaxHandshakeAge != "180s" {
		t.Errorf("MaxHandshakeAge = %q, want untouched default 180s", c.MaxHandshakeAge)
	}
}

func TestLoadConfigMissingFile(t *testing.T) {
	if _, err := LoadConfig(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func TestConfigValidate(t *testing.T) {
	valid := func() Config {
		c := Defaults()
		c.Targets = []string{"x"}
		c.ExpectedCountry = "CH"
		return c
	}
	if err := valid().Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	noTargets := valid()
	noTargets.Targets = nil
	if err := noTargets.Validate(); err == nil {
		t.Error("empty targets accepted")
	}

	noCountry := valid()
	noCountry.VerifyEgress = true
	noCountry.ExpectedCountry = ""
	if err := noCountry.Validate(); err == nil {
		t.Error("verify_egress without expected_country accepted")
	}

	verifyOffNoCountry := valid()
	verifyOffNoCountry.VerifyEgress = false
	verifyOffNoCountry.ExpectedCountry = ""
	if err := verifyOffNoCountry.Validate(); err != nil {
		t.Errorf("verify_egress=false without country should be fine: %v", err)
	}

	badCycles := valid()
	badCycles.DownCyclesToKill = 0
	if err := badCycles.Validate(); err == nil {
		t.Error("down_cycles_to_kill=0 accepted")
	}

	placeholder := valid()
	placeholder.ExpectedCountry = "CHANGE_ME"
	if err := placeholder.Validate(); err == nil {
		t.Error("placeholder expected_country accepted")
	}

	oneLetter := valid()
	oneLetter.ExpectedCountry = "D"
	if err := oneLetter.Validate(); err == nil {
		t.Error("1-letter expected_country accepted")
	}
}

func TestConfigDurations(t *testing.T) {
	c := Defaults()
	c.Targets = []string{"x"}
	c.ExpectedCountry = "CH"
	d, err := c.Durations()
	if err != nil {
		t.Fatalf("Durations: %v", err)
	}
	if d.poll != 10*time.Second {
		t.Errorf("poll = %v, want 10s", d.poll)
	}
	if d.maxHandshakeAge != 180*time.Second {
		t.Errorf("maxHandshakeAge = %v, want 180s", d.maxHandshakeAge)
	}
	if d.killGrace != 3*time.Second {
		t.Errorf("killGrace = %v, want 3s", d.killGrace)
	}
	if d.probeInterval != 300*time.Second {
		t.Errorf("probeInterval = %v, want 300s", d.probeInterval)
	}
	if d.probeTimeout != 5*time.Second {
		t.Errorf("probeTimeout = %v, want 5s", d.probeTimeout)
	}

	c.PollInterval = "nonsense"
	if _, err := c.Durations(); err == nil {
		t.Error("invalid duration string accepted")
	}
}

func TestConfigHeartbeatDuration(t *testing.T) {
	c := Defaults()
	c.Targets = []string{"x"}
	c.ExpectedCountry = "CH"
	d, err := c.Durations()
	if err != nil {
		t.Fatalf("Durations: %v", err)
	}
	if d.heartbeat != 10*time.Minute {
		t.Errorf("heartbeat = %v, want 10m", d.heartbeat)
	}
	c.HeartbeatInterval = "0s"
	if d, err = c.Durations(); err != nil || d.heartbeat != 0 {
		t.Errorf("heartbeat_interval 0s = %v, err %v; want 0/disabled", d.heartbeat, err)
	}
	c.HeartbeatInterval = "bogus"
	if _, err := c.Durations(); err == nil {
		t.Error("invalid heartbeat_interval accepted")
	}
}

func TestLoadConfigRejectsUnknownAndTrailingJSON(t *testing.T) {
	for name, body := range map[string]string{
		"unknown field":  `{"interfce":"wg0"}`,
		"trailing value": `{} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadConfig(path); err == nil {
				t.Fatalf("LoadConfig accepted %s", name)
			}
		})
	}
}

func TestConfigValidateSemanticBounds(t *testing.T) {
	valid := func() Config {
		cfg := Defaults()
		cfg.Targets = []string{"worker"}
		cfg.ExpectedCountry = "CH"
		return cfg
	}
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "empty interface", mutate: func(c *Config) { c.Interface = "" }},
		{name: "long target", mutate: func(c *Config) { c.Targets = []string{"1234567890123456"} }},
		{name: "duplicate target", mutate: func(c *Config) { c.Targets = []string{"worker", "worker"} }},
		{name: "bad expected IP", mutate: func(c *Config) { c.ExpectedIP = "not-an-ip" }},
		{name: "insecure probe URL", mutate: func(c *Config) { c.ProbeURL = "http://example.com" }},
		{name: "pattern without capture", mutate: func(c *Config) { c.CountryPattern = `loc=[A-Z]{2}` }},
		{name: "zero poll", mutate: func(c *Config) { c.PollInterval = "0s" }},
		{name: "negative handshake age", mutate: func(c *Config) { c.MaxHandshakeAge = "-1s" }},
		{name: "negative grace", mutate: func(c *Config) { c.KillGrace = "-1s" }},
		{name: "negative heartbeat", mutate: func(c *Config) { c.HeartbeatInterval = "-1s" }},
		{name: "negative probe interval", mutate: func(c *Config) { c.ProbeInterval = "-1s" }},
		{name: "zero probe timeout", mutate: func(c *Config) { c.ProbeTimeout = "0s" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := valid()
			tc.mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatalf("invalid config accepted: %+v", cfg)
			}
		})
	}
}

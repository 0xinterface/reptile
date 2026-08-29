package app

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestSetConfigFileKeysCreatesValidFile(t *testing.T) {
	t.Chdir(t.TempDir())
	cfg, err := SetConfigFileKeys("config.json", []string{
		"expected_country", "de",
		"poll_interval", "5s",
		"targets", "a,b",
	})
	if err != nil {
		t.Fatalf("SetConfigFileKeys: %v", err)
	}
	if cfg.ExpectedCountry != "DE" {
		t.Errorf("ExpectedCountry = %q, want DE", cfg.ExpectedCountry)
	}
	if cfg.PollInterval != "5s" {
		t.Errorf("PollInterval = %q, want 5s", cfg.PollInterval)
	}
	if len(cfg.Targets) != 2 || cfg.Targets[0] != "a" {
		t.Errorf("Targets = %v, want [a b]", cfg.Targets)
	}
	onDisk, err := os.ReadFile("config.json")
	if err != nil {
		t.Fatalf("file not persisted: %v", err)
	}
	if !strings.Contains(string(onDisk), `"expected_country": "DE"`) {
		t.Errorf("file = %s", onDisk)
	}
}

func TestSetConfigFileKeysUpdatesExistingKeepingOtherKeys(t *testing.T) {
	t.Chdir(t.TempDir())
	if _, err := SetConfigFileKeys("config.json", []string{
		"targets", "keep",
		"expected_country", "CH",
	}); err != nil {
		t.Fatal(err)
	}
	cfg, err := SetConfigFileKeys("config.json", []string{"poll_interval", "5s"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ExpectedCountry != "CH" || len(cfg.Targets) != 1 || cfg.Targets[0] != "keep" {
		t.Errorf("cfg = %+v; want CH + targets [keep]", cfg)
	}
}

func TestSetConfigFileKeysValidation(t *testing.T) {
	t.Chdir(t.TempDir())
	if _, err := SetConfigFileKeys("config.json", []string{
		"targets", "keep",
		"expected_country", "CH",
	}); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		pairs []string
	}{
		{"bad duration", []string{"poll_interval", "x"}},
		{"unknown key", []string{"nope", "1"}},
		{"odd pairs", []string{"targets"}},
		{"bad regex", []string{"country_pattern", "("}},
		{"bad country", []string{"expected_country", "D"}},
		{"bad int", []string{"down_cycles_to_kill", "zero"}},
	}
	for _, tc := range cases {
		if _, err := SetConfigFileKeys("config.json", tc.pairs); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
}

func TestRenderConfigTable(t *testing.T) {
	c := Defaults()
	c.ExpectedCountry = "CH"
	c.Targets = []string{"a", "b"}
	var buf strings.Builder
	if err := RenderConfigTable(&buf, c); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"interface", "wg0", "expected_country", "CH", "targets", "a,b", "max_handshake_age", "180s"} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q:\n%s", want, out)
		}
	}
	if i := strings.Index(out, "dnsbl_zones"); i == -1 || i > strings.Index(out, "interface") {
		t.Errorf("table not sorted by key:\n%s", out)
	}
	var _ = time.Second
}

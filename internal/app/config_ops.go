package app

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type configRow struct {
	Key   string
	Value string
}

// configRows renders the effective config as rows sorted by key. Single
// source of truth for both the display table and reload diffing.
func configRows(c Config) []configRow {
	rows := []configRow{
		{"interface", c.Interface},
		{"poll_interval", c.PollInterval},
		{"max_handshake_age", c.MaxHandshakeAge},
		{"down_cycles_to_kill", strconv.Itoa(c.DownCyclesToKill)},
		{"kill_grace", c.KillGrace},
		{"heartbeat_interval", c.HeartbeatInterval},
		{"ping_target", c.PingTarget},
		{"verify_egress", strconv.FormatBool(c.VerifyEgress)},
		{"expected_country", c.ExpectedCountry},
		{"expected_ip", c.ExpectedIP},
		{"probe_url", c.ProbeURL},
		{"country_pattern", c.CountryPattern},
		{"ip_pattern", c.IPPattern},
		{"probe_interval", c.ProbeInterval},
		{"probe_timeout", c.ProbeTimeout},
		{"dnsbl_zones", strings.Join(c.DNSBLZones, ",")},
		{"targets", strings.Join(c.Targets, ",")},
		{"wg_conf", c.WGConf},
		{"extra_accept", strings.Join(c.ExtraAccept, ",")},
		{"socket_path", c.SocketPath},
		{"log_file", c.LogFile},
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Key < rows[j].Key })
	return rows
}

// RenderConfigTable writes the effective config as an aligned key-value
// table sorted by key.
func RenderConfigTable(w io.Writer, c Config) error {
	rows := configRows(c)
	width := 0
	for _, r := range rows {
		if len(r.Key) > width {
			width = len(r.Key)
		}
	}
	for _, r := range rows {
		if _, err := fmt.Fprintf(w, "%-*s  %s\n", width, r.Key, r.Value); err != nil {
			return err
		}
	}
	return nil
}

// diffKeys returns the keys whose effective value changed between two
// configs.
func diffKeys(old, new Config) []string {
	o, n := configRows(old), configRows(new)
	var changed []string
	for i := range o {
		if o[i].Value != n[i].Value {
			changed = append(changed, o[i].Key)
		}
	}
	return changed
}

// SetConfigFileKeys applies key=value pairs to the config file (creating it
// from defaults when missing), validates the complete result, and persists it
// atomically (temp file + rename, 0600). pairs is a flat
// ["key", "value", ...] slice.
func SetConfigFileKeys(path string, pairs []string) (Config, error) {
	if len(pairs)%2 != 0 {
		return Config{}, fmt.Errorf("odd number of key/value arguments")
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return Config{}, err
		}
		cfg = Defaults()
	}
	for i := 0; i < len(pairs); i += 2 {
		if err := applyKey(&cfg, pairs[i], pairs[i+1]); err != nil {
			return Config{}, err
		}
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("resulting config is invalid: %w", err)
	}

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return Config{}, err
	}
	out = append(out, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return Config{}, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// applyKey mutates one config field from its string form. Unknown keys and
// malformed values are rejected.
func applyKey(c *Config, k, v string) error {
	switch k {
	case "interface":
		c.Interface = v
	case "poll_interval", "max_handshake_age", "kill_grace", "heartbeat_interval", "probe_interval", "probe_timeout":
		if _, err := time.ParseDuration(v); err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
		switch k {
		case "poll_interval":
			c.PollInterval = v
		case "max_handshake_age":
			c.MaxHandshakeAge = v
		case "kill_grace":
			c.KillGrace = v
		case "heartbeat_interval":
			c.HeartbeatInterval = v
		case "probe_interval":
			c.ProbeInterval = v
		case "probe_timeout":
			c.ProbeTimeout = v
		}
	case "down_cycles_to_kill":
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return fmt.Errorf("down_cycles_to_kill: want integer >= 1, got %q", v)
		}
		c.DownCyclesToKill = n
	case "verify_egress":
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("verify_egress: %w", err)
		}
		c.VerifyEgress = b
	case "expected_country":
		upper := strings.ToUpper(strings.TrimSpace(v))
		if !countryRe.MatchString(upper) {
			return fmt.Errorf("expected_country %q must be a two-letter ISO country code", v)
		}
		c.ExpectedCountry = upper
	case "expected_ip":
		c.ExpectedIP = strings.TrimSpace(v)
	case "probe_url":
		c.ProbeURL = v
	case "country_pattern":
		if _, err := regexp.Compile(v); err != nil {
			return fmt.Errorf("country_pattern: %w", err)
		}
		c.CountryPattern = v
	case "ip_pattern":
		if _, err := regexp.Compile(v); err != nil {
			return fmt.Errorf("ip_pattern: %w", err)
		}
		c.IPPattern = v
	case "dnsbl_zones":
		c.DNSBLZones = splitList(v)
	case "targets":
		c.Targets = splitList(v)
	case "wg_conf":
		c.WGConf = v
	case "extra_accept":
		c.ExtraAccept = splitList(v)
	case "socket_path":
		c.SocketPath = v
	case "log_file":
		c.LogFile = v
	default:
		return fmt.Errorf("unknown config key %q", k)
	}
	return nil
}

func splitList(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

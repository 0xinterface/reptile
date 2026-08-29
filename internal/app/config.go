package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

// Config is loaded from JSON over Defaults(); absent keys keep their default.
// Durations stay strings and are parsed by Durations() so errors surface as
// actionable messages naming the offending key.
type Config struct {
	Interface         string   `json:"interface"`
	PollInterval      string   `json:"poll_interval"`
	MaxHandshakeAge   string   `json:"max_handshake_age"`
	DownCyclesToKill  int      `json:"down_cycles_to_kill"`
	KillGrace         string   `json:"kill_grace"`
	HeartbeatInterval string   `json:"heartbeat_interval"`
	PingTarget        string   `json:"ping_target"`
	VerifyEgress      bool     `json:"verify_egress"`
	ExpectedCountry   string   `json:"expected_country"`
	ExpectedIP        string   `json:"expected_ip"`
	ProbeURL          string   `json:"probe_url"`
	CountryPattern    string   `json:"country_pattern"`
	IPPattern         string   `json:"ip_pattern"`
	ProbeInterval     string   `json:"probe_interval"`
	ProbeTimeout      string   `json:"probe_timeout"`
	DNSBLZones        []string `json:"dnsbl_zones"`
	Targets           []string `json:"targets"`
	WGConf            string   `json:"wg_conf"`
	ExtraAccept       []string `json:"extra_accept"`
	SocketPath        string   `json:"socket_path"`
	LogFile           string   `json:"log_file"`
}

type durations struct {
	poll            time.Duration
	maxHandshakeAge time.Duration
	killGrace       time.Duration
	heartbeat       time.Duration
	probeInterval   time.Duration
	probeTimeout    time.Duration
}

var (
	countryRe = regexp.MustCompile(`^[A-Z]{2}$`)
	ifaceRe   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
)

func Defaults() Config {
	return Config{
		Interface:         "wg0",
		PollInterval:      "10s",
		MaxHandshakeAge:   "180s",
		DownCyclesToKill:  2,
		KillGrace:         "3s",
		HeartbeatInterval: "10m",
		VerifyEgress:      true,
		ProbeURL:          "https://1.1.1.1/cdn-cgi/trace",
		CountryPattern:    `(?m)^loc=([A-Z]{2})`,
		IPPattern:         `(?m)^ip=([0-9a-fA-F.:]+)`,
		ProbeInterval:     "300s",
		ProbeTimeout:      "5s",
		DNSBLZones:        []string{"zen.spamhaus.org", "b.barracudacentral.org", "bl.spamcop.net"},
		WGConf:            "/etc/wireguard/wg0.conf",
		SocketPath:        "/run/reptile/agent.sock",
		LogFile:           "/var/lib/reptile/events.log",
	}
}

// LoadConfig merges the JSON file at path over Defaults. Empty path means
// defaults only.
func LoadConfig(path string) (Config, error) {
	c := Defaults()
	if path == "" {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			err = fmt.Errorf("multiple JSON values")
		}
		return c, fmt.Errorf("parse %s: trailing data: %w", path, err)
	}
	c.ExpectedCountry = strings.ToUpper(strings.TrimSpace(c.ExpectedCountry))
	c.ExpectedIP = strings.TrimSpace(c.ExpectedIP)
	return c, nil
}

func (c Config) Validate() error {
	if !ifaceRe.MatchString(c.Interface) {
		return fmt.Errorf("interface %q must be 1-15 letters, digits, dots, underscores, or hyphens", c.Interface)
	}
	if len(c.Targets) == 0 {
		return fmt.Errorf("targets must list at least one process name")
	}
	seenTargets := make(map[string]bool, len(c.Targets))
	for _, target := range c.Targets {
		if target == "" || target != strings.TrimSpace(target) {
			return fmt.Errorf("target %q must be non-empty without leading or trailing whitespace", target)
		}
		if len(target) > 15 {
			return fmt.Errorf("target %q exceeds Linux comm's 15-byte limit", target)
		}
		for _, r := range target {
			if r < 0x20 || r == 0x7f {
				return fmt.Errorf("target %q contains a control character", target)
			}
		}
		if seenTargets[target] {
			return fmt.Errorf("target %q is listed more than once", target)
		}
		seenTargets[target] = true
	}
	if c.VerifyEgress {
		if strings.TrimSpace(c.ExpectedCountry) == "" {
			return fmt.Errorf("verify_egress=true requires expected_country")
		}
		if !countryRe.MatchString(c.ExpectedCountry) {
			return fmt.Errorf("expected_country %q must be a two-letter ISO country code", c.ExpectedCountry)
		}
	}
	if c.ExpectedIP != "" && net.ParseIP(c.ExpectedIP) == nil {
		return fmt.Errorf("expected_ip %q is not an IP address", c.ExpectedIP)
	}
	probeURL, err := url.ParseRequestURI(c.ProbeURL)
	if err != nil || probeURL.Scheme != "https" || probeURL.Host == "" {
		return fmt.Errorf("probe_url %q must be an absolute HTTPS URL", c.ProbeURL)
	}
	patterns := []struct {
		key     string
		pattern string
	}{
		{key: "country_pattern", pattern: c.CountryPattern},
		{key: "ip_pattern", pattern: c.IPPattern},
	}
	for _, item := range patterns {
		re, err := regexp.Compile(item.pattern)
		if err != nil {
			return fmt.Errorf("%s: %w", item.key, err)
		}
		if re.NumSubexp() < 1 {
			return fmt.Errorf("%s must contain a capture group", item.key)
		}
	}
	for _, zone := range c.DNSBLZones {
		if zone == "" || zone != strings.TrimSpace(zone) || strings.ContainsAny(zone, " \t\r\n") {
			return fmt.Errorf("dnsbl zone %q is invalid", zone)
		}
	}
	if c.DownCyclesToKill < 1 {
		return fmt.Errorf("down_cycles_to_kill must be >= 1")
	}
	d, err := c.Durations()
	if err != nil {
		return err
	}
	switch {
	case d.poll <= 0:
		return fmt.Errorf("poll_interval must be > 0")
	case d.maxHandshakeAge <= 0:
		return fmt.Errorf("max_handshake_age must be > 0")
	case d.killGrace < 0:
		return fmt.Errorf("kill_grace must be >= 0")
	case d.heartbeat < 0:
		return fmt.Errorf("heartbeat_interval must be >= 0")
	case d.probeInterval < 0:
		return fmt.Errorf("probe_interval must be >= 0")
	case d.probeTimeout <= 0:
		return fmt.Errorf("probe_timeout must be > 0")
	}
	return nil
}

func (c Config) Durations() (durations, error) {
	var d durations
	var err error
	if d.poll, err = time.ParseDuration(c.PollInterval); err != nil {
		return d, fmt.Errorf("poll_interval: %w", err)
	}
	if d.maxHandshakeAge, err = time.ParseDuration(c.MaxHandshakeAge); err != nil {
		return d, fmt.Errorf("max_handshake_age: %w", err)
	}
	if d.killGrace, err = time.ParseDuration(c.KillGrace); err != nil {
		return d, fmt.Errorf("kill_grace: %w", err)
	}
	if d.probeInterval, err = time.ParseDuration(c.ProbeInterval); err != nil {
		return d, fmt.Errorf("probe_interval: %w", err)
	}
	if d.probeTimeout, err = time.ParseDuration(c.ProbeTimeout); err != nil {
		return d, fmt.Errorf("probe_timeout: %w", err)
	}
	if d.heartbeat, err = time.ParseDuration(c.HeartbeatInterval); err != nil {
		return d, fmt.Errorf("heartbeat_interval: %w", err)
	}
	return d, nil
}

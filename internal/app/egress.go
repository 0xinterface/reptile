package app

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ALookup is the DNS surface used for DNSBL checks; net.DefaultResolver
// satisfies it, tests inject fakes.
type ALookup interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// EgressChecker proves where the tunnel really exits. "Down" is fail-closed:
// probe failure, unparsable response, wrong country/IP, or a DNSBL hit all
// count as unproven. Verdicts are cached for TTL so the poll loop can call
// Check every cycle.
//
// After every Check, LastCountry/LastIP hold the observed probe values and
// Probed reports whether this call actually hit the network (false when the
// verdict came from cache).
//
// Apply hot-swaps config-derived fields under the same mutex that Check
// holds, so the agent goroutine can reconfigure while the poll loop probes.
type EgressChecker struct {
	mu sync.Mutex

	Iface           string
	URL             string
	CountryRe       *regexp.Regexp
	IPRe            *regexp.Regexp
	Timeout         time.Duration
	TTL             time.Duration
	ExpectedCountry string
	ExpectedIP      string
	Zones           []string
	Lookup          ALookup
	Client          *http.Client
	Now             func() time.Time
	Logf            func(format string, args ...any)

	LastCountry string
	LastIP      string
	Probed      bool

	httpClient *http.Client
	transport  *http.Transport
	verdict    bool
	reason     string
	ts         time.Time
	set        bool
}

// Apply hot-applies the mutable subset of a new config. Config fields are
// validated first (patterns compile, URL parses, durations parse); on error
// nothing is mutated.
func (e *EgressChecker) Apply(c Config) error {
	countryRe, err := regexp.Compile(c.CountryPattern)
	if err != nil {
		return fmt.Errorf("country_pattern: %w", err)
	}
	ipRe, err := regexp.Compile(c.IPPattern)
	if err != nil {
		return fmt.Errorf("ip_pattern: %w", err)
	}
	if _, err := url.Parse(c.ProbeURL); err != nil {
		return fmt.Errorf("probe_url: %w", err)
	}
	timeout, err := time.ParseDuration(c.ProbeTimeout)
	if err != nil {
		return fmt.Errorf("probe_timeout: %w", err)
	}
	ttl, err := time.ParseDuration(c.ProbeInterval)
	if err != nil {
		return fmt.Errorf("probe_interval: %w", err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.transport != nil {
		e.transport.CloseIdleConnections()
	}
	e.Iface = c.Interface
	e.URL = c.ProbeURL
	e.CountryRe, e.IPRe = countryRe, ipRe
	e.Timeout, e.TTL = timeout, ttl
	e.ExpectedCountry = strings.ToUpper(strings.TrimSpace(c.ExpectedCountry))
	e.ExpectedIP = c.ExpectedIP
	e.Zones = append(e.Zones[:0], c.DNSBLZones...)
	e.httpClient = nil
	e.transport = nil
	e.invalidateLocked()
	return nil
}

func (e *EgressChecker) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *EgressChecker) logf(format string, args ...any) {
	if e.Logf != nil {
		e.Logf(format, args...)
	}
}

// client returns the injected client or a persistent interface-bound client.
// The caller holds e.mu.
func (e *EgressChecker) client() *http.Client {
	if e.Client != nil {
		return e.Client
	}
	if e.httpClient == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.Proxy = nil
		tr.DialContext = ifaceDialer(e.Iface, e.Timeout).DialContext
		e.transport = tr
		e.httpClient = &http.Client{Timeout: e.Timeout, Transport: tr}
	}
	return e.httpClient
}

type egressResult struct {
	OK      bool
	Reason  string
	IP      string
	Country string
	Probed  bool
}

func (e *EgressChecker) evaluate(ctx context.Context, fresh bool) egressResult {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := e.now()
	if !fresh && e.set && now.Sub(e.ts) < e.TTL {
		e.Probed = false
		return egressResult{
			OK: e.verdict, Reason: e.reason,
			IP: e.LastIP, Country: e.LastCountry,
		}
	}
	ok, reason := e.probe(ctx)
	e.verdict, e.reason, e.ts, e.set = ok, reason, now, true
	e.Probed = true
	return egressResult{
		OK: ok, Reason: reason, IP: e.LastIP, Country: e.LastCountry, Probed: true,
	}
}

func (e *EgressChecker) Check(ctx context.Context) (bool, string) {
	result := e.evaluate(ctx, false)
	return result.OK, result.Reason
}

// CheckFresh bypasses the verdict cache and runs a probe now.
func (e *EgressChecker) CheckFresh(ctx context.Context) (bool, string) {
	result := e.evaluate(ctx, true)
	return result.OK, result.Reason
}

// Invalidate discards proof tied to the current tunnel session. The next
// Check must probe the newly established session instead of using its cache.
func (e *EgressChecker) Invalidate() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.invalidateLocked()
}

func (e *EgressChecker) invalidateLocked() {
	e.verdict, e.reason, e.ts, e.set = false, "", time.Time{}, false
	e.LastCountry, e.LastIP, e.Probed = "", "", false
}

// Proof returns an internally consistent snapshot of the last observation.
func (e *EgressChecker) Proof() (ip, country string, probed bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.LastIP, e.LastCountry, e.Probed
}

func (e *EgressChecker) probe(ctx context.Context) (bool, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.URL, nil)
	if err != nil {
		return false, fmt.Sprintf("probe request build failed: %v", err)
	}
	resp, err := e.client().Do(req)
	if err != nil {
		return false, fmt.Sprintf("probe request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Sprintf("probe returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil {
		return false, fmt.Sprintf("probe read failed: %v", err)
	}
	text := string(body)

	// Record proof before verdict checks so mismatches still carry the
	// observed values into logs.
	cc := ""
	if m := e.CountryRe.FindStringSubmatch(text); len(m) > 1 {
		cc = strings.ToUpper(strings.TrimSpace(m[1]))
	}
	e.LastCountry = cc

	ip := ""
	if m := e.IPRe.FindStringSubmatch(text); len(m) > 1 {
		ip = strings.TrimSpace(m[1])
	}
	e.LastIP = ip

	if cc == "" {
		return false, "no country parsed from probe response"
	}
	if cc != e.ExpectedCountry {
		return false, fmt.Sprintf("egress country %s != expected %s", cc, e.ExpectedCountry)
	}
	if e.ExpectedIP != "" && ip != e.ExpectedIP {
		return false, fmt.Sprintf("egress IP %s != expected %s", ip, e.ExpectedIP)
	}

	if len(e.Zones) > 0 {
		if ip == "" {
			return false, "no exit IP parsed but dnsbl_zones configured"
		}
		if listed, zone := e.blacklisted(ctx, ip); listed {
			return false, fmt.Sprintf("egress IP %s listed in %s", ip, zone)
		}
	}
	return true, ""
}

func (e *EgressChecker) blacklisted(ctx context.Context, ip string) (bool, string) {
	rev, ok := reverseIPv4(ip)
	if !ok {
		e.logf("egress IP %s is not IPv4; skipping DNSBL check", ip)
		return false, ""
	}
	lookup := e.Lookup
	if lookup == nil {
		lookup = net.DefaultResolver
	}
	for _, zone := range e.Zones {
		q := rev + "." + zone
		qctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		answers, err := lookup.LookupHost(qctx, q)
		cancel()
		if err != nil {
			e.logf("dnsbl query %s failed: %v", q, err)
			continue
		}
		for _, a := range answers {
			if listedAnswer(a) {
				return true, zone
			}
		}
	}
	return false, ""
}

// reverseIPv4 flips octets for DNSBL queries; non-IPv4 input reports false.
func reverseIPv4(ip string) (string, bool) {
	b := net.ParseIP(ip).To4()
	if b == nil {
		return "", false
	}
	return fmt.Sprintf("%d.%d.%d.%d", b[3], b[2], b[1], b[0]), true
}

// listedAnswer: a DNSBL hit is an A record in 127.0.0.0/8, excluding
// 127.255.255.0/24, which DNSBL operators reserve for error/refusal codes
// (e.g. Spamhaus query-refused from public resolvers).
func listedAnswer(ans string) bool {
	b := net.ParseIP(strings.TrimSpace(ans)).To4()
	if b == nil || b[0] != 127 {
		return false
	}
	return !(b[1] == 255 && b[2] == 255)
}

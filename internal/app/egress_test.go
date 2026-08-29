package app

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeLookup struct {
	calls   []string
	answers map[string][]string
}

func (f *fakeLookup) LookupHost(ctx context.Context, host string) ([]string, error) {
	f.calls = append(f.calls, host)
	if a, ok := f.answers[host]; ok {
		return a, nil
	}
	return nil, fmt.Errorf("nxdomain")
}

func mustCompile(t *testing.T, p string) *regexp.Regexp {
	t.Helper()
	re, err := regexp.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	return re
}

func traceServer(t *testing.T, body string, hits *int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits != nil {
			atomic.AddInt32(hits, 1)
		}
		fmt.Fprint(w, body)
	}))
}

func baseChecker(t *testing.T, srv *httptest.Server) *EgressChecker {
	t.Helper()
	return &EgressChecker{
		URL:             srv.URL,
		CountryRe:       mustCompile(t, `(?m)^loc=([A-Z]{2})$`),
		IPRe:            mustCompile(t, `(?m)^ip=([0-9a-fA-F.:]+)$`),
		Timeout:         2 * time.Second,
		TTL:             5 * time.Minute,
		ExpectedCountry: "CH",
		Now:             func() time.Time { return time.Unix(1000, 0) },
	}
}

func TestEgressOk(t *testing.T) {
	srv := traceServer(t, "ip=198.51.100.7\nloc=CH\ncolo=ZRH\n", nil)
	defer srv.Close()
	up, reason := baseChecker(t, srv).Check(context.Background())
	if !up {
		t.Fatalf("want up, reason: %s", reason)
	}
}

func TestEgressCountryMismatch(t *testing.T) {
	srv := traceServer(t, "ip=198.51.100.7\nloc=DE\n", nil)
	defer srv.Close()
	up, reason := baseChecker(t, srv).Check(context.Background())
	if up {
		t.Fatal("wrong country must be down")
	}
	if reason != "egress country DE != expected CH" {
		t.Errorf("reason = %q", reason)
	}
}

func TestEgressIPMismatch(t *testing.T) {
	srv := traceServer(t, "ip=198.51.100.7\nloc=CH\n", nil)
	defer srv.Close()
	e := baseChecker(t, srv)
	e.ExpectedIP = "198.51.100.99"
	up, reason := e.Check(context.Background())
	if up {
		t.Fatal("wrong exit IP must be down")
	}
	if reason != "egress IP 198.51.100.7 != expected 198.51.100.99" {
		t.Errorf("reason = %q", reason)
	}
}

func TestEgressUnparsableBody(t *testing.T) {
	srv := traceServer(t, "hello world\n", nil)
	defer srv.Close()
	up, reason := baseChecker(t, srv).Check(context.Background())
	if up {
		t.Fatal("unparsable probe must be down (fail-closed)")
	}
	if !strings.Contains(reason, "no country parsed") {
		t.Errorf("reason = %q", reason)
	}
}

func TestEgressRequestFailure(t *testing.T) {
	srv := traceServer(t, "ip=1.2.3.4\nloc=CH\n", nil)
	url := srv.URL
	srv.Close() // nothing listens anymore
	e := baseChecker(t, srv)
	e.URL = url
	up, reason := e.Check(context.Background())
	if up {
		t.Fatal("probe failure must be down (fail-closed)")
	}
	if !strings.Contains(reason, "probe request failed") {
		t.Errorf("reason = %q", reason)
	}
}

func TestEgressListedInDNSBL(t *testing.T) {
	srv := traceServer(t, "ip=203.0.113.9\nloc=CH\n", nil)
	defer srv.Close()
	lk := &fakeLookup{answers: map[string][]string{
		"9.113.0.203.zen.example": {"127.0.0.4"},
	}}
	e := baseChecker(t, srv)
	e.Lookup = lk
	e.Zones = []string{"zen.example"}
	up, reason := e.Check(context.Background())
	if up {
		t.Fatal("blacklisted exit IP must be down")
	}
	if !strings.Contains(reason, "listed in zen.example") {
		t.Errorf("reason = %q", reason)
	}
	if len(lk.calls) != 1 || lk.calls[0] != "9.113.0.203.zen.example" {
		t.Errorf("dnsbl queries = %v", lk.calls)
	}
}

func TestEgressQueryRefusedIsNotAHit(t *testing.T) {
	// 127.255.255.0/24 are DNSBL operator error codes (e.g. Spamhaus
	// query-refused), never hits.
	srv := traceServer(t, "ip=203.0.113.9\nloc=CH\n", nil)
	defer srv.Close()
	lk := &fakeLookup{answers: map[string][]string{
		"9.113.0.203.zen.example": {"127.255.255.254"},
	}}
	e := baseChecker(t, srv)
	e.Lookup = lk
	e.Zones = []string{"zen.example"}
	if up, reason := e.Check(context.Background()); !up {
		t.Fatalf("refused-code answer must not count as a hit, reason: %s", reason)
	}
}

func TestEgressV6SkipsDNSBL(t *testing.T) {
	srv := traceServer(t, "ip=2001:db8::1\nloc=CH\n", nil)
	defer srv.Close()
	lk := &fakeLookup{}
	e := baseChecker(t, srv)
	e.IPRe = mustCompile(t, `(?m)^ip=(\S+)$`)
	e.Lookup = lk
	e.Zones = []string{"zen.example"}
	if up, reason := e.Check(context.Background()); !up {
		t.Fatalf("v6 exit with DNSBL zones should skip lookups, reason: %s", reason)
	}
	if len(lk.calls) != 0 {
		t.Errorf("unexpected dnsbl queries: %v", lk.calls)
	}
}

func TestEgressJSONProvider(t *testing.T) {
	srv := traceServer(t, `{"ip":"198.51.100.7","country_code":"CH","asn":123}`, nil)
	defer srv.Close()
	e := baseChecker(t, srv)
	e.CountryRe = mustCompile(t, `"country_code"\s*:\s*"([A-Za-z]{2})"`)
	e.IPRe = mustCompile(t, `"ip"\s*:\s*"([^"]+)"`)
	if up, reason := e.Check(context.Background()); !up {
		t.Fatalf("JSON provider patterns should work, reason: %s", reason)
	}
}

func TestEgressCache(t *testing.T) {
	var hits int32
	srv := traceServer(t, "ip=198.51.100.7\nloc=CH\n", &hits)
	defer srv.Close()

	now := time.Unix(1000, 0)
	e := baseChecker(t, srv)
	e.TTL = time.Minute
	e.Now = func() time.Time { return now }

	if up, _ := e.Check(context.Background()); !up {
		t.Fatal("first check should pass")
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("hits = %d, want 1", hits)
	}
	now = now.Add(30 * time.Second)
	if up, _ := e.Check(context.Background()); !up {
		t.Fatal("cached verdict should pass")
	}
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("cached check must not re-probe, hits = %d", hits)
	}
	now = now.Add(31 * time.Second) // 61s > TTL
	if up, _ := e.Check(context.Background()); !up {
		t.Fatal("expired cache must re-probe and pass")
	}
	if atomic.LoadInt32(&hits) != 2 {
		t.Fatalf("hits = %d, want 2 after expiry", hits)
	}

	// failure verdicts are cached with the same discipline (fresh counter)
	var hits2 int32
	srv2 := traceServer(t, "loc=DE\n", &hits2)
	defer srv2.Close()
	e.URL = srv2.URL
	now = now.Add(61 * time.Second) // expire the cached ok verdict
	if up, _ := e.Check(context.Background()); up {
		t.Fatal("mismatch must fail")
	}
	if atomic.LoadInt32(&hits2) != 1 {
		t.Fatalf("probe should have run once, hits2 = %d", hits2)
	}
	now = now.Add(10 * time.Second)
	e.Check(context.Background())
	if atomic.LoadInt32(&hits2) != 1 {
		t.Fatalf("failed verdict must be cached, hits2 = %d", hits2)
	}
}

func TestEgressExposesProof(t *testing.T) {
	srv := traceServer(t, "ip=198.51.100.7\nloc=CH\n", nil)
	defer srv.Close()

	now := time.Unix(1000, 0)
	e := baseChecker(t, srv)
	e.TTL = time.Minute
	e.Now = func() time.Time { return now }

	if up, _ := e.Check(context.Background()); !up {
		t.Fatal("want up")
	}
	if !e.Probed || e.LastCountry != "CH" || e.LastIP != "198.51.100.7" {
		t.Errorf("proof after probe = probed=%v %q/%q, want true CH/198.51.100.7", e.Probed, e.LastCountry, e.LastIP)
	}

	now = now.Add(10 * time.Second)
	if up, _ := e.Check(context.Background()); !up {
		t.Fatal("want up (cached)")
	}
	if e.Probed {
		t.Error("cached check must not claim a fresh probe")
	}

	now = now.Add(61 * time.Second) // expire; mismatch records OBSERVED values
	srv2 := traceServer(t, "ip=198.51.100.8\nloc=DE\n", nil)
	defer srv2.Close()
	e.URL = srv2.URL
	if up, _ := e.Check(context.Background()); up {
		t.Fatal("want down")
	}
	if e.LastCountry != "DE" || e.LastIP != "198.51.100.8" {
		t.Errorf("proof after mismatch = %q/%q, want observed DE/198.51.100.8", e.LastCountry, e.LastIP)
	}
}

func TestEgressCheckFreshBypassesCache(t *testing.T) {
	var hits int32
	srv := traceServer(t, "ip=198.51.100.7\nloc=CH\n", &hits)
	defer srv.Close()

	now := time.Unix(1000, 0)
	e := baseChecker(t, srv)
	e.TTL = time.Hour
	e.Now = func() time.Time { return now }

	if up, _ := e.Check(context.Background()); !up {
		t.Fatal("first check should pass")
	}
	if up, _ := e.CheckFresh(context.Background()); !up {
		t.Fatal("fresh check should pass")
	}
	if atomic.LoadInt32(&hits) != 2 {
		t.Fatalf("hits = %d, want 2 (fresh must not read cache)", hits)
	}
}

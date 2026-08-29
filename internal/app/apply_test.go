package app

import (
	"context"
	"testing"
	"time"
)

func TestEgressApplyChangesVerdict(t *testing.T) {
	srv := traceServer(t, "ip=198.51.100.7\nloc=DE\n", nil)
	defer srv.Close()

	e := baseChecker(t, srv) // expects CH
	if up, reason := e.Check(context.Background()); up {
		t.Fatalf("DE must fail against CH: %s", reason)
	}

	// hot-apply a complete config that expects DE. Interface stays empty:
	// on Linux the probe dialer binds to it (SO_BINDTODEVICE) and a unit
	// test must not depend on a host interface existing.
	e.Apply(Config{
		ExpectedCountry: "DE",
		CountryPattern:  `(?m)^loc=([A-Z]{2})$`,
		IPPattern:       `(?m)^ip=(\S+)$`,
		ProbeInterval:   "300s",
		ProbeTimeout:    "5s",
		ProbeURL:        srv.URL,
	})
	if up, _ := e.CheckFresh(context.Background()); !up {
		t.Fatal("after applying expected_country=DE the same probe must pass")
	}
	if e.ExpectedCountry != "DE" {
		t.Errorf("ExpectedCountry = %q, want DE", e.ExpectedCountry)
	}
}

func TestApplyRejectsBadURLWithoutMutating(t *testing.T) {
	srv := traceServer(t, "ip=198.51.100.7\nloc=CH\n", nil)
	defer srv.Close()
	e := baseChecker(t, srv)

	// rejected apply first: checker must stay servable afterwards
	if err := e.Apply(Config{
		ExpectedCountry: "CH",
		CountryPattern:  `(?m)^loc=([A-Z]{2})$`,
		IPPattern:       `(?m)^ip=(\S+)$`,
		ProbeInterval:   "300s",
		ProbeTimeout:    "5s",
		ProbeURL:        "://bad",
	}); err == nil {
		t.Fatal("invalid probe URL must be rejected")
	}
	if up, _ := e.CheckFresh(context.Background()); !up {
		t.Fatal("rejected apply must leave the checker working")
	}

	// then a good apply is accepted and takes effect
	if err := e.Apply(Config{
		ExpectedCountry: "CH",
		CountryPattern:  `(?m)^loc=([A-Z]{2})$`,
		IPPattern:       `(?m)^ip=(\S+)$`,
		ProbeInterval:   "300s",
		ProbeTimeout:    "5s",
		ProbeURL:        "https://example.invalid/",
	}); err != nil {
		t.Fatalf("good apply: %v", err)
	}
	if e.URL != "https://example.invalid/" {
		t.Errorf("URL = %q, want updated", e.URL)
	}
}

func TestTunnelApplyUpdatesThreshold(t *testing.T) {
	run := &fakeRunner{responses: map[string]string{"wg": twoPeerDump}}
	tc := &TunnelChecker{Iface: "wg0", MaxAge: 150 * time.Second, Runner: run,
		Now: func() time.Time { return time.Unix(1_700_000_200, 0) }}

	// handshake is 100s old; 150s max: up
	if up, _ := tc.Check(context.Background()); !up {
		t.Fatal("100s-old handshake must be up under 150s max")
	}
	tc.Apply(Config{MaxHandshakeAge: "50s"})
	if up, reason := tc.Check(context.Background()); up {
		t.Fatalf("applied max_handshake_age=50s must make the 100s-old handshake down (%s)", reason)
	}
	if tc.MaxAge != 50*time.Second {
		t.Errorf("MaxAge = %v, want 50s", tc.MaxAge)
	}
}

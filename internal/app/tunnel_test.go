package app

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	calls     []string
	responses map[string]string
	errs      map[string]error
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	if e, ok := f.errs[name]; ok {
		return "", e
	}
	if r, ok := f.responses[name]; ok {
		return r, nil
	}
	return "", nil
}

func dumpLine(parts ...string) string { return strings.Join(parts, "\t") }

func newChecker(run *fakeRunner, maxAge time.Duration) *TunnelChecker {
	base := time.Unix(1_700_000_100, 0)
	return &TunnelChecker{
		Iface:  "wg0",
		MaxAge: maxAge,
		Runner: run,
		Now:    func() time.Time { return base },
	}
}

// two peers: A handshaked 100s before base, B exactly at base.
var twoPeerDump = dumpLine("wg0", "cHJpdk=", "51820", "off") + "\n" +
	dumpLine("PUB_A", "(off)", "(none)", "0.0.0.0/0", "1700000000", "1", "2", "25") + "\n" +
	dumpLine("PUB_B", "(off)", "(none)", "10.0.0.0/24", "1700000100", "3", "4", "25")

func TestTunnelUpWhenFresh(t *testing.T) {
	run := &fakeRunner{responses: map[string]string{"wg": twoPeerDump}}
	tc := newChecker(run, 180*time.Second)
	up, reason := tc.Check(context.Background())
	if !up {
		t.Fatalf("want up, got down: %s", reason)
	}
	if reason != "" {
		t.Errorf("reason = %q on success, want empty", reason)
	}
}

func TestTunnelDownWhenStale(t *testing.T) {
	run := &fakeRunner{responses: map[string]string{"wg": twoPeerDump}}
	tc := newChecker(run, 180*time.Second)
	tc.Now = func() time.Time { return time.Unix(1_700_000_100+181, 0) }
	up, reason := tc.Check(context.Background())
	if up {
		t.Fatal("stale handshake must be down")
	}
	if !strings.Contains(reason, "181s old") {
		t.Errorf("reason = %q, want staleness with age", reason)
	}
}

func TestTunnelPicksFreshestPeer(t *testing.T) {
	// A is stale (age 100), B fresh (age 0): freshest must carry the verdict.
	dump := dumpLine("wg0", "k", "51820", "off") + "\n" +
		dumpLine("PUB_A", "(off)", "(none)", "0.0.0.0/0", "1700000000", "1", "1", "25") + "\n" +
		dumpLine("PUB_B", "(off)", "(none)", "10.0.0.0/24", "1700000100", "1", "1", "25")
	run := &fakeRunner{responses: map[string]string{"wg": dump}}
	tc := newChecker(run, 60*time.Second)
	if up, reason := tc.Check(context.Background()); !up {
		t.Fatalf("freshest peer is within max age; want up, reason: %s", reason)
	}

	// both stale: best age 100s > 60s max
	dump = dumpLine("wg0", "k", "51820", "off") + "\n" +
		dumpLine("PUB_A", "(off)", "(none)", "0.0.0.0/0", "1700000000", "1", "1", "25") + "\n" +
		dumpLine("PUB_B", "(off)", "(none)", "10.0.0.0/24", "1700000000", "1", "1", "25")
	run.responses["wg"] = dump
	if up, reason := tc.Check(context.Background()); up {
		t.Fatalf("all peers stale; want down, reason: %s", reason)
	}
}

func TestTunnelNoHandshakeYet(t *testing.T) {
	dump := dumpLine("wg0", "k", "51820", "off") + "\n" +
		dumpLine("PUB_A", "(off)", "(none)", "0.0.0.0/0", "0", "0", "0", "25")
	run := &fakeRunner{responses: map[string]string{"wg": dump}}
	tc := newChecker(run, time.Minute)
	up, reason := tc.Check(context.Background())
	if up {
		t.Fatal("handshake epoch 0 means the tunnel never connected")
	}
	if !strings.Contains(reason, "no handshake") {
		t.Errorf("reason = %q", reason)
	}
}

func TestTunnelInterfaceMissing(t *testing.T) {
	run := &fakeRunner{errs: map[string]error{"wg": fmt.Errorf("exit status 1")}}
	tc := newChecker(run, time.Minute)
	up, reason := tc.Check(context.Background())
	if up {
		t.Fatal("missing interface must be down")
	}
	if !strings.Contains(reason, "wg show") {
		t.Errorf("reason = %q, want mention of wg show failure", reason)
	}
}

func TestTunnelMalformedLinesIgnored(t *testing.T) {
	dump := "garbage line\nshort\tline\n" +
		dumpLine("PUB_A", "(off)", "(none)", "0.0.0.0/0", "1700000100", "1", "1", "25")
	run := &fakeRunner{responses: map[string]string{"wg": dump}}
	tc := newChecker(run, time.Minute)
	if up, reason := tc.Check(context.Background()); !up {
		t.Fatalf("want up despite malformed lines, reason: %s", reason)
	}
}

func TestTunnelPingForcesHandshakeBeforeReading(t *testing.T) {
	run := &fakeRunner{responses: map[string]string{"wg": twoPeerDump}}
	tc := newChecker(run, time.Minute)
	tc.PingTarget = "10.66.66.1"
	tc.Check(context.Background())

	var pingIdx, wgIdx = -1, -1
	for i, c := range run.calls {
		switch {
		case strings.HasPrefix(c, "ping "):
			pingIdx = i
			if !strings.Contains(c, "-I wg0") || !strings.Contains(c, "10.66.66.1") {
				t.Errorf("ping args = %q, want interface-bound target ping", c)
			}
		case strings.HasPrefix(c, "wg "):
			wgIdx = i
		}
	}
	if pingIdx == -1 {
		t.Fatal("ping not invoked though ping_target configured")
	}
	if wgIdx == -1 || pingIdx > wgIdx {
		t.Errorf("call order = %v, want ping before wg show (forces fresh handshake)", run.calls)
	}
}

func TestTunnelNoPingWhenUnset(t *testing.T) {
	run := &fakeRunner{responses: map[string]string{"wg": twoPeerDump}}
	tc := newChecker(run, time.Minute)
	tc.Check(context.Background())
	for _, c := range run.calls {
		if strings.HasPrefix(c, "ping ") {
			t.Errorf("unexpected ping: %q", c)
		}
	}
}

func TestParseLatestHandshake(t *testing.T) {
	if got := parseLatestHandshake(twoPeerDump); got != 1700000100 {
		t.Errorf("parseLatestHandshake = %d, want 1700000100 (freshest peer)", got)
	}
	if got := parseLatestHandshake("wg0\tk\t51820\toff\n"); got != 0 {
		t.Errorf("interface-only dump = %d, want 0", got)
	}
	if got := parseLatestHandshake(""); got != 0 {
		t.Errorf("empty dump = %d, want 0", got)
	}
}

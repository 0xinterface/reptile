package app

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func join(logs []string) string { return strings.Join(logs, "\n") }

func TestWatchdogDebouncesBeforeKilling(t *testing.T) {
	kills := 0
	s := wdState{}

	s1, logs := cycle(s, false, "handshake 999s old", false, false, 2, func() { kills++ })
	if kills != 0 {
		t.Fatalf("kills after first failed cycle = %d, want 0", kills)
	}
	if !strings.Contains(join(logs), "possibly DOWN (1/2)") {
		t.Errorf("logs = %v, want unconfirmed marker", logs)
	}

	s2, logs := cycle(s1, false, "handshake 999s old", false, false, 2, func() { kills++ })
	if kills != 1 {
		t.Fatalf("kills after second failed cycle = %d, want 1", kills)
	}
	if !strings.Contains(join(logs), "killing targets") {
		t.Errorf("logs = %v, want confirmation", logs)
	}

	// still down: kill again (catches processes spawned during the outage),
	// but stay quiet about the transition
	_, logs = cycle(s2, false, "handshake 999s old", false, false, 2, func() { kills++ })
	if kills != 2 {
		t.Fatalf("kills after third failed cycle = %d, want 2", kills)
	}
	if len(logs) != 0 {
		t.Errorf("steady-state down should not log, got %v", logs)
	}
}

func TestWatchdogEgressGatesEvenWhenTunnelUp(t *testing.T) {
	kills := 0
	s := wdState{}
	// tunnel fine, egress wrong country: verify=true gates
	s1, logs := cycle(s, true, "", true, false, 2, func() { kills++ })
	if kills != 0 {
		t.Fatalf("kills = %d, want 0 (debounce)", kills)
	}
	if !strings.Contains(join(logs), "possibly DOWN (1/2)") {
		t.Errorf("logs = %v, want unconfirmed", logs)
	}
	_, _ = cycle(s1, true, "egress country DE != expected CH", true, false, 2, func() { kills++ })
	if kills != 1 {
		t.Fatalf("kills = %d, want 1 (egress failure must kill)", kills)
	}
}

func TestWatchdogEgressNotConsultedWhenTunnelDown(t *testing.T) {
	kills := 0
	// egressOK=true is irrelevant when the tunnel is down: still down.
	_, _ = cycle(wdState{}, false, "no handshake recorded", true, true, 1, func() { kills++ })
	if kills != 1 {
		t.Fatalf("kills = %d, want 1", kills)
	}
}

func TestWatchdogVerifyOffIgnoresEgress(t *testing.T) {
	kills := 0
	// verify=false, egressOK=false: tunnel up means up.
	s, logs := cycle(wdState{}, true, "", false, false, 1, func() { kills++ })
	if kills != 0 || s.announced != "up" {
		t.Fatalf("kills=%d announced=%q logs=%v; want quiet up", kills, s.announced, logs)
	}
}

func TestWatchdogRecoveryDoesNotRestart(t *testing.T) {
	kills := 0
	s := wdState{}
	s1, _ := cycle(s, false, "x", false, false, 2, func() { kills++ })
	s2, _ := cycle(s1, false, "x", false, false, 2, func() { kills++ })
	if s2.announced != "down" {
		t.Fatalf("announced = %q, want down", s2.announced)
	}
	s3, logs := cycle(s2, true, "", true, true, 2, func() { kills++ })
	// one kill happened at confirmation; the recovery cycle must not kill
	if kills != 1 {
		t.Fatalf("kills = %d, want 1 (recovery must not kill or restart)", kills)
	}
	if s3.announced != "up" || !strings.Contains(join(logs), "tunnel UP") {
		t.Fatalf("recovery: announced=%q logs=%v, want UP transition", s3.announced, logs)
	}
}

func TestWatchdogQuietWhenSteadyUp(t *testing.T) {
	kills := 0
	s := wdState{announced: "up"}
	s2, logs := cycle(s, true, "", true, true, 2, func() { kills++ })
	if kills != 0 || len(logs) != 0 {
		t.Fatalf("steady up: kills=%d logs=%v, want silence", kills, logs)
	}
	if s2.streak != 0 {
		t.Errorf("streak = %d, want 0", s2.streak)
	}
}

func TestRunWatchdogDrivesDebounceAndPublishesState(t *testing.T) {
	cfg := Defaults()
	cfg.Targets = []string{"worker"}
	cfg.ExpectedCountry = "CH"
	cfg.VerifyEgress = false
	cfg.PollInterval = "5ms"
	cfg.HeartbeatInterval = "0s"
	cfg.DownCyclesToKill = 2

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var (
		tunnelCalls atomic.Int32
		kills       atomic.Int32
	)
	store := NewStore()
	err := runWatchdog(
		ctx,
		NewLive(cfg),
		func() (bool, string) {
			tunnelCalls.Add(1)
			return false, "no handshake"
		},
		func() (bool, string) {
			t.Fatal("egress must not run while the tunnel is down")
			return false, ""
		},
		func() (string, string) { return "", "" },
		func() {
			kills.Add(1)
			cancel()
		},
		store,
		func(string, ...any) {},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("runWatchdog error = %v, want context cancellation", err)
	}
	if tunnelCalls.Load() < 2 || kills.Load() != 1 {
		t.Fatalf("tunnel calls=%d kills=%d, want at least 2/1", tunnelCalls.Load(), kills.Load())
	}
	status := store.Snapshot()
	if status.State != "down" || status.Streak < 2 || status.Reason != "no handshake" {
		t.Fatalf("status = %+v, want confirmed down state", status)
	}
}

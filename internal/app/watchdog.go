package app

import (
	"context"
	"fmt"
	"time"
)

type wdState struct {
	streak    int
	announced string // "", "up", "down"
}

// cycle advances the kill-switch state machine by one poll.
//
// The tunnel counts as safe only if tunnelOK and (not verify || egressOK).
// downCycles consecutive unsafe polls confirm DOWN; from confirmation on,
// kill runs every poll so processes spawned during an outage are reaped.
// Recovery restarts nothing: killed processes stay dead by design.
// Returns the new state and log lines to emit (empty = stay quiet).
func cycle(s wdState, tunnelOK bool, reason string, verify, egressOK bool, downCycles int, kill func()) (wdState, []string) {
	if tunnelOK && (!verify || egressOK) {
		if s.announced == "up" && s.streak == 0 {
			return s, nil
		}
		return wdState{announced: "up"}, []string{"tunnel UP"}
	}

	streak := s.streak + 1
	if streak < downCycles {
		return wdState{streak: streak, announced: s.announced},
			[]string{fmt.Sprintf("tunnel possibly DOWN (%d/%d): %s", streak, downCycles, reason)}
	}

	var logs []string
	if s.announced != "down" {
		logs = append(logs, fmt.Sprintf("tunnel DOWN - killing targets: %s", reason))
	}
	kill()
	return wdState{streak: streak, announced: "down"}, logs
}

// runWatchdog drives cycle on the poll ticker until ctx is cancelled.
// proof returns the egress checker's last observed (ip, country) for the
// periodic heartbeat line; every poll's verdict is published to store for
// the agent socket. A heartbeat_interval of 0 disables heartbeats.
func runWatchdog(ctx context.Context, cfg Config, tunnel func() (bool, string), egress func() (bool, string), proof func() (string, string), killer func(), store *Store, logf func(string, ...any)) error {
	d, err := cfg.Durations()
	if err != nil {
		return err
	}
	logf("watchdog started: iface=%s poll=%s max_handshake_age=%s verify_egress=%v heartbeat=%s targets=%v",
		cfg.Interface, cfg.PollInterval, cfg.MaxHandshakeAge, cfg.VerifyEgress, cfg.HeartbeatInterval, cfg.Targets)

	ticker := time.NewTicker(d.poll)
	defer ticker.Stop()
	var heartbeatC <-chan time.Time
	if d.heartbeat > 0 {
		hb := time.NewTicker(d.heartbeat)
		defer hb.Stop()
		heartbeatC = hb.C
	}

	state := wdState{}
	for {
		select {
		case <-ctx.Done():
			logf("watchdog stopping")
			return ctx.Err()
		case <-ticker.C:
		case <-heartbeatC:
			ip, country := proof()
			logf(fmt.Sprintf("heartbeat: state=%s streak=%d exit_ip=%s country=%s",
				stateLabel(state), state.streak, ip, country))
			continue
		}

		tOK, tReason := tunnel()
		eOK := false
		reason := tReason
		if cfg.VerifyEgress && tOK {
			eOK, reason = egress()
		}
		var logs []string
		state, logs = cycle(state, tOK, reason, cfg.VerifyEgress, eOK, cfg.DownCyclesToKill, killer)
		for _, l := range logs {
			logf("%s", l)
		}
		ip, country := proof()
		store.Set(stateLabel(state), state.streak, reason, ip, country)
	}
}

func stateLabel(s wdState) string {
	if s.announced == "" {
		return "unknown"
	}
	return s.announced
}

package app

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Runner abstracts command execution so TunnelChecker is testable.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).Output()
	return string(out), err
}

// parseLatestHandshake parses `wg show <iface> dump`. The first line is the
// interface itself (4 fields); peer lines carry the latest handshake as unix
// seconds in field 4. Malformed lines are skipped. Returns 0 when no peer
// ever handshaked.
func parseLatestHandshake(dump string) int64 {
	var latest int64
	for _, line := range strings.Split(dump, "\n") {
		f := strings.Split(line, "\t")
		if len(f) < 5 {
			continue
		}
		ts, err := strconv.ParseInt(strings.TrimSpace(f[4]), 10, 64)
		if err != nil {
			continue
		}
		if ts > latest {
			latest = ts
		}
	}
	return latest
}

// TunnelChecker reports whether the tunnel works at the transport level.
// Apply hot-swaps config-derived fields under the same mutex Check holds.
type TunnelChecker struct {
	mu sync.Mutex

	Iface      string
	MaxAge     time.Duration
	PingTarget string
	Runner     Runner
	Now        func() time.Time
}

// Apply hot-applies the mutable subset of a new config. Invalid durations
// are rejected so a reload can fall back to the previous settings.
func (t *TunnelChecker) Apply(c Config) error {
	maxAge, err := time.ParseDuration(c.MaxHandshakeAge)
	if err != nil {
		return fmt.Errorf("max_handshake_age: %w", err)
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.MaxAge = maxAge
	t.PingTarget = c.PingTarget
	return nil
}

// Check reports whether the tunnel works at the transport level: the
// interface answers and its freshest peer handshake is recent. WireGuard
// interfaces stay UP while peers vanish, so handshake staleness is the only
// authoritative liveness signal.
func (t *TunnelChecker) Check(ctx context.Context) (bool, string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.PingTarget != "" {
		// Best-effort: forces a fresh handshake on an otherwise idle tunnel
		// so staleness below is a meaningful disconnect signal.
		_, _ = t.Runner.Run(ctx, "ping", "-n", "-q", "-c", "1", "-W", "2", "-I", t.Iface, t.PingTarget)
	}
	dump, err := t.Runner.Run(ctx, "wg", "show", t.Iface, "dump")
	if err != nil {
		return false, "wg show failed (interface missing or not a WireGuard device)"
	}
	latest := parseLatestHandshake(dump)
	if latest == 0 {
		return false, "no handshake recorded"
	}
	age := t.now().Unix() - latest
	if age > int64(t.MaxAge.Seconds()) {
		return false, fmt.Sprintf("handshake %ds old (max %ds)", age, int64(t.MaxAge.Seconds()))
	}
	return true, ""
}

func (t *TunnelChecker) now() time.Time {
	if t.Now != nil {
		return t.Now()
	}
	return time.Now()
}

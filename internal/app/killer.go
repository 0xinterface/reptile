package app

import (
	"context"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type proc struct {
	PID  int
	Comm string
}

type ProcLister interface {
	List() ([]proc, error)
}

// procLister scans /proc on every call; entries for vanished processes are
// skipped. Linux-only at runtime (the daemon targets Linux).
type procLister struct{}

func (procLister) List() ([]proc, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var out []proc
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/comm")
		if err != nil {
			continue // process vanished between readdir and read
		}
		out = append(out, proc{PID: pid, Comm: strings.TrimSpace(string(b))})
	}
	return out, nil
}

// KillTargets signals every process whose comm exactly matches a target:
// SIGTERM first, then SIGKILL to survivors after grace. Returns the target
// names that had matches (sorted). Intended to be called every poll while
// the tunnel is unsafe, which also reaps processes spawned mid-outage.
func KillTargets(ctx context.Context, lister ProcLister, targets []string, grace time.Duration, logKill func(event string, pid int, comm string)) []string {
	want := make(map[string]bool, len(targets))
	for _, t := range targets {
		want[t] = true
	}
	notify := func(event string, pid int, comm string) {
		if logKill != nil {
			logKill(event, pid, comm)
		}
	}
	procs, err := lister.List()
	if err != nil {
		notify("list_failed", 0, "")
		return nil
	}

	matched := map[string]bool{}
	var termPIDs []proc
	for _, p := range procs {
		if want[p.Comm] {
			matched[p.Comm] = true
			termPIDs = append(termPIDs, p)
		}
	}
	if len(termPIDs) == 0 {
		return nil
	}

	names := make([]string, 0, len(matched))
	for n := range matched {
		names = append(names, n)
	}
	sort.Strings(names)

	for _, p := range termPIDs {
		notify("SIGTERM", p.PID, p.Comm)
		_ = syscall.Kill(p.PID, syscall.SIGTERM)
	}

	select {
	case <-time.After(grace):
	case <-ctx.Done():
		return names
	}

	if procs2, err := lister.List(); err == nil {
		for _, p := range procs2 {
			if want[p.Comm] {
				notify("SIGKILL", p.PID, p.Comm)
				_ = syscall.Kill(p.PID, syscall.SIGKILL)
			}
		}
	}
	return names
}

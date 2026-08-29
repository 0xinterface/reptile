package app

import (
	"context"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

type fakeLister struct {
	procs []proc
}

func (f fakeLister) List() ([]proc, error) { return f.procs, nil }

func spawn(t *testing.T, name string, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(name, args...)
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn %s: %v", name, err)
	}
	return cmd
}

func waitExit(t *testing.T, cmd *exec.Cmd, within time.Duration, shouldExit bool) {
	t.Helper()
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	select {
	case <-done:
		if !shouldExit {
			t.Fatalf("pid %d exited early", cmd.Process.Pid)
		}
	case <-time.After(within):
		if shouldExit {
			t.Fatalf("pid %d still alive after %v", cmd.Process.Pid, within)
		}
	}
}

func TestKillTargetsTermThenKillEscalation(t *testing.T) {
	sleep1 := spawn(t, "sleep", "30")
	sleep2 := spawn(t, "sleep", "30")
	// ignores SIGTERM; must be escalated to SIGKILL
	stubborn := spawn(t, "sh", "-c", `trap "" TERM; sleep 30`)
	defer func() {
		_ = syscall.Kill(sleep1.Process.Pid, 9)
		_ = syscall.Kill(sleep2.Process.Pid, 9)
		_ = syscall.Kill(stubborn.Process.Pid, 9)
	}()

	lister := fakeLister{procs: []proc{
		{sleep1.Process.Pid, "sleep"},
		{sleep2.Process.Pid, "sleep"},
		{stubborn.Process.Pid, "sleep"},
	}}
	var events []string
	killed := KillTargets(context.Background(), lister, []string{"sleep"}, 300*time.Millisecond,
		func(event string, pid int, comm string) {
			events = append(events, event+" "+comm)
		})

	if len(killed) != 1 || killed[0] != "sleep" {
		t.Errorf("killed = %v, want [sleep]", killed)
	}
	termCount, killCount := 0, 0
	for _, e := range events {
		switch e {
		case "SIGTERM sleep":
			termCount++
		case "SIGKILL sleep":
			killCount++
		}
	}
	if termCount != 3 {
		t.Errorf("SIGTERM events = %d, want 3 (one per matched pid)", termCount)
	}
	if killCount != 3 {
		t.Errorf("SIGKILL events = %d, want 3 (every matched pid re-checked after grace)", killCount)
	}
	waitExit(t, sleep1, 5*time.Second, true)
	waitExit(t, sleep2, 5*time.Second, true)
	waitExit(t, stubborn, 5*time.Second, true) // proves SIGKILL escalation happened
}

func TestKillTargetsSparesNonTargets(t *testing.T) {
	innocent := spawn(t, "sleep", "30")
	defer func() { _ = syscall.Kill(innocent.Process.Pid, 9) }()

	lister := fakeLister{procs: []proc{{innocent.Process.Pid, "otherproc"}}}
	killed := KillTargets(context.Background(), lister, []string{"sleep"}, 100*time.Millisecond, nil)
	if len(killed) != 0 {
		t.Errorf("killed = %v, want none", killed)
	}
	waitExit(t, innocent, 300*time.Millisecond, false) // must still be running
}

func TestKillTargetsNoMatchSkipsGrace(t *testing.T) {
	lister := fakeLister{procs: []proc{{1, "init-like"}}}
	start := time.Now()
	killed := KillTargets(context.Background(), lister, []string{"sleep"}, 2*time.Second, nil)
	if len(killed) != 0 {
		t.Errorf("killed = %v, want none", killed)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("no-match path waited %v; grace sleep must be skipped", elapsed)
	}
}

func TestKillTargetsMultipleTargets(t *testing.T) {
	a := spawn(t, "sleep", "30")
	b := spawn(t, "sleep", "30")
	defer func() {
		_ = syscall.Kill(a.Process.Pid, 9)
		_ = syscall.Kill(b.Process.Pid, 9)
	}()
	lister := fakeLister{procs: []proc{
		{a.Process.Pid, "torrentd"},
		{b.Process.Pid, "syncd"},
	}}
	killed := KillTargets(context.Background(), lister, []string{"torrentd", "syncd"}, 200*time.Millisecond, nil)
	if len(killed) != 2 {
		t.Errorf("killed = %v, want both targets", killed)
	}
	waitExit(t, a, 5*time.Second, true)
	waitExit(t, b, 5*time.Second, true)
}

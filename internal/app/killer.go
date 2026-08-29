package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
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

type killOptions struct {
	Lister ProcLister
	Signal func(pid int, sig syscall.Signal) error
	Grace  time.Duration
	Log    func(event string, pid int, comm string, err error)
}

const maxSignalWorkers = 32

// signalProcesses dispatches one signal per process with bounded concurrency.
// The returned errors retain process order so logging remains deterministic.
func signalProcesses(
	procs []proc,
	sig syscall.Signal,
	signal func(pid int, sig syscall.Signal) error,
) []error {
	if len(procs) == 0 {
		return []error{}
	}
	workers := len(procs)
	if workers > maxSignalWorkers {
		workers = maxSignalWorkers
	}

	errs := make([]error, len(procs))
	jobs := make(chan int)
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for i := range jobs {
				errs[i] = signal(procs[i].PID, sig)
			}
		}()
	}
	for i := range procs {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return errs
}

// killTargets signals every process whose comm exactly matches a target:
// SIGTERM first, then SIGKILL to matching survivors and replacements after
// grace. It returns every target name matched and all enforcement failures.
func killTargets(ctx context.Context, targets []string, opts killOptions) ([]string, error) {
	lister := opts.Lister
	if lister == nil {
		lister = procLister{}
	}
	signal := opts.Signal
	if signal == nil {
		signal = syscall.Kill
	}
	notify := func(event string, p proc, err error) {
		if opts.Log != nil {
			opts.Log(event, p.PID, p.Comm, err)
		}
	}

	want := make(map[string]bool, len(targets))
	for _, target := range targets {
		want[target] = true
	}
	procs, err := lister.List()
	if err != nil {
		return nil, fmt.Errorf("list target processes: %w", err)
	}

	matched := map[string]bool{}
	termPIDs := []proc{}
	for _, p := range procs {
		if want[p.Comm] {
			matched[p.Comm] = true
			termPIDs = append(termPIDs, p)
		}
	}
	if len(termPIDs) == 0 {
		return nil, nil
	}

	names := make([]string, 0, len(matched))
	for name := range matched {
		names = append(names, name)
	}
	sort.Strings(names)

	var failures []error
	sendAll := func(event string, sig syscall.Signal, procs []proc) {
		for i, err := range signalProcesses(procs, sig, signal) {
			p := procs[i]
			notify(event, p, err)
			if err != nil && !errors.Is(err, syscall.ESRCH) {
				failures = append(failures, fmt.Errorf("%s pid=%d comm=%q: %w", event, p.PID, p.Comm, err))
			}
		}
	}
	sendAll("SIGTERM", syscall.SIGTERM, termPIDs)

	timer := time.NewTimer(opts.Grace)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		return names, errors.Join(failures...)
	}

	procs, err = lister.List()
	if err != nil {
		failures = append(failures, fmt.Errorf("re-list target processes: %w", err))
		return names, errors.Join(failures...)
	}
	killPIDs := []proc{}
	for _, p := range procs {
		if want[p.Comm] {
			killPIDs = append(killPIDs, p)
		}
	}
	sendAll("SIGKILL", syscall.SIGKILL, killPIDs)
	return names, errors.Join(failures...)
}

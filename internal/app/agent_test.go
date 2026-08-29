package app

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreSnapshot(t *testing.T) {
	s := NewStore()
	if got := s.Snapshot().State; got != "unknown" {
		t.Errorf("initial state = %q, want unknown", got)
	}
	s.Set("down", 2, "egress country DE != expected CH", "198.51.100.8", "DE")
	st := s.Snapshot()
	if st.State != "down" || st.Streak != 2 || st.Reason != "egress country DE != expected CH" ||
		st.ExitIP != "198.51.100.8" || st.Country != "DE" {
		t.Errorf("snapshot = %+v", st)
	}
	if _, err := time.Parse(time.RFC3339, st.UpdatedAt); err != nil {
		t.Errorf("updated_at %q not RFC3339: %v", st.UpdatedAt, err)
	}
}

func startServer(t *testing.T, store *Store, prober func() Status) string {
	t.Helper()
	t.Chdir(t.TempDir()) // macOS limits unix socket paths to 104 bytes
	srv := NewServer("agent.sock", store, prober)
	ln, err := srv.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

func TestAgentStatusRoundTrip(t *testing.T) {
	store := NewStore()
	store.Set("up", 0, "", "198.51.100.7", "CH")
	path := startServer(t, store, nil)

	st, err := Query(path, "status")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if st.State != "up" || st.ExitIP != "198.51.100.7" || st.Country != "CH" {
		t.Errorf("status = %+v", st)
	}
}

func TestAgentProbeRunsFreshCheck(t *testing.T) {
	store := NewStore()
	calls := 0
	path := startServer(t, store, func() Status {
		calls++
		store.Set("down", 3, "probe request failed", "", "")
		return store.Snapshot()
	})

	st, err := Query(path, "probe")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if calls != 1 {
		t.Errorf("prober calls = %d, want 1", calls)
	}
	if st.State != "down" || st.Streak != 3 || st.Reason != "probe request failed" {
		t.Errorf("probe status = %+v", st)
	}
}

func TestAgentUnknownCommand(t *testing.T) {
	path := startServer(t, NewStore(), nil)
	if _, err := Query(path, "self-destruct"); err == nil {
		t.Fatal("unknown command must error")
	}
}

func TestAgentListenReplacesStaleSocket(t *testing.T) {
	t.Chdir(t.TempDir())
	path := "agent.sock"
	if err := os.WriteFile(path, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	srv := NewServer(path, NewStore(), nil)
	ln, err := srv.Listen()
	if err != nil {
		t.Fatalf("Listen over stale socket file: %v", err)
	}
	defer ln.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("socket file missing after Listen: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&os.ModeSocket == 0 {
		t.Error("path is not a socket after Listen")
	}
}

func TestQueryUnreachableSocket(t *testing.T) {
	if _, err := Query(filepath.Join(t.TempDir(), "missing.sock"), "status"); err == nil {
		t.Fatal("querying a missing socket must error")
	}
}

var _ = context.Background

func TestAgentReloadCommand(t *testing.T) {
	t.Chdir(t.TempDir())
	calls := 0
	srv := NewServer("agent.sock", NewStore(), nil)
	srv.Reloader = func() ([]string, []string, error) {
		calls++
		return []string{"expected_country"}, []string{"interface"}, nil
	}
	ln, err := srv.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = ln.Close() })

	resp, err := QueryResponse("agent.sock", "reload")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if calls != 1 {
		t.Errorf("reloader calls = %d, want 1", calls)
	}
	if len(resp.Applied) != 1 || resp.Applied[0] != "expected_country" {
		t.Errorf("applied = %v", resp.Applied)
	}
	if len(resp.RestartRequired) != 1 || resp.RestartRequired[0] != "interface" {
		t.Errorf("restart_required = %v", resp.RestartRequired)
	}

	if _, err = QueryResponse("agent.sock", "reload-nonsense"); err == nil {
		t.Error("unknown command must error")
	}
}

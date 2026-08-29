package app

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Store publishes the watchdog state machine's live snapshot to the agent
// socket. All access is mutex-guarded; the watchdog writes, the agent reads.
type Store struct {
	mu        sync.Mutex
	state     string
	streak    int
	reason    string
	exitIP    string
	country   string
	updatedAt time.Time
}

func NewStore() *Store { return &Store{state: "unknown"} }

func (s *Store) Set(state string, streak int, reason, exitIP, country string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state, s.streak, s.reason, s.exitIP, s.country = state, streak, reason, exitIP, country
	s.updatedAt = time.Now()
}

func (s *Store) Snapshot() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := Status{
		State:   s.state,
		Streak:  s.streak,
		Reason:  s.reason,
		ExitIP:  s.exitIP,
		Country: s.country,
	}
	if !s.updatedAt.IsZero() {
		st.UpdatedAt = s.updatedAt.UTC().Format(time.RFC3339)
	}
	return st
}

// Status is the JSON payload served over the agent socket.
type Status struct {
	State     string `json:"state"`
	Streak    int    `json:"streak"`
	Reason    string `json:"reason,omitempty"`
	ExitIP    string `json:"exit_ip,omitempty"`
	Country   string `json:"country,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

type agentRequest struct {
	Cmd string `json:"cmd"`
}

type agentResponse struct {
	OK     bool    `json:"ok"`
	Error  string  `json:"error,omitempty"`
	Status *Status `json:"status,omitempty"`
}

// Server serves the newline-JSON agent protocol on a unix socket:
// the client sends {"cmd":"status"} or {"cmd":"probe"} and receives one
// JSON agentResponse.
type Server struct {
	path   string
	store  *Store
	prober func() Status

	mu     sync.Mutex
	closed bool
	ln     net.Listener
}

func NewServer(path string, store *Store, prober func() Status) *Server {
	return &Server{path: path, store: store, prober: prober}
}

// Listen creates the socket directory, replaces any stale socket file from a
// previous run, and binds. Call Serve with the returned listener.
func (s *Server) Listen() (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return nil, err
	}
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	ln, err := net.Listen("unix", s.path)
	if err != nil {
		return nil, err
	}
	s.ln = ln
	return ln, nil
}

// Close stops the listener; Serve then returns nil.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	if s.ln != nil {
		return s.ln.Close()
	}
	return nil
}

// Serve accepts connections until the listener is closed. Each connection
// carries exactly one request and one response.
func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				return nil
			}
			return err
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()
	var req agentRequest
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(agentResponse{OK: false, Error: "bad request: " + err.Error()})
		return
	}
	switch req.Cmd {
	case "status":
		st := s.store.Snapshot()
		_ = json.NewEncoder(conn).Encode(agentResponse{OK: true, Status: &st})
	case "probe":
		st := s.store.Snapshot()
		if s.prober != nil {
			st = s.prober()
		}
		_ = json.NewEncoder(conn).Encode(agentResponse{OK: true, Status: &st})
	default:
		_ = json.NewEncoder(conn).Encode(agentResponse{OK: false, Error: fmt.Sprintf("unknown command %q", req.Cmd)})
	}
}

// Query is the client side: connects to the agent socket, sends one command,
// returns the status payload. Non-OK responses surface as errors.
func Query(path string, cmd string) (Status, error) {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return Status{}, err
	}
	defer conn.Close()
	if err := json.NewEncoder(conn).Encode(agentRequest{Cmd: cmd}); err != nil {
		return Status{}, err
	}
	var r agentResponse
	if err := json.NewDecoder(conn).Decode(&r); err != nil {
		return Status{}, err
	}
	if !r.OK {
		return Status{}, fmt.Errorf("%s", r.Error)
	}
	if r.Status == nil {
		return Status{}, fmt.Errorf("empty response")
	}
	return *r.Status, nil
}

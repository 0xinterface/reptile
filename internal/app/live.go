package app

import "sync"

// Live holds the daemon's current config behind a lock so the agent
// goroutine can hot-swap it while the poll loop reads it.
type Live struct {
	mu  sync.RWMutex
	cfg Config
}

func NewLive(c Config) *Live { return &Live{cfg: c} }

// Get returns a snapshot of the current config.
func (l *Live) Get() Config {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.cfg
}

// Set swaps the current config.
func (l *Live) Set(c Config) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.cfg = c
}

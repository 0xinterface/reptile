package app

import (
	"sync"
	"testing"
)

func TestLiveGetSet(t *testing.T) {
	l := NewLive(Config{Interface: "wg0"})
	if got := l.Get().Interface; got != "wg0" {
		t.Fatalf("initial = %q, want wg0", got)
	}
	l.Set(Config{Interface: "wg9"})
	if got := l.Get().Interface; got != "wg9" {
		t.Fatalf("after Set = %q, want wg9", got)
	}
}

func TestLiveConcurrentAccess(t *testing.T) {
	l := NewLive(Config{Interface: "wg0"})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for range 200 {
				l.Set(Config{Interface: "wg1"})
			}
		}()
		go func() {
			defer wg.Done()
			for range 200 {
				_ = l.Get().Interface
			}
		}()
	}
	wg.Wait()
}

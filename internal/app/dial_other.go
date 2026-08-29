//go:build !linux

package app

import (
	"net"
	"time"
)

// ifaceDialer on non-Linux (local test host) cannot bind to an interface;
// the daemon targets Linux where dial_linux.go provides the real binding.
func ifaceDialer(iface string, timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout}
}

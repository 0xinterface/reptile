//go:build linux

package app

import (
	"context"
	"net"
	"syscall"
	"time"
)

// ifaceDialer returns a dialer whose traffic can only leave via the given
// interface (SO_BINDTODEVICE, needs CAP_NET_ADMIN; the daemon runs as root).
// For hostname probe URLs, DNS is routed through the same interface.
func ifaceDialer(iface string, timeout time.Duration) *net.Dialer {
	d := &net.Dialer{Timeout: timeout}
	if iface == "" {
		return d
	}
	bind := func(network, address string, c syscall.RawConn) error {
		var sockErr error
		if err := c.Control(func(fd uintptr) {
			sockErr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
		}); err != nil {
			return err
		}
		return sockErr
	}
	d.Control = bind
	d.Resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: timeout, Control: bind}).DialContext(ctx, network, address)
		},
	}
	return d
}

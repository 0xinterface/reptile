// Command reptile is a WireGuard kill switch: it verifies tunnel liveness
// and egress proof (country, exit IP, DNSBL reputation), kills configured
// target processes when conditions break, and while running exposes an
// agent socket that the same binary queries as a client (status, history).
package main

import "github.com/0xinterface/reptile/internal/app"

func main() { app.Run() }

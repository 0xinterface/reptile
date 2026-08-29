# reptile

A WireGuard kill switch for Linux. `reptile` watches a designated WireGuard
tunnel, continuously proves that traffic is really exiting where it should,
and **kills configured processes whenever that proof breaks** — closing the
gap between "the interface is up" and "the tunnel is actually safe".

Two independent layers:

1. **Watchdog daemon** (`standby`) — polls the tunnel and, while any safety
   condition fails, repeatedly `SIGTERM`/`SIGKILL`s your target processes
   (so processes started mid-outage die too).
2. **nftables kill switch** (`firewall up`) — always-on egress policy:
   everything leaves the host **only** via the tunnel, except exact literal
   WireGuard endpoint address/port pairs, loopback, DHCP, required IPv6
   neighbor discovery, and explicitly configured `extra_accept` rules.

## Why "interface is up" is not enough

A WireGuard interface does not disconnect: `wg0` keeps its address while the
peer silently vanishes. The only authoritative liveness signal is the
**latest handshake age**. On top of that, a working tunnel can still exit in
the wrong country or through a rotten IP, so reptile treats "safe" as a
conjunction that must all hold:

| # | condition | source |
|---|-----------|--------|
| 1 | interface exists | `ip link` via `wg show <iface> dump` |
| 2 | freshest peer handshake ≤ `max_handshake_age` | same (peer lines, field 4) |
| 3 | probe bound to the tunnel resolves to `expected_country` (and `expected_ip` if set) | HTTPS probe with `SO_BINDTODEVICE` |
| 4 | exit IP not listed in any `dnsbl_zones` | reverse-IP DNSBL A-lookups |

Everything is **fail-closed**: a probe timeout, an unparsable answer, or a
DNS hiccup in the geo path counts as *unproven*, and unproven means kill.
(Blacklist infra errors alone degrade to a warning; only an actual
`127.0.0.0/8` DNSBL answer counts as a hit.)

Install, set `expected_country` and `targets`, enable two units — done.

## Requirements

- Linux (systemd), WireGuard via `wg-quick` (`/etc/wireguard/<iface>.conf`)
- literal-IP WireGuard `Endpoint` values when the firewall is enabled
- root (the daemon needs `CAP_KILL`, `CAP_NET_ADMIN`, `CAP_NET_RAW`)
- `wg`, `nft`, `curl` on PATH

## Install

From a machine with Go:

```sh
go install github.com/0xinterface/reptile/cmd/reptile@latest
sudo reptile install
```

`install` self-copies the binary to `/usr/local/bin/reptile`, writes the
example config to `/etc/reptile/config.json` (never overwrites an existing
one), installs the embedded systemd units, and activates them. The watchdog
refuses to start until you replace the `CHANGE_ME` placeholders:

```sh
sudoedit /etc/reptile/config.json   # set targets + expected_country
sudo systemctl start reptile
reptile check && journalctl -u reptile -f
```

`--root <dir>` installs into a directory tree instead (containers/testing),
`--no-activate` skips systemctl. Release binaries are also cross-compiled
per push in CI (`dist/reptile-linux-amd64|arm64`): drop one on the host and
run `sudo ./reptile install`.

## Commands

| command | purpose |
|---|---|
| `reptile standby` | run the watchdog daemon (agent socket + log file tee). `daemon` is an alias. |
| `reptile status [-probe]` | query the running daemon over its socket; `-probe` forces a fresh egress evaluation. Exit 1 when down. |
| `reptile history [-n N] [-level info\|warn\|error] [--no-color]` | recent events from the log file with level highlighting; works while the daemon is down |
| `reptile config [set key value ...]` | show effective config or atomically validate, save, and hot-apply safe settings |
| `reptile check` | one-shot evaluation of every configured condition; exit 0 = proven safe |
| `reptile install [flags]` | see above |
| `reptile firewall up\|down` | engage/remove the nftables kill switch (normally managed by its unit) |

## Configuration

`/etc/reptile/config.json` — strict JSON over defaults; absent keys keep
defaults, while unknown keys and trailing JSON are rejected. The complete
configuration is semantically validated before start, reload, or `config set`.
Path defaults: config `/etc/reptile/config.json`, socket
`/run/reptile/agent.sock`, log `/var/lib/reptile/events.log`.

```jsonc
{
  "interface": "wg0",
  "poll_interval": "10s",        // watchdog cadence
  "max_handshake_age": "180s",   // handshake older than this = transport dead
  "down_cycles_to_kill": 2,      // consecutive failing polls before killing
  "kill_grace": "3s",            // SIGTERM -> wait -> SIGKILL
  "heartbeat_interval": "10m",   // periodic state log line; "0s" disables
  "ping_target": "",             // optional tunnel IP; pinged each poll to
                                 //   force handshakes on an idle tunnel
  "verify_egress": true,
  "expected_country": "CH",      // REQUIRED: two-letter ISO country of the exit
  "expected_ip": "",             // optional exact exit IP pin
  "probe_url": "https://1.1.1.1/cdn-cgi/trace",
  "country_pattern": "(?m)^loc=([A-Z]{2})",
  "ip_pattern": "(?m)^ip=([0-9a-fA-F.:]+)",
  "probe_interval": "300s",      // cache TTL; invalidated on tunnel failure
  "probe_timeout": "5s",
  "dnsbl_zones": ["zen.spamhaus.org", "b.barracudacentral.org", "bl.spamcop.net"],
  "targets": ["transmission-daemon"],  // exact comm names, 15-char limit
  "wg_conf": "/etc/wireguard/wg0.conf",
  "extra_accept": [],            // raw nft rules appended to the output chain
  "socket_path": "/run/reptile/agent.sock",  // "" disables the agent
  "log_file": "/var/lib/reptile/events.log"  // "" disables the file sink
}
```

`reptile config set` persists only a completely valid result. Safe daemon
settings are applied live. Changes to `interface`, `socket_path`, or
`log_file` report `systemctl restart reptile`; changes to `interface`,
`wg_conf`, or `extra_accept` report
`systemctl reload reptile-firewall`.

Notes:

- `targets` are matched against the kernel `comm` (like `pkill -x`,
  truncated to 15 bytes). A systemd unit with `Restart=always` will respawn
  after each kill — such services need unit-level stopping, which reptile
  intentionally does not do.
- `probe_url` defaults to Cloudflare's `cdn-cgi/trace` because it is HTTPS to
  a **literal IP** (no DNS dependency inside the tunnel) and returns
  `loc=<country>` / `ip=<exit ip>`. Any service works — point `probe_url`
  elsewhere and adapt the two regexes, e.g. for
  [ipwho.is](https://ipwho.is): `"country_pattern":
  "\"country_code\"\\s*:\\s*\"([A-Za-z]{2})\"`,
  `"ip_pattern": "\"ip\"\\s*:\\s*\"([^\"]+)\""`. Hostname probe URLs resolve
  DNS **through the tunnel** — add `DNS = …` to your wg-quick config or use a
  literal-IP service.
- `dnsbl_zones`: a hit is an A answer in `127.0.0.0/8` (operator refusal
  codes `127.255.255.x` are correctly ignored). `zen.spamhaus.org` returns
  refusal codes when queried via public resolvers (8.8.8.8/1.1.1.1) — run a
  local resolver or drop the zone. Set `[]` to disable reputation checks.
- `extra_accept` is spliced verbatim into the output chain, e.g.
  `"ip daddr 192.168.0.0/16 accept"` for LAN access while down.

## WireGuard config recommendations

In `/etc/wireguard/wg0.conf` `[Peer]`:

```ini
PersistentKeepalive = 25
```

Without periodic handshakes an idle-but-healthy tunnel looks stale and gets
killed as a false positive. Either set keepalive or point `ping_target` at an
IP inside the tunnel (it is pinged once per poll to force fresh handshakes).

The firewall derives exact allowed transport address/port pairs from the
`Endpoint =` lines of `wg_conf` at unit start. Endpoints must use literal IPv4
or IPv6 addresses; hostnames are rejected rather than opening a port to every
destination. After changing endpoints run
`systemctl reload reptile-firewall`.

## Agent mode

While `standby` runs, it serves newline-JSON on the unix socket:

```
-> {"cmd":"status"}    <- {"ok":true,"status":{"state":"up","streak":0,
                            "exit_ip":"198.51.100.7","country":"CH",
                            "updated_at":"2026-08-29T07:00:00Z"}}
-> {"cmd":"probe"}     <- same shape, after a fresh tunnel+egress evaluation
```

`reptile status` / `reptile status -probe` are thin clients. The watchdog
publishes every poll verdict (state, streak, failure reason, observed exit)
to the socket, so an agent can watch safety in real time.
The socket is mode `0600`; requests have deadlines and bounded concurrency.

## Logging

Records go to stderr (journald-friendly, no duplicate timestamp — level
padded, `key=value` attrs) and, when `log_file` is set, to the file sink
(always timestamped, 0600). Steady state is silent; you get:

```
INFO  tunnel possibly DOWN (1/2): handshake 999s old (max 180s)
WARN  sent SIGTERM comm=torrentd pid=1234
INFO  tunnel DOWN - killing targets: egress country DE != expected CH
WARN  egress check failed reason="probe request failed" observed_country=DE observed_ip=198.51.100.8
INFO  egress verified country=CH ip=198.51.100.7
INFO  heartbeat: state=up streak=0 exit_ip=198.51.100.7 country=CH
INFO  tunnel UP
```

`reptile history` reads the file (also after the daemon stopped);
`journalctl -u reptile -f` covers the console sink. No rotation — hook up
logrotate if the heartbeat volume bothers you.

## Systemd units

- `reptile.service` — the watchdog; `Restart=on-failure`, deliberately **not**
  bound to `wg-quick@wg0` (it must keep killing while the tunnel is down).
  `RuntimeDirectory=reptile` and `StateDirectory=reptile` provide narrowly
  writable paths inside `ProtectSystem=strict`. Other hardening includes
  `NoNewPrivileges`, `UMask=0077`,
  `CapabilityBoundingSet=CAP_KILL CAP_NET_ADMIN CAP_NET_RAW`, and
  `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK`.
- `reptile-firewall.service` — oneshot, `DefaultDependencies=no`,
  ordered after `network-pre.target`; engages the nftables kill switch at
  boot, removes its table on stop.

## Operational check

After installing, verify the whole chain once:

```sh
reptile check                      # tunnel UP + egress proven
sudo wg-quick down wg0             # deliberate outage
# within ~2 polls: journal shows "tunnel DOWN - killing targets",
# targets die, `reptile status` exits 1, non-tunnel egress is dropped
sudo wg-quick up wg0
reptile status                     # state=up again (killed targets stay dead)
```

## Releasing

1. GitHub → **Actions → tag → Run workflow** → enter a version (e.g. `v0.1.0`).
   The workflow validates it, pushes an annotated tag on `main`.
2. The tag push triggers the `release` workflow: GoReleaser cross-compiles
   linux amd64/arm64 with full version stamping, generates SHA256 checksums
   and a changelog from conventional commits, and publishes the GitHub
   release with all artifacts.

Config: `.goreleaser.yaml`. CI validates it on every PR
(`goreleaser check` job).

## Development

```sh
go build ./cmd/reptile        # local build
go test -race ./...           # portable unit/behavior suite
sudo env "PATH=/usr/sbin:$PATH" REPTILE_REQUIRE_INTEGRATION=1 \
  go test -tags=integration -count=1 -run '^TestFirewallNamespace$' ./internal/app
sudo env "PATH=/usr/sbin:$PATH" REPTILE_REQUIRE_SYSTEMD=1 \
  go test -tags=integration -count=1 -run '^TestInstalledSystemdSandbox$' ./internal/app
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o dist/reptile-linux-amd64 ./cmd/reptile
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o dist/reptile-linux-arm64 ./cmd/reptile
```

### Build metadata

`reptile version` prints version, commit, build date, OS/arch and Go
toolchain. Stamping precedence:

1. `-ldflags` `-X` values — CI stamps `version` (ref name), `commit` (SHA)
   and `buildDate` on every build.
2. Without ldflags, the Go toolchain's embedded VCS info is used:
   `go install`/`go build` from a git checkout automatically carries the
   module version (tag or pseudo-version), the commit revision and the
   commit time. Untagged installs show a `v0.0.0-…` pseudo-version; tag
   releases (`git tag v0.1.0 && git push --tags`) for clean versions.

CI (`.github/workflows/ci.yml`) runs gofmt, `go vet`, race tests, a privileged
nftables network-namespace test, offline systemd unit validation, an
architecture-verified cross-build matrix, and `govulncheck` on every push to
`main` and every PR. Actions are least-privilege (`contents: read`,
`persist-credentials: false`).

Layout: `cmd/reptile` is a thin entry point; everything lives in
`internal/app` (config, tunnel, egress, killer, watchdog, firewall, agent,
logging, install). External commands (`wg`, `ip`, `ping`, `nft`,
`systemctl`) are invoked through injectable runners — that is what makes the
kill logic testable off-Linux.

## Known limitations

- Linux-only at runtime (the `/proc` scanner and `SO_BINDTODEVICE` dialer
  are Linux-specific; the suite runs anywhere, the daemon targets Linux).
- Killing cannot stop systemd services that auto-restart (see `targets`).
- `expected_country` is a single-country allowlist, not a denylist — that is
  strictly stronger than any country blacklist.
- Config changes hot-apply when safe. Interface, socket, and log wiring need a
  watchdog restart; interface, WireGuard config, and extra firewall accepts
  need a firewall reload. The CLI reports the exact service command.
- The fail-closed firewall requires literal-IP WireGuard endpoints; hostname
  endpoints are rejected.
- Log file has no rotation.
- Privileged Linux CI exercises the real nftables policy in network
  namespaces. GitHub-hosted runners do not provide a running systemd manager,
  so CI validates the unit files offline; run `TestInstalledSystemdSandbox`
  explicitly on a systemd host before release.

## License

MIT.

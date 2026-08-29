#!/bin/sh
# Convenience wrapper for dist/ users:
#   1. installs the prebuilt dist/ binary (or builds one) as /usr/local/bin/reptile
#   2. delegates the rest to `reptile install` (config, units, activation)
#
# Prefer, on a machine with Go:
#   go install github.com/0xinterface/reptile/cmd/reptile@latest
#   sudo reptile install
set -eu
cd "$(dirname "$0")"

case "$(uname -m)" in
	x86_64) goarch=amd64 ;;
	aarch64 | arm64) goarch=arm64 ;;
	*) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac
bin="dist/reptile-linux-$goarch"

if [ ! -f "$bin" ]; then
	command -v go >/dev/null 2>&1 || {
		echo "no prebuilt binary at $bin and no go toolchain to build one" >&2
		exit 1
	}
	mkdir -p dist
	GOOS=linux GOARCH=$goarch go build -o "$bin" ./cmd/reptile
fi

install -m 755 "$bin" /usr/local/bin/reptile
exec reptile install "$@"

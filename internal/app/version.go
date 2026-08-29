package app

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"runtime/debug"
)

// Injected at build time via -ldflags
// (-X github.com/0xinterface/reptile/internal/app.version=...). CI stamps
// the ref name, commit SHA and build date; plain `go build` leaves "dev".
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

// BuildInfo describes the running binary.
type BuildInfo struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	Date      string `json:"date"`
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
	GoVersion string `json:"go_version"`
}

// GetBuildInfo returns the running binary's build metadata. Precedence:
// ldflags-stamped values (CI/release builds) over the VCS info that the Go
// toolchain embeds automatically for `go install`/`go build` from a git
// checkout (vcs.revision, vcs.time, module version).
func GetBuildInfo() BuildInfo {
	bi := BuildInfo{
		Version:   version,
		Commit:    commit,
		Date:      buildDate,
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
		GoVersion: runtime.Version(),
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return bi
	}
	if bi.Version == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		bi.Version = info.Main.Version
	}
	if bi.Commit == "unknown" {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if s.Value != "" {
					rev := s.Value
					if len(rev) > 12 {
						rev = rev[:12]
					}
					bi.Commit = rev
				}
			case "vcs.time":
				bi.Date = s.Value
			case "vcs.modified":
				if s.Value == "true" {
					bi.Commit += "-dirty"
				}
			}
		}
	}
	return bi
}

// RenderVersion writes the build info as key=value lines.
func RenderVersion(w io.Writer, bi BuildInfo) error {
	for _, kv := range []struct{ k, v string }{
		{"version", bi.Version},
		{"commit", bi.Commit},
		{"date", bi.Date},
		{"goos", bi.GOOS},
		{"goarch", bi.GOARCH},
		{"go", bi.GoVersion},
	} {
		if _, err := fmt.Fprintf(w, "%s=%s\n", kv.k, kv.v); err != nil {
			return err
		}
	}
	return nil
}

func runVersion() int {
	if err := RenderVersion(os.Stdout, GetBuildInfo()); err != nil {
		slog.Error(fmt.Sprintf("render: %v", err))
		return 1
	}
	return 0
}

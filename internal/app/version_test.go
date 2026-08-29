package app

import (
	"bytes"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

func TestBuildInfoPopulated(t *testing.T) {
	bi := GetBuildInfo()
	if bi.Version == "" {
		t.Error("version must never be empty (default: dev)")
	}
	if bi.GOARCH != runtime.GOARCH {
		t.Errorf("GOARCH = %q, want %q", bi.GOARCH, runtime.GOARCH)
	}
	if bi.GOOS != runtime.GOOS {
		t.Errorf("GOOS = %q, want %q", bi.GOOS, runtime.GOOS)
	}
	if bi.GoVersion == "" {
		t.Error("go version missing")
	}
	// Built from a git checkout, the toolchain embeds vcs.revision — this
	// is exactly what `go install` binaries rely on for commit info.
	if bi.Commit == "unknown" {
		hasVCS := false
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, s := range info.Settings {
				if s.Key == "vcs.revision" && s.Value != "" {
					hasVCS = true
				}
			}
		}
		if hasVCS {
			t.Error("commit = unknown although VCS revision is available")
		}
		t.Skip("no VCS revision embedded in this build")
	}
}

func TestRenderVersion(t *testing.T) {
	bi := BuildInfo{Version: "v1.2.3", Commit: "abc1234", Date: "2026-08-29T00:00:00Z",
		GOOS: "linux", GOARCH: "arm64", GoVersion: "go1.27.0"}
	var buf bytes.Buffer
	if err := RenderVersion(&buf, bi); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"version=v1.2.3", "commit=abc1234", "date=2026-08-29T00:00:00Z",
		"goos=linux", "goarch=arm64", "go=go1.27.0",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("output missing %q:\n%s", want, buf.String())
		}
	}
}

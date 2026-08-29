package app

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestFanoutWritesToEverySink(t *testing.T) {
	var console, file bytes.Buffer
	h := NewFanoutHandler(NewConsoleHandler(&console, false), NewConsoleHandler(&file, true))
	r := slog.NewRecord(time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC), slog.LevelWarn, "sent SIGKILL", 0)
	r.AddAttrs(slog.String("comm", "torrentd"))
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	for name, buf := range map[string]*bytes.Buffer{"console": &console, "file": &file} {
		if !strings.Contains(buf.String(), "WARN  sent SIGKILL comm=torrentd") {
			t.Errorf("%s sink missing record: %q", name, buf.String())
		}
	}
	if !strings.HasPrefix(file.String(), "10:00:00 ") {
		t.Errorf("file sink must carry its own timestamp, got %q", file.String())
	}
	if strings.HasPrefix(console.String(), "10:") {
		t.Errorf("console sink must not timestamp, got %q", console.String())
	}
}

func TestFanoutWithAttrsPropagates(t *testing.T) {
	var a, b bytes.Buffer
	h := NewFanoutHandler(NewConsoleHandler(&a, false), NewConsoleHandler(&b, false)).WithAttrs([]slog.Attr{slog.String("unit", "reptile")})
	r := slog.NewRecord(time.Now(), slog.LevelInfo, "hello", 0)
	_ = h.Handle(context.Background(), r)
	for name, buf := range map[string]*bytes.Buffer{"a": &a, "b": &b} {
		if !strings.Contains(buf.String(), "unit=reptile") {
			t.Errorf("%s sink missing bound attr: %q", name, buf.String())
		}
	}
}

func TestFanoutEnabledAgreesWithSinks(t *testing.T) {
	h := NewFanoutHandler(NewConsoleHandler(io.Discard, false))
	if h.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("debug must stay disabled through fanout")
	}
	if !h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("info must be enabled through fanout")
	}
}

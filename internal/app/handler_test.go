package app

import (
	"bytes"
	"context"
	"log/slog"
	"regexp"
	"testing"
	"time"
)

func TestConsoleHandlerFormat(t *testing.T) {
	var buf bytes.Buffer
	h := NewConsoleHandler(&buf, false)
	r := slog.NewRecord(time.Date(2026, 8, 29, 15, 4, 5, 0, time.UTC), slog.LevelWarn, "sent SIGKILL", 0)
	r.AddAttrs(slog.String("comm", "torrentd"), slog.Int("pid", 1234), slog.String("reason", "ignored SIGTERM"))
	if err := h.Handle(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	want := "WARN  sent SIGKILL comm=torrentd pid=1234 reason=\"ignored SIGTERM\"\n"
	if buf.String() != want {
		t.Errorf("got %q, want %q", buf.String(), want)
	}
}

func TestConsoleHandlerTimeOnlyWhenAsked(t *testing.T) {
	r := slog.NewRecord(time.Date(2026, 8, 29, 15, 4, 5, 0, time.UTC), slog.LevelInfo, "tunnel UP", 0)

	var withTime bytes.Buffer
	if err := NewConsoleHandler(&withTime, true).Handle(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`^\d{2}:\d{2}:\d{2} INFO  tunnel UP`).MatchString(withTime.String()) {
		t.Errorf("got %q, want short-time prefix", withTime.String())
	}

	var noTime bytes.Buffer
	if err := NewConsoleHandler(&noTime, false).Handle(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`^\d`).MatchString(noTime.String()) {
		t.Errorf("no-time handler must not print a timestamp, got %q", noTime.String())
	}
}

func TestConsoleHandlerLevels(t *testing.T) {
	var buf bytes.Buffer
	h := NewConsoleHandler(&buf, false)
	if h.Enabled(context.Background(), slog.LevelDebug) {
		t.Error("debug must be disabled")
	}
	if !h.Enabled(context.Background(), slog.LevelInfo) {
		t.Error("info must be enabled")
	}
	r := slog.NewRecord(time.Now(), slog.LevelDebug, "noisy", 0)
	_ = h.Handle(context.Background(), r)
	if buf.Len() != 0 {
		t.Errorf("debug record must not be written, got %q", buf.String())
	}
}

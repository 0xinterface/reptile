package app

import (
	"context"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
)

// consoleHandler renders human-first lines:
//
//	[HH:MM:SS ]LEVEL  message key=value key=value
//
// Levels are padded to a fixed width so they align vertically; values that
// contain whitespace are quoted. Under journald pass showTime=false - the
// journal adds its own timestamps and `-o cat` strips its prefix, leaving a
// clean line. Interactively a short local time keeps context.
type consoleHandler struct {
	w        io.Writer
	showTime bool
	mu       *sync.Mutex
	attrs    []slog.Attr
}

// NewConsoleHandler returns a slog.Handler with the layout above.
func NewConsoleHandler(w io.Writer, showTime bool) slog.Handler {
	return &consoleHandler{w: w, showTime: showTime, mu: &sync.Mutex{}}
}

func (h *consoleHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= slog.LevelInfo
}

func (h *consoleHandler) Handle(ctx context.Context, r slog.Record) error {
	if !h.Enabled(ctx, r.Level) {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()

	var b strings.Builder
	if h.showTime {
		b.WriteString(r.Time.Format("15:04:05"))
		b.WriteByte(' ')
	}
	switch {
	case r.Level < slog.LevelInfo:
		b.WriteString("DEBUG ")
	case r.Level < slog.LevelWarn:
		b.WriteString("INFO  ")
	case r.Level < slog.LevelError:
		b.WriteString("WARN  ")
	default:
		b.WriteString("ERROR ")
	}
	b.WriteString(r.Message)
	for _, a := range h.attrs {
		appendAttr(&b, a)
	}
	r.Attrs(func(a slog.Attr) bool {
		appendAttr(&b, a)
		return true
	})
	b.WriteByte('\n')
	_, err := io.WriteString(h.w, b.String())
	return err
}

func (h *consoleHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	c := *h
	c.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &c
}

func (h *consoleHandler) WithGroup(string) slog.Handler { return h }

func appendAttr(b *strings.Builder, a slog.Attr) {
	s := a.Value.Resolve().String()
	if strings.ContainsAny(s, " \t\"") {
		s = strconv.Quote(s)
	}
	b.WriteByte(' ')
	b.WriteString(a.Key)
	b.WriteByte('=')
	b.WriteString(s)
}

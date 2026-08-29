package app

import (
	"context"
	"log/slog"
)

// fanoutHandler fans each record out to every handler, e.g. console and
// log file sinks sharing one slog logger.
type fanoutHandler struct {
	hs []slog.Handler
}

// NewFanoutHandler fans each record out to every handler. Enabled reports
// true when any sink would accept the level; Handle skips disabled sinks.
func NewFanoutHandler(hs ...slog.Handler) slog.Handler {
	return fanoutHandler{hs: hs}
}

func (f fanoutHandler) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range f.hs {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (f fanoutHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range f.hs {
		if !h.Enabled(ctx, r.Level) {
			continue
		}
		if err := h.Handle(ctx, r.Clone()); err != nil {
			return err
		}
	}
	return nil
}

func (f fanoutHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	hs := make([]slog.Handler, len(f.hs))
	for i, h := range f.hs {
		hs[i] = h.WithAttrs(attrs)
	}
	return fanoutHandler{hs: hs}
}

func (f fanoutHandler) WithGroup(name string) slog.Handler {
	hs := make([]slog.Handler, len(f.hs))
	for i, h := range f.hs {
		hs[i] = h.WithGroup(name)
	}
	return fanoutHandler{hs: hs}
}

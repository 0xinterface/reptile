package app

import (
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Entry is one parsed event line from the log file:
// TIME LEVEL rest (rest = message + key=value attrs, kept verbatim).
type Entry struct {
	Time  string
	Level string
	Rest  string
	Rank  int
}

// Level ranks for filtering.
const (
	RankInfo = iota
	RankWarn
	RankError
)

var levelRank = map[string]int{"INFO": RankInfo, "WARN": RankWarn, "ERROR": RankError}

var levelColor = map[string]string{
	"INFO":  "\x1b[32m",
	"WARN":  "\x1b[33m",
	"ERROR": "\x1b[31m",
}

var timeRe = regexp.MustCompile(`^\d{2}:\d{2}:\d{2}$`)

// ParseEvents parses log file lines (the file handler's output format),
// dropping lines that are not events.
func ParseEvents(lines []string) []Entry {
	var out []Entry
	for _, line := range lines {
		if e, ok := parseEvent(line); ok {
			out = append(out, e)
		}
	}
	return out
}

func parseEvent(line string) (Entry, bool) {
	line = strings.TrimRight(line, "\n")
	tok := strings.SplitN(line, " ", 3)
	if len(tok) < 3 || !timeRe.MatchString(tok[0]) {
		return Entry{}, false
	}
	lvl := strings.ToUpper(strings.TrimSpace(tok[1]))
	rank, ok := levelRank[lvl]
	if !ok {
		return Entry{}, false
	}
	return Entry{Time: tok[0], Level: lvl, Rest: strings.TrimSpace(tok[2]), Rank: rank}, true
}

// FilterMin keeps entries whose rank is at least min.
func FilterMin(entries []Entry, min int) []Entry {
	out := []Entry{}
	for _, e := range entries {
		if e.Rank >= min {
			out = append(out, e)
		}
	}
	return out
}

// RenderEntries writes entries; with color, the level token is ANSI-colored
// (INFO green, WARN yellow, ERROR red) and the rest stays clean.
func RenderEntries(w io.Writer, entries []Entry, color bool) error {
	for _, e := range entries {
		lvl := e.Level
		if color {
			if c, ok := levelColor[lvl]; ok {
				lvl = c + lvl + "\x1b[0m"
			}
		}
		if _, err := fmt.Fprintf(w, "%s %-5s %s\n", e.Time, lvl, e.Rest); err != nil {
			return err
		}
	}
	return nil
}

package app

import (
	"bufio"
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

const maxHistoryEntries = 100_000

// ReadRecentEvents streams a log and retains only the last n entries at or
// above min. Memory use is bounded independently of the log file size.
func ReadRecentEvents(r io.Reader, min, n int) ([]Entry, error) {
	if n < 0 || n > maxHistoryEntries {
		return nil, fmt.Errorf("history count must be between 0 and %d", maxHistoryEntries)
	}
	if n == 0 {
		return []Entry{}, nil
	}

	ring := make([]Entry, n)
	seen := 0
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		entry, ok := parseEvent(sc.Text())
		if !ok || entry.Rank < min {
			continue
		}
		ring[seen%n] = entry
		seen++
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read history: %w", err)
	}

	count := minInt(seen, n)
	out := make([]Entry, count)
	start := 0
	if seen > n {
		start = seen % n
	}
	for i := range count {
		out[i] = ring[(start+i)%n]
	}
	return out, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

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

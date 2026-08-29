package app

import (
	"bytes"
	"strings"
	"testing"
)

var historyLines = []string{
	"15:04:05 INFO  tunnel UP",
	"15:04:06 WARN  sent SIGTERM comm=torrentd pid=9",
	"15:04:07 ERROR config: bad",
	"this line is not a log entry",
}

func TestParseEventsDropsMalformed(t *testing.T) {
	entries := ParseEvents(historyLines)
	if len(entries) != 3 {
		t.Fatalf("entries = %d, want 3 (malformed dropped)", len(entries))
	}
	if entries[0].Time != "15:04:05" || entries[0].Level != "INFO" || entries[0].Rest != "tunnel UP" {
		t.Errorf("entry0 = %+v", entries[0])
	}
	if entries[1].Level != "WARN" {
		t.Errorf("entry1 level = %q", entries[1].Level)
	}
}

func TestHistoryFilterMinLevel(t *testing.T) {
	entries := ParseEvents(historyLines)
	warnPlus := FilterMin(entries, RankWarn)
	if len(warnPlus) != 2 {
		t.Fatalf("warn+ = %d entries, want 2", len(warnPlus))
	}
	errOnly := FilterMin(entries, RankError)
	if len(errOnly) != 1 || errOnly[0].Level != "ERROR" {
		t.Fatalf("error-only = %+v", errOnly)
	}
}

func TestHistoryRenderColorsLevelOnly(t *testing.T) {
	entries := ParseEvents([]string{"15:04:06 WARN  sent SIGTERM comm=torrentd pid=9"})
	var colored bytes.Buffer
	if err := RenderEntries(&colored, entries, true); err != nil {
		t.Fatal(err)
	}
	out := colored.String()
	if !strings.Contains(out, "\x1b[33mWARN\x1b[0m") {
		t.Errorf("colored output missing yellow WARN: %q", out)
	}
	if !strings.Contains(out, "15:04:06 ") || !strings.Contains(out, "sent SIGTERM comm=torrentd pid=9") {
		t.Errorf("colored output lost content: %q", out)
	}

	var plain bytes.Buffer
	if err := RenderEntries(&plain, entries, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain.String(), "\x1b[") {
		t.Errorf("plain output must have no escapes: %q", plain.String())
	}
	if plain.String() != "15:04:06 WARN  sent SIGTERM comm=torrentd pid=9\n" {
		t.Errorf("plain render = %q", plain.String())
	}
}

func TestReadRecentEventsStreamsFilteredTail(t *testing.T) {
	input := strings.Join([]string{
		"15:04:01 INFO first",
		"15:04:02 WARN second",
		"malformed",
		"15:04:03 ERROR third",
		"15:04:04 WARN fourth",
	}, "\n")
	entries, err := ReadRecentEvents(strings.NewReader(input), RankWarn, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].Rest != "third" || entries[1].Rest != "fourth" {
		t.Fatalf("entries = %+v, want last two warn-or-higher events", entries)
	}
}

func TestReadRecentEventsRejectsUnsafeCounts(t *testing.T) {
	for _, n := range []int{-1, maxHistoryEntries + 1} {
		if _, err := ReadRecentEvents(strings.NewReader(""), RankInfo, n); err == nil {
			t.Errorf("count %d accepted", n)
		}
	}
}

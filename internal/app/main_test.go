package app

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestHelperCommandProcess(t *testing.T) {
	switch os.Getenv("REPTILE_COMMAND_HELPER") {
	case "history-negative":
		os.Args = []string{
			"reptile",
			"-config", os.Getenv("REPTILE_COMMAND_CONFIG"),
			"history", "-n", "-1",
		}
		Run()
	case "version":
		os.Args = []string{"reptile", "version"}
		Run()
	}
}

func TestCommandDispatchRejectsNegativeHistoryCount(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "events.log")
	if err := os.WriteFile(logPath, []byte("15:04:05 INFO  tunnel UP\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := Defaults()
	cfg.Targets = []string{"worker"}
	cfg.ExpectedCountry = "CH"
	cfg.LogFile = logPath
	configPath := filepath.Join(dir, "config.json")
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, body, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperCommandProcess$")
	cmd.Env = append(os.Environ(),
		"REPTILE_COMMAND_HELPER=history-negative",
		"REPTILE_COMMAND_CONFIG="+configPath,
	)
	out, err := cmd.CombinedOutput()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
		t.Fatalf("history exit = %v, want code 2\n%s", err, out)
	}
	if strings.Contains(string(out), "panic:") {
		t.Fatalf("invalid history count panicked:\n%s", out)
	}
}

func TestCommandDispatchVersionWithoutConfig(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperCommandProcess$")
	cmd.Env = append(os.Environ(), "REPTILE_COMMAND_HELPER=version")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("version command failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "version=") || !strings.Contains(string(out), "goarch=") {
		t.Fatalf("version output incomplete:\n%s", out)
	}
}

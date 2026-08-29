package app

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallWritesFilesUnderRoot(t *testing.T) {
	root := t.TempDir()
	if code := runInstall([]string{"--root", root, "--no-activate"}); code != 0 {
		t.Fatalf("runInstall exit = %d, want 0", code)
	}

	bin := filepath.Join(root, "usr/local/bin/reptile")
	fi, err := os.Stat(bin)
	if err != nil {
		t.Fatalf("binary not installed: %v", err)
	}
	if fi.Mode()&0o111 == 0 {
		t.Error("installed binary not executable")
	}

	cfg, err := os.ReadFile(filepath.Join(root, "etc/reptile/config.json"))
	if err != nil {
		t.Fatalf("config not installed: %v", err)
	}
	if !strings.Contains(string(cfg), `"expected_country": "CHANGE_ME"`) {
		t.Error("installed config must carry the placeholder sentinel")
	}

	unit, err := os.ReadFile(filepath.Join(root, "etc/systemd/system/reptile.service"))
	if err != nil {
		t.Fatalf("watchdog unit not installed: %v", err)
	}
	if !strings.Contains(string(unit), "ExecStart=/usr/local/bin/reptile standby") {
		t.Errorf("unit ExecStart wrong:\n%s", unit)
	}
	fw, err := os.ReadFile(filepath.Join(root, "etc/systemd/system/reptile-firewall.service"))
	if err != nil {
		t.Fatalf("firewall unit not installed: %v", err)
	}
	if !strings.Contains(string(fw), "reptile firewall up") {
		t.Errorf("firewall unit ExecStart wrong:\n%s", fw)
	}
}

func TestInstallKeepsExistingConfig(t *testing.T) {
	root := t.TempDir()
	cfgDir := filepath.Join(root, "etc/reptile")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	mine := []byte(`{"targets":["mine"],"expected_country":"CH"}`)
	if err := os.WriteFile(filepath.Join(cfgDir, "config.json"), mine, 0o600); err != nil {
		t.Fatal(err)
	}
	if code := runInstall([]string{"--root", root, "--no-activate"}); code != 0 {
		t.Fatalf("runInstall exit = %d", code)
	}
	got, _ := os.ReadFile(filepath.Join(cfgDir, "config.json"))
	if string(got) != string(mine) {
		t.Error("existing config was clobbered")
	}
}

func TestInstallRootSlashRequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; cannot test the refusal")
	}
	if code := runInstall([]string{"--no-activate"}); code == 0 {
		t.Fatal("install to / without root must fail")
	}
}

func TestEmbeddedAssetsExist(t *testing.T) {
	for _, name := range []string{
		"assets/reptile.service",
		"assets/reptile-firewall.service",
		"assets/config.example.json",
	} {
		if _, err := assets.ReadFile(name); err != nil {
			t.Errorf("embedded asset %s: %v", name, err)
		}
	}
}

// Regression: on a fresh host /etc/reptile/config.json does not exist yet;
// `reptile install` must not require the file it is about to create.
func TestHelperInstallProcess(t *testing.T) {
	if os.Getenv("REPTILE_HELPER") != "install" {
		return
	}
	os.Args = []string{"reptile", "install",
		"--root", os.Getenv("REPTILE_HELPER_ROOT"), "--no-activate"}
	Run()
}

func TestInstallSubcommandOnFreshHost(t *testing.T) {
	root := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperInstallProcess$", "-test.v")
	cmd.Env = append(os.Environ(),
		"REPTILE_HELPER=install",
		"REPTILE_HELPER_ROOT="+root,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("install on fresh host failed: %v\n%s", err, out)
	}
	cfg, err := os.ReadFile(filepath.Join(root, "etc/reptile/config.json"))
	if err != nil {
		t.Fatalf("config not placed: %v", err)
	}
	if !strings.Contains(string(cfg), `"expected_country": "CHANGE_ME"`) {
		t.Error("placed config is not the example sentinel")
	}
}

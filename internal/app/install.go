package app

import (
	"embed"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
)

//go:embed assets/reptile.service assets/reptile-firewall.service assets/config.example.json
var assets embed.FS

// runInstall installs the running binary (self-copy) to
// <root>/usr/local/bin/reptile, the example config to <root>/etc/reptile
// (keeping any existing config), and the embedded systemd units to
// <root>/etc/systemd/system. With the default root ("/") it then activates
// the units via systemctl unless --no-activate is given.
func runInstall(args []string) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	root := fs.String("root", "/", "installation root (for testing/containers)")
	noActivate := fs.Bool("no-activate", false, "write files but skip systemctl activation")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *root == "/" && os.Geteuid() != 0 {
		slog.Error("install to / requires root (use --root for testing)")
		return 1
	}

	exe, err := os.Executable()
	if err != nil {
		slog.Error(fmt.Sprintf("cannot locate running binary: %v", err))
		return 1
	}
	if err := copyFile(exe, filepath.Join(*root, "usr/local/bin/reptile"), 0o755); err != nil {
		slog.Error(fmt.Sprintf("install binary: %v", err))
		return 1
	}

	cfgPath := filepath.Join(*root, "etc/reptile/config.json")
	if _, err := os.Stat(cfgPath); err == nil {
		slog.Info("keeping existing config", "path", cfgPath)
	} else {
		example, err := assets.ReadFile("assets/config.example.json")
		if err != nil {
			slog.Error(fmt.Sprintf("embedded example config: %v", err))
			return 1
		}
		if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
			slog.Error(fmt.Sprintf("config dir: %v", err))
			return 1
		}
		if err := os.WriteFile(cfgPath, example, 0o600); err != nil {
			slog.Error(fmt.Sprintf("write config: %v", err))
			return 1
		}
		slog.Info("installed example config", "path", cfgPath)
	}

	for _, name := range []string{"reptile.service", "reptile-firewall.service"} {
		body, err := assets.ReadFile("assets/" + name)
		if err != nil {
			slog.Error(fmt.Sprintf("embedded unit %s: %v", name, err))
			return 1
		}
		dst := filepath.Join(*root, "etc/systemd/system", name)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			slog.Error(fmt.Sprintf("unit dir: %v", err))
			return 1
		}
		if err := os.WriteFile(dst, body, 0o644); err != nil {
			slog.Error(fmt.Sprintf("write unit: %v", err))
			return 1
		}
	}

	if *root != "/" || *noActivate {
		slog.Info(fmt.Sprintf("files written under %s - activate manually: systemctl daemon-reload && systemctl enable --now reptile-firewall reptile", *root))
		return 0
	}

	for _, sargs := range [][]string{
		{"daemon-reload"},
		{"enable", "--now", "reptile-firewall.service"},
		{"enable", "reptile.service"},
	} {
		cmd := exec.Command("systemctl", sargs...)
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			slog.Error(fmt.Sprintf("systemctl %v: %v", sargs, err))
			return 1
		}
	}
	slog.Info("installed - edit /etc/reptile/config.json (targets, expected_country), then: systemctl start reptile && reptile status")
	return 0
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}

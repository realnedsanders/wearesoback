// Package pi installs wasb's gate as a pi extension.
package pi

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

//go:embed wasb-gate.ts
var extension string

// defaultBin is the line Install points at the wasb binary.
const defaultBin = `process.env.WASB_BIN || "wasb";`

// Install writes the gate into pi's personal extensions, set to run the wasb
// binary at bin, and returns the file written. Personal extensions load in
// every session; project extensions need project trust, which print and RPC
// modes skip, so a project install would silently not gate them.
func Install(bin string) (string, error) {
	if err := checkVersion(); err != nil {
		return "", err
	}
	dir := os.Getenv("PI_CODING_AGENT_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(home, ".pi", "agent")
	}
	if !strings.Contains(extension, defaultBin) {
		return "", errors.New("the embedded extension does not name its wasb binary")
	}
	quoted, err := json.Marshal(bin)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "extensions", "wasb-gate.ts")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}
	src := strings.Replace(extension, defaultBin, "process.env.WASB_BIN || "+string(quoted)+";", 1)
	return path, os.WriteFile(path, []byte(src), 0o644)
}

// checkVersion refuses a pi older than 1.4: it lacks agent_before_settle, so
// it would load the gate and never run it.
func checkVersion() error {
	out, err := exec.Command("pi", "--version").Output()
	if err != nil {
		return nil // pi is not installed yet; the gate loads once it is
	}
	v := strings.TrimSpace(string(out))
	var major, minor int
	if _, err := fmt.Sscanf(v, "%d.%d", &major, &minor); err != nil {
		return fmt.Errorf("cannot read the pi version from %q", v)
	}
	if major < 1 || major == 1 && minor < 4 {
		return fmt.Errorf("pi %s is too old: the gate needs pi 1.4 or later", v)
	}
	return nil
}

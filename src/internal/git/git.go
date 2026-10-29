// Package git runs the git binary.
package git

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Run runs git in dir with env appended to the process environment and
// returns stdout without surrounding whitespace.
func Run(dir string, env []string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

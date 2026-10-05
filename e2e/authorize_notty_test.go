//go:build unix

package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Without --yes and without a terminal every question is answered no, and the
// sweep carries on. It used to die with status 2 at the first question: the
// terminal check redirected ":" to /dev/tty, and a failed redirection on a
// special built-in ends a POSIX shell. Setsid takes away the controlling
// terminal, which is what cron, CI or an agent running the script looks like.
func TestAuthorizeWithoutTerminalDeclinesInsteadOfDying(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	agentDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(agentDir, 0o755); err != nil {
		t.Fatal(err)
	}
	keyA := "ssh-ed25519 AAAAonekeyAAAA alice@laptop"
	keyB := "ssh-ed25519 AAAAtwokeyBBBB bob@desktop"
	authFile := filepath.Join(agentDir, "agent_authorized_keys")
	if err := os.WriteFile(authFile, []byte(keyA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keysFile := filepath.Join(dir, "want")
	if err := os.WriteFile(keysFile, []byte(keyA+"\n"+keyB+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	shim := filepath.Join(dir, "ssh")
	writeSSHShim(t, shim, agentDir)

	cmd := exec.Command("sh", repoFile(t, "deploy/authorize.sh"), "proxy", keysFile)
	cmd.Env = append(os.Environ(), "MULTISSH_SSH="+shim, "MULTISSH_YES=")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("authorize.sh died without a terminal: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "no change approved") {
		t.Errorf("expected the addition to be declined, got:\n%s", out)
	}
	got, err := os.ReadFile(authFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "AAAAtwokeyBBBB") {
		t.Errorf("a key was added without approval:\n%s", got)
	}
}

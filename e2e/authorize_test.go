package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// authorize.sh pushes a curated login-key set to targets with per-key approval.
// Reaching a target uses the real ssh client and the network, which the rest of
// this package deliberately avoids; here the ssh client is replaced by a shim
// that runs the base64 payload locally against a fake agent state directory. So
// this exercises everything the script actually decides -- the diff, the render,
// the atomic round-trip -- without a hop.
//
// The shim distinguishes the two invocations the script makes: a plain listing
// (no -J) prints one connected target; a jump (-J ... "authorize@name" CMD)
// runs CMD under sh with MULTISSH_AGENT_DIRS pointed at the fake state dir, so
// the read and write payloads operate on a real file.
func writeSSHShim(t *testing.T, path, agentDir string) {
	t.Helper()
	shim := `#!/bin/sh
# Fake ssh. Args are the real SSHOPTS plus either the proxy alone (listing) or
# -J proxy authorize@name <command>.
is_jump=
cmd=
for a in "$@"; do
    case "$a" in
        -J) is_jump=1 ;;
        # Like the real client: options glued into one word are refused, which
        # is how an unsplit $SSHOPTS shows up.
        -*' '*) echo "unknown option -- ' '" >&2; exit 255 ;;
    esac
    cmd=$a   # the last argument is the remote command on a jump
done
if [ -z "$is_jump" ]; then
    printf ' multiSSH proxy\n\n ONLINE (1)\n\n   laptop  laptop.aaaaaaaaaaaa  linux  v1 current\n'
    exit 0
fi
# MULTISSH_SHIM_CONPTY prints what Windows' ConPTY puts in front of every
# command's output: setup sequences and a window title, no newline after.
[ -n "${MULTISSH_SHIM_CONPTY:-}" ] && printf '\033[?9001h\033[?1004h\033[?25l\033[2J\033[m\033[H\033]0;Administrator: powershell.exe\007\033[?25h'
MULTISSH_AGENT_DIRS='` + agentDir + `' sh -c "$cmd"
`
	if err := os.WriteFile(path, []byte(shim), 0o755); err != nil {
		t.Fatal(err)
	}
}

func repoFile(t *testing.T, rel string) string {
	t.Helper()
	wd, err := os.Getwd() // the e2e package directory
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(wd, "..", rel)
}

func runAuthorize(t *testing.T, shim, keysFile, agentDir string, names ...string) string {
	t.Helper()
	args := append([]string{repoFile(t, "deploy/authorize.sh"), "proxy", keysFile}, names...)
	cmd := exec.Command("sh", append(args, "--yes")...)
	cmd.Env = append(os.Environ(),
		"MULTISSH_SSH="+shim,
		"MULTISSH_YES=1",
	)
	// The shim is not on PATH; the script invokes $MULTISSH_SSH directly, which
	// it runs as a bare word, so it must be an absolute path -- which it is.
	_ = agentDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("authorize.sh failed: %v\n%s", err, out)
	}
	return string(out)
}

func TestAuthorizeAddsAnApprovedKey(t *testing.T) {
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

	// The target currently accepts only keyA.
	authFile := filepath.Join(agentDir, "agent_authorized_keys")
	if err := os.WriteFile(authFile, []byte(keyA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// We want it to accept both.
	keysFile := filepath.Join(dir, "want")
	if err := os.WriteFile(keysFile, []byte(keyA+"\n"+keyB+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	shim := filepath.Join(dir, "ssh")
	writeSSHShim(t, shim, agentDir)

	out := runAuthorize(t, shim, keysFile, agentDir)
	if !strings.Contains(out, "updated") {
		t.Errorf("expected an update, got:\n%s", out)
	}

	got, err := os.ReadFile(authFile)
	if err != nil {
		t.Fatal(err)
	}
	body := string(got)
	if !strings.Contains(body, "AAAAtwokeyBBBB") {
		t.Errorf("the approved key was not added:\n%s", body)
	}
	if !strings.Contains(body, "AAAAonekeyAAAA") {
		t.Errorf("the existing key was dropped:\n%s", body)
	}
}

func TestAuthorizeRemovesAKeyButNeverPushesEmpty(t *testing.T) {
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
	if err := os.WriteFile(authFile, []byte(keyA+"\n"+keyB+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Want only keyB: keyA should be removed.
	keysFile := filepath.Join(dir, "want")
	if err := os.WriteFile(keysFile, []byte(keyB+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	shim := filepath.Join(dir, "ssh")
	writeSSHShim(t, shim, agentDir)

	runAuthorize(t, shim, keysFile, agentDir)

	got, _ := os.ReadFile(authFile)
	body := string(got)
	if strings.Contains(body, "AAAAonekeyAAAA") {
		t.Errorf("the removed key is still present:\n%s", body)
	}
	if !strings.Contains(body, "AAAAtwokeyBBBB") {
		t.Errorf("the kept key was lost:\n%s", body)
	}
	if strings.TrimSpace(body) == "" {
		t.Error("the file was emptied")
	}
}

// Refusing to push an empty set is a safety property: approving the removal of
// every key would otherwise lock everyone out of the target for good.
func TestAuthorizeRefusesToEmptyTheKeys(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	agentDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(agentDir, 0o755); err != nil {
		t.Fatal(err)
	}
	keyA := "ssh-ed25519 AAAAonekeyAAAA alice@laptop"
	authFile := filepath.Join(agentDir, "agent_authorized_keys")
	if err := os.WriteFile(authFile, []byte(keyA+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// An empty want set: the script must refuse before touching the target.
	keysFile := filepath.Join(dir, "want")
	if err := os.WriteFile(keysFile, []byte("# nobody\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	shim := filepath.Join(dir, "ssh")
	writeSSHShim(t, shim, agentDir)

	cmd := exec.Command("sh", repoFile(t, "deploy/authorize.sh"), "proxy", keysFile, "--yes")
	cmd.Env = append(os.Environ(), "MULTISSH_SSH="+shim, "MULTISSH_YES=1")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Errorf("expected a non-zero exit for an empty keys file, got success:\n%s", out)
	}

	// The target's file must be untouched.
	got, _ := os.ReadFile(authFile)
	if !strings.Contains(string(got), "AAAAonekeyAAAA") {
		t.Errorf("the target's keys were altered despite the refusal:\n%s", got)
	}
}

// Naming targets narrows the sweep: a matching name (canonical or the short
// label) is updated, a name that matches nothing leaves every target alone.
func TestAuthorizeOnlyTouchesNamedTargets(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	for _, tc := range []struct {
		names []string
		want  bool
	}{
		{[]string{"laptop"}, true},
		{[]string{"laptop.aaaaaaaaaaaa"}, true},
		{[]string{"desktop", "laptop"}, true},
		{[]string{"desktop"}, false},
	} {
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

		out := runAuthorize(t, shim, keysFile, agentDir, tc.names...)
		got, err := os.ReadFile(authFile)
		if err != nil {
			t.Fatal(err)
		}
		if added := strings.Contains(string(got), "AAAAtwokeyBBBB"); added != tc.want {
			t.Errorf("names %v: key added = %v, want %v\n%s", tc.names, added, tc.want, out)
		}
	}
}

// Windows' ConPTY glues terminal setup sequences and a window title onto the
// first line of output. That must not be read as a key: a target whose keys
// already match is left alone instead of being "updated" to drop the noise.
func TestAuthorizeIgnoresConPTYNoise(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	agentDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(agentDir, 0o755); err != nil {
		t.Fatal(err)
	}
	keyA := "ssh-ed25519 AAAAonekeyAAAA alice@laptop"
	authFile := filepath.Join(agentDir, "agent_authorized_keys")
	before := "# login keys\n" + keyA + "\n"
	if err := os.WriteFile(authFile, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	keysFile := filepath.Join(dir, "want")
	if err := os.WriteFile(keysFile, []byte(keyA+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	shim := filepath.Join(dir, "ssh")
	writeSSHShim(t, shim, agentDir)
	t.Setenv("MULTISSH_SHIM_CONPTY", "1")

	out := runAuthorize(t, shim, keysFile, agentDir)
	if !strings.Contains(out, "already matches") {
		t.Errorf("terminal noise was taken for a key:\n%s", out)
	}
	got, err := os.ReadFile(authFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != before {
		t.Errorf("file was rewritten:\n%q", got)
	}
}

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func renderedInstaller(t *testing.T, builds map[string]string) string {
	t.Helper()

	dir := t.TempDir()
	for name, body := range builds {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}

	return installScript(newDistributor(dir), caPub,
		"https://multissh.example.com", []string{"wss://multissh.example.com/agent"})
}

// The generated script must at least parse. A syntax error would only surface
// on the target machine, halfway through an install, with no way back.
func TestGeneratedScriptsParse(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	script := renderedInstaller(t, map[string]string{
		"linux-amd64": "binary", "darwin-arm64": "binary",
	})
	path := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("sh", "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("install.sh does not parse: %v\n%s", err, out)
	}
}

func TestNoPlaceholdersSurviveRendering(t *testing.T) {
	script := renderedInstaller(t, map[string]string{"linux-amd64": "binary"})
	if m := regexp.MustCompile(`__[A-Z_]+__`).FindString(script); m != "" {
		t.Errorf("unsubstituted placeholder %s left in the rendered script", m)
	}
	if !strings.Contains(script, "https://multissh.example.com") {
		t.Error("the proxy's address did not make it into the script")
	}
	if !strings.Contains(script, "ssh-ed25519 ") {
		t.Error("the certificate authority did not make it into the script")
	}
}

// expected_hash is extracted and run on its own, because the bug it regresses
// against was in its *exit status*, not its output -- and that only bit when
// the script ran under `set -e`, several lines later, at the point of use.
func runExpectedHash(t *testing.T, script, platform string) (out string, ok bool) {
	t.Helper()

	// The function body, lifted from the generated script.
	fn := regexp.MustCompile(`(?ms)^expected_hash\(\) \{.*?^\}`).FindString(script)
	if fn == "" {
		t.Fatal("could not find expected_hash in the generated script; if it was renamed or reformatted, update this test rather than deleting it")
	}
	hashes := regexp.MustCompile(`(?m)^HASHES='([^']*)'`).FindStringSubmatch(script)
	if hashes == nil {
		t.Fatal("could not find HASHES in the generated script")
	}

	// Reproduces the call site: an assignment from a command substitution,
	// under `set -e`. If the function exits non-zero the shell dies here and
	// the marker never prints.
	prog := "set -eu\nHASHES='" + hashes[1] + "'\nPLATFORM='" + platform + "'\n" +
		fn + "\nWANT=$(expected_hash)\nprintf 'SURVIVED:%s' \"$WANT\"\n"

	res, err := exec.Command("sh", "-c", prog).CombinedOutput()
	if err != nil {
		return string(res), false
	}
	got, found := strings.CutPrefix(strings.TrimSpace(string(res)), "SURVIVED:")
	return got, found
}

// Regression. The loop's exit status leaked out of expected_hash: when the
// platform being installed was not the last entry in HASHES, the final `case`
// fell through with a non-zero status, and under `set -eu` the installer died
// silently right after printing its summary. It stayed hidden for as long as
// the proxy served exactly one build and the match therefore came last.
func TestExpectedHashSurvivesEveryPosition(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}

	// Five builds, so the platform under test is first, middle and last in
	// turn -- the shapes that differ are "match, then more entries" and
	// "no match at all".
	script := renderedInstaller(t, map[string]string{
		"darwin-amd64": "a", "darwin-arm64": "b",
		"linux-amd64": "c", "linux-arm64": "d", "windows-amd64": "e",
	})

	for _, platform := range []string{
		"darwin-amd64", "darwin-arm64", "linux-amd64", "linux-arm64", "windows-amd64",
	} {
		got, ok := runExpectedHash(t, script, platform)
		if !ok {
			t.Errorf("the script aborted looking up %s: %s", platform, got)
			continue
		}
		if len(got) != 64 {
			t.Errorf("expected_hash for %s returned %q, want a sha256", platform, got)
		}
	}

	// A platform with no build must come back empty *and* zero, so the caller
	// can report "no build for this platform" rather than the shell exiting
	// without explanation.
	got, ok := runExpectedHash(t, script, "plan9-arm64")
	if !ok {
		t.Errorf("the script aborted on an unknown platform instead of reporting it: %s", got)
	}
	if got != "" {
		t.Errorf("expected_hash invented %q for a platform with no build", got)
	}
}

// A proxy serving no builds at all must still produce a runnable script that
// says so, rather than one that fails obscurely.
func TestScriptWithNoBuilds(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	script := renderedInstaller(t, nil)
	got, ok := runExpectedHash(t, script, "linux-amd64")
	if !ok {
		t.Errorf("the script aborted when the proxy had no builds: %s", got)
	}
	if got != "" {
		t.Errorf("expected_hash returned %q with no builds present", got)
	}
}

// The distributor must not join a client-supplied path onto its directory.
func TestDistributorServesOnlyKnownBuilds(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "linux-amd64"), []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	d := newDistributor(dir)

	hashes, version := d.snapshot()
	if len(hashes) != 1 {
		t.Fatalf("found %d builds, want 1", len(hashes))
	}
	if version == "none" || version == "" {
		t.Error("a directory with a build reported no version")
	}
	if _, ok := hashes["../../etc/passwd"]; ok {
		t.Error("a traversal path is a known build")
	}
}

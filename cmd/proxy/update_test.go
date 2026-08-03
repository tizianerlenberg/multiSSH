package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Regressions in the agent update path.
//
// All three of these were live at once, and none was visible from reading the
// script: the first reported success while doing nothing, and the other two
// only appeared when the update was driven the way it has to be driven in
// practice -- over the agent's own tunnel, on a machine reachable no other way.
// Each left a machine either un-updatable or permanently unreachable.

func installerSource(t *testing.T) string {
	t.Helper()
	return renderedInstaller(t, map[string]string{"linux-amd64": "binary", "darwin-arm64": "binary"})
}

// section pulls one shell function or block out of the script, so an assertion
// is about the code that runs rather than about the whole file.
func section(t *testing.T, script, start, end string) string {
	t.Helper()
	re := regexp.MustCompile(`(?ms)` + start + `.*?` + end)
	got := re.FindString(script)
	if got == "" {
		t.Fatalf("could not find the block between %q and %q; if it was renamed or reformatted, update this test rather than deleting it", start, end)
	}
	return got
}

// Regression. download_binary used to stop the service before moving the new
// binary into place. Driven over the agent's own tunnel -- the only way to
// reach a machine behind NAT -- that stop killed the update script with it,
// because systemd tears down the whole cgroup. The binary was never replaced,
// the unit stayed stopped, and systemd would not restart it because it had been
// stopped deliberately. One update, machine gone for good.
//
// The fix is an ordering property, so that is what is asserted: nothing may
// stop the service before the binary is in place.
func TestDownloadBinaryNeverStopsTheServiceFirst(t *testing.T) {
	body := section(t, installerSource(t), `^download_binary\(\) \{`, `^\}`)

	if strings.Contains(body, "svc_stop") {
		t.Error("download_binary stops the service; an update driven over the tunnel would kill itself before replacing the binary")
	}
	if !strings.Contains(body, `mv "$NEW" "$BIN"`) {
		t.Error("download_binary no longer swaps the binary with a rename; ETXTBSY will force a stop back into this path")
	}
	// The temporary file has to sit beside the target. Across filesystems mv
	// degrades to copy-and-unlink, which cannot write a running executable.
	if !strings.Contains(body, `NEW="$BIN.new"`) {
		t.Error("the download target is not beside the binary; mv would fall back to a copy and hit ETXTBSY")
	}
	if !strings.Contains(body, `"$BIN.prev"`) {
		t.Error("the outgoing binary is not kept, so --rollback has nothing to go back to")
	}
}

// The update path must restart, not start: svc_start on a running unit is a
// no-op under systemd, so the machine would keep running the old binary while
// reporting success.
func TestUpdateRestartsRatherThanStarts(t *testing.T) {
	script := installerSource(t)
	body := section(t, script, `^if \[ "\$MODE" = update \]; then`, `^fi`)

	if !strings.Contains(body, "svc_restart") {
		t.Error("the update path does not call svc_restart; the new binary would sit unused until something else restarted the agent")
	}
	if strings.Contains(body, "svc_start") {
		t.Error("the update path calls svc_start, which does nothing to an already-running unit")
	}
}

// Regression. `manage.sh --update` compared the manifest's recorded version
// against the version baked into its own copy at install time. Those are set
// from the same value, so they were always equal and the command printed
// "already current" forever -- while being the documented way to update.
func TestSavedScriptRefetchesBeforeComparingVersions(t *testing.T) {
	script := installerSource(t)

	if !strings.Contains(script, "MULTISSH_NO_REFETCH") {
		t.Fatal("nothing re-fetches the installer; a saved copy can only ever compare its own frozen version against the manifest it wrote, and will always report 'already current'")
	}

	refetch := section(t, script, `if \[ "\$MODE" = update \] && \[ -z "\$\{MULTISSH_NO_REFETCH:-\}" \]; then`, `^fi`)
	if !strings.Contains(refetch, "$BASE_URL/install.sh") {
		t.Error("the re-fetch does not ask the proxy for the current script")
	}
	// The handed-over copy must be told where this install actually lives, or
	// it falls back to defaults and reports that nothing is installed.
	for _, pass := range []string{"MULTISSH_STATE_DIR", "MULTISSH_PREFIX"} {
		if !strings.Contains(refetch, pass) {
			t.Errorf("the re-fetched script is not told %s, so a non-default install would not be found", pass)
		}
	}
	// And it must not recurse: the fresh copy has to skip this block.
	if !strings.Contains(refetch, "MULTISSH_NO_REFETCH=1") {
		t.Error("the re-fetched script is not marked, so it would re-fetch again forever")
	}
}

// Regression. The saved script recomputed its paths from scope defaults, so
// running it on an install that used custom directories reported "nothing
// installed here" -- while sitting in the very directory holding the manifest.
func TestScriptPrefersTheManifestBesideIt(t *testing.T) {
	script := installerSource(t)
	if !strings.Contains(script, "SELF_DIR=") {
		t.Fatal("the script does not locate itself, so the saved copy cannot find its own manifest")
	}
	if !strings.Contains(script, `[ -f "$SELF_DIR/manifest" ]`) {
		t.Error("a manifest beside the script is not preferred over the scope defaults")
	}
}

// An uninstall run over the tunnel is killed the moment the service stops, so
// everything that can be done beforehand must be.
func TestUninstallRemovesBeforeStopping(t *testing.T) {
	body := section(t, installerSource(t), `^if \[ "\$MODE" = uninstall \]; then`, `^fi`)

	stop := strings.Index(body, "svc_stop")
	rmState := strings.Index(body, `rm -rf "$STATE"`)
	if stop < 0 || rmState < 0 {
		t.Fatal("uninstall no longer both stops the service and removes the state directory")
	}
	if stop < rmState {
		t.Error("uninstall stops the service before removing anything; over the tunnel that kills it half-finished")
	}
}

// The scripts shipped for deployment run against a live proxy, so a syntax
// error in one is discovered at the worst possible time.
func TestDeploymentScriptsParse(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	dir, err := filepath.Abs("../../deploy")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("no deploy directory: %v", err)
	}
	found := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sh") {
			continue
		}
		found++
		path := filepath.Join(dir, e.Name())
		if out, err := exec.Command("sh", "-n", path).CombinedOutput(); err != nil {
			t.Errorf("%s does not parse: %v\n%s", e.Name(), err, out)
		}
	}
	if found == 0 {
		t.Error("no deployment scripts found")
	}
}

// The build state shown in the listing drives every update decision, so its
// edge cases matter more than they look.
func TestBuildState(t *testing.T) {
	current := map[string]bool{"aaaaaaaaaaaa": true}

	if got := buildState("aaaaaaaaaaaa", current, true); got != "current" {
		t.Errorf("a served build reported as %q", got)
	}
	if got := buildState("bbbbbbbbbbbb", current, true); got != "OUTDATED" {
		t.Errorf("an unserved build reported as %q", got)
	}
	// An agent predating build reporting is not behind, it is silent. Calling
	// it outdated would send someone updating a machine that is already fine.
	if got := buildState("", current, true); got != "" {
		t.Errorf("an agent that sent no build reported as %q", got)
	}
	// With no builds on offer there is nothing to compare against, and marking
	// every target outdated would be worse than saying nothing.
	if got := buildState("aaaaaaaaaaaa", nil, false); got != "" {
		t.Errorf("with no builds served, a target reported as %q", got)
	}
}

func TestDistributorBuilds(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "linux-amd64"), []byte("one"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "darwin-arm64"), []byte("two"), 0o755); err != nil {
		t.Fatal(err)
	}
	d := newDistributor(dir)

	if !d.serving() {
		t.Fatal("a directory with builds reports as serving nothing")
	}
	builds := d.builds()
	if len(builds) != 2 {
		t.Fatalf("found %d build IDs, want 2", len(builds))
	}
	for id := range builds {
		if len(id) != 12 {
			t.Errorf("build ID %q is not the short form", id)
		}
	}

	// Publishing a build must be visible without recreating the distributor,
	// because SIGHUP calls scan on the running one.
	if err := os.WriteFile(filepath.Join(dir, "linux-arm64"), []byte("three"), 0o755); err != nil {
		t.Fatal(err)
	}
	d.scan()
	if len(d.builds()) != 3 {
		t.Error("scan did not pick up a newly published build")
	}

	empty := newDistributor(t.TempDir())
	if empty.serving() {
		t.Error("an empty directory reports as serving builds")
	}
}

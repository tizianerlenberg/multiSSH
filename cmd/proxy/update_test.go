package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
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

// Regression. build.sh names its packages relative to the repository root, but
// push.sh calls it from wherever the developer happens to be standing. It used
// to say "Run from the repository root" and then fail with "go.mod file not
// found" the first time deployment tooling called it.
func TestBuildScriptResolvesItsOwnRoot(t *testing.T) {
	path, err := filepath.Abs("../../deploy/build.sh")
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("no build.sh: %v", err)
	}
	if !strings.Contains(string(body), `cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"`) {
		t.Error("build.sh does not move to the repository root; calling it from anywhere else fails on go.mod")
	}
	// A relative output directory must still mean what the caller meant, which
	// requires resolving it before moving.
	if !strings.Contains(string(body), "OUT=$(pwd)/$OUT") {
		t.Error("build.sh does not resolve a relative output directory before changing directory")
	}
}

// Regression. install-proxy.sh started the service and then told you to create
// users_authorized_keys -- but the proxy treats that file as mandatory and
// exits without it, so a first install crash-looped and the script reported a
// proxy that would not run.
func TestProxyInstallerCreatesTheUsersFileBeforeStarting(t *testing.T) {
	path, err := filepath.Abs("../../deploy/install-proxy.sh")
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("no install-proxy.sh: %v", err)
	}
	script := string(body)

	create := strings.Index(script, `> "$STATE/users_authorized_keys"`)
	start := strings.Index(script, "systemctl start multissh-proxy")
	if create < 0 {
		t.Fatal("install-proxy.sh never creates users_authorized_keys; a first install will crash-loop")
	}
	if start < 0 {
		t.Fatal("install-proxy.sh no longer starts the service")
	}
	if create > start {
		t.Error("install-proxy.sh starts the proxy before creating users_authorized_keys")
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

// The Windows installer had never been run by anyone, and two of its bugs were
// the kind that only appear at the last step of a real install -- after the
// machine has already enrolled and taken a name on the proxy.

// withoutComments strips PowerShell comment lines, so an assertion about what
// the script *does* is not satisfied or defeated by a comment explaining what
// it deliberately does not do.
func withoutComments(script string) string {
	var b strings.Builder
	for _, line := range strings.Split(script, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func powershellInstaller(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "windows-amd64"), []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return installPowerShell(newDistributor(dir), caPub,
		"https://multissh.example.com", []string{"wss://multissh.example.com/agent"})
}

// Regression. PowerShell runs a function definition as a statement, so calling
// one from a block placed above its definition fails at runtime with "the term
// is not recognized". -Rollback did exactly that.
func TestPowerShellDefinesEveryFunctionBeforeUse(t *testing.T) {
	script := powershellInstaller(t)

	lastDef := strings.LastIndex(script, "\nfunction ")
	firstCall := strings.Index(script, "\n$elevated = Test-Admin\n")
	if lastDef < 0 {
		t.Fatal("no function definitions found")
	}
	if firstCall < 0 {
		t.Fatal("could not find the first executable statement ($elevated = Test-Admin)")
	}
	if lastDef > firstCall {
		t.Error("a function is defined after the script starts executing; anything calling it earlier fails at runtime")
	}
}

// Regression. schtasks caps the whole /TR command line at 261 characters. The
// real argument list is over 300, so registering the task failed outright --
// at the very last step, on a machine that had already enrolled. It also could
// not express restart-on-failure and left the default three-day execution time
// limit in place, which would have killed the agent after three days.
func TestPowerShellUsesRegisterScheduledTask(t *testing.T) {
	script := powershellInstaller(t)

	if strings.Contains(withoutComments(script), "schtasks") {
		t.Error("install.ps1 still uses schtasks; its /TR argument is capped at 261 characters and the real one is longer")
	}
	for _, want := range []string{
		"Register-ScheduledTask",
		"New-ScheduledTaskAction",
		"-ExecutionTimeLimit ([TimeSpan]::Zero)", // or the agent dies after three days
		"-RestartCount",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("install.ps1 does not use %s", want)
		}
	}
}

// Executing a downloaded .ps1 is subject to the execution policy, which a
// default Windows install refuses -- and not needing one changed is the whole
// point of the piped installer. The re-fetch must run as a scriptblock.
func TestPowerShellRefetchAvoidsTheExecutionPolicy(t *testing.T) {
	script := powershellInstaller(t)

	if !strings.Contains(script, "[scriptblock]::Create($fetched)") {
		t.Error("the re-fetched installer is not run as a scriptblock; the execution policy would refuse a downloaded file")
	}
	if strings.Contains(script, "& $fresh") {
		t.Error("the re-fetched installer is invoked as a file path")
	}
}

// A byte-order mark in front of an ssh-ed25519 line makes the agent fail to
// parse its own certificate, with a message pointing nowhere near the cause.
// Set-Content's default encoding differs between Windows PowerShell and 7.
func TestPowerShellWritesKeyFilesAsAscii(t *testing.T) {
	script := powershellInstaller(t)
	if !strings.Contains(script, "-Encoding ascii") {
		t.Error("key files are written without an explicit encoding")
	}
	for _, f := range []string{"agent_identity-cert.pub", "proxy_ca.pub", "agent_authorized_keys"} {
		if !strings.Contains(script, "Write-KeyFile (Join-Path $StateDir '"+f+"')") {
			t.Errorf("%s is not written through Write-KeyFile", f)
		}
	}
}

// Windows gained the two scopes Linux already had. The SYSTEM install is the
// rescue path -- reachable before anyone logs in; the user install is the
// comfortable one, with a profile, a PATH and per-user tools such as winget.
// Both are meant to coexist on one machine, which is the constraint most of
// these assertions are really about.
func TestPowerShellSupportsBothScopes(t *testing.T) {
	script := withoutComments(powershellInstaller(t))

	if !strings.Contains(script, "[ValidateSet('system', 'user')]") {
		t.Fatal("install.ps1 takes no -Scope")
	}

	// Scope follows elevation, and nothing else. An earlier version also
	// consulted which manifests existed and produced a dead end: unelevated on
	// a machine with a system install resolved to system and then refused
	// itself.
	if !strings.Contains(script, "if ($elevated) { $Scope = 'system' } else { $Scope = 'user' }") {
		t.Error("scope no longer follows elevation directly; check it cannot resolve to a scope it then refuses")
	}
	if !strings.Contains(script, "-Scope user to install for yourself") {
		t.Error("a system install without elevation does not point at the user scope")
	}

	// Coexistence: separate directories and, crucially, separate task names.
	// Scheduled tasks share one namespace across the machine, so the same name
	// would mean the second install silently replaced the first.
	for _, want := range []string{
		"$UserInstallDir   = Join-Path $env:LOCALAPPDATA 'multiSSH'",
		`$TaskName   = "multiSSH agent ($env:USERNAME)"`,
		"$TaskName   = 'multiSSH agent'",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("install.ps1 is missing %q", want)
		}
	}

	// A user-scope task must run as the user, at logon, without demanding
	// rights the user does not have. The system scope is a service now and has
	// no task principal at all.
	for _, want := range []string{
		"-AtLogOn -User $me",
		"-LogonType Interactive -RunLevel Limited",
	} {
		if !strings.Contains(script, want) {
			t.Errorf("install.ps1 is missing the task principal detail %q", want)
		}
	}
	if strings.Contains(script, "-LogonType ServiceAccount") {
		t.Error("the system scope still registers a scheduled task; it installs a service now")
	}

	// icacls hands the directory to SYSTEM and Administrators, which is wrong
	// for a user install and would fail without elevation anyway. Checked on
	// the script with its comments intact, and by looking for an enclosing
	// block that is still open at that point rather than merely one somewhere
	// above.
	full := powershellInstaller(t)
	at := strings.Index(full, "icacls $StateDir")
	if at < 0 {
		t.Fatal("icacls is gone; the system state directory is no longer locked down")
	}
	before := full[:at]
	guard := strings.LastIndex(before, "if ($Scope -eq 'system') {")
	if guard < 0 || strings.Contains(before[guard:], "\n}") {
		t.Error("icacls is not inside an `if ($Scope -eq 'system')` block")
	}

	// The manifest has to record which scope it belongs to, or update and
	// uninstall would work on the wrong paths.
	if !strings.Contains(script, "scope     = $Scope") {
		t.Error("the manifest records a hardcoded scope")
	}
}

// Two agents on one machine can both ask the proxy for a friendly name, but
// only one can hold it; the loser is reachable under its canonical name alone.
// That is correct behaviour and quietly baffling, so the second install steers
// its suggested name away from the first.
func TestPowerShellSuggestsANonCollidingName(t *testing.T) {
	script := withoutComments(powershellInstaller(t))

	if !strings.Contains(script, `$default = "$default-$Scope"`) {
		t.Error("the suggested name does not avoid the other scope's")
	}
	// The other scope's task, not its manifest: a system install's state
	// directory is locked to SYSTEM and Administrators, so an unelevated shell
	// cannot see it to know it is there.
	if !strings.Contains(script, "Get-ScheduledTask -TaskName $otherTask") {
		t.Error("the other scope is detected by something other than its scheduled task; a system state directory is unreadable to an unelevated user")
	}
	if strings.Contains(script, "Test-Path $systemManifest") {
		t.Error("the other scope is detected by its manifest, which an unelevated shell cannot read")
	}
}

// Regression. The updater matched any indented line containing a dot, which
// swept up prose from the CONNECT section and solemnly set about updating a
// machine called "you." -- the sentence had ended in a full stop.
func TestUpdateScriptParsesOnlyTheOnlineSection(t *testing.T) {
	if _, err := exec.LookPath("awk"); err != nil {
		t.Skip("no awk")
	}
	script, err := os.ReadFile("../../deploy/update-agents.sh")
	if err != nil {
		t.Skipf("no update-agents.sh: %v", err)
	}
	prog := section(t, string(script), `^    listing \| awk '`, `}'`)
	prog = strings.TrimPrefix(prog, "    listing | awk '")
	prog = strings.TrimSuffix(prog, "'")

	listing := `
 multiSSH proxy

 ONLINE (2)

   pcuser-pc        pcuser-pc.nth7qgghi7j7        linux    v1 OUTDATED
       host key  SHA256:/XmRlLQzuatMnjzd87t4qacwiU+MNBNBwdkce60vTz4
       identity  SHA256:hGFnasqDqhL/6mTmiGX/7ogUM6Y0XgDPMPc49Waqou0
   rosa-maria-lapt  rosa-maria-lapt.eceqxx2be7uw  windows  v1 current
       identity  SHA256:5UuBiRDBot0w6K7hUdVKe+zL/OZXtJsuJFuXGvtpxLE

 NOT CONNECTED (1)

     gone.5kfv27ccikum  last seen 27m ago

 CONNECT

   ssh -J <thisproxy> user@pcuser-pc

   paste the host key above into it and ssh checks it for you.
   'identity' is a different key: the handle for -revoke.
`
	cmd := exec.Command("awk", prog)
	cmd.Stdin = strings.NewReader(listing)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("awk: %v", err)
	}

	got := strings.Fields(strings.TrimSpace(string(out)))
	want := []string{
		"pcuser-pc.nth7qgghi7j7", "linux", "OUTDATED",
		"rosa-maria-lapt.eceqxx2be7uw", "windows", "current",
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("field %d = %q, want %q", i, got[i], want[i])
		}
	}
	if strings.Contains(string(out), "you.") {
		t.Error("prose from the CONNECT section was parsed as a target")
	}
	if strings.Contains(string(out), "gone.") {
		t.Error("a disconnected target was listed for update; it cannot be reached")
	}
}

// The user-scope agent used to open a console window on the desktop, and
// closing it killed the agent. A GUI-subsystem binary allocates no console --
// which leaves nowhere for logs to go, so the installer must pass -log.
func TestWindowsAgentIsBuiltWithoutAConsole(t *testing.T) {
	body, err := os.ReadFile("../../deploy/build.sh")
	if err != nil {
		t.Skipf("no build.sh: %v", err)
	}
	if !strings.Contains(string(body), "-H windowsgui") {
		t.Error("the Windows agent is not linked as a GUI binary; it will open a console window a user can close")
	}
	if !strings.Contains(withoutComments(powershellInstaller(t)), "-log `\"$logPath`\"") {
		t.Error("install.ps1 does not pass -log; a GUI binary has no stderr and its logs would go nowhere")
	}
}

// A machine-wide install is a real service now. The scheduled task remains
// correct for a user install, which cannot create services at all.
func TestPowerShellInstallsAServiceForTheSystemScope(t *testing.T) {
	script := withoutComments(powershellInstaller(t))

	if !strings.Contains(script, "New-Service -Name $ServiceName") {
		t.Error("the system scope does not create a service")
	}
	if !strings.Contains(script, "sc.exe failure $ServiceName") {
		t.Error("the service has no restart-on-failure configured")
	}
	// Remove-Service is PowerShell 6+, and this may be Windows PowerShell 5.1.
	if strings.Contains(script, "Remove-Service") {
		t.Error("Remove-Service is used, which does not exist in Windows PowerShell 5.1")
	}
	// The user scope must still use a task.
	if !strings.Contains(script, "Register-ScheduledTask") {
		t.Error("the user scope no longer registers a scheduled task")
	}
}

// The landing page exists so a long, exact command can be copied rather than
// retyped onto a machine that has no convenient way to receive text.
func TestLandingPageOffersTheInstallCommands(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "linux-amd64"), []byte("b"), 0o755); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	serveLanding(newDistributor(dir), "https://multissh.example.com/", "px.example.com -p 2022")(
		rec, httptest.NewRequest("GET", "/", nil))

	body := rec.Body.String()
	for _, want := range []string{
		"curl -fsSL https://multissh.example.com/install.sh | sudo sh",
		"irm https://multissh.example.com/install.ps1",
		"ssh px.example.com -p 2022",
		"navigator.clipboard.writeText",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the page does not offer %q", want)
		}
	}
	// The trailing slash on the base URL must not survive into the commands.
	if strings.Contains(body, "example.com//") {
		t.Error("a doubled slash reached the install command")
	}

	// Anything but / is not the landing page; /healthz and /install.sh share
	// this mux and must not be swallowed.
	rec404 := httptest.NewRecorder()
	serveLanding(newDistributor(dir), "https://x", "")(rec404, httptest.NewRequest("GET", "/nope", nil))
	if rec404.Code != 404 {
		t.Errorf("an unknown path returned %d, not 404", rec404.Code)
	}
}

// A machine installed before the system scope became a service is running a
// scheduled task. An uninstaller that only knew about services would remove
// the binary and leave the task behind, scheduled, pointing at a file that no
// longer exists.
func TestPowerShellUninstallAlsoRemovesALegacyTask(t *testing.T) {
	script := withoutComments(powershellInstaller(t))
	remove := section(t, script, `^function Remove-AgentTask \{`, `^\}`)

	if !strings.Contains(remove, "sc.exe delete $ServiceName") {
		t.Error("uninstall does not remove the service")
	}
	// Unconditional: outside the system-scope branch, so it runs either way.
	if !strings.Contains(remove, "Unregister-ScheduledTask") {
		t.Error("uninstall does not remove the scheduled task")
	}
	idx := strings.Index(remove, "Unregister-ScheduledTask")
	closing := strings.Index(remove, "\n    }")
	if closing >= 0 && idx < closing {
		t.Error("the task removal is inside the system-scope branch; a legacy task would survive an uninstall")
	}
}

// Regression. Unregistering a scheduled task removes the definition but does
// not stop an instance already running. Uninstall unregistered first and then
// asked Task Scheduler to stop a task it no longer knew about, so the agent
// kept running with its keys deleted underneath it -- absent from
// Get-ScheduledTask, still connected to the proxy, still listed online, and
// unable to serve a session.
func TestPowerShellUninstallKillsTheRunningAgent(t *testing.T) {
	script := withoutComments(powershellInstaller(t))
	body := section(t, script, `^if \(\$Uninstall\) \{`, `^\}`)

	if !strings.Contains(body, "$running = @(Find-AgentProcesses $m.binary)") {
		t.Fatal("uninstall does not locate the running agent process")
	}
	if !strings.Contains(body, "Stop-Process -Force") {
		t.Error("uninstall never kills the running agent")
	}
	// Captured before the binary is renamed, or it can no longer be matched.
	find := strings.Index(body, "Find-AgentProcesses")
	move := strings.Index(body, "Move-Item -Force $m.binary")
	kill := strings.Index(body, "Stop-Process -Force")
	if find > move {
		t.Error("the running process is looked up after the binary is renamed aside")
	}
	if kill < move {
		t.Error("the agent is killed before the files are removed; an uninstall over the tunnel would not finish")
	}

	// Matched by path so that uninstalling one scope leaves the other running.
	if !strings.Contains(script, "$_.Path -eq $binary") {
		t.Error("agent processes are matched by name alone; uninstalling one scope would kill the other")
	}
}

// Regression. Linking the Windows agent as a GUI binary -- so it never opens a
// console window a user could close -- broke reading its output: PowerShell
// only waits for and captures console applications, so `& $Binary -show-keys`
// returned immediately with nothing, and the install failed at enrolment with
// "the agent could not generate its keys".
func TestPowerShellRunsTheAgentThroughStartProcess(t *testing.T) {
	script := withoutComments(powershellInstaller(t))

	if strings.Contains(script, "& $Binary -show-keys") {
		t.Error("the agent is invoked with & , which neither waits for nor captures a GUI-subsystem binary")
	}
	if !strings.Contains(script, "Start-Process -FilePath $Binary") {
		t.Error("the agent is not run through Start-Process")
	}
	for _, want := range []string{"-Wait -PassThru", "-RedirectStandardOutput $out"} {
		if !strings.Contains(script, want) {
			t.Errorf("Invoke-Agent is missing %q", want)
		}
	}

	// Windows PowerShell does not quote array elements, and these paths live
	// under a user profile -- "C:\Users\Firstname Lastname\..." would arrive
	// as two arguments.
	if !strings.Contains(script, `'-show-keys -identity "{0}" -host-key "{1}"' -f $idPath, $hostPath`) {
		t.Error("the agent's arguments are not explicitly quoted; a user profile path containing a space would be split")
	}
}

// Package e2e drives the real proxy and agent binaries over loopback.
//
// These tests exist because everything this project had previously verified
// lived in shell scripts in a scratch directory, which was wiped mid-session.
// The properties below are the ones whose breakage would be either invisible
// or catastrophic: that `ssh -L` reaches nothing, that a target is reachable
// under both its names, that the proxy can be rebuilt from its CA key alone,
// and that a revoked machine cannot come back.
package e2e

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"multissh/internal/sshx"
)

var proxyBin, agentBin string

// safeLog collects a subprocess's output. os/exec copies into it from its own
// goroutine while the test reads it to make assertions, so the lock is not
// decoration -- a plain strings.Builder here is a data race.
type safeLog struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *safeLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *safeLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func TestMain(m *testing.M) {
	// m.Run would parse these, but testing.Short is consulted before that to
	// decide whether building the binaries is worth it at all.
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	dir, err := os.MkdirTemp("", "multissh-e2e-bin")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)

	for _, b := range []struct{ out, pkg string }{
		{"proxy", "../cmd/proxy"},
		{"agent", "../cmd/agent"},
	} {
		path := filepath.Join(dir, b.out)
		cmd := exec.Command("go", "build", "-o", path, b.pkg)
		if out, err := cmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "building %s: %v\n%s", b.pkg, err, out)
			os.Exit(1)
		}
		if b.out == "proxy" {
			proxyBin = path
		} else {
			agentBin = path
		}
	}
	os.Exit(m.Run())
}

// freePort asks the kernel for one and hands it back. There is a race between
// releasing it and the proxy binding it, which is tolerable here and avoids
// hard-coding ports that would collide between parallel packages.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

type fixture struct {
	t         *testing.T
	dir       string
	userAddr  string
	wsAddr    string
	canonical string
	friendly  string
	agentFP   string
	userKey   ssh.Signer
	caPub     ssh.PublicKey
	proxyLog  *safeLog
	agentLog  *safeLog
	proxyCmd  *exec.Cmd
}

// stopProxy kills the running proxy and waits for its listener to go, so a
// restart does not race the old process for the port.
func (f *fixture) stopProxy() {
	f.t.Helper()
	if f.proxyCmd == nil {
		return
	}
	f.proxyCmd.Process.Kill()
	f.proxyCmd.Wait()
	f.proxyCmd = nil

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", f.userAddr, 200*time.Millisecond)
		if err != nil {
			return
		}
		c.Close()
		time.Sleep(50 * time.Millisecond)
	}
	f.t.Fatal("the proxy's listener never went away")
}

// run executes the proxy in one of its exit-immediately modes.
func (f *fixture) run(args ...string) string {
	f.t.Helper()
	cmd := exec.Command(proxyBin, args...)
	cmd.Dir = f.dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		f.t.Fatalf("proxy %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func writePub(t *testing.T, path string, key ssh.PublicKey) {
	t.Helper()
	if err := os.WriteFile(path, ssh.MarshalAuthorizedKey(key), 0o644); err != nil {
		t.Fatal(err)
	}
}

// setup creates keys and enrols one agent, without starting anything.
func setup(t *testing.T) *fixture {
	t.Helper()
	if testing.Short() {
		t.Skip("end-to-end test needs to build and run binaries")
	}

	f := &fixture{
		t:        t,
		dir:      t.TempDir(),
		friendly: "laptop",
		proxyLog: &safeLog{},
		agentLog: &safeLog{},
	}
	p := func(name string) string { return filepath.Join(f.dir, name) }

	userKey, err := sshx.LoadOrCreateHostKey(p("user_key"))
	if err != nil {
		t.Fatal(err)
	}
	f.userKey = userKey
	writePub(t, p("users_authorized_keys"), userKey.PublicKey())

	identity, err := sshx.LoadOrCreateHostKey(p("agent_identity"))
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := sshx.LoadOrCreateHostKey(p("agent_host_key"))
	if err != nil {
		t.Fatal(err)
	}
	f.agentFP = ssh.FingerprintSHA256(identity.PublicKey())
	writePub(t, p("agent_identity.pub"), identity.PublicKey())
	writePub(t, p("agent_host_key.pub"), hostKey.PublicKey())

	// The proxy signs the identity and derives the name from the host key.
	out := f.run("-sign", "agent_identity.pub", "-sign-host-key", "agent_host_key.pub",
		"-sign-label", f.friendly)
	for _, line := range strings.Split(out, "\n") {
		if fields := strings.Fields(line); len(fields) == 2 && fields[0] == "canonical" {
			f.canonical = fields[1]
		}
	}
	if f.canonical == "" {
		t.Fatalf("could not find the canonical name in:\n%s", out)
	}
	// The name has to commit to the host key, or trust-on-first-use on the
	// target is unverifiable and the proxy is back in the trust chain.
	if !sshx.VerifyCanonicalName(f.canonical, hostKey.PublicKey()) {
		t.Fatalf("canonical name %q does not verify against the agent's host key", f.canonical)
	}

	caPubText := f.run("-show-ca")
	if err := os.WriteFile(p("proxy_ca.pub"), []byte(caPubText), 0o644); err != nil {
		t.Fatal(err)
	}
	caPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(caPubText))
	if err != nil {
		t.Fatal(err)
	}
	f.caPub = caPub

	// The agent lets in whoever holds the user key, as the installer arranges.
	writePub(t, p("agent_authorized_keys"), userKey.PublicKey())

	f.userAddr = fmt.Sprintf("127.0.0.1:%d", freePort(t))
	f.wsAddr = fmt.Sprintf("127.0.0.1:%d", freePort(t))
	return f
}

// startProxy runs the proxy until the test ends.
func (f *fixture) startProxy(extra ...string) {
	f.t.Helper()
	args := append([]string{
		"-user-addr", f.userAddr,
		"-agent-addr", f.wsAddr,
	}, extra...)
	f.proxyCmd = f.start(proxyBin, args, f.proxyLog)
	f.waitForListener(f.userAddr)
}

func (f *fixture) startAgent(extra ...string) {
	f.t.Helper()
	args := append([]string{
		"-proxy", "ws://" + f.wsAddr + "/agent",
		"-identity", "agent_identity",
		"-host-key", "agent_host_key",
		"-identity-cert", "agent_identity-cert.pub",
		"-ca", "proxy_ca.pub",
		"-authorized-keys", "agent_authorized_keys",
	}, extra...)
	f.start(agentBin, args, f.agentLog)
}

func (f *fixture) start(bin string, args []string, log *safeLog) *exec.Cmd {
	f.t.Helper()
	cmd := exec.Command(bin, args...)
	cmd.Dir = f.dir
	// One sink for both streams: the programs log through the standard log
	// package, whose writes are already serialised.
	cmd.Stdout = log
	cmd.Stderr = log
	if err := cmd.Start(); err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if f.t.Failed() {
			f.t.Logf("%s log:\n%s", filepath.Base(bin), log.String())
		}
	})
	return cmd
}

func (f *fixture) waitForListener(addr string) {
	f.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	f.t.Fatalf("nothing listening on %s after 10s", addr)
}

// dialProxy connects as an ordinary user would, verifying the proxy through
// the certificate authority exactly as an @cert-authority line does.
func (f *fixture) dialProxy() *ssh.Client {
	f.t.Helper()
	checker := &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
			return sshx.SameKey(auth, f.caPub)
		},
	}
	c, err := ssh.Dial("tcp", f.userAddr, &ssh.ClientConfig{
		User:            "me",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(f.userKey)},
		HostKeyCallback: checker.CheckHostKey,
		Timeout:         10 * time.Second,
	})
	if err != nil {
		f.t.Fatalf("connecting to the proxy: %v", err)
	}
	f.t.Cleanup(func() { c.Close() })
	return c
}

// shellListing runs a plain `ssh proxy`, which serves its output on a shell
// request rather than an exec -- exec is refused there on purpose.
func (f *fixture) shellListing(c *ssh.Client) string {
	f.t.Helper()
	sess, err := c.NewSession()
	if err != nil {
		f.t.Fatal(err)
	}
	defer sess.Close()
	out := &strings.Builder{}
	sess.Stdout = out
	if err := sess.Shell(); err != nil {
		f.t.Fatalf("shell on the proxy: %v", err)
	}
	sess.Wait()
	return out.String()
}

// waitForTarget polls until name appears in the listing.
//
// The deadline is generous because `go test ./...` builds and runs every
// package at once: the agent competes for CPU with whatever else is compiling,
// and a tight bound here shows up as a test that fails only under load.
func (f *fixture) waitForTarget(name string) string {
	f.t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		c := f.dialProxy()
		last = f.shellListing(c)
		c.Close()
		// "not connected" also mentions known names, so match the live section.
		live, _, _ := strings.Cut(last, "not connected")
		if strings.Contains(live, name) {
			return last
		}
		time.Sleep(200 * time.Millisecond)
	}
	f.t.Fatalf("%q never appeared in the listing. Last listing:\n%s\nagent log:\n%s",
		name, last, f.agentLog.String())
	return ""
}

// jumpTo does what `ssh -J proxy user@name` does: a direct-tcpip channel
// naming the target, then a complete SSH handshake inside it that the proxy
// cannot read.
func (f *fixture) jumpTo(c *ssh.Client, name string) (*ssh.Client, ssh.PublicKey, error) {
	f.t.Helper()
	tunnel, err := c.Dial("tcp", name+":22")
	if err != nil {
		return nil, nil, err
	}

	var seen ssh.PublicKey
	inner, chans, reqs, err := ssh.NewClientConn(tunnel, name, &ssh.ClientConfig{
		User: "whoever",
		Auth: []ssh.AuthMethod{ssh.PublicKeys(f.userKey)},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			seen = key
			return nil // trust on first use, as a client's known_hosts would
		},
		Timeout: 10 * time.Second,
	})
	if err != nil {
		tunnel.Close()
		return nil, nil, err
	}
	client := ssh.NewClient(inner, chans, reqs)
	f.t.Cleanup(func() { client.Close() })
	return client, seen, nil
}

func TestTargetIsReachableUnderBothNames(t *testing.T) {
	f := setup(t)
	f.startProxy()
	f.startAgent()
	listing := f.waitForTarget(f.canonical)

	if !strings.Contains(listing, f.friendly) {
		t.Errorf("the friendly name is missing from the listing:\n%s", listing)
	}
	// The protocol version and the identity fingerprint are what an upgrade
	// sweep and a revocation are planned from, so they have to be visible.
	if !strings.Contains(listing, sshx.DescribeProtocol(sshx.ProtocolVersion)) {
		t.Errorf("the listing does not show the agent's protocol version:\n%s", listing)
	}
	if !strings.Contains(listing, f.agentFP) {
		t.Errorf("the listing does not show the identity fingerprint:\n%s", listing)
	}

	for _, name := range []string{f.canonical, f.friendly} {
		c := f.dialProxy()
		inner, hostKey, err := f.jumpTo(c, name)
		if err != nil {
			t.Fatalf("jumping to %q: %v", name, err)
		}

		sess, err := inner.NewSession()
		if err != nil {
			t.Fatalf("session on %q: %v", name, err)
		}
		out, err := sess.Output("echo multissh-reached-the-target")
		sess.Close()
		if err != nil {
			t.Fatalf("exec on %q: %v", name, err)
		}
		if !strings.Contains(string(out), "multissh-reached-the-target") {
			t.Errorf("exec on %q returned %q", name, out)
		}

		// Whichever name was used, the host key behind it is the one the
		// canonical name commits to. This is the check a person can make by
		// eye, and the reason the proxy is not in the trust chain.
		if !sshx.VerifyCanonicalName(f.canonical, hostKey) {
			t.Errorf("the host key served for %q does not match the canonical name", name)
		}
	}
}

// The security boundary. `ssh -L` and `ssh -J` are byte-identical on the wire,
// so the registry lookup is what stops the proxy being turned into an open
// relay onto its own network. If this ever passes something through, the proxy
// has become a port forwarder for anyone holding a user key.
func TestProxyForwardsNowhereButRegisteredTargets(t *testing.T) {
	f := setup(t)
	f.startProxy()
	f.startAgent()
	f.waitForTarget(f.canonical)

	// Something that really is listening, to be sure the refusal is the
	// registry's doing rather than a connection that would have failed anyway.
	victim, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer victim.Close()

	c := f.dialProxy()
	for _, dest := range []string{
		victim.Addr().String(),
		"127.0.0.1:22",
		"localhost:80",
		"example.com:443",
		f.wsAddr,       // the proxy's own agent listener
		"nosuchtarget", // simply unregistered
	} {
		host, port, err := net.SplitHostPort(dest)
		if err != nil {
			host, port = dest, "22"
		}
		conn, err := c.Dial("tcp", net.JoinHostPort(host, port))
		if err == nil {
			conn.Close()
			t.Errorf("the proxy opened a connection to %q", dest)
		}
	}

	// And the port is ignored for a target that does exist, because it is
	// never used: the tunnel goes to the agent, not to a port on it.
	if _, err := c.Dial("tcp", f.canonical+":9999"); err != nil {
		t.Errorf("a registered target was refused on an odd port: %v", err)
	}
}

// The proxy is not a shell host. It serves a listing and nothing else, so that
// a user key is authority to reach targets and never authority on the proxy
// itself.
func TestProxyRefusesEverythingButListingAndJump(t *testing.T) {
	f := setup(t)
	f.startProxy()

	c := f.dialProxy()

	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Run("id"); err == nil {
		t.Error("the proxy executed a command")
	}
	sess.Close()

	sess2, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess2.RequestSubsystem("sftp"); err == nil {
		t.Error("the proxy accepted a subsystem request")
	}
	sess2.Close()

	// Remote forwarding would make the proxy open a listening port, which is
	// the one thing its two-listener design promises never to do.
	if _, err := c.Listen("tcp", "127.0.0.1:0"); err == nil {
		t.Error("ssh -R made the proxy open a port")
	}
}

// The recoverability claim, which is the reason the proxy holds no list of
// agents at all: restore one file and every target comes back unaided.
func TestProxyRecoversFromTheCAKeyAlone(t *testing.T) {
	f := setup(t)
	f.startProxy()
	f.startAgent()
	f.waitForTarget(f.canonical)

	// Destroy the proxy: kill it, take away its host key and every advisory
	// record. Only proxy_ca_key survives, as a backup would hold.
	f.stopProxy()
	for _, name := range []string{"proxy_host_key", "friendly_labels", "last_seen"} {
		if err := os.Remove(filepath.Join(f.dir, name)); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}

	f.startProxy()
	listing := f.waitForTarget(f.canonical)
	if !strings.Contains(listing, f.friendly) {
		t.Errorf("the friendly name did not heal after the rebuild:\n%s", listing)
	}

	// And it is reachable, not merely listed.
	c := f.dialProxy()
	inner, _, err := f.jumpTo(c, f.canonical)
	if err != nil {
		t.Fatalf("target unreachable after the proxy was rebuilt: %v", err)
	}
	sess, err := inner.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if out, err := sess.Output("echo recovered"); err != nil || !strings.Contains(string(out), "recovered") {
		t.Errorf("exec after recovery: %q %v", out, err)
	}
}

// Certificates never expire, so revocation is the only lever that removes a
// machine's access. If it does not hold, that trade was a bad one.
func TestRevokedAgentCannotRegister(t *testing.T) {
	f := setup(t)

	out := f.run("-revoke", f.agentFP, "-revoke-note", "test")
	if !strings.Contains(out, "revoked") {
		t.Fatalf("revoke said: %s", out)
	}

	f.startProxy()
	f.startAgent()

	// Give it long enough to have registered if it were going to.
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		c := f.dialProxy()
		listing := f.shellListing(c)
		c.Close()
		live, _, _ := strings.Cut(listing, "not connected")
		if strings.Contains(live, f.canonical) {
			t.Fatalf("a revoked agent registered:\n%s", listing)
		}
		time.Sleep(300 * time.Millisecond)
	}

	if !strings.Contains(f.proxyLog.String(), "revoked") {
		t.Errorf("the proxy did not say it was refusing a revoked key:\n%s", f.proxyLog.String())
	}

	// Lifting it lets the machine back in, so revocation is not a one-way
	// door taken by mistake.
	f.run("-unrevoke", f.agentFP)
	f.stopProxy()
	f.startProxy()
	f.waitForTarget(f.canonical)
}

// The version floor has to actually refuse, and say why somewhere the operator
// will find it. Without this the handshake is decoration.
func TestProxyRefusesAgentsBelowTheProtocolFloor(t *testing.T) {
	f := setup(t)
	f.startProxy("-min-agent-protocol", "99")
	f.startAgent()

	time.Sleep(4 * time.Second)

	c := f.dialProxy()
	listing := f.shellListing(c)
	live, _, _ := strings.Cut(listing, "not connected")
	if strings.Contains(live, f.canonical) {
		t.Fatalf("an agent below the protocol floor registered:\n%s", listing)
	}

	// The agent prints the proxy's banner, so the machine's own log explains
	// the refusal rather than showing an unattributed auth failure.
	if !strings.Contains(f.agentLog.String(), "needs agent protocol") {
		t.Errorf("the agent was not told why it was refused:\n%s", f.agentLog.String())
	}
}

// An upgrade sweep needs two things the proxy did not used to provide: knowing
// which machines are behind, and being able to publish a new build without
// disconnecting everyone to do it.
func TestBuildReportingAndReloadWithoutDisconnecting(t *testing.T) {
	f := setup(t)

	// Serve the very binary this test's agent runs, so it starts out current.
	distDir := filepath.Join(f.dir, "dist")
	if err := os.MkdirAll(distDir, 0o755); err != nil {
		t.Fatal(err)
	}
	served := filepath.Join(distDir, "linux-amd64")
	agentBytes, err := os.ReadFile(agentBin)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(served, agentBytes, 0o755); err != nil {
		t.Fatal(err)
	}

	f.startProxy("-dist", distDir)
	f.startAgent()
	listing := f.waitForTarget(f.canonical)
	if !strings.Contains(listing, "current") {
		t.Fatalf("an agent running the served binary is not reported current:\n%s", listing)
	}

	// Publish a different build and tell the proxy to re-read it. Appending a
	// byte is enough: the identity of a build is its hash.
	if err := os.WriteFile(served, append(agentBytes, '\n'), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := f.proxyCmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(15 * time.Second)
	var got string
	for time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		c := f.dialProxy()
		got = f.shellListing(c)
		c.Close()
		if strings.Contains(got, "OUTDATED") {
			break
		}
	}
	if !strings.Contains(got, "OUTDATED") {
		t.Fatalf("the proxy did not notice a new build after SIGHUP:\n%s", got)
	}

	// The whole point of a reload is that nobody pays for it. The agent must
	// still be there on the same connection, not having reconnected.
	if n := strings.Count(f.agentLog.String(), "registered with proxy"); n != 1 {
		t.Errorf("the agent registered %d times across a reload, want 1:\n%s", n, f.agentLog.String())
	}
	c := f.dialProxy()
	if _, _, err := f.jumpTo(c, f.canonical); err != nil {
		t.Errorf("target unreachable after the proxy reloaded: %v", err)
	}

	// And the count is visible to monitoring.
	resp, err := http.Get("http://" + f.wsAddr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var health struct {
		Outdated int `json:"outdated"`
	}
	if err := json.Unmarshal(body, &health); err != nil {
		t.Fatal(err)
	}
	if health.Outdated != 1 {
		t.Errorf("healthz reports %d outdated, want 1: %s", health.Outdated, body)
	}
}

// A fresh install has no authorised users yet: install-proxy.sh creates the
// file empty and you add your key afterwards. The proxy must come up in that
// state -- it used to treat the missing file as fatal, so a first deployment
// crash-looped -- and must pick up a key without a restart, because restarting
// to authorise a person costs every agent its connection.
func TestProxyStartsWithNoAuthorisedUsersAndReloadsThem(t *testing.T) {
	f := setup(t)

	users := filepath.Join(f.dir, "users_authorized_keys")
	if err := os.WriteFile(users, []byte("# nobody yet\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	f.startProxy()
	f.startAgent()

	// Agents register regardless: they authenticate by certificate, not by
	// anything in this file. A proxy with no users is still collecting targets.
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(f.proxyLog.String(), "agent registered") {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !strings.Contains(f.proxyLog.String(), "agent registered") {
		t.Fatalf("the agent never registered against a proxy with no users:\n%s", f.proxyLog.String())
	}

	// Nobody can log in yet, though.
	if _, err := ssh.Dial("tcp", f.userAddr, &ssh.ClientConfig{
		User:            "me",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(f.userKey)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}); err == nil {
		t.Error("a proxy with an empty users file let someone in")
	}

	// Authorise the key and reload rather than restart.
	if err := os.WriteFile(users, ssh.MarshalAuthorizedKey(f.userKey.PublicKey()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := f.proxyCmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Second)

	c := f.dialProxy()
	if listing := f.shellListing(c); !strings.Contains(listing, f.canonical) {
		t.Errorf("could not list targets after authorising a key by reload:\n%s", listing)
	}
	// And nobody was disconnected to do it.
	if n := strings.Count(f.agentLog.String(), "registered with proxy"); n != 1 {
		t.Errorf("the agent registered %d times across a users reload, want 1", n)
	}
}

// The check a person can actually make on first connect: ssh prints the
// target's host key fingerprint, and the listing shows the same string. They
// have to be byte-identical, because comparing them is the whole point --
// the canonical name's own hash cannot serve, being a different function in a
// different alphabet from anything ssh prints.
func TestListingShowsTheHostKeyFingerprintSshWillPrint(t *testing.T) {
	f := setup(t)
	f.startProxy()
	f.startAgent()
	listing := f.waitForTarget(f.canonical)

	// The agent's real host key, read from the file it was generated into.
	hostSigner, err := sshx.LoadOrCreateHostKey(filepath.Join(f.dir, "agent_host_key"))
	if err != nil {
		t.Fatal(err)
	}
	want := ssh.FingerprintSHA256(hostSigner.PublicKey())

	if !strings.Contains(listing, "host key  "+want) {
		t.Errorf("the listing does not show the host key fingerprint %s:\n%s", want, listing)
	}
	// And it must be distinguishable from the identity fingerprint, which is a
	// different key entirely and is only the handle for -revoke.
	if !strings.Contains(listing, "identity  "+f.agentFP) {
		t.Errorf("the listing does not label the identity fingerprint:\n%s", listing)
	}
	if want == f.agentFP {
		t.Fatal("host key and identity key are the same key; the whole distinction is gone")
	}

	// What ssh is offered on the wire must be that same key.
	c := f.dialProxy()
	_, served, err := f.jumpTo(c, f.canonical)
	if err != nil {
		t.Fatal(err)
	}
	if got := ssh.FingerprintSHA256(served); got != want {
		t.Errorf("the key served to the client is %s, but the listing advertised %s", got, want)
	}
}

// Copying a file off a machine that is half broken is a large part of what a
// rescue tool is for, and until sftp existed the embedded server could not do
// it at all -- scp on a modern OpenSSH client speaks the sftp subsystem, so
// both were out.
func TestSftpMovesFilesBothWays(t *testing.T) {
	f := setup(t)
	f.startProxy()
	f.startAgent()
	f.waitForTarget(f.canonical)

	c := f.dialProxy()
	inner, _, err := f.jumpTo(c, f.canonical)
	if err != nil {
		t.Fatal(err)
	}
	client, err := sftp.NewClient(inner)
	if err != nil {
		t.Fatalf("opening the sftp subsystem: %v", err)
	}
	defer client.Close()

	// Off the target: the rescue direction.
	onTarget := filepath.Join(f.dir, "rescue-me.txt")
	want := "the file we want to rescue\n"
	if err := os.WriteFile(onTarget, []byte(want), 0o600); err != nil {
		t.Fatal(err)
	}
	rf, err := client.Open(onTarget)
	if err != nil {
		t.Fatalf("opening a file on the target: %v", err)
	}
	got, err := io.ReadAll(rf)
	rf.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("read %q, want %q", got, want)
	}

	// And onto it.
	dest := filepath.Join(f.dir, "landed.txt")
	wf, err := client.Create(dest)
	if err != nil {
		t.Fatalf("creating a file on the target: %v", err)
	}
	if _, err := wf.Write([]byte("pushed from the client\n")); err != nil {
		t.Fatal(err)
	}
	wf.Close()
	back, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("the file never arrived: %v", err)
	}
	if string(back) != "pushed from the client\n" {
		t.Errorf("landed as %q", back)
	}
}

// Only sftp. The embedded server is not a general subsystem host, and adding
// one must not have opened it up to others.
func TestOtherSubsystemsAreStillRefused(t *testing.T) {
	f := setup(t)
	f.startProxy()
	f.startAgent()
	f.waitForTarget(f.canonical)

	c := f.dialProxy()
	inner, _, err := f.jumpTo(c, f.canonical)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := inner.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if err := sess.RequestSubsystem("netconf"); err == nil {
		t.Error("an unrelated subsystem was accepted")
	}
}

func TestHealthzReportsWithoutNamingTargets(t *testing.T) {
	f := setup(t)
	f.startProxy()
	f.startAgent()
	f.waitForTarget(f.canonical)

	resp, err := http.Get("http://" + f.wsAddr + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz returned %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	var health struct {
		Status    string `json:"status"`
		Connected int    `json:"connected"`
		Known     int    `json:"known"`
		Protocol  int    `json:"protocol"`
	}
	if err := json.Unmarshal(body, &health); err != nil {
		t.Fatalf("healthz returned %q: %v", body, err)
	}
	if health.Status != "ok" || health.Connected != 1 {
		t.Errorf("healthz = %+v", health)
	}
	if health.Protocol != sshx.ProtocolVersion {
		t.Errorf("healthz reports protocol %d", health.Protocol)
	}

	// This endpoint is unauthenticated and shares a hostname with the
	// installer, so it must not disclose which machines exist.
	for _, secret := range []string{f.canonical, f.friendly, f.agentFP} {
		if strings.Contains(string(body), secret) {
			t.Errorf("healthz disclosed %q:\n%s", secret, body)
		}
	}
}

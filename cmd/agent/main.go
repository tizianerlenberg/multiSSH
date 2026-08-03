// multiSSH agent: runs on the target, dials out to the proxy, and serves a
// self-contained SSH server over the tunnel.
//
// It binds no listening port. It reads no system SSH configuration, uses no
// PAM, and switches no users, which is precisely what makes it a rescue tool:
// a broken sshd on this machine has no bearing on whether you can get in.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
	"multissh/internal/sshx"
)

const (
	minBackoff = time.Second
	maxBackoff = 60 * time.Second
	// healthySession is how long a connection must last to count as good
	// enough to reset the backoff.
	healthySession = 60 * time.Second
)

// ptyProcess is a shell attached to a pseudo-terminal. The implementations
// live in pty_unix.go and pty_windows.go; nothing else in the agent knows
// which platform it is on.
type ptyProcess interface {
	io.Reader
	io.Writer
	Resize(cols, rows uint16) error
	Wait() (uint32, error)
	// Terminate ends the shell, and as much of what it started as the
	// platform allows.
	Terminate()
}

func main() {
	var (
		proxyAddr = flag.String("proxy", "", "proxy websocket URL, e.g. wss://multissh.example.com/agent")
		identity  = flag.String("identity", "agent_identity", "key identifying this agent to the proxy")
		hostKey   = flag.String("host-key", "agent_host_key", "host key of the embedded ssh server")
		authKeys  = flag.String("authorized-keys", "agent_authorized_keys", "keys allowed to log in here")
		proxyHost = flag.String("proxy-host", "", "override the HTTP Host header for ws/wss (use when DNS is unavailable)")
		idCert    = flag.String("identity-cert", "agent_identity-cert.pub", "certificate naming this machine, issued by the proxy")
		caFile    = flag.String("ca", "proxy_ca.pub", "the proxy's certificate authority, pinned")
		showKeys  = flag.Bool("show-keys", false, "create the keys if absent, print their public halves, and exit")
	)
	flag.Parse()
	log.SetFlags(log.Ltime)

	idSigner, err := sshx.LoadOrCreateHostKey(*identity)
	if err != nil {
		log.Fatalf("identity: %v", err)
	}
	hostSigner, err := sshx.LoadOrCreateHostKey(*hostKey)
	if err != nil {
		log.Fatalf("host key: %v", err)
	}
	// Enrolment needs the public halves before there is a certificate to run
	// with. Doing it here means the installer needs no ssh-keygen, which a
	// minimal container or a stock Windows box may not have.
	if *showKeys {
		fmt.Printf("identity %s", ssh.MarshalAuthorizedKey(idSigner.PublicKey()))
		fmt.Printf("host %s", ssh.MarshalAuthorizedKey(hostSigner.PublicKey()))
		return
	}

	log.Printf("agent identity  %s", ssh.FingerprintSHA256(idSigner.PublicKey()))
	log.Printf("embedded hostkey %s", ssh.FingerprintSHA256(hostSigner.PublicKey()))

	// The certificate carries our names, so the proxy need not remember us.
	// The name we present must match a principal in it.
	cert, err := sshx.LoadCert(*idCert)
	if err != nil {
		log.Fatalf("identity certificate: %v (enrol this machine first)", err)
	}
	authSigner, err := ssh.NewCertSigner(cert, idSigner)
	if err != nil {
		log.Fatalf("identity certificate: %v", err)
	}
	if len(cert.ValidPrincipals) == 0 {
		log.Fatalf("identity certificate carries no name")
	}
	canonical := cert.ValidPrincipals[0]
	log.Printf("canonical name %s", canonical)

	// The embedded server keeps a plain host key on purpose. If the proxy
	// certified it, a compromised proxy could mint one for a machine it
	// controls and impersonate this target to the user with no warning. On
	// trust-on-first-use it cannot, and the canonical name above commits to
	// this key so the user can check it by eye.
	if !sshx.VerifyCanonicalName(canonical, hostSigner.PublicKey()) {
		log.Fatalf("certificate names %q but that does not match this host key; re-enrol", canonical)
	}

	hostKeyCB, err := proxyVerifier(*caFile)
	if err != nil {
		log.Fatalf("proxy verification: %v", err)
	}

	clientCfg := &ssh.ClientConfig{
		User: canonical,
		Auth: []ssh.AuthMethod{ssh.PublicKeys(authSigner)},
		// The identification string carries the protocol version, so a proxy
		// too new for this agent can say so before authentication rather than
		// failing in some later, less legible way.
		ClientVersion:   sshx.AgentVersion(),
		HostKeyCallback: hostKeyCB,
		// Whatever the proxy refuses us for, it says here. Without this the
		// message would be discarded and the operator would see only that
		// authentication failed.
		BannerCallback: func(msg string) error {
			for _, line := range strings.Split(strings.TrimSpace(msg), "\n") {
				log.Printf("proxy says: %s", strings.TrimSpace(line))
			}
			return nil
		},
		Timeout: 10 * time.Second,
	}
	log.Printf("protocol %s", sshx.DescribeProtocol(sshx.ProtocolVersion))

	// Hold a registration open with every proxy at once rather than failing
	// over between them. One certificate is valid at all of them, so this
	// costs one connection each and removes any failover delay: whichever
	// proxy the user reaches, this machine is already there.
	var proxies []string
	for _, p := range strings.Split(*proxyAddr, ",") {
		if p = strings.TrimSpace(p); p != "" {
			proxies = append(proxies, p)
		}
	}
	if len(proxies) == 0 {
		log.Fatal("-proxy is required, e.g. wss://multissh.example.com/agent")
	}

	var wg sync.WaitGroup
	for _, p := range proxies {
		wg.Add(1)
		go func(target string) {
			defer wg.Done()
			maintain(target, *proxyHost, clientCfg, hostSigner, *authKeys)
		}(p)
	}
	wg.Wait()
}

// maintain keeps one proxy registration alive forever. The agent is the side
// that must survive NAT timeouts, laptop sleep and the proxy restarting, so
// this never gives up.
func maintain(target, wsHost string, cfg *ssh.ClientConfig, hostSigner ssh.Signer, authKeys string) {
	backoff := minBackoff
	for {
		started := time.Now()
		err := session(target, wsHost, cfg, hostSigner, authKeys)
		log.Printf("[%s] disconnected: %v", target, err)

		// A session that stayed up proves this proxy is reachable, so start
		// over from a short delay. Without this the backoff only ever grows,
		// and an agent that has reconnected a few times over its life is stuck
		// waiting the maximum every time -- slowest exactly when it matters.
		if time.Since(started) >= healthySession {
			backoff = minBackoff
		}

		jitter := time.Duration(rand.Int63n(int64(backoff / 2)))
		time.Sleep(backoff + jitter)
		if backoff < maxBackoff {
			backoff *= 2
		}
	}
}

// proxyVerifier authenticates the proxy by its certificate authority rather
// than a specific key, so the proxy can be rebuilt on new hardware with a fresh
// host key and every agent still accepts it. That is what makes the proxy
// recoverable from a single backed-up file.
func proxyVerifier(caPath string) (ssh.HostKeyCallback, error) {
	caPub, err := sshx.LoadPublicKey(caPath)
	if err != nil {
		return nil, err
	}
	log.Printf("trusting proxies certified by %s", ssh.FingerprintSHA256(caPub))
	checker := &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
			return sshx.SameKey(auth, caPub)
		},
	}
	return checker.CheckHostKey, nil
}

// dialProxy reaches the proxy over a WebSocket, which is ordinary HTTP/1.1
// with an Upgrade header. That survives restrictive firewalls and lets a
// reverse proxy front the service on :443, since it is indistinguishable from
// HTTPS on the wire.
//
// hostOverride sets the HTTP Host header independently of the address dialled,
// so a target can reach the proxy by IP when DNS is unavailable -- a plausible
// state of affairs for something billed as a last resort. It is not enough for
// wss:// to a bare IP, which would also need the TLS SNI overridden.
func dialProxy(target, hostOverride string, timeout time.Duration) (net.Conn, error) {
	if !strings.HasPrefix(target, "ws://") && !strings.HasPrefix(target, "wss://") {
		return nil, fmt.Errorf("-proxy must be a ws:// or wss:// URL, got %q", target)
	}

	// This context bounds the HTTP upgrade only.
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	c, _, err := websocket.Dial(ctx, target, &websocket.DialOptions{Host: hostOverride})
	if err != nil {
		return nil, err
	}
	// The session's own context must outlive the dial, or it would be
	// cancelled the moment this function returns.
	return websocket.NetConn(context.Background(), c, websocket.MessageBinary), nil
}

// canonicalAddr reduces a target to host:port. Host key checking parses this
// with net.SplitHostPort, so handing it a whole ws:// URL fails before the
// certificate is ever examined.
func canonicalAddr(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	if u.Port() != "" {
		return u.Host
	}
	if u.Scheme == "wss" {
		return net.JoinHostPort(u.Host, "443")
	}
	return net.JoinHostPort(u.Host, "80")
}

// session holds one registration open until the connection dies.
func session(addr, wsHost string, cfg *ssh.ClientConfig, hostSigner ssh.Signer, authKeys string) error {
	raw, err := dialProxy(addr, wsHost, cfg.Timeout)
	if err != nil {
		return err
	}
	conn, chans, reqs, err := ssh.NewClientConn(raw, canonicalAddr(addr), cfg)
	if err != nil {
		raw.Close()
		return err
	}
	client := ssh.NewClient(conn, chans, reqs)
	defer client.Close()

	// A proxy ahead of this agent still serves it -- refusing would strand the
	// machine over a difference it may not even notice -- but the mismatch is
	// worth saying out loud, since an upgrade sweep has to start somewhere.
	if pv := sshx.ParseProxyVersion(conn.ServerVersion()); pv > sshx.ProtocolVersion {
		log.Printf("[%s] proxy speaks protocol %s, this agent %s; consider updating this machine",
			addr, sshx.DescribeProtocol(pv), sshx.DescribeProtocol(sshx.ProtocolVersion))
	}
	log.Printf("registered with proxy at %s", addr)

	// Keep the NAT mapping alive from the inside; consumer routers can expire
	// idle entries in well under a minute.
	go func() {
		t := time.NewTicker(25 * time.Second)
		defer t.Stop()
		for range t.C {
			if _, _, err := client.SendRequest("keepalive@openssh.com", true, nil); err != nil {
				client.Close()
				return
			}
		}
	}()

	go func() {
		for nc := range client.HandleChannelOpen(sshx.TunnelChannelType) {
			// The payload only describes the tunnel; nothing in version 1
			// changes what happens next, so an unknown version is served and
			// noted rather than refused. Refusing would turn a proxy upgrade
			// into an outage on every machine not updated in step.
			req := sshx.ParseTunnelRequest(nc.ExtraData())
			ch, chReqs, err := nc.Accept()
			if err != nil {
				continue
			}
			go ssh.DiscardRequests(chReqs)
			go serveEmbedded(ch, hostSigner, authKeys, int(req.Version))
		}
	}()

	return client.Wait()
}

// serveEmbedded runs a complete SSH server across one tunnel channel. The
// client's handshake terminates here, so the proxy sees only ciphertext.
func serveEmbedded(ch ssh.Channel, hostSigner ssh.Signer, authKeys string, tunnelVersion int) {
	if tunnelVersion > sshx.ProtocolVersion {
		log.Printf("tunnel opened at protocol %s, above this agent's %s; serving it anyway",
			sshx.DescribeProtocol(tunnelVersion), sshx.DescribeProtocol(sshx.ProtocolVersion))
	}
	allowed, err := sshx.LoadAuthorizedKeys(authKeys)
	if err != nil {
		log.Printf("authorized_keys: %v", err)
		ch.Close()
		return
	}

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !allowed[string(key.Marshal())] {
				return nil, fmt.Errorf("key not authorized")
			}
			return nil, nil
		},
	}
	cfg.AddHostKey(hostSigner)

	conn, chans, reqs, err := ssh.NewServerConn(
		sshx.ChannelConn{Channel: ch, Local: "agent", Remote: "proxy"}, cfg)
	if err != nil {
		log.Printf("embedded handshake failed: %v", err)
		ch.Close()
		return
	}
	defer conn.Close()
	log.Printf("embedded login as %q (%s)", conn.User(), conn.ClientVersion())

	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "only sessions are served")
			continue
		}
		go serveSession(nc)
	}
	log.Printf("embedded session ended")
}

type ptyRequest struct {
	Term                   string
	Cols, Rows, WidP, HigP uint32
	Modes                  string
}

type winChange struct {
	Cols, Rows, WidP, HigP uint32
}

func serveSession(nc ssh.NewChannel) {
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}

	var (
		mu      sync.Mutex
		shell   ptyProcess
		winCols = uint16(80)
		winRows = uint16(24)
		term    = "xterm"
		started bool
	)

	// Whatever ends the session, the shell must go with it, or a rescue box
	// slowly fills up with orphaned shells.
	defer func() {
		mu.Lock()
		s := shell
		mu.Unlock()
		if s != nil {
			s.Terminate()
		}
		ch.Close()
	}()

	start := func(command string) bool {
		mu.Lock()
		defer mu.Unlock()
		if started {
			return false
		}
		started = true

		s, err := startShell(command, term, winCols, winRows)
		if err != nil {
			fmt.Fprintf(ch, "multissh: cannot start shell: %v\r\n", err)
			return false
		}
		shell = s

		go io.Copy(s, ch)
		go io.Copy(ch, s)
		go func() {
			code, _ := s.Wait()
			ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{code}))
			ch.Close()
		}()
		return true
	}

	for req := range reqs {
		switch req.Type {
		case "pty-req":
			var p ptyRequest
			if err := ssh.Unmarshal(req.Payload, &p); err == nil {
				mu.Lock()
				term, winCols, winRows = p.Term, uint16(p.Cols), uint16(p.Rows)
				mu.Unlock()
			}
			if req.WantReply {
				req.Reply(true, nil)
			}

		case "window-change":
			var w winChange
			if err := ssh.Unmarshal(req.Payload, &w); err == nil {
				mu.Lock()
				winCols, winRows = uint16(w.Cols), uint16(w.Rows)
				if shell != nil {
					shell.Resize(winCols, winRows)
				}
				mu.Unlock()
			}

		case "shell":
			ok := start("")
			if req.WantReply {
				req.Reply(ok, nil)
			}

		case "exec":
			var e struct{ Command string }
			if err := ssh.Unmarshal(req.Payload, &e); err != nil {
				req.Reply(false, nil)
				continue
			}
			ok := start(e.Command)
			if req.WantReply {
				req.Reply(ok, nil)
			}

		default:
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

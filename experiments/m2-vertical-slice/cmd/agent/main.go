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
	"os"
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
		proxyAddr = flag.String("proxy", "127.0.0.1:2223", "proxy address: host:port, or ws://host/agent")
		identity  = flag.String("identity", "agent_identity", "key identifying this agent to the proxy")
		hostKey   = flag.String("host-key", "agent_host_key", "host key of the embedded ssh server")
		authKeys  = flag.String("authorized-keys", "agent_authorized_keys", "keys allowed to log in here")
		proxyHost = flag.String("proxy-host", "", "override the HTTP Host header for ws/wss (use when DNS is unavailable)")
		knownKey  = flag.String("known-proxy-key", "known_proxy_key", "pinned proxy host key; trusted on first use when absent")
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
	log.Printf("agent identity  %s", ssh.FingerprintSHA256(idSigner.PublicKey()))
	log.Printf("embedded hostkey %s", ssh.FingerprintSHA256(hostSigner.PublicKey()))

	hostKeyCB, err := tofuProxyKey(*knownKey)
	if err != nil {
		log.Fatalf("proxy host key: %v", err)
	}

	clientCfg := &ssh.ClientConfig{
		User:            "agent",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(idSigner)},
		HostKeyCallback: hostKeyCB,
		Timeout:         10 * time.Second,
	}

	// Reconnect forever: the agent is the side that must survive NAT timeouts,
	// laptop sleep, and the proxy restarting.
	backoff := minBackoff
	for {
		started := time.Now()
		err := session(*proxyAddr, *proxyHost, clientCfg, hostSigner, *authKeys)
		log.Printf("disconnected from proxy: %v", err)

		// A session that stayed up proves the proxy is reachable, so start
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

// tofuProxyKey pins the proxy's host key the way an ssh client's known_hosts
// does: trusted on first connect, refused if it ever changes afterwards.
// Pre-seed the file at install time to close the first-connect window.
func tofuProxyKey(path string) (ssh.HostKeyCallback, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		pk, _, _, _, err := ssh.ParseAuthorizedKey(data)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
		log.Printf("proxy host key pinned to %s", ssh.FingerprintSHA256(pk))
		return ssh.FixedHostKey(pk), nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		log.Printf("trusting proxy host key on first use: %s", ssh.FingerprintSHA256(key))
		return os.WriteFile(path, ssh.MarshalAuthorizedKey(key), 0o600)
	}, nil
}

// dialProxy reaches the proxy over a plain socket, or over a WebSocket when
// given a ws:// or wss:// URL. The WebSocket form is what survives restrictive
// firewalls and lets a reverse proxy front the service on :443, since it is
// indistinguishable from ordinary HTTPS.
// hostOverride sets the HTTP Host header independently of the address dialled,
// so a target can reach the proxy by IP when DNS is unavailable -- a plausible
// state of affairs for something billed as a last resort. Note that wss:// to a
// bare IP would also need the TLS SNI overridden, which is not implemented.
func dialProxy(target, hostOverride string, timeout time.Duration) (net.Conn, error) {
	if !strings.HasPrefix(target, "ws://") && !strings.HasPrefix(target, "wss://") {
		return net.DialTimeout("tcp", target, timeout)
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

// session holds one registration open until the connection dies.
func session(addr, wsHost string, cfg *ssh.ClientConfig, hostSigner ssh.Signer, authKeys string) error {
	raw, err := dialProxy(addr, wsHost, cfg.Timeout)
	if err != nil {
		return err
	}
	conn, chans, reqs, err := ssh.NewClientConn(raw, addr, cfg)
	if err != nil {
		raw.Close()
		return err
	}
	client := ssh.NewClient(conn, chans, reqs)
	defer client.Close()
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
			ch, chReqs, err := nc.Accept()
			if err != nil {
				continue
			}
			go ssh.DiscardRequests(chReqs)
			go serveEmbedded(ch, hostSigner, authKeys)
		}
	}()

	return client.Wait()
}

// serveEmbedded runs a complete SSH server across one tunnel channel. The
// client's handshake terminates here, so the proxy sees only ciphertext.
func serveEmbedded(ch ssh.Channel, hostSigner ssh.Signer, authKeys string) {
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

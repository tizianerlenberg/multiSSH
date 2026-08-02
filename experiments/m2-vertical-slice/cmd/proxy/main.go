// multiSSH proxy: a jump host whose targets dial in to it.
//
// Two listeners, always, and never any others:
//
//	-user-addr   normal ssh clients (ssh proxy / ssh -J proxy user@label)
//	-agent-addr  targets registering themselves
//
// The proxy implements exactly two things on the user side: a session that
// prints the target list, and direct-tcpip to a registered label. Anything
// else is refused, and no client-supplied string ever reaches a dial call.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
	"multissh/internal/sshx"
)

const (
	// handshakeTimeout bounds an unauthenticated connection, as OpenSSH's
	// LoginGraceTime does.
	handshakeTimeout = 30 * time.Second
	// keepaliveInterval/Timeout decide how fast a vanished agent is evicted.
	keepaliveInterval = 30 * time.Second
	keepaliveTimeout  = 15 * time.Second
	// tunnelOpenTimeout stops a user waiting on an unresponsive agent.
	tunnelOpenTimeout = 10 * time.Second
)

// registry tracks which agents are currently connected.
type registry struct {
	mu sync.RWMutex
	m  map[string]ssh.Conn
}

func newRegistry() *registry { return &registry{m: make(map[string]ssh.Conn)} }

// add registers conn under label, evicting any earlier connection. A half-open
// TCP session can leave a ghost behind; the newest connection always wins.
func (r *registry) add(label string, conn ssh.Conn) {
	r.mu.Lock()
	old, existed := r.m[label]
	r.m[label] = conn
	r.mu.Unlock()
	if existed && old != conn {
		log.Printf("registry: evicting stale registration for %q", label)
		old.Close()
	}
}

// remove drops label only if it still points at conn. Without this identity
// check, a dying connection would deregister the agent that just replaced it.
func (r *registry) remove(label string, conn ssh.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.m[label]; ok && cur == conn {
		delete(r.m, label)
	}
}

func (r *registry) get(label string) (ssh.Conn, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.m[label]
	return c, ok
}

func (r *registry) labels() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.m))
	for l := range r.m {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

func main() {
	var (
		userAddr  = flag.String("user-addr", "127.0.0.1:2222", "listen address for ssh clients")
		agentAddr = flag.String("agent-addr", "127.0.0.1:2223", "raw TCP listen address for agents (empty to disable)")
		wsAddr    = flag.String("agent-ws-addr", "", "websocket listen address for agents, e.g. 127.0.0.1:8080 (empty to disable)")
		wsPath    = flag.String("agent-ws-path", "/agent", "websocket path")
		hostKey   = flag.String("host-key", "proxy_host_key", "proxy host key (created if absent)")
		caKey     = flag.String("ca-key", "proxy_ca_key", "certificate authority key (created if absent)")
		usersFile = flag.String("users", "users_authorized_keys", "authorized_keys for users")
		agentFile = flag.String("agents", "agents_authorized_keys", "optional '<label> <pubkey>' fallback list")

		showCA       = flag.Bool("show-ca", false, "print the certificate authority public key and exit")
		signKey      = flag.String("sign", "", "issue a certificate for this public key file, then exit")
		signLabel    = flag.String("sign-label", "", "label/principal to put in the certificate")
		signType     = flag.String("sign-type", "user", "certificate type: user (agent identity) or host")
		signValidity = flag.Duration("sign-validity", 0, "certificate lifetime; 0 never expires")
	)
	flag.Parse()
	log.SetFlags(log.Ltime)

	ca, err := sshx.LoadOrCreateHostKey(*caKey)
	if err != nil {
		log.Fatalf("ca key: %v", err)
	}

	// The public half of the authority is what agents and your known_hosts
	// pin, so make it easy to obtain.
	if *showCA {
		os.Stdout.Write(ssh.MarshalAuthorizedKey(ca.PublicKey()))
		return
	}

	// Signing mode: issue a certificate and exit. This is what enrollment will
	// call once the installer exists.
	if *signKey != "" {
		if err := issueCert(ca, *signKey, *signLabel, *signType, *signValidity); err != nil {
			log.Fatalf("sign: %v", err)
		}
		return
	}

	signer, err := sshx.LoadOrCreateHostKey(*hostKey)
	if err != nil {
		log.Fatalf("host key: %v", err)
	}
	log.Printf("proxy host key %s", ssh.FingerprintSHA256(signer.PublicKey()))
	log.Printf("certificate authority %s", ssh.FingerprintSHA256(ca.PublicKey()))

	users, err := sshx.LoadAuthorizedKeys(*usersFile)
	if err != nil {
		log.Fatalf("users: %v", err)
	}
	// Optional now: an agent presenting a certificate needs no entry here.
	agents, err := sshx.LoadAgentKeys(*agentFile)
	if err != nil {
		log.Fatalf("agents: %v", err)
	}
	log.Printf("loaded %d user key(s), %d static agent key(s)", len(users), len(agents))

	// Sign our own host key afresh on every start, with no principals, so it
	// is valid whatever address agents reach us on. This is what lets the
	// proxy be rebuilt on a new machine with a new host key: agents pin the
	// authority, not the key, so they accept the replacement without being
	// touched.
	hostCert, err := sshx.SignCert(ca, signer.PublicKey(), ssh.HostCert, "multissh-proxy", nil, 0)
	if err != nil {
		log.Fatalf("host certificate: %v", err)
	}
	agentHostSigner, err := ssh.NewCertSigner(hostCert, signer)
	if err != nil {
		log.Fatalf("host certificate signer: %v", err)
	}

	reg := newRegistry()

	userCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !users[string(key.Marshal())] {
				return nil, fmt.Errorf("unauthorized user key")
			}
			return nil, nil
		},
	}
	// Offer both the certificate and the bare key. OpenSSH prefers whichever
	// it already trusts, so a client with an @cert-authority line accepts a
	// rebuilt proxy without edits, while one with a plain known_hosts entry
	// keeps working unchanged.
	userCfg.AddHostKey(agentHostSigner)
	userCfg.AddHostKey(signer)

	caPub := ca.PublicKey()
	certChecker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool { return sshx.SameKey(auth, caPub) },
	}

	agentCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// Preferred path: a certificate we signed. CheckCert verifies the
			// signature, the validity window, and that the username the agent
			// claims is one of the principals we put in the certificate --
			// so the label is still ours to assign, without storing it.
			if cert, ok := key.(*ssh.Certificate); ok {
				if err := certChecker.CheckCert(c.User(), cert); err != nil {
					return nil, fmt.Errorf("certificate rejected: %w", err)
				}
				return &ssh.Permissions{Extensions: map[string]string{"label": c.User()}}, nil
			}
			// Fallback for agents enrolled before certificates existed.
			label, ok := agents[string(key.Marshal())]
			if !ok {
				return nil, fmt.Errorf("no certificate and key is not in %s", *agentFile)
			}
			return &ssh.Permissions{Extensions: map[string]string{"label": label}}, nil
		},
	}
	// Agents verify us through the authority, so present the certificate.
	agentCfg.AddHostKey(agentHostSigner)

	agentHandler := func(c *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
		handleAgent(reg, c, chans, reqs)
	}
	if *agentAddr == "" && *wsAddr == "" {
		log.Fatal("no agent listener configured: set -agent-addr or -agent-ws-addr")
	}
	if *agentAddr != "" {
		go serve(*agentAddr, "agent", agentCfg, agentHandler)
	}
	if *wsAddr != "" {
		go serveWebSocket(*wsAddr, *wsPath, "agent", agentCfg, agentHandler)
	}

	serve(*userAddr, "user", userCfg, func(c *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
		handleUser(reg, c, chans, reqs)
	})
}

// issueCert signs a public key and writes "<path>-cert.pub" beside it, the
// same naming OpenSSH uses.
func issueCert(ca ssh.Signer, pubPath, label, kind string, validity time.Duration) error {
	if label == "" {
		return fmt.Errorf("-sign-label is required")
	}
	pub, err := sshx.LoadPublicKey(pubPath)
	if err != nil {
		return err
	}

	certType := uint32(ssh.UserCert)
	if kind == "host" {
		certType = ssh.HostCert
	} else if kind != "user" {
		return fmt.Errorf("-sign-type must be user or host")
	}

	cert, err := sshx.SignCert(ca, pub, certType, label, []string{label}, validity)
	if err != nil {
		return err
	}

	out := strings.TrimSuffix(pubPath, ".pub") + "-cert.pub"
	if err := sshx.WriteCert(out, cert); err != nil {
		return err
	}

	expiry := "never expires"
	if validity > 0 {
		expiry = "expires " + time.Unix(int64(cert.ValidBefore), 0).Format(time.RFC3339)
	}
	fmt.Printf("wrote %s\n  type       %s\n  principal  %s\n  authority  %s\n  %s\n",
		out, kind, label, ssh.FingerprintSHA256(ca.PublicKey()), expiry)
	return nil
}

type connHandler func(*ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request)

// takeConn runs the SSH server handshake over any transport: a plain socket,
// or a WebSocket presented as a net.Conn.
func takeConn(nc net.Conn, kind string, cfg *ssh.ServerConfig, h connHandler) {
	defer nc.Close()

	// Bound the handshake, or a client that connects and never speaks pins a
	// goroutine and a socket indefinitely. OpenSSH calls this LoginGraceTime.
	nc.SetDeadline(time.Now().Add(handshakeTimeout))
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		log.Printf("%s handshake from %s failed: %v", kind, nc.RemoteAddr(), err)
		return
	}
	// Clear it, or an idle session would be torn down mid-use.
	nc.SetDeadline(time.Time{})

	defer conn.Close()
	h(conn, chans, reqs)
}

func serve(addr, kind string, cfg *ssh.ServerConfig, h connHandler) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen %s: %v", addr, err)
	}
	log.Printf("%s listener on %s", kind, addr)
	for {
		nc, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go takeConn(nc, kind, cfg, h)
	}
}

// serveWebSocket carries the agent protocol inside an ordinary HTTP upgrade,
// so a reverse proxy such as Caddy can front it on :443 alongside other
// subdomains, and the traffic looks like plain HTTPS on the wire. Bind this to
// loopback and let the reverse proxy terminate TLS: SSH runs inside the
// WebSocket, so the reverse proxy only ever relays ciphertext.
func serveWebSocket(addr, path, kind string, cfg *ssh.ServerConfig, h connHandler) {
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			log.Printf("%s websocket upgrade from %s failed: %v", kind, r.RemoteAddr, err)
			return
		}
		// Binary frames, and a context that outlives the handshake so the
		// session is not cancelled underneath us.
		takeConn(websocket.NetConn(context.Background(), c, websocket.MessageBinary), kind, cfg, h)
	})

	// No server-wide timeouts: these connections are meant to stay open.
	srv := &http.Server{Addr: addr, Handler: mux}
	log.Printf("%s websocket listener on %s%s", kind, addr, path)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("websocket listen %s: %v", addr, err)
	}
}

// handleAgent keeps the agent's connection parked in the registry until it dies.
func handleAgent(reg *registry, conn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	label := conn.Permissions.Extensions["label"]

	// Answer keepalives; refuse everything else, including tcpip-forward.
	go func() {
		for r := range reqs {
			if r.WantReply {
				r.Reply(r.Type == "keepalive@openssh.com", nil)
			}
		}
	}()
	// Agents are spoken to, not listened to.
	go func() {
		for nc := range chans {
			nc.Reject(ssh.Prohibited, "agents may not open channels")
		}
	}()

	reg.add(label, conn)
	log.Printf("agent %q registered from %s", label, conn.RemoteAddr())

	// The agent sends its own keepalives, but nothing here would notice them
	// stopping. Without probing from this side, a half-open connection (a
	// sleeping laptop) stays registered until the kernel gives up on the TCP
	// session, which can take many minutes, and the label meanwhile accepts
	// connections that hang.
	stop := make(chan struct{})
	defer close(stop)
	go probeLiveness(conn, label, stop)

	conn.Wait() // blocks until the connection dies
	reg.remove(label, conn)
	log.Printf("agent %q disconnected", label)
}

// probeLiveness pings the agent and closes the connection when it stops
// answering, which makes conn.Wait return and the registration go away.
// A false reply still proves liveness: x/crypto/ssh clients refuse unknown
// global requests by design, so only an error or a timeout counts as dead.
func probeLiveness(conn ssh.Conn, label string, stop <-chan struct{}) {
	t := time.NewTicker(keepaliveInterval)
	defer t.Stop()

	for {
		select {
		case <-stop:
			return
		case <-t.C:
		}

		errc := make(chan error, 1)
		go func() {
			_, _, err := conn.SendRequest("keepalive@openssh.com", true, nil)
			errc <- err
		}()

		select {
		case err := <-errc:
			if err != nil {
				log.Printf("agent %q failed keepalive: %v", label, err)
				conn.Close()
				return
			}
		case <-time.After(keepaliveTimeout):
			log.Printf("agent %q timed out on keepalive, dropping", label)
			conn.Close()
			return
		case <-stop:
			return
		}
	}
}

func handleUser(reg *registry, conn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	log.Printf("user %q connected from %s", conn.User(), conn.RemoteAddr())

	// Draining is mandatory or the connection deadlocks. Replying false is the
	// refusal: this is what stops `ssh -R` opening ports on the proxy.
	go func() {
		for r := range reqs {
			if r.Type != "keepalive@openssh.com" {
				log.Printf("  refused global request %q", r.Type)
			}
			if r.WantReply {
				r.Reply(false, nil)
			}
		}
	}()

	for nc := range chans {
		switch nc.ChannelType() {
		case "session":
			go serveListing(reg, nc)
		case "direct-tcpip":
			go serveJump(reg, conn, nc)
		default:
			log.Printf("  refused channel %q", nc.ChannelType())
			nc.Reject(ssh.UnknownChannelType, "not supported")
		}
	}
}

// serveListing answers a plain `ssh proxy` with the available targets.
func serveListing(reg *registry, nc ssh.NewChannel) {
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	defer ch.Close()

	for req := range reqs {
		switch req.Type {
		case "pty-req", "shell":
			if req.WantReply {
				req.Reply(true, nil)
			}
			if req.Type != "shell" {
				continue
			}
			labels := reg.labels()
			fmt.Fprintf(ch, "\r\n multiSSH proxy\r\n\r\n")
			if len(labels) == 0 {
				fmt.Fprintf(ch, " no targets currently registered\r\n")
			} else {
				fmt.Fprintf(ch, " registered targets (%d):\r\n\r\n", len(labels))
				for _, l := range labels {
					fmt.Fprintf(ch, "   %s\r\n", l)
				}
				fmt.Fprintf(ch, "\r\n connect with:  ssh -J <thisproxy> user@%s\r\n", labels[0])
			}
			fmt.Fprintf(ch, "\r\n")
			ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{0}))
			return
		default:
			// exec, subsystem, x11-req, auth-agent-req all land here.
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}
}

// openTunnel asks the agent for a channel, giving up rather than blocking on
// an agent whose connection is half-open and not yet known to be dead.
func openTunnel(agent ssh.Conn) (ssh.Channel, <-chan *ssh.Request, error) {
	type result struct {
		ch   ssh.Channel
		reqs <-chan *ssh.Request
		err  error
	}
	done := make(chan result, 1)
	go func() {
		ch, reqs, err := agent.OpenChannel(sshx.TunnelChannelType, nil)
		done <- result{ch, reqs, err}
	}()

	select {
	case r := <-done:
		if r.err != nil {
			return nil, nil, fmt.Errorf("agent refused tunnel: %w", r.err)
		}
		return r.ch, r.reqs, nil
	case <-time.After(tunnelOpenTimeout):
		// If it lands after we gave up, discard it rather than leak a channel.
		go func() {
			if r := <-done; r.err == nil {
				r.ch.Close()
			}
		}()
		return nil, nil, fmt.Errorf("agent did not answer within %s", tunnelOpenTimeout)
	}
}

// serveJump routes `ssh -J proxy user@label` to the registered agent.
func serveJump(reg *registry, conn *ssh.ServerConn, nc ssh.NewChannel) {
	var d sshx.DirectTCPIP
	if err := ssh.Unmarshal(nc.ExtraData(), &d); err != nil {
		nc.Reject(ssh.ConnectionFailed, "bad payload")
		return
	}

	// Registry lookup only. DestHost is never dialled and DestPort is ignored,
	// so `ssh -L` cannot reach anything the proxy can reach.
	agent, ok := reg.get(d.DestHost)
	if !ok {
		log.Printf("  user %q -> %q: no such target", conn.User(), d.DestHost)
		nc.Reject(ssh.ConnectionFailed, "no such target")
		return
	}

	tunnel, tReqs, err := openTunnel(agent)
	if err != nil {
		log.Printf("  user %q -> %q: %v", conn.User(), d.DestHost, err)
		nc.Reject(ssh.ConnectionFailed, "target unreachable")
		return
	}
	go ssh.DiscardRequests(tReqs)

	client, cReqs, err := nc.Accept()
	if err != nil {
		tunnel.Close()
		return
	}
	go ssh.DiscardRequests(cReqs)

	log.Printf("  user %q -> %q: tunnel open", conn.User(), d.DestHost)
	sshx.Pipe(client, tunnel)
	log.Printf("  user %q -> %q: tunnel closed", conn.User(), d.DestHost)
}

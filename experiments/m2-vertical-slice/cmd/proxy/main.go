// multiSSH proxy: a jump host whose targets dial in to it.
//
// Two listeners, always, and never any others:
//   -user-addr   normal ssh clients (ssh proxy / ssh -J proxy user@label)
//   -agent-addr  targets registering themselves
//
// The proxy implements exactly two things on the user side: a session that
// prints the target list, and direct-tcpip to a registered label. Anything
// else is refused, and no client-supplied string ever reaches a dial call.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"sort"
	"sync"

	"time"

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
		agentAddr = flag.String("agent-addr", "127.0.0.1:2223", "listen address for agents")
		hostKey   = flag.String("host-key", "proxy_host_key", "proxy host key (created if absent)")
		usersFile = flag.String("users", "users_authorized_keys", "authorized_keys for users")
		agentFile = flag.String("agents", "agents_authorized_keys", "'<label> <pubkey>' per line")
	)
	flag.Parse()
	log.SetFlags(log.Ltime)

	signer, err := sshx.LoadOrCreateHostKey(*hostKey)
	if err != nil {
		log.Fatalf("host key: %v", err)
	}
	log.Printf("proxy host key %s", ssh.FingerprintSHA256(signer.PublicKey()))

	users, err := sshx.LoadAuthorizedKeys(*usersFile)
	if err != nil {
		log.Fatalf("users: %v", err)
	}
	agents, err := sshx.LoadAgentKeys(*agentFile)
	if err != nil {
		log.Fatalf("agents: %v", err)
	}
	log.Printf("loaded %d user key(s), %d agent key(s)", len(users), len(agents))

	reg := newRegistry()

	userCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !users[string(key.Marshal())] {
				return nil, fmt.Errorf("unauthorized user key")
			}
			return nil, nil
		},
	}
	userCfg.AddHostKey(signer)

	agentCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			label, ok := agents[string(key.Marshal())]
			if !ok {
				return nil, fmt.Errorf("unregistered agent key")
			}
			// The label comes from the proxy's config, never from the agent.
			return &ssh.Permissions{Extensions: map[string]string{"label": label}}, nil
		},
	}
	agentCfg.AddHostKey(signer)

	go serve(*agentAddr, "agent", agentCfg, func(c *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
		handleAgent(reg, c, chans, reqs)
	})
	serve(*userAddr, "user", userCfg, func(c *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
		handleUser(reg, c, chans, reqs)
	})
}

func serve(addr, kind string, cfg *ssh.ServerConfig, h func(*ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request)) {
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
		go func() {
			defer nc.Close()

			// Bound the handshake, or a client that connects and never speaks
			// pins a goroutine and a socket indefinitely. OpenSSH calls this
			// LoginGraceTime.
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
		}()
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

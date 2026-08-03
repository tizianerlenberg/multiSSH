// multiSSH proxy: a jump host whose targets dial in to it.
//
// Two listeners, always, and never any others:
//
//	-user-addr   normal ssh clients (ssh proxy / ssh -J proxy user@name)
//	-agent-addr  targets registering themselves, over a websocket
//
// The proxy implements exactly two things on the user side: a session that
// prints the target list, and direct-tcpip to a registered label. Anything
// else is refused, and no client-supplied string ever reaches a dial call.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
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

	// authFailWindow/Burst slow down key guessing against the ssh listeners.
	// The /enroll endpoint has its own limiter; this covers the other door.
	authFailWindow = 5 * time.Minute
	authFailBurst  = 10
)

// authFailures counts recent failed handshakes per source address, so a host
// that keeps guessing is turned away before the expensive part.
var authFailures = newLimiter(authFailWindow, authFailBurst)

// sourceHost strips the port: a new connection gets a new one, so counting
// with it would treat every attempt as a different peer and limit nothing.
func sourceHost(addr net.Addr) string {
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		return host
	}
	return addr.String()
}

// registration is one connected agent under one of its names. The fingerprint
// is of the agent's identity key -- the thing the proxy authenticates -- so
// re-issuing a certificate for a machine is not mistaken for a new machine.
type registration struct {
	conn ssh.Conn
	fp   string
}

// registry tracks which agents are currently connected. A target appears under
// its canonical name always, and under its friendly name when it holds one.
type registry struct {
	mu sync.RWMutex
	m  map[string]registration
}

// stdLogf exists so enroll.go can log without a second import alias.
func stdLogf(format string, args ...any) { log.Printf(format, args...) }

func newRegistry() *registry { return &registry{m: make(map[string]registration)} }

// add claims name for conn.
//
// A machine reconnecting presents the same identity key, so its stale entry is
// replaced: a half-open TCP session leaves a ghost behind and the live
// connection must win. A *different* key claiming a name that is already taken
// is refused. Allowing it to evict instead would let two machines kick each
// other off forever, leaving neither reliably reachable.
func (r *registry) add(name string, conn ssh.Conn, fp string) error {
	r.mu.Lock()
	old, existed := r.m[name]
	if existed && old.fp != fp {
		r.mu.Unlock()
		return fmt.Errorf("%q is held by a different machine (%s)", name, old.fp)
	}
	r.m[name] = registration{conn: conn, fp: fp}
	r.mu.Unlock()

	if existed && old.conn != conn {
		log.Printf("registry: replacing stale registration for %q", name)
		old.conn.Close()
	}
	return nil
}

// remove drops name only if it still points at conn. Without this identity
// check, a dying connection would deregister the agent that just replaced it.
func (r *registry) remove(name string, conn ssh.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.m[name]; ok && cur.conn == conn {
		delete(r.m, name)
	}
}

func (r *registry) get(name string) (ssh.Conn, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.m[name]
	return c.conn, ok
}

// listing pairs each canonical name with the friendly name pointing at the
// same connection, so `ssh proxy` can show both.
func (r *registry) listing() [][2]string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	friendly := make(map[ssh.Conn]string)
	var canonical []string
	for name, reg := range r.m {
		if sshx.IsCanonicalName(name) {
			canonical = append(canonical, name)
		} else {
			friendly[reg.conn] = name
		}
	}
	sort.Strings(canonical)

	out := make([][2]string, 0, len(canonical))
	for _, c := range canonical {
		out = append(out, [2]string{friendly[r.m[c].conn], c})
	}
	return out
}

func main() {
	var (
		userAddr   = flag.String("user-addr", "127.0.0.1:2222", "listen address for ssh clients")
		wsAddr     = flag.String("agent-addr", "127.0.0.1:8080", "websocket listen address for agents; front it with a reverse proxy")
		wsPath     = flag.String("agent-ws-path", "/agent", "websocket path")
		hostKey    = flag.String("host-key", "proxy_host_key", "proxy host key (created if absent)")
		caKey      = flag.String("ca-key", "proxy_ca_key", "certificate authority PRIVATE key; this proxy can then enrol machines")
		caPubFile  = flag.String("ca", "", "certificate authority PUBLIC key; runs this proxy as a verify-only standby")
		hostCert   = flag.String("host-cert", "proxy_host_key-cert.pub", "host certificate issued by the primary; required on a standby")
		usersFile  = flag.String("users", "users_authorized_keys", "authorized_keys for users")
		ledgerPath = flag.String("labels", "friendly_labels", "advisory record of which machine owns which friendly name")
		seenFile   = flag.String("last-seen", "last_seen", "advisory record of when each target was last connected")
		pwFile     = flag.String("passwords", "enrol_passwords.json", "enrolment passwords, argon2id hashed")
		distDir    = flag.String("dist", "dist", "directory of agent builds named <os>-<arch>")
		publicURL  = flag.String("public-url", "", "how targets reach this proxy, e.g. https://multissh.example.com; enables the installer")
		enrolValid = flag.Duration("enrol-validity", 0, "lifetime of issued certificates; 0 never expires")

		showCA        = flag.Bool("show-ca", false, "print the certificate authority public key and exit")
		signKey       = flag.String("sign", "", "issue a certificate for this public key file, then exit")
		signHostKey   = flag.String("sign-host-key", "", "the agent's host public key; the canonical name is derived from it")
		signLabel     = flag.String("sign-label", "", "desired friendly name")
		signValidity  = flag.Duration("sign-validity", 0, "certificate lifetime; 0 never expires")
		signProxy     = flag.String("sign-proxy-host", "", "issue a host certificate for a standby proxy's host key, then exit")
		addPassword   = flag.String("add-password", "", "create an enrolment password with this label, then exit")
		pwValidity    = flag.Duration("password-validity", 0, "lifetime of the new password; 0 never expires")
		listPasswords = flag.Bool("list-passwords", false, "show enrolment passwords and exit")
		delPassword   = flag.String("remove-password", "", "delete the enrolment password with this label, then exit")
	)
	flag.Parse()
	log.SetFlags(log.Ltime)

	// Verifying a certificate needs only the authority's public key; issuing
	// one needs the private key. A standby therefore runs on the public half
	// alone: it can authenticate every agent, and can enrol nothing. That
	// keeps the private key on one machine while access survives losing it.
	var (
		ca    ssh.Signer
		caPub ssh.PublicKey
		err   error
	)
	if *caPubFile != "" {
		caPub, err = sshx.LoadPublicKey(*caPubFile)
		if err != nil {
			log.Fatalf("ca: %v", err)
		}
	} else {
		ca, err = sshx.LoadOrCreateHostKey(*caKey)
		if err != nil {
			log.Fatalf("ca key: %v", err)
		}
		caPub = ca.PublicKey()
	}

	// The public half of the authority is what agents and your known_hosts
	// pin, so make it easy to obtain.
	if *showCA {
		os.Stdout.Write(ssh.MarshalAuthorizedKey(caPub))
		return
	}

	if ca == nil && (*signKey != "" || *signProxy != "") {
		log.Fatal("this is a standby (-ca): issuing certificates needs the private key")
	}

	// Signing mode: issue a certificate and exit. This is what enrollment will
	// call once the installer exists.
	if *signKey != "" {
		if err := issueCert(ca, *signKey, *signHostKey, *signLabel, *ledgerPath, *signValidity); err != nil {
			log.Fatalf("sign: %v", err)
		}
		return
	}

	if *listPasswords || *addPassword != "" || *delPassword != "" {
		if err := managePasswords(*pwFile, *addPassword, *delPassword, *listPasswords, *pwValidity); err != nil {
			log.Fatalf("passwords: %v", err)
		}
		return
	}

	// A standby cannot sign its own host key, so the primary does it once.
	if *signProxy != "" {
		if err := issueProxyHostCert(ca, *signProxy); err != nil {
			log.Fatalf("sign-proxy-host: %v", err)
		}
		return
	}

	signer, err := sshx.LoadOrCreateHostKey(*hostKey)
	if err != nil {
		log.Fatalf("host key: %v", err)
	}
	role := "primary"
	if ca == nil {
		role = "standby (verify only)"
	}
	log.Printf("running as %s", role)
	log.Printf("proxy host key %s", ssh.FingerprintSHA256(signer.PublicKey()))
	log.Printf("certificate authority %s", ssh.FingerprintSHA256(caPub))

	users, err := sshx.LoadAuthorizedKeys(*usersFile)
	if err != nil {
		log.Fatalf("users: %v", err)
	}
	book, err := openLedger(*ledgerPath)
	if err != nil {
		log.Fatalf("labels: %v", err)
	}
	seen, err := openSightings(*seenFile)
	if err != nil {
		log.Fatalf("last-seen: %v", err)
	}
	log.Printf("loaded %d user key(s)", len(users))

	// Agents pin the authority rather than a key, so a proxy rebuilt on new
	// hardware with a new host key is accepted without touching a target. The
	// primary signs its own host key afresh at every start, with no
	// principals, so it is valid at whatever address agents reach it on; a
	// standby presents the certificate the primary issued it once.
	var certSigner ssh.Signer
	if ca != nil {
		cert, err := sshx.SignCert(ca, signer.PublicKey(), ssh.HostCert, "multissh-proxy", nil, 0)
		if err != nil {
			log.Fatalf("host certificate: %v", err)
		}
		certSigner, err = ssh.NewCertSigner(cert, signer)
		if err != nil {
			log.Fatalf("host certificate: %v", err)
		}
	} else {
		cert, err := sshx.LoadCert(*hostCert)
		if err != nil {
			log.Fatalf("host certificate: %v (a standby needs one issued by the primary)", err)
		}
		certSigner, err = ssh.NewCertSigner(cert, signer)
		if err != nil {
			log.Fatalf("host certificate: %v", err)
		}
	}
	agentHostSigner := certSigner

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

	certChecker := &ssh.CertChecker{
		IsUserAuthority: func(auth ssh.PublicKey) bool { return sshx.SameKey(auth, caPub) },
	}

	agentCfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			// Only a certificate we signed. CheckCert verifies the signature,
			// the validity window, and that the name the agent claims is one
			// of the principals we put in the certificate -- so names remain
			// ours to assign without our storing them anywhere.
			cert, ok := key.(*ssh.Certificate)
			if !ok {
				return nil, fmt.Errorf("agents must present a certificate")
			}
			if err := certChecker.CheckCert(c.User(), cert); err != nil {
				return nil, fmt.Errorf("certificate rejected: %w", err)
			}
			if !sshx.IsCanonicalName(c.User()) {
				return nil, fmt.Errorf("agents must connect under their canonical name")
			}
			// Principals are [canonical, friendly]; the friendly one is a
			// request, granted later only if unclaimed.
			ext := map[string]string{
				"canonical": c.User(),
				"fp":        ssh.FingerprintSHA256(cert.Key),
			}
			for _, p := range cert.ValidPrincipals {
				if !sshx.IsCanonicalName(p) {
					ext["friendly"] = p
					break
				}
			}
			return &ssh.Permissions{Extensions: ext}, nil
		},
	}
	// Agents verify us through the authority, so present the certificate.
	agentCfg.AddHostKey(agentHostSigner)

	agentHandler := func(c *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
		handleAgent(reg, book, seen, c, chans, reqs)
	}
	// The installer is only offered when the proxy knows the address targets
	// should use, since it has to bake that into the script it generates.
	var extra *httpExtras
	if *publicURL != "" {
		if ca == nil {
			log.Print("standby: serving no installer, since enrolment needs the private authority key")
		} else {
			pws, err := loadPasswords(*pwFile)
			if err != nil {
				log.Fatalf("passwords: %v", err)
			}
			if len(pws) == 0 {
				log.Printf("no enrolment passwords yet; create one with -add-password")
			}
			dist := newDistributor(*distDir)
			hashes, version := dist.snapshot()
			log.Printf("installer at %s/install.sh, %d build(s), version %s", *publicURL, len(hashes), version)
			extra = &httpExtras{
				dist:    dist,
				baseURL: strings.TrimSuffix(*publicURL, "/"),
				proxies: agentURLs(*publicURL, *wsPath),
				caPub:   caPub,
				enrol: &enroller{
					ca:        ca,
					passwords: pws,
					usersFile: *usersFile,
					proxies:   agentURLs(*publicURL, *wsPath),
					limit:     newLimiter(enrolRateWindow, enrolRateBurst),
					validity:  *enrolValid,
				},
			}
		}
	}

	go serveWebSocket(*wsAddr, *wsPath, "agent", agentCfg, agentHandler, extra)

	serve(*userAddr, "user", userCfg, func(c *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
		handleUser(reg, seen, c, chans, reqs)
	})
}

// issueCert signs a public key and writes "<path>-cert.pub" beside it, the
// same naming OpenSSH uses.
// issueProxyHostCert certifies a standby proxy's host key. No principals, so
// it is valid at whatever address agents reach that standby on, matching what
// the primary signs for itself. A standby needs this once and never holds
// private authority material.
func issueProxyHostCert(ca ssh.Signer, pubPath string) error {
	pub, err := sshx.LoadPublicKey(pubPath)
	if err != nil {
		return err
	}
	cert, err := sshx.SignCert(ca, pub, ssh.HostCert, "multissh-proxy-standby", nil, 0)
	if err != nil {
		return err
	}
	out := strings.TrimSuffix(pubPath, ".pub") + "-cert.pub"
	if err := sshx.WriteCert(out, cert); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n  a standby presenting this is trusted by every agent\n  authority  %s\n",
		out, ssh.FingerprintSHA256(ca.PublicKey()))
	return nil
}

// issueCert enrols one machine. It signs the agent's identity key so the proxy
// can authenticate it later without remembering anything, and derives the
// canonical name from the agent's *host* key so that name commits to the key
// the user's client will verify.
//
// The host key is deliberately not signed. Were the proxy to certify target
// host keys, a compromised proxy could mint one for a machine it controls and
// impersonate a target to you, with no warning from your client. Leaving
// targets on trust-on-first-use keeps the proxy out of that trust chain.
func issueCert(ca ssh.Signer, idPath, hostPath, label string, ledgerPath string, validity time.Duration) error {
	if label == "" {
		return fmt.Errorf("-sign-label is required")
	}
	if hostPath == "" {
		return fmt.Errorf("-sign-host-key is required: the canonical name is derived from it")
	}

	idPub, err := sshx.LoadPublicKey(idPath)
	if err != nil {
		return err
	}
	hostPub, err := sshx.LoadPublicKey(hostPath)
	if err != nil {
		return err
	}

	canonical, err := sshx.CanonicalName(label, hostPub)
	if err != nil {
		return err
	}

	// Both names travel in the certificate; the proxy grants the friendly one
	// at connect time only if no other machine holds it.
	cert, err := sshx.SignCert(ca, idPub, ssh.UserCert, canonical,
		[]string{canonical, label}, validity)
	if err != nil {
		return err
	}

	out := strings.TrimSuffix(idPath, ".pub") + "-cert.pub"
	if err := sshx.WriteCert(out, cert); err != nil {
		return err
	}

	expiry := "never expires"
	if validity > 0 {
		expiry = "expires " + time.Unix(int64(cert.ValidBefore), 0).Format(time.RFC3339)
	}
	fmt.Printf("wrote %s\n  canonical  %s\n  friendly   %s (granted only if unclaimed)\n  authority  %s\n  %s\n",
		out, canonical, label, ssh.FingerprintSHA256(ca.PublicKey()), expiry)
	return nil
}

type connHandler func(*ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request)

// takeConn runs the SSH server handshake over any transport: a plain socket,
// or a WebSocket presented as a net.Conn.
func takeConn(nc net.Conn, kind string, cfg *ssh.ServerConfig, h connHandler) {
	defer nc.Close()

	peer := sourceHost(nc.RemoteAddr())
	if authFailures.count(peer) >= authFailBurst {
		log.Printf("%s refusing %s: too many recent auth failures", kind, peer)
		return
	}

	// Bound the handshake, or a client that connects and never speaks pins a
	// goroutine and a socket indefinitely. OpenSSH calls this LoginGraceTime.
	nc.SetDeadline(time.Now().Add(handshakeTimeout))
	conn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		authFailures.allow(peer)
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
// httpExtras are the enrolment routes, served beside the agent websocket on
// the same listener so one reverse-proxy entry covers everything.
type httpExtras struct {
	dist    *distributor
	enrol   *enroller
	baseURL string
	proxies []string
	caPub   ssh.PublicKey
}

// agentURLs turns the public https:// address into the wss:// the agent dials.
func agentURLs(public, path string) []string {
	u := strings.TrimSuffix(public, "/")
	u = strings.Replace(u, "https://", "wss://", 1)
	u = strings.Replace(u, "http://", "ws://", 1)
	return []string{u + path}
}

func serveWebSocket(addr, path, kind string, cfg *ssh.ServerConfig, h connHandler, extra *httpExtras) {
	mux := http.NewServeMux()
	if extra != nil {
		mux.HandleFunc("/install.sh", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/x-shellscript")
			io.WriteString(w, installScript(extra.dist, extra.caPub, extra.baseURL, extra.proxies))
		})
		mux.HandleFunc("/install.ps1", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			io.WriteString(w, installPowerShell(extra.dist, extra.caPub, extra.baseURL, extra.proxies))
		})
		mux.HandleFunc("/dist/", extra.dist.serveBinary)
		mux.HandleFunc("/enroll", extra.enrol.handle)
	}
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
func handleAgent(reg *registry, book *ledger, seen *sightings, conn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	canonical := conn.Permissions.Extensions["canonical"]
	friendly := conn.Permissions.Extensions["friendly"]
	fp := conn.Permissions.Extensions["fp"]

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

	// The canonical name is derived from the agent's own host key, so a clash
	// here means someone ground a key or replayed a certificate. Refuse.
	if err := reg.add(canonical, conn, fp); err != nil {
		log.Printf("REFUSING agent from %s: %v; arriving key %s", conn.RemoteAddr(), err, fp)
		conn.Close()
		return
	}
	names := []string{canonical}

	// The friendly name is convenience, and the only ambiguous surface. Serve
	// it only when this machine owns it; otherwise the target stays reachable
	// canonically and the clash is reported rather than silently resolved.
	if friendly != "" {
		switch {
		case !book.claim(friendly, fp):
			log.Printf("agent %q wanted the name %q, which belongs to another machine; "+
				"it is reachable canonically only", canonical, friendly)
		default:
			if err := reg.add(friendly, conn, fp); err != nil {
				log.Printf("agent %q could not take %q: %v", canonical, friendly, err)
			} else {
				names = append(names, friendly)
			}
		}
	}

	seen.seen(canonical)
	log.Printf("agent registered from %s as %s", conn.RemoteAddr(), strings.Join(names, " and "))

	// The agent sends its own keepalives, but nothing here would notice them
	// stopping. Without probing from this side, a half-open connection (a
	// sleeping laptop) stays registered until the kernel gives up on the TCP
	// session, which can take many minutes, and the name meanwhile accepts
	// connections that hang.
	stop := make(chan struct{})
	defer close(stop)
	go probeLiveness(conn, canonical, stop)

	conn.Wait() // blocks until the connection dies
	seen.seen(canonical)
	for _, n := range names {
		reg.remove(n, conn)
	}
	log.Printf("agent %q disconnected", canonical)
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

func handleUser(reg *registry, seen *sightings, conn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
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
			go serveListing(reg, seen, nc)
		case "direct-tcpip":
			go serveJump(reg, conn, nc)
		default:
			log.Printf("  refused channel %q", nc.ChannelType())
			nc.Reject(ssh.UnknownChannelType, "not supported")
		}
	}
}

// serveListing answers a plain `ssh proxy` with the available targets.
func serveListing(reg *registry, seen *sightings, nc ssh.NewChannel) {
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
			list := reg.listing()
			fmt.Fprintf(ch, "\r\n multiSSH proxy\r\n\r\n")
			if len(list) == 0 {
				fmt.Fprintf(ch, " no targets currently registered\r\n")
			} else {
				fmt.Fprintf(ch, " registered targets (%d):\r\n\r\n", len(list))
				for _, t := range list {
					fmt.Fprintf(ch, "   %-20s %s\r\n", t[0], t[1])
				}
				pick := list[0][0]
				if pick == "" {
					pick = list[0][1]
				}
				fmt.Fprintf(ch, "\r\n connect with:  ssh -J <thisproxy> user@%s\r\n", pick)
			}

			// Machines that have registered before but are not here now. A
			// rescue tool is most likely to fail by quietly decaying, so an
			// absence should be visible without being asked for.
			online := map[string]bool{}
			for _, t := range list {
				online[t[1]] = true
			}
			var missing []string
			for _, k := range seen.known() {
				if !online[k.Name] {
					missing = append(missing, fmt.Sprintf("   %-24s last seen %s", k.Name, ago(k.When)))
				}
			}
			if len(missing) > 0 {
				fmt.Fprintf(ch, "\r\n not connected (%d):\r\n\r\n", len(missing))
				for _, m := range missing {
					fmt.Fprintf(ch, "%s\r\n", m)
				}
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

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
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
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

// slots bounds how many connections may be in flight on one listener.
//
// Every accepted connection costs a goroutine, a socket and, once
// authenticated, whatever the session holds. Nothing capped that, so a single
// user key -- or anyone at all, since an unauthenticated connection is
// accepted before it proves anything -- could open sockets until the proxy ran
// out of memory and took every registered target down with it.
//
// A counting semaphore rather than a rate limit: the concern is how many exist
// at once, not how fast they arrive. The two limits complement each other,
// which is why both are here.
type slots struct {
	ch   chan struct{}
	kind string
}

func newSlots(n int, kind string) *slots {
	if n <= 0 {
		return nil // unlimited
	}
	return &slots{ch: make(chan struct{}, n), kind: kind}
}

// take reports whether a slot was free. It never waits: a caller made to queue
// would hold the socket open anyway, which is the resource being protected.
func (s *slots) take() bool {
	if s == nil {
		return true
	}
	select {
	case s.ch <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *slots) give() {
	if s == nil {
		return
	}
	<-s.ch
}

func (s *slots) inUse() int {
	if s == nil {
		return 0
	}
	return len(s.ch)
}

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
// It is also the handle revocation works on, which is why it is shown to the
// user rather than kept in the log.
type registration struct {
	conn     ssh.Conn
	fp       string
	proto    int
	build    string
	platform string
	// hostFP is the fingerprint of the agent's *host* key, as ssh prints it on
	// first connect. Reported by the agent and checked against the canonical
	// name before it is stored, so it can be compared with what a client is
	// being offered.
	hostFP string
}

// target is one row of the listing `ssh proxy` prints.
type target struct {
	Friendly  string
	Canonical string
	Proto     int
	FP        string
	Build     string
	Platform  string
	HostFP    string
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
func (r *registry) add(name string, conn ssh.Conn, fp string, proto int, build, platform string) error {
	r.mu.Lock()
	old, existed := r.m[name]
	if existed && old.fp != fp {
		r.mu.Unlock()
		return fmt.Errorf("%q is held by a different machine (%s)", name, old.fp)
	}
	r.m[name] = registration{conn: conn, fp: fp, proto: proto, build: build, platform: platform}
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
func (r *registry) listing() []target {
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

	out := make([]target, 0, len(canonical))
	for _, c := range canonical {
		reg := r.m[c]
		out = append(out, target{
			Friendly:  friendly[reg.conn],
			Canonical: c,
			Proto:     reg.proto,
			FP:        reg.fp,
			Build:     reg.build,
			Platform:  reg.platform,
			HostFP:    reg.hostFP,
		})
	}
	return out
}

// setHostFP records the agent's host key fingerprint against every name that
// connection holds. It arrives as a separate request after registration, so it
// cannot be set when the entry is created.
func (r *registry) setHostFP(conn ssh.Conn, fp string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, reg := range r.m {
		if reg.conn == conn {
			reg.hostFP = fp
			r.m[name] = reg
		}
	}
}

// connections returns every distinct live agent connection with its
// fingerprint, so a sweep (revocation, counting) does not see a machine twice
// for holding two names.
func (r *registry) connections() map[ssh.Conn]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[ssh.Conn]string, len(r.m))
	for _, reg := range r.m {
		out[reg.conn] = reg.fp
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
		revFile    = flag.String("revoked", "revoked_keys", "barred agent identity fingerprints; NOT advisory, back this up")
		distDir    = flag.String("dist", "dist", "directory of agent builds named <os>-<arch>")
		publicURL  = flag.String("public-url", "", "how targets reach this proxy, e.g. https://multissh.example.com; enables the installer")
		enrolValid = flag.Duration("enrol-validity", 0, "lifetime of issued certificates; 0 never expires")
		sshHost    = flag.String("ssh-host", "", "how users reach the ssh listener, e.g. proxy.example.com -p 2022; shown on the landing page")
		staleAfter = flag.Duration("stale-after", 30*24*time.Hour, "flag targets not seen for this long as stale")
		// The default accepts everything, including agents installed before
		// the version handshake existed. Refusing old agents strands machines
		// nobody is going to walk over to, so it stays a decision taken
		// deliberately here rather than one a proxy upgrade makes for you.
		maxUsers  = flag.Int("max-user-connections", 64, "connections in flight on the user listener; 0 is unlimited")
		maxAgents = flag.Int("max-agent-connections", 2048, "connections in flight on the agent listener; 0 is unlimited")
		minProto  = flag.Int("min-agent-protocol", sshx.LegacyProtocol, "refuse agents older than this protocol version")

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
		revoke        = flag.String("revoke", "", "bar this agent identity fingerprint (SHA256:...), then exit")
		unrevoke      = flag.String("unrevoke", "", "lift a revocation, then exit")
		revokeNote    = flag.String("revoke-note", "", "why, recorded beside the fingerprint")
		listRevoked   = flag.Bool("list-revoked", false, "show revoked fingerprints and exit")
		forget        = flag.String("forget", "", "drop a target from the friendly-name ledger and the last-seen record, then exit")
	)
	flag.Parse()
	log.SetFlags(log.Ltime)

	// Revocation is handled before anything else touches a key. It needs no
	// authority at all -- a standby can revoke too, and should be able to,
	// since it is what still works when the primary is gone -- and running it
	// after the block below would create a certificate authority as a side
	// effect of listing revoked keys.
	if *listRevoked || *revoke != "" || *unrevoke != "" {
		if err := manageRevocations(*revFile, *revoke, *unrevoke, *listRevoked, *revokeNote, *ledgerPath); err != nil {
			log.Fatalf("revoke: %v", err)
		}
		return
	}

	// Forgetting a target needs no authority either, and is the counterpart to
	// uninstalling an agent: the machine is gone, but the proxy still holds its
	// friendly name and its history. Leaving the name bound is the trap --
	// reinstalling generates a new identity key, the old binding refuses it,
	// and the machine returns reachable only under its canonical name.
	if *forget != "" {
		book, err := openLedger(*ledgerPath)
		if err != nil {
			log.Fatalf("labels: %v", err)
		}
		seen, err := openSightings(*seenFile)
		if err != nil {
			log.Fatalf("last-seen: %v", err)
		}
		var did []string
		if book.forget(*forget) {
			did = append(did, "released the friendly name")
		}
		if seen.forget(*forget) {
			did = append(did, "dropped it from the last-seen record")
		}
		// A canonical name is what the listing shows for a disconnected
		// target, but the ledger is keyed by friendly name, so try both ends.
		if base, _, ok := strings.Cut(*forget, "."); ok && book.forget(base) {
			did = append(did, fmt.Sprintf("released the friendly name %q", base))
		}
		if len(did) == 0 {
			fmt.Printf("nothing known about %q\n", *forget)
			return
		}
		for _, d := range did {
			fmt.Printf("  %s\n", d)
		}
		fmt.Printf("\nreload the proxy for this to take effect on the running one:\n")
		fmt.Printf("  systemctl reload multissh-proxy\n")
		return
	}

	// Enrolment passwords need no authority either, and for the same reason
	// must be handled before one is loaded: LoadOrCreateHostKey *creates* the
	// key when it is absent, so running this from the wrong directory used to
	// leave behind a stray file named proxy_ca_key that was not the authority
	// at all. For a tool whose whole backup story is "keep proxy_ca_key", a
	// decoy of that name is worse than untidy.
	if *listPasswords || *addPassword != "" || *delPassword != "" {
		if err := managePasswords(*pwFile, *addPassword, *delPassword, *listPasswords, *pwValidity); err != nil {
			log.Fatalf("passwords: %v", err)
		}
		return
	}

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
	log.Printf("running as %s, build %s", role, describeBuild(ownBuildID()))
	log.Printf("proxy host key %s", ssh.FingerprintSHA256(signer.PublicKey()))
	log.Printf("certificate authority %s", ssh.FingerprintSHA256(caPub))

	// Held behind a pointer so SIGHUP can swap it. Authorising a person should
	// not cost every agent its connection, which a restart would.
	var users atomic.Pointer[map[string]bool]
	loadUsers := func() (int, error) {
		u, err := sshx.LoadAuthorizedKeys(*usersFile)
		if err != nil {
			return 0, err
		}
		users.Store(&u)
		return len(u), nil
	}
	if _, err := loadUsers(); err != nil {
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
	revoked, err := openRevocations(*revFile)
	if err != nil {
		log.Fatalf("revoked: %v", err)
	}
	log.Printf("loaded %d user key(s), %d revoked agent key(s)", len(*users.Load()), revoked.count())

	// Silent decay is this tool's real failure mode: an agent that stopped
	// months ago is otherwise discovered during the emergency it existed for.
	// Say so at startup, where it is seen without being asked for.
	if stale := seen.staleSince(time.Now().Add(-*staleAfter)); len(stale) > 0 {
		log.Printf("WARNING: %d target(s) not seen in %s:", len(stale), *staleAfter)
		for _, s := range stale {
			log.Printf("    %s  last seen %s", s.Name, ago(s.When))
		}
	}

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
	go revoked.watch(reg)

	// Built whether or not the installer is served: the listing uses it to say
	// which targets are running a binary this proxy still hands out, and that
	// is worth knowing even on a standby that enrols nobody.
	dist := newDistributor(*distDir)

	userCfg := &ssh.ServerConfig{
		ServerVersion: sshx.ProxyVersion(),
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if !(*users.Load())[string(key.Marshal())] {
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
		ServerVersion: sshx.ProxyVersion(),
		// An agent refused for its protocol version would otherwise see only
		// "authentication failed", on a machine nobody is standing next to.
		// This puts the reason in the agent's own log.
		//
		// Only the version case can be reported this way: the banner is sent
		// before any key is offered, so revocation -- a fact about the key --
		// is not yet knowable here. That refusal is named in the proxy's log
		// instead, which is where whoever revoked the machine is looking.
		BannerCallback: func(c ssh.ConnMetadata) string {
			if v := sshx.ParseAgentVersion(c.ClientVersion()); v < *minProto {
				return fmt.Sprintf("this proxy needs agent protocol %s or newer; you speak %s. Re-run the installer to update.\n",
					sshx.DescribeProtocol(*minProto), sshx.DescribeProtocol(v))
			}
			return ""
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			proto := sshx.ParseAgentVersion(c.ClientVersion())
			if proto < *minProto {
				return nil, fmt.Errorf("agent protocol %s is below the minimum %s",
					sshx.DescribeProtocol(proto), sshx.DescribeProtocol(*minProto))
			}
			// Only a certificate we signed: the signature is what carries the
			// name, which is why this proxy needs no list of machines.
			//
			// It must be Authenticate, never CheckCert. CheckCert verifies the
			// signature against cert.SignatureKey -- the authority named
			// INSIDE the certificate, chosen by whoever presents it -- and
			// never consults IsUserAuthority or the certificate type. Setting
			// IsUserAuthority and then calling CheckCert reads as correct and
			// checks nothing at all: any host able to reach this endpoint
			// could mint its own authority, derive a real canonical name from
			// a host key it held, self-sign that name, and register. It would
			// then pass the first-connect fingerprint check too, because the
			// name really was derived from the key it serves.
			cert, ok := key.(*ssh.Certificate)
			if !ok {
				return nil, fmt.Errorf("agents must present a certificate")
			}
			// Revocation is checked before the certificate, and on the key
			// inside it rather than on the certificate: re-issuing a
			// certificate must not undo a revocation, and re-enrolling the
			// same machine reuses the same identity key.
			fp := ssh.FingerprintSHA256(cert.Key)
			if reason, yes := revoked.revoked(fp); yes {
				log.Printf("REFUSING revoked agent %s from %s (%s)", fp, c.RemoteAddr(), reason)
				return nil, fmt.Errorf("this identity key is revoked")
			}
			// Authenticate performs everything CheckCert does, and first checks
			// that the signing authority is ours and that this is a user
			// certificate rather than a host one. Without the type check, the
			// host certificate a standby proxy carries -- issued with no
			// principals, so valid for every name -- would itself be a
			// permanent credential to register as any agent.
			if _, err := certChecker.Authenticate(c, key); err != nil {
				return nil, fmt.Errorf("certificate rejected: %w", err)
			}
			if !sshx.IsCanonicalName(c.User()) {
				return nil, fmt.Errorf("agents must connect under their canonical name")
			}
			// Principals are [canonical, friendly]; the friendly one is a
			// request, granted later only if unclaimed.
			ext := map[string]string{
				"canonical": c.User(),
				"fp":        fp,
				"proto":     strconv.Itoa(proto),
				"build":     sshx.ParseAgentBuild(c.ClientVersion()),
				"platform":  sshx.ParseAgentPlatform(c.ClientVersion()),
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
			hashes, version := dist.snapshot()
			log.Printf("installer at %s/install.sh, %d build(s), version %s", *publicURL, len(hashes), version)
			extra = &httpExtras{
				dist:     dist,
				userHost: *sshHost,
				baseURL:  strings.TrimSuffix(*publicURL, "/"),
				proxies:  agentURLs(*publicURL, *wsPath),
				caPub:    caPub,
				enrol: &enroller{
					ca:        ca,
					usersFile: *usersFile,
					proxies:   agentURLs(*publicURL, *wsPath),
					limit:     newLimiter(enrolRateWindow, enrolRateBurst),
					validity:  *enrolValid,
					revoked:   revoked,
				},
			}
			extra.enrol.passwords.Store(&pws)
		}
	}

	// SIGHUP re-reads everything that can change without a restart. Restarting
	// costs every agent its connection, which is an absurd price for adding a
	// key -- and for enrolment passwords it was worse than a price: read only
	// at startup, withdrawing one wrote the file and changed nothing, so a
	// credential you believed you had revoked went on working.
	//
	// Each reload keeps the previous value when the file cannot be read. A
	// typo in one file must not empty the set of people who can log in, nor
	// silently disable enrolment.
	go func() {
		hup := make(chan os.Signal, 1)
		signal.Notify(hup, syscall.SIGHUP)
		for range hup {
			dist.scan()
			hashes, version := dist.snapshot()
			log.Printf("reloaded %d agent build(s), version %s", len(hashes), version)

			if n, err := loadUsers(); err != nil {
				log.Printf("reload: users: %v (keeping the previous %d)", err, len(*users.Load()))
			} else {
				log.Printf("reloaded %d user key(s)", n)
			}

			if err := book.reload(); err != nil {
				log.Printf("reload: labels: %v (keeping the previous set)", err)
			}
			if err := seen.reload(); err != nil {
				log.Printf("reload: last-seen: %v (keeping the previous set)", err)
			}

			if extra != nil {
				if n, err := extra.enrol.reload(*pwFile); err != nil {
					log.Printf("reload: passwords: %v (keeping the previous set)", err)
				} else {
					log.Printf("reloaded %d enrolment password(s)", n)
				}
			}
		}
	}()

	// The agent limit is generous and the user limit is not: agents are the
	// population this exists to serve and each holds one long-lived
	// connection, while user connections are few, short, and the cheaper thing
	// to lose if someone is being a nuisance.
	agentSlots := newSlots(*maxAgents, "agent")
	userSlots := newSlots(*maxUsers, "user")

	go serveWebSocket(*wsAddr, *wsPath, "agent", agentCfg, agentHandler,
		serveHealth(reg, seen, revoked, dist, *staleAfter), extra, agentSlots)

	serve(*userAddr, "user", userCfg, func(c *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
		handleUser(reg, seen, dist, *staleAfter, c, chans, reqs)
	}, userSlots)
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
func takeConn(nc net.Conn, kind string, cfg *ssh.ServerConfig, h connHandler, limit *slots) {
	defer nc.Close()

	if !limit.take() {
		log.Printf("%s refusing %s: %d connections already in flight", kind, nc.RemoteAddr(), limit.inUse())
		return
	}
	defer limit.give()

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

func serve(addr, kind string, cfg *ssh.ServerConfig, h connHandler, limit *slots) {
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
		go takeConn(nc, kind, cfg, h, limit)
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
	dist     *distributor
	enrol    *enroller
	userHost string
	baseURL  string
	proxies  []string
	caPub    ssh.PublicKey
}

// agentURLs turns the public https:// address into the wss:// the agent dials.
func agentURLs(public, path string) []string {
	u := strings.TrimSuffix(public, "/")
	u = strings.Replace(u, "https://", "wss://", 1)
	u = strings.Replace(u, "http://", "ws://", 1)
	return []string{u + path}
}

// serveHealth answers monitoring without authentication, so it must give away
// nothing. Counts only: target names and fingerprints are deliberately absent,
// because this shares a public hostname with the installer and knowing which
// machines exist is itself worth something to an attacker. Names live in the
// authenticated listing.
func serveHealth(reg *registry, seen *sightings, revoked *revocations, dist *distributor, staleAfter time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list := reg.listing()
		known := seen.known()
		stale := seen.staleSince(time.Now().Add(-staleAfter))

		outdated := 0
		if current, know := dist.builds(), dist.serving(); know {
			for _, t := range list {
				if t.Build != "" && !current[t.Build] {
					outdated++
				}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		// The proxy's own build, so a deployment can be confirmed from the
		// outside rather than taken on trust. Agents report theirs; this is
		// the same question asked of the thing serving the answer.
		json.NewEncoder(w).Encode(struct {
			Status     string `json:"status"`
			Connected  int    `json:"connected"`
			Known      int    `json:"known"`
			Stale      int    `json:"stale"`
			StaleAfter string `json:"stale_after"`
			Outdated   int    `json:"outdated"`
			Revoked    int    `json:"revoked"`
			Protocol   int    `json:"protocol"`
			Build      string `json:"build"`
		}{
			Status:     "ok",
			Connected:  len(list),
			Known:      len(known),
			Stale:      len(stale),
			StaleAfter: staleAfter.String(),
			Outdated:   outdated,
			Revoked:    revoked.count(),
			Protocol:   sshx.ProtocolVersion,
			Build:      ownBuildID(),
		})
	}
}

func serveWebSocket(addr, path, kind string, cfg *ssh.ServerConfig, h connHandler, health http.HandlerFunc, extra *httpExtras, limit *slots) {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", health)
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
		mux.HandleFunc("/", serveLanding(extra.dist, extra.baseURL, extra.userHost))
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
		takeConn(websocket.NetConn(context.Background(), c, websocket.MessageBinary), kind, cfg, h, limit)
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
	proto, _ := strconv.Atoi(conn.Permissions.Extensions["proto"])
	build := conn.Permissions.Extensions["build"]
	platform := conn.Permissions.Extensions["platform"]

	// Answer keepalives, accept a host key report, refuse everything else --
	// tcpip-forward included.
	go func() {
		for r := range reqs {
			if r.Type == sshx.HostKeyRequestType {
				// Believed only if it matches the name the agent is registered
				// under. The name is derived from this very key, so a report
				// that does not reproduce it is either a broken agent or one
				// claiming to be a machine it is not.
				if key := sshx.ParseHostKeyReport(r.Payload); key == nil {
					log.Printf("agent %q sent an unreadable host key report", canonical)
				} else if !sshx.VerifyCanonicalName(canonical, key) {
					log.Printf("REFUSING host key from agent %q: it does not match that name", canonical)
				} else {
					reg.setHostFP(conn, ssh.FingerprintSHA256(key))
				}
				if r.WantReply {
					r.Reply(true, nil)
				}
				continue
			}
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
	if err := reg.add(canonical, conn, fp, proto, build, platform); err != nil {
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
			if err := reg.add(friendly, conn, fp, proto, build, platform); err != nil {
				log.Printf("agent %q could not take %q: %v", canonical, friendly, err)
			} else {
				names = append(names, friendly)
			}
		}
	}

	seen.seen(canonical)
	// The fingerprint is logged on the way in, not only when something goes
	// wrong: it is the handle -revoke takes, so it has to be obtainable from a
	// machine that is behaving normally.
	log.Printf("agent registered from %s as %s, protocol %s, build %s, identity %s",
		conn.RemoteAddr(), strings.Join(names, " and "), sshx.DescribeProtocol(proto),
		describeBuild(build), fp)

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

func handleUser(reg *registry, seen *sightings, dist *distributor, staleAfter time.Duration, conn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
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
			go serveListing(reg, seen, dist, staleAfter, nc)
		case "direct-tcpip":
			go serveJump(reg, conn, nc)
		default:
			log.Printf("  refused channel %q", nc.ChannelType())
			nc.Reject(ssh.UnknownChannelType, "not supported")
		}
	}
}

// serveListing answers a plain `ssh proxy` with the available targets.
func serveListing(reg *registry, seen *sightings, dist *distributor, staleAfter time.Duration, nc ssh.NewChannel) {
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	defer ch.Close()
	staleBefore := time.Now().Add(-staleAfter)
	current := dist.builds()
	knowBuilds := dist.serving()

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
			online := map[string]bool{}
			for _, t := range list {
				online[t.Canonical] = true
			}
			var missing []sighting
			for _, k := range seen.known() {
				if !online[k.Name] {
					missing = append(missing, k)
				}
			}

			// Widths come from the data. Fixed ones truncated nothing but
			// misaligned everything the moment a name outgrew them, which for
			// a canonical name -- a label plus a twelve-character hash -- is
			// most of the time.
			nameW, canonW, platW := len("name"), len("address"), 0
			for _, t := range list {
				nameW = max(nameW, len(t.Friendly))
				canonW = max(canonW, len(t.Canonical))
				platW = max(platW, len(t.Platform))
			}

			fmt.Fprintf(ch, "\r\n multiSSH proxy\r\n")

			if len(list) == 0 {
				fmt.Fprintf(ch, "\r\n no targets are connected right now.\r\n")
			} else {
				fmt.Fprintf(ch, "\r\n ONLINE (%d)\r\n\r\n", len(list))
				for _, t := range list {
					state := buildState(t.Build, current, knowBuilds)
					fmt.Fprintf(ch, "   %-*s  %-*s  %-*s  %s %s\r\n",
						nameW, t.Friendly, canonW, t.Canonical,
						platW, t.Platform, sshx.DescribeProtocol(t.Proto), state)
					// Two different keys, so both are named. Leaving them
					// unlabelled invited exactly the reading that they were
					// the same thing, or that one was checkable against the
					// other.
					if t.HostFP != "" {
						fmt.Fprintf(ch, "       host key  %s\r\n", t.HostFP)
					}
					fmt.Fprintf(ch, "       identity  %s\r\n", t.FP)
				}
			}

			if len(missing) > 0 {
				fmt.Fprintf(ch, "\r\n NOT CONNECTED (%d)\r\n\r\n", len(missing))
				anyStale := false
				for _, m := range missing {
					mark := " "
					if m.When.Before(staleBefore) {
						mark, anyStale = "!", true
					}
					fmt.Fprintf(ch, "   %s %-*s  last seen %s\r\n", mark, canonW, m.Name, ago(m.When))
				}
				if anyStale {
					fmt.Fprintf(ch, "\r\n   ! not seen in over %s\r\n", staleAfter)
				}
			}

			if len(list) > 0 {
				pick := list[0].Friendly
				if pick == "" {
					pick = list[0].Canonical
				}
				fmt.Fprintf(ch, "\r\n CONNECT\r\n\r\n")
				fmt.Fprintf(ch, "   ssh -J <thisproxy> user@%s\r\n", pick)
				fmt.Fprintf(ch, "\r\n   The username is ignored. On first connect ssh shows the target's\r\n")
				fmt.Fprintf(ch, "   host key fingerprint and offers a (yes/no/[fingerprint]) prompt --\r\n")
				fmt.Fprintf(ch, "   paste the host key above into it and ssh checks it for you.\r\n")
				fmt.Fprintf(ch, "\r\n   'identity' is a different key: the handle for -revoke.\r\n")
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

// ownBuildID hashes this executable, so `push.sh` can confirm from /healthz
// that the binary it shipped is the one now running, rather than reporting
// success because a command exited zero.
var ownBuildID = sync.OnceValue(func() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	id, err := sshx.BuildIDOfFile(exe)
	if err != nil {
		return ""
	}
	return id
})

// describeBuild renders a build ID for a log line.
func describeBuild(build string) string {
	if build == "" {
		return "unknown"
	}
	return build
}

// buildState says whether a target is running a binary this proxy still serves,
// which is the question an upgrade sweep asks.
//
// Silence when the proxy serves no builds: with nothing to compare against
// every agent would be labelled outdated, which is worse than saying nothing.
// Silence too when the agent sent no build ID, since that means it predates
// build reporting rather than that it is behind.
func buildState(build string, current map[string]bool, know bool) string {
	switch {
	case !know || build == "":
		return ""
	case current[build]:
		return "current"
	default:
		return "OUTDATED"
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
		ch, reqs, err := agent.OpenChannel(sshx.TunnelChannelType, sshx.MarshalTunnelRequest())
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

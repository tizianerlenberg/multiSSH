package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"golang.org/x/crypto/ssh"
	"multissh/internal/sshx"
)

// An agent must present a certificate signed by THIS proxy's authority. The
// check that enforces that is the whole reason the proxy needs no list of
// registered machines: the signature is what carries the name.
//
// x/crypto makes this easy to get wrong. CertChecker.CheckCert verifies the
// signature against cert.SignatureKey -- the authority named inside the
// certificate, which the presenter chose. Only CertChecker.Authenticate
// consults IsUserAuthority and the certificate type. Calling the former and
// setting the latter's callback looks correct and checks nothing: any host that
// can reach the agent endpoint self-signs whatever name it likes.
func TestAgentWithAForeignCAIsRefused(t *testing.T) {
	f := setup(t)
	f.startProxy()

	// An attacker's own authority, identity and host key. None of these has
	// ever been near the proxy.
	_, caPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	foreignCA, err := ssh.NewSignerFromKey(caPriv)
	if err != nil {
		t.Fatal(err)
	}
	_, idPriv, _ := ed25519.GenerateKey(rand.Reader)
	identity, err := ssh.NewSignerFromKey(idPriv)
	if err != nil {
		t.Fatal(err)
	}
	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}

	// The name is derived honestly from a host key the attacker holds, so the
	// proxy's own VerifyCanonicalName will accept it and the listing will show
	// a host key fingerprint matching what ssh prints on first connect. That is
	// what makes this worse than a plain bypass: it survives the eye-check.
	canonical, err := sshx.CanonicalName("laptop", hostSigner.PublicKey())
	if err != nil {
		t.Fatal(err)
	}

	cert, err := sshx.SignCert(foreignCA, identity.PublicKey(), ssh.UserCert,
		canonical, []string{canonical, "laptop"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	certSigner, err := ssh.NewCertSigner(cert, identity)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws://"+f.wsAddr+"/agent", nil)
	if err != nil {
		t.Fatalf("dialling the agent endpoint: %v", err)
	}
	raw := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
	defer raw.Close()

	conn, chans, reqs, err := ssh.NewClientConn(raw, f.wsAddr, &ssh.ClientConfig{
		User:            canonical,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		ClientVersion:   sshx.AgentVersion("deadbeefcafe", "linux"),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // the proxy's identity is not what is under test
		Timeout:         10 * time.Second,
	})
	if err == nil {
		conn.Close()
		go ssh.DiscardRequests(reqs)
		go func() {
			for nc := range chans {
				nc.Reject(ssh.Prohibited, "")
			}
		}()
		t.Fatalf("the proxy accepted a certificate signed by an authority it has never seen; "+
			"any host able to reach the agent endpoint can register as %q", canonical)
	}
	if !strings.Contains(err.Error(), "unable to authenticate") {
		t.Logf("refused, but not at authentication: %v", err)
	}
}

// A standby proxy holds a host certificate issued by the primary, deliberately
// with no principals so it is valid at whatever address agents reach it on.
// CheckCert treats an empty principal list as "valid for all" and never looks
// at the certificate type, so that certificate was also a permanent credential
// to register as any agent at all -- held by a machine documented as needing no
// private authority material.
func TestProxyHostCertificateIsNotAnAgentCredential(t *testing.T) {
	f := setup(t)
	f.startProxy()

	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	standbyHost, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatal(err)
	}
	writePub(t, f.dir+"/standby_host.pub", standbyHost.PublicKey())

	// Issued by the real proxy, exactly as a standby's is. The mode writes the
	// certificate beside the key rather than to stdout.
	f.run("-sign-proxy-host", "standby_host.pub")
	cert, err := sshx.LoadCert(f.dir + "/standby_host-cert.pub")
	if err != nil {
		t.Fatalf("reading the issued host certificate: %v", err)
	}
	if cert.CertType != ssh.HostCert {
		t.Fatalf("expected a host certificate, got type %d", cert.CertType)
	}
	if len(cert.ValidPrincipals) != 0 {
		t.Logf("note: the host certificate now carries principals %q", cert.ValidPrincipals)
	}

	certSigner, err := ssh.NewCertSigner(cert, standbyHost)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ws, _, err := websocket.Dial(ctx, "ws://"+f.wsAddr+"/agent", nil)
	if err != nil {
		t.Fatalf("dialling the agent endpoint: %v", err)
	}
	raw := websocket.NetConn(context.Background(), ws, websocket.MessageBinary)
	defer raw.Close()

	conn, _, _, err := ssh.NewClientConn(raw, f.wsAddr, &ssh.ClientConfig{
		User:            f.canonical, // any name at all: no principals means all of them
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(certSigner)},
		ClientVersion:   sshx.AgentVersion("deadbeefcafe", "linux"),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	})
	if err == nil {
		conn.Close()
		t.Fatal("a proxy host certificate was accepted as an agent credential")
	}
}

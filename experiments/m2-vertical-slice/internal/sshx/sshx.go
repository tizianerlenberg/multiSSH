// Package sshx holds the small pieces the proxy and the agent both need:
// on-disk key handling, an ssh.Channel -> net.Conn adapter, and a copy loop
// that respects SSH half-close.
package sshx

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// TunnelChannelType is the channel the proxy opens toward a registered agent.
const TunnelChannelType = "tunnel@multissh"

// DirectTCPIP is the RFC 4254 section 7.2 direct-tcpip payload. DestPort is
// fully client-controlled, so never act on it.
type DirectTCPIP struct {
	DestHost string
	DestPort uint32
	OrigHost string
	OrigPort uint32
}

// LoadOrCreateHostKey reads an ed25519 private key, generating and persisting
// one on first run. Written as PKCS#8 so ssh.ParsePrivateKey reads it back.
func LoadOrCreateHostKey(path string) (ssh.Signer, error) {
	if data, err := os.ReadFile(path); err == nil {
		return ssh.ParsePrivateKey(data)
	} else if !os.IsNotExist(err) {
		return nil, err
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

// LoadAuthorizedKeys returns the set of accepted public keys, indexed by their
// wire encoding. Blank lines and comments are skipped.
func LoadAuthorizedKeys(path string) (map[string]bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	set := make(map[string]bool)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			continue
		}
		set[string(pk.Marshal())] = true
	}
	return set, sc.Err()
}

// LoadAgentKeys parses "<label> <authorized_keys line>" and maps each public
// key to its label. The proxy assigns labels, so an agent cannot claim one
// belonging to a different key.
func LoadAgentKeys(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		// Optional: agents presenting a certificate need no entry here.
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	byKey := make(map[string]string)
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		label, rest, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(rest)))
		if err != nil {
			continue
		}
		byKey[string(pk.Marshal())] = label
	}
	return byKey, sc.Err()
}

type chanAddr string

func (a chanAddr) Network() string { return "ssh-tunnel" }
func (a chanAddr) String() string  { return string(a) }

// ChannelConn presents an ssh.Channel as a net.Conn, which is what lets the
// agent run a full SSH server over the tunnel without binding a port.
// Deadlines are no-ops; the SSH handshake does not rely on them.
type ChannelConn struct {
	ssh.Channel
	Local, Remote string
}

func (c ChannelConn) LocalAddr() net.Addr             { return chanAddr(c.Local) }
func (c ChannelConn) RemoteAddr() net.Addr            { return chanAddr(c.Remote) }
func (c ChannelConn) SetDeadline(time.Time) error      { return nil }
func (c ChannelConn) SetReadDeadline(time.Time) error  { return nil }
func (c ChannelConn) SetWriteDeadline(time.Time) error { return nil }

// Pipe joins two channels, signalling EOF per direction with CloseWrite so the
// opposite direction can still drain. Closing outright would truncate output.
func Pipe(a, b ssh.Channel) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(a, b)
		a.CloseWrite()
	}()
	go func() {
		defer wg.Done()
		io.Copy(b, a)
		b.CloseWrite()
	}()
	wg.Wait()
	a.Close()
	b.Close()
}

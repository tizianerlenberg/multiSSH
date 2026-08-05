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
	"path/filepath"
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

// WriteFileAtomic writes data to a temporary file in the same directory, syncs
// it, and renames it over path. rename(2) is atomic within a filesystem, so a
// reader sees either the whole old file or the whole new one, never a truncated
// mix. This matters for the files whose partial write is silently wrong rather
// than merely absent -- a half-written revocation list un-revokes whatever fell
// past the cut, a half-written key is unparseable. The temp file must share the
// directory, or the rename crosses filesystems and degrades to copy-and-unlink.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	// Best-effort cleanup: harmless if the rename already consumed it.
	defer os.Remove(tmp)

	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// Sync the directory so the rename itself survives a crash, not just the
	// file's contents. Best-effort: some platforms disallow opening a dir.
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
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
	if err := WriteFileAtomic(path, pemBytes, 0o600); err != nil {
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

func (c ChannelConn) LocalAddr() net.Addr              { return chanAddr(c.Local) }
func (c ChannelConn) RemoteAddr() net.Addr             { return chanAddr(c.Remote) }
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

package sshx

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

// Certificates replace the proxy's list of registered agent keys. A signature
// the proxy can verify carries the label with it, so the proxy holds one
// signing key instead of state that grows with every machine enrolled. Losing
// the list used to mean re-enrolling every target, which is impossible in the
// situation this tool exists for.

// SignCert issues a certificate for pub. A validity of zero never expires,
// which is deliberate for a rescue tool: a machine that has been switched off
// longer than its certificate lasts would otherwise lock itself out, and
// revocation is the better lever for removing access.
func SignCert(ca ssh.Signer, pub ssh.PublicKey, certType uint32, keyID string, principals []string, validity time.Duration) (*ssh.Certificate, error) {
	var serial [8]byte
	if _, err := rand.Read(serial[:]); err != nil {
		return nil, err
	}

	validBefore := uint64(ssh.CertTimeInfinity)
	if validity > 0 {
		validBefore = uint64(time.Now().Add(validity).Unix())
	}

	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          binary.BigEndian.Uint64(serial[:]),
		CertType:        certType,
		KeyId:           keyID,
		ValidPrincipals: principals,
		// Slack for clock skew between the proxy and a target that may have
		// been offline, and whose clock may be well out as a result.
		ValidAfter:  uint64(time.Now().Add(-10 * time.Minute).Unix()),
		ValidBefore: validBefore,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		return nil, err
	}
	return cert, nil
}

// WriteCert writes a certificate in the one-line authorized_keys form.
func WriteCert(path string, cert *ssh.Certificate) error {
	return os.WriteFile(path, ssh.MarshalAuthorizedKey(cert), 0o644)
}

// LoadCert reads a certificate, refusing a plain public key.
func LoadCert(path string) (*ssh.Certificate, error) {
	pub, err := LoadPublicKey(path)
	if err != nil {
		return nil, err
	}
	cert, ok := pub.(*ssh.Certificate)
	if !ok {
		return nil, fmt.Errorf("%s holds a public key, not a certificate", path)
	}
	return cert, nil
}

// LoadPublicKey reads one public key in authorized_keys form.
func LoadPublicKey(path string) (ssh.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(data)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return pub, nil
}

// SameKey compares public keys by their wire encoding.
func SameKey(a, b ssh.PublicKey) bool {
	return a != nil && b != nil && string(a.Marshal()) == string(b.Marshal())
}

// Exists reports whether a path is present, for optional certificate files.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

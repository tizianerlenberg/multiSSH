package sshx

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Every target has two names.
//
// The canonical name embeds a hash of the target's own host key and its own
// label, so it is unique by construction and needs no bookkeeping to stay that
// way. More importantly the name *commits to the key your client verifies*: no other
// machine can be given that name, because the string is derived from a key it
// does not hold. That keeps the proxy out of the trust chain -- it cannot
// substitute a different host key for a canonical name even if it is
// compromised, and you can check the fingerprint against the name by eye on
// the one connection where trust-on-first-use is exposed.
//
// The friendly name is convenience only, and is the sole ambiguous surface, so
// the proxy serves it only when it is unambiguously bound to one machine.

// hashLen is deliberately generous. Accidental collisions would need far less,
// but a short hash could be ground out by anyone able to enrol a machine, to
// deny an existing canonical name. Sixty bits makes that infeasible and costs
// nothing, since this name is rarely typed.
const hashLen = 12

// Lowercase base32 without padding. The alphabet omits nothing, but the case
// folding keeps names typeable and consistent with hostname conventions.
var b32 = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// friendlyRe is the whole namespace separation: friendly names cannot contain
// a dot, canonical names always do, so the two can never be confused.
var friendlyRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidFriendlyName reports whether s may be used as a friendly name.
func ValidFriendlyName(s string) bool { return friendlyRe.MatchString(s) }

// IsCanonicalName reports whether s looks like a derived name rather than a
// friendly one.
func IsCanonicalName(s string) bool { return strings.Contains(s, ".") }

// nameDomain separates this hash from any other use of the same key material,
// so a digest computed elsewhere can never be mistaken for a name.
const nameDomain = "multissh-canonical-name-v1"

// CanonicalName derives "<base>.<hash of base and hostKey>".
//
// The label goes into the hash as well as in front of it. Hashing the host key
// alone would leave the label free: the same machine could be presented under
// any number of canonical names, each verifying perfectly, and "laptop" and
// "backup-server" could be the same box with no way to tell. Binding it costs
// nothing and makes the whole name, not just its tail, commit to the key.
func CanonicalName(base string, hostKey ssh.PublicKey) (string, error) {
	if !ValidFriendlyName(base) {
		return "", fmt.Errorf("label %q must be lowercase letters, digits and dashes, and must not contain a dot", base)
	}
	h := sha256.New()
	h.Write([]byte(nameDomain))
	h.Write([]byte{0})
	// The label alphabet excludes NUL, so this separator cannot be produced
	// from within either field.
	h.Write([]byte(base))
	h.Write([]byte{0})
	h.Write(hostKey.Marshal())
	return base + "." + b32.EncodeToString(h.Sum(nil))[:hashLen], nil
}

// VerifyCanonicalName checks that a host key matches the name claiming it.
// This is what makes trust-on-first-use checkable rather than blind.
func VerifyCanonicalName(name string, hostKey ssh.PublicKey) bool {
	base, _, ok := strings.Cut(name, ".")
	if !ok {
		return false
	}
	want, err := CanonicalName(base, hostKey)
	return err == nil && want == name
}

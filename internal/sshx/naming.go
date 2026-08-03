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
// The canonical name embeds a hash of the target's own host key, so it is
// unique by construction and needs no bookkeeping to stay that way. More
// importantly the name *commits to the key your client verifies*: no other
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

// CanonicalName derives "<base>.<hash of hostKey>".
func CanonicalName(base string, hostKey ssh.PublicKey) (string, error) {
	if !ValidFriendlyName(base) {
		return "", fmt.Errorf("label %q must be lowercase letters, digits and dashes, and must not contain a dot", base)
	}
	sum := sha256.Sum256(hostKey.Marshal())
	return base + "." + b32.EncodeToString(sum[:])[:hashLen], nil
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

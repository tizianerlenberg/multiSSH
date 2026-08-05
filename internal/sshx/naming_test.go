package sshx

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The canonical name has to be a pure function of the label and the host key,
// or a proxy rebuilt from the CA alone would derive a different name for a
// machine it has already enrolled, and every known_hosts entry would break.
func TestCanonicalNameIsDeterministic(t *testing.T) {
	key := testKey(t)
	first, err := CanonicalName("laptop", key)
	if err != nil {
		t.Fatal(err)
	}
	second, err := CanonicalName("laptop", key)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("not deterministic: %q then %q", first, second)
	}
	if !strings.HasPrefix(first, "laptop.") {
		t.Errorf("canonical name %q does not start with its label", first)
	}
	if got := len(strings.TrimPrefix(first, "laptop.")); got != hashLen {
		t.Errorf("hash part is %d characters, want %d", got, hashLen)
	}
}

// The whole point of deriving the name from the host key is that no other
// machine can hold it. Two keys must never produce the same name for the same
// label.
func TestCanonicalNameDiffersPerHostKey(t *testing.T) {
	a, err := CanonicalName("laptop", testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	b, err := CanonicalName("laptop", testKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("two host keys produced the same canonical name %q", a)
	}
}

// VerifyCanonicalName is what makes the agent refuse a certificate naming a
// host key it does not hold, and what lets a user check a name by eye.
func TestVerifyCanonicalName(t *testing.T) {
	key, other := testKey(t), testKey(t)
	name, err := CanonicalName("laptop", key)
	if err != nil {
		t.Fatal(err)
	}

	if !VerifyCanonicalName(name, key) {
		t.Error("a name did not verify against the key it was derived from")
	}
	if VerifyCanonicalName(name, other) {
		t.Error("a name verified against a different host key")
	}
	if VerifyCanonicalName("laptop", key) {
		t.Error("a name with no hash part verified")
	}
	if VerifyCanonicalName(name+"x", key) {
		t.Error("a tampered name verified")
	}
	// Substituting the label while keeping the hash must fail too, or the
	// friendly-looking part of the name would mean nothing.
	if VerifyCanonicalName("desktop"+strings.TrimPrefix(name, "laptop"), key) {
		t.Error("a name with a swapped label verified")
	}
}

// A friendly name containing a dot could be mistaken for a canonical one, and
// that separation is the entire namespace boundary.
func TestFriendlyNamesRejectDots(t *testing.T) {
	valid := []string{"laptop", "web-01", "a", "0", strings.Repeat("a", 63)}
	for _, s := range valid {
		if !ValidFriendlyName(s) {
			t.Errorf("%q should be a valid friendly name", s)
		}
		if IsCanonicalName(s) {
			t.Errorf("%q should not read as canonical", s)
		}
	}

	invalid := []string{
		"laptop.niwru7dfuvu5", // a canonical name
		"laptop.",
		".laptop",
		"has space",
		"UPPER",
		"-leading-dash",
		"under_score",
		"",
		strings.Repeat("a", 64),
	}
	for _, s := range invalid {
		if ValidFriendlyName(s) {
			t.Errorf("%q should be rejected as a friendly name", s)
		}
	}

	if _, err := CanonicalName("has.dot", testKey(t)); err == nil {
		t.Error("CanonicalName accepted a label containing a dot")
	}
}

// Anything the proxy hands back must round-trip, since the agent checks the
// name in its own certificate against its own key before it will start.
func TestCanonicalNamesAreAlwaysCanonicalShaped(t *testing.T) {
	for _, label := range []string{"a", "laptop", "web-01"} {
		name, err := CanonicalName(label, testKey(t))
		if err != nil {
			t.Fatal(err)
		}
		if !IsCanonicalName(name) {
			t.Errorf("%q does not read as a canonical name", name)
		}
		if ValidFriendlyName(name) {
			t.Errorf("%q would also pass as a friendly name", name)
		}
	}
}

// M10. IsCanonicalName only checks for a dot, but the canonical name is logged
// and written to the last-seen file. ValidCanonicalName is the strict form: it
// accepts exactly what CanonicalName emits and refuses anything that could
// smuggle a control character into those sinks.
func TestValidCanonicalName(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	real, err := CanonicalName("laptop", signer.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if !ValidCanonicalName(real) {
		t.Errorf("a name from CanonicalName failed ValidCanonicalName: %q", real)
	}

	for _, bad := range []string{
		"laptop",                 // no hash: a friendly name, not canonical
		"laptop.short",           // hash too short / wrong alphabet
		"laptop.\x1b[2Kaaaaaaaa", // control character in the hash
		"ev\nil.abcdefghijkl",    // newline in the label
		"laptop.ABCDEFGHIJKL",    // uppercase is outside the base32 alphabet
	} {
		if ValidCanonicalName(bad) {
			t.Errorf("ValidCanonicalName accepted %q", bad)
		}
	}
}

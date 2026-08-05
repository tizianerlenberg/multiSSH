package main

import (
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// realClientHost decides whose address a rate limit is charged to. Getting it
// wrong two different ways was live at once: the header was trusted from
// anyone, so a client on the open internet could forge its own key and evade
// the limit -- or set someone else's address and frame them into it -- and the
// leftmost entry was taken, the one entirely under the client's control.
func TestRealClientHostTrustsTheHeaderOnlyFromAProxy(t *testing.T) {
	// The documented deployment: a reverse proxy on loopback.
	trusted, err := parseTrustedProxies("127.0.0.0/8,::1/128")
	if err != nil {
		t.Fatal(err)
	}

	// Directly exposed: the peer is a real remote address, not a trusted
	// proxy, so its X-Forwarded-For is a forgery and must be ignored. The
	// address charged is the socket peer, port stripped.
	r := httptest.NewRequest("POST", "/enroll", nil)
	r.RemoteAddr = "203.0.113.9:54321"
	r.Header.Set("X-Forwarded-For", "10.0.0.1") // an attacker's invention
	if got := realClientHost(r, trusted); got != "203.0.113.9" {
		t.Errorf("exposed proxy honoured a forged header: got %q, want the real peer", got)
	}

	// Behind the trusted proxy on loopback: the forwarded client is believed.
	r = httptest.NewRequest("POST", "/enroll", nil)
	r.RemoteAddr = "127.0.0.1:44444"
	r.Header.Set("X-Forwarded-For", "198.51.100.7")
	if got := realClientHost(r, trusted); got != "198.51.100.7" {
		t.Errorf("fronted proxy did not use the forwarded client: got %q", got)
	}

	// A client that prepends forged hops cannot escape: the trusted proxy
	// appends the address it actually saw, so the rightmost entry is the one
	// still under our control.
	r = httptest.NewRequest("POST", "/enroll", nil)
	r.RemoteAddr = "127.0.0.1:44444"
	r.Header.Set("X-Forwarded-For", "1.2.3.4, 5.6.7.8, 198.51.100.7")
	if got := realClientHost(r, trusted); got != "198.51.100.7" {
		t.Errorf("took a forgeable leftmost entry instead of the rightmost: got %q", got)
	}

	// No header behind the proxy: fall back to the peer.
	r = httptest.NewRequest("POST", "/enroll", nil)
	r.RemoteAddr = "127.0.0.1:44444"
	if got := realClientHost(r, trusted); got != "127.0.0.1" {
		t.Errorf("no header, got %q", got)
	}
}

// The rate-limiter map is keyed by attacker-chosen source address on a public
// listener. Nothing dropped stale keys, so it grew for the life of the process.
func TestLimiterForgetsAddressesThatAgeOut(t *testing.T) {
	l := newLimiter(20*time.Millisecond, 3)
	for i := 0; i < 500; i++ {
		l.allow(fmt.Sprintf("10.0.0.%d", i)) // each a distinct, one-shot source
	}
	if n := len(l.seen); n < 400 {
		t.Fatalf("only %d keys after 500 distinct sources; test is not exercising growth", n)
	}

	time.Sleep(40 * time.Millisecond) // everything is now older than the window

	// A later call sweeps: the map must not still hold the aged-out crowd.
	l.allow("10.0.1.1")
	if n := len(l.seen); n > 5 {
		t.Errorf("map still holds %d keys after the window elapsed; it is unbounded", n)
	}
}

// The same mistake on the SSH side, where the address arrives as a net.Addr.
func TestSourceHostStripsThePort(t *testing.T) {
	addr, err := net.ResolveTCPAddr("tcp", "203.0.113.9:2222")
	if err != nil {
		t.Fatal(err)
	}
	if got := sourceHost(addr); got != "203.0.113.9" {
		t.Errorf("sourceHost = %q", got)
	}
}

// The bug above in the form it would take: attempts from one host must
// accumulate against one key.
func TestLimiterCountsPerHostNotPerConnection(t *testing.T) {
	l := newLimiter(time.Minute, 3)

	for i := 0; i < 3; i++ {
		if !l.allow("203.0.113.9") {
			t.Fatalf("attempt %d was refused while under the burst", i+1)
		}
	}
	if l.allow("203.0.113.9") {
		t.Error("the burst was exceeded without being refused")
	}
	if !l.allow("198.51.100.7") {
		t.Error("one host's attempts counted against another's")
	}
}

// count must not itself record an attempt, or merely checking would exhaust
// the budget. The SSH path checks before deciding whether to serve at all.
func TestLimiterCountDoesNotRecord(t *testing.T) {
	l := newLimiter(time.Minute, 2)
	for i := 0; i < 10; i++ {
		if l.count("203.0.113.9") != 0 {
			t.Fatal("count recorded an attempt")
		}
	}
	if !l.allow("203.0.113.9") {
		t.Error("counting exhausted the budget")
	}
	if l.count("203.0.113.9") != 1 {
		t.Error("count did not see the recorded attempt")
	}
}

func TestLimiterForgetsOldAttempts(t *testing.T) {
	l := newLimiter(50*time.Millisecond, 1)
	if !l.allow("host") {
		t.Fatal("first attempt refused")
	}
	if l.allow("host") {
		t.Fatal("second attempt allowed within the window")
	}
	time.Sleep(80 * time.Millisecond)
	if !l.allow("host") {
		t.Error("the window never expired")
	}
}

func TestPasswordHashing(t *testing.T) {
	p, err := newPassword("laptops", "correct horse battery", 0)
	if err != nil {
		t.Fatal(err)
	}
	if !p.matches("correct horse battery") {
		t.Error("the password does not match itself")
	}
	if p.matches("wrong") {
		t.Error("a wrong password matched")
	}
	if p.expired() {
		t.Error("a password with no lifetime reported as expired")
	}

	// The plaintext must not be recoverable from what is stored.
	if p.Hash == "" || p.Salt == "" {
		t.Fatal("nothing was stored")
	}
	same, err := newPassword("laptops", "correct horse battery", 0)
	if err != nil {
		t.Fatal(err)
	}
	if same.Hash == p.Hash {
		t.Error("two hashes of one password are identical; the salt is not being used")
	}
}

func TestPasswordExpiry(t *testing.T) {
	p, err := newPassword("short", "hunter2hunter2", -time.Second)
	if err != nil {
		t.Fatal(err)
	}
	// A negative lifetime is treated as "no lifetime" by newPassword, so build
	// the expired case directly rather than asserting on a quirk.
	p.Expires = time.Now().Add(-time.Minute)
	if !p.expired() {
		t.Error("a password past its expiry did not report as expired")
	}
	if !p.matches("hunter2hunter2") {
		t.Error("expiry should not change whether the hash matches; the caller checks both")
	}
}

// Regression. Passwords were read once at startup, so -remove-password wrote
// the file and changed nothing in the running proxy: a credential you believed
// you had withdrawn went on being accepted until something restarted it. For a
// thing whose whole job is letting new machines in, that is the wrong way
// round to fail.
func TestEnrolPasswordsAreReloadable(t *testing.T) {
	path := tempFile(t, "enrol_passwords.json")
	first, err := newPassword("original", "correct horse battery", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := savePasswords(path, []password{first}); err != nil {
		t.Fatal(err)
	}

	e := &enroller{}
	if n, err := e.reload(path); err != nil || n != 1 {
		t.Fatalf("reload = %d, %v", n, err)
	}
	if !(*e.passwords.Load())[0].matches("correct horse battery") {
		t.Fatal("the loaded password does not match itself")
	}

	// Replace it, as `-remove-password` then `-add-password` does.
	second, err := newPassword("original", "a different one entirely", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := savePasswords(path, []password{second}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.reload(path); err != nil {
		t.Fatal(err)
	}

	set := *e.passwords.Load()
	if len(set) != 1 {
		t.Fatalf("after reload there are %d passwords", len(set))
	}
	if set[0].matches("correct horse battery") {
		t.Error("the withdrawn password is still accepted after a reload")
	}
	if !set[0].matches("a different one entirely") {
		t.Error("the replacement password is not accepted after a reload")
	}
}

// An unreadable file must not silently disable enrolment.
func TestReloadKeepsThePreviousSetOnError(t *testing.T) {
	path := tempFile(t, "enrol_passwords.json")
	p, err := newPassword("keepme", "correct horse battery", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := savePasswords(path, []password{p}); err != nil {
		t.Fatal(err)
	}

	e := &enroller{}
	if _, err := e.reload(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{ this is not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.reload(path); err == nil {
		t.Fatal("a corrupt password file reloaded without error")
	}
	if !(*e.passwords.Load())[0].matches("correct horse battery") {
		t.Error("a corrupt file wiped the passwords already in force")
	}
}

// The name clash has to be reported before a password is typed, not after.
func TestAddPasswordRejectsDuplicateNameBeforePrompting(t *testing.T) {
	path := tempFile(t, "enrol_passwords.json")
	p, err := newPassword("laptops", "correct horse battery", 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := savePasswords(path, []password{p}); err != nil {
		t.Fatal(err)
	}

	// No MULTISSH_NEW_PASSWORD and no terminal in a test, so readSecret would
	// fail with its own message. Getting the duplicate error instead proves
	// the check ran first.
	t.Setenv("MULTISSH_NEW_PASSWORD", "")
	err = managePasswords(path, "laptops", "", false, 0)
	if err == nil {
		t.Fatal("a duplicate name was accepted")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error was %q, want the duplicate-name complaint before any prompt", err)
	}
	if !strings.Contains(err.Error(), "-remove-password") {
		t.Errorf("the error does not say how to fix it: %q", err)
	}
}

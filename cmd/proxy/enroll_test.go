package main

import (
	"net"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// Regression. clientAddr once returned RemoteAddr whole, port included. Every
// connection gets a fresh source port, so each attempt landed under its own key
// and the rate limit counted to one forever -- while looking entirely correct
// in the code and in any test that made a single request.
//
// It would also have stayed hidden in production: behind Caddy the
// X-Forwarded-For path carries no port, so only a directly exposed proxy -- the
// case where the limit actually matters -- was unprotected.
func TestClientAddrStripsThePort(t *testing.T) {
	r := httptest.NewRequest("POST", "/enroll", nil)
	r.RemoteAddr = "203.0.113.9:54321"
	if got := clientAddr(r); got != "203.0.113.9" {
		t.Errorf("clientAddr = %q, want the address without its port", got)
	}

	r.RemoteAddr = "[2001:db8::1]:54321"
	if got := clientAddr(r); got != "2001:db8::1" {
		t.Errorf("clientAddr for IPv6 = %q", got)
	}

	// A reverse proxy's report wins, and its first entry is the client.
	r.Header.Set("X-Forwarded-For", "198.51.100.7, 203.0.113.1")
	if got := clientAddr(r); got != "198.51.100.7" {
		t.Errorf("clientAddr behind a proxy = %q", got)
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

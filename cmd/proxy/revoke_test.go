package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	fpA = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	fpB = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
)

func tempFile(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name)
}

// A proxy with no revocation file yet must start, not fail. This is the normal
// state for every install.
func TestMissingRevocationFileIsEmpty(t *testing.T) {
	r, err := openRevocations(tempFile(t, "revoked_keys"))
	if err != nil {
		t.Fatalf("a missing file should not be an error: %v", err)
	}
	if r.count() != 0 {
		t.Errorf("count = %d on a missing file", r.count())
	}
	if _, yes := r.revoked(fpA); yes {
		t.Error("a key was revoked by an absent file")
	}
}

func TestRevokeRoundTrip(t *testing.T) {
	path := tempFile(t, "revoked_keys")
	ledger := tempFile(t, "friendly_labels")

	if err := manageRevocations(path, fpA, "", false, "stolen laptop", ledger); err != nil {
		t.Fatal(err)
	}

	r, err := openRevocations(path)
	if err != nil {
		t.Fatal(err)
	}
	note, yes := r.revoked(fpA)
	if !yes {
		t.Fatal("the key was not revoked")
	}
	if note != "stolen laptop" {
		t.Errorf("note = %q", note)
	}
	if _, yes := r.revoked(fpB); yes {
		t.Error("an unrelated key was revoked")
	}

	// The file has to say plainly that it is not advisory, because unlike
	// every other file the proxy keeps, losing it silently undoes the work.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "NOT advisory") {
		t.Error("the file does not warn that losing it un-revokes everything")
	}

	if err := manageRevocations(path, "", fpA, false, "", ledger); err != nil {
		t.Fatal(err)
	}
	again, err := openRevocations(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, yes := again.revoked(fpA); yes {
		t.Error("un-revoking did not take")
	}
}

// A mistyped fingerprint would revoke nothing while appearing to have worked,
// which for a security control is the worst outcome there is.
func TestRevokeRejectsMalformedFingerprints(t *testing.T) {
	path := tempFile(t, "revoked_keys")
	ledger := tempFile(t, "friendly_labels")

	for _, bad := range []string{
		"",
		"laptop",
		"MD5:aa:bb:cc",
		"SHA256:tooshort",
		strings.TrimPrefix(fpA, "SHA256:"), // fingerprint without its prefix
		fpA + "extra",
	} {
		if err := manageRevocations(path, bad, "", false, "", ledger); err == nil {
			t.Errorf("%q was accepted as a fingerprint", bad)
		}
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("a rejected revocation still wrote the file")
	}
}

func TestUnrevokingSomethingUnrevokedIsAnError(t *testing.T) {
	path := tempFile(t, "revoked_keys")
	if err := manageRevocations(path, "", fpA, false, "", tempFile(t, "labels")); err == nil {
		t.Error("un-revoking a key that was not revoked reported success")
	}
}

// Revoking must take effect without restarting the proxy, since restarting
// drops every session -- including, plausibly, the one being used to revoke.
func TestReloadPicksUpChanges(t *testing.T) {
	path := tempFile(t, "revoked_keys")
	r, err := openRevocations(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := manageRevocations(path, fpA, "", false, "", tempFile(t, "labels")); err != nil {
		t.Fatal(err)
	}
	changed, err := r.reload()
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("reload did not notice the file appearing")
	}
	if _, yes := r.revoked(fpA); !yes {
		t.Error("the reloaded set does not hold the new revocation")
	}

	// An unchanged file must not be re-read on every sweep.
	if changed, _ := r.reload(); changed {
		t.Error("reload reported a change on an untouched file")
	}
}

// Checking only at authentication would leave a machine revoked today
// connected until it next reconnects, which for a healthy agent is never.
func TestSweepDropsConnectedRevokedAgents(t *testing.T) {
	path := tempFile(t, "revoked_keys")
	if err := manageRevocations(path, fpA, "", false, "gone", tempFile(t, "labels")); err != nil {
		t.Fatal(err)
	}
	r, err := openRevocations(path)
	if err != nil {
		t.Fatal(err)
	}

	reg := newRegistry()
	doomed, spared := &fakeConn{}, &fakeConn{}
	reg.add("bad.aaaa", doomed, fpA, 1, "", "")
	reg.add("bad", doomed, fpA, 1, "", "") // same machine, two names
	reg.add("good.bbbb", spared, fpB, 1, "", "")

	r.sweep(reg)

	if !doomed.isClosed() {
		t.Error("a revoked agent stayed connected")
	}
	if spared.isClosed() {
		t.Error("the sweep closed an agent that was not revoked")
	}
}

func TestSweepOnEmptySetTouchesNothing(t *testing.T) {
	r, err := openRevocations(tempFile(t, "revoked_keys"))
	if err != nil {
		t.Fatal(err)
	}
	reg := newRegistry()
	conn := &fakeConn{}
	reg.add("laptop.aaaa", conn, fpA, 1, "", "")

	r.sweep(reg)
	if conn.isClosed() {
		t.Error("an empty revocation set closed a connection")
	}
}

// Comments and blank lines are normal in a hand-edited file, and a stray
// comment must not read as a revoked fingerprint.
func TestRevocationFileParsing(t *testing.T) {
	path := tempFile(t, "revoked_keys")
	body := "# a header\n\n" + fpA + "  2026-08-03 stolen\n" + fpB + "\n   \n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	r, err := openRevocations(path)
	if err != nil {
		t.Fatal(err)
	}
	if r.count() != 2 {
		t.Fatalf("parsed %d entries, want 2", r.count())
	}
	if note, _ := r.revoked(fpA); note != "2026-08-03 stolen" {
		t.Errorf("note = %q", note)
	}
	// A bare fingerprint with no note is still revoked; presence is the
	// decision, not the note.
	if _, yes := r.revoked(fpB); !yes {
		t.Error("a fingerprint with no note was not treated as revoked")
	}
}

func TestStaleSince(t *testing.T) {
	path := tempFile(t, "last_seen")
	now := time.Now().UTC()
	body := "fresh.aaaa " + now.Format(time.RFC3339) + "\n" +
		"old.bbbb " + now.Add(-90*24*time.Hour).Format(time.RFC3339) + "\n" +
		"ancient.cccc " + now.Add(-400*24*time.Hour).Format(time.RFC3339) + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	s, err := openSightings(path)
	if err != nil {
		t.Fatal(err)
	}
	stale := s.staleSince(now.Add(-30 * 24 * time.Hour))
	if len(stale) != 2 {
		t.Fatalf("found %d stale targets, want 2", len(stale))
	}
	// Oldest first: the one worth worrying about most is at the top.
	if stale[0].Name != "ancient.cccc" || stale[1].Name != "old.bbbb" {
		t.Errorf("stale targets came back as %v", stale)
	}
	if len(s.staleSince(now.Add(-500*24*time.Hour))) != 0 {
		t.Error("a cutoff older than everything still found stale targets")
	}
}

package main

import (
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// fakeConn stands in for an agent's connection. Only Close is ever reached by
// the registry; the embedded interface supplies the rest of the method set and
// would panic loudly if anything else were called, which is the point.
type fakeConn struct {
	ssh.Conn
	mu     sync.Mutex
	closed bool
}

func (c *fakeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *fakeConn) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// A laptop that slept leaves a half-open connection behind. When it comes back
// it presents the same identity key, so the live connection must displace the
// ghost -- otherwise the machine is listed but unreachable, which is the worst
// of both.
func TestReconnectReplacesGhost(t *testing.T) {
	reg := newRegistry()
	ghost, live := &fakeConn{}, &fakeConn{}

	if err := reg.add("laptop.abc", ghost, "SHA256:same", 1, ""); err != nil {
		t.Fatal(err)
	}
	if err := reg.add("laptop.abc", live, "SHA256:same", 1, ""); err != nil {
		t.Fatalf("same machine was refused on reconnect: %v", err)
	}

	got, ok := reg.get("laptop.abc")
	if !ok {
		t.Fatal("target vanished after reconnect")
	}
	if got != ssh.Conn(live) {
		t.Error("registry still points at the stale connection")
	}
	if !ghost.isClosed() {
		t.Error("the displaced connection was left open")
	}
}

// A different machine claiming a held name must be refused rather than evict
// the holder. Letting it evict would let two machines kick each other off
// forever, leaving neither reliably reachable -- which for a rescue tool is
// indistinguishable from being down.
func TestDifferentKeyCannotStealAName(t *testing.T) {
	reg := newRegistry()
	holder, impostor := &fakeConn{}, &fakeConn{}

	if err := reg.add("laptop", holder, "SHA256:mine", 1, ""); err != nil {
		t.Fatal(err)
	}
	err := reg.add("laptop", impostor, "SHA256:theirs", 1, "")
	if err == nil {
		t.Fatal("a different key was allowed to take a held name")
	}

	got, _ := reg.get("laptop")
	if got != ssh.Conn(holder) {
		t.Error("the holder lost its name to the impostor")
	}
	if holder.isClosed() {
		t.Error("the holder's connection was closed")
	}
}

// A dying connection must not deregister the one that replaced it.
func TestRemoveOnlyAffectsTheCurrentConnection(t *testing.T) {
	reg := newRegistry()
	ghost, live := &fakeConn{}, &fakeConn{}

	reg.add("laptop.abc", ghost, "SHA256:same", 1, "")
	reg.add("laptop.abc", live, "SHA256:same", 1, "")

	// The ghost's handler now unwinds and cleans up after itself.
	reg.remove("laptop.abc", ghost)

	if _, ok := reg.get("laptop.abc"); !ok {
		t.Fatal("the live registration was removed by the connection it replaced")
	}

	reg.remove("laptop.abc", live)
	if _, ok := reg.get("laptop.abc"); ok {
		t.Error("the live connection could not remove itself")
	}
}

// The listing pairs the two names of one machine on one row, and carries the
// fingerprint and protocol version the user needs to revoke or to plan an
// upgrade.
func TestListingPairsNames(t *testing.T) {
	reg := newRegistry()
	one, two := &fakeConn{}, &fakeConn{}

	reg.add("laptop.aaaa", one, "SHA256:one", 1, "")
	reg.add("laptop", one, "SHA256:one", 1, "")
	reg.add("server.bbbb", two, "SHA256:two", 0, "") // no friendly name

	list := reg.listing()
	if len(list) != 2 {
		t.Fatalf("listing has %d rows, want 2 (one per machine, not per name)", len(list))
	}
	// Sorted by canonical name, so laptop comes first.
	if list[0].Friendly != "laptop" || list[0].Canonical != "laptop.aaaa" {
		t.Errorf("row 0 = %+v", list[0])
	}
	if list[0].FP != "SHA256:one" || list[0].Proto != 1 {
		t.Errorf("row 0 lost its fingerprint or version: %+v", list[0])
	}
	if list[1].Friendly != "" || list[1].Canonical != "server.bbbb" {
		t.Errorf("row 1 = %+v", list[1])
	}
}

// A machine holding two names is one machine. Anything sweeping connections --
// revocation, the health count -- must not see it twice.
func TestConnectionsDeduplicates(t *testing.T) {
	reg := newRegistry()
	conn := &fakeConn{}
	reg.add("laptop.aaaa", conn, "SHA256:one", 1, "")
	reg.add("laptop", conn, "SHA256:one", 1, "")

	got := reg.connections()
	if len(got) != 1 {
		t.Fatalf("one machine under two names counted as %d connections", len(got))
	}
	if got[conn] != "SHA256:one" {
		t.Errorf("fingerprint came back as %q", got[conn])
	}
}

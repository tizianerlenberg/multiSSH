package sshx

import (
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestVersionStringsRoundTrip(t *testing.T) {
	if got := ParseAgentVersion([]byte(AgentVersion("", ""))); got != ProtocolVersion {
		t.Errorf("agent version round-tripped to %d, want %d", got, ProtocolVersion)
	}
	if got := ParseProxyVersion([]byte(ProxyVersion())); got != ProtocolVersion {
		t.Errorf("proxy version round-tripped to %d, want %d", got, ProtocolVersion)
	}
	// An agent must not read as a proxy or the floor check would pass for the
	// wrong peer.
	if got := ParseProxyVersion([]byte(AgentVersion("", ""))); got != LegacyProtocol {
		t.Errorf("an agent identification parsed as proxy version %d", got)
	}
}

// RFC 4253 section 4.2 forbids whitespace and the minus sign in the software
// version. Getting this wrong would produce an identification string some
// implementations reject outright.
func TestVersionStringsAreLegal(t *testing.T) {
	for _, v := range []string{AgentVersion("", ""), ProxyVersion()} {
		if len(v) < 8 || v[:8] != "SSH-2.0-" {
			t.Errorf("%q does not begin with SSH-2.0-", v)
		}
		for _, c := range v[8:] {
			if c == ' ' || c == '-' || c < 0x20 || c > 0x7e {
				t.Errorf("%q contains %q, which RFC 4253 forbids in a software version", v, c)
			}
		}
	}
}

// Anything that does not carry a version is an older peer, not a broken one.
func TestUnknownIdentificationReadsAsLegacy(t *testing.T) {
	for _, id := range []string{
		"SSH-2.0-Go",
		"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
		"SSH-2.0-multissh_agent_",
		"SSH-2.0-multissh_agent_notanumber",
		"SSH-2.0-multissh_agent_-1",
		"",
	} {
		if got := ParseAgentVersion([]byte(id)); got != LegacyProtocol {
			t.Errorf("ParseAgentVersion(%q) = %d, want %d", id, got, LegacyProtocol)
		}
	}
	// A trailing comment is allowed by the RFC and must not defeat parsing.
	if got := ParseAgentVersion([]byte(AgentVersion("", "") + " some comment")); got != ProtocolVersion {
		t.Errorf("a commented identification parsed as %d", got)
	}
}

func TestTunnelRequestRoundTrip(t *testing.T) {
	got := ParseTunnelRequest(MarshalTunnelRequest())
	if got.Version != ProtocolVersion {
		t.Errorf("tunnel request version %d, want %d", got.Version, ProtocolVersion)
	}
}

// A proxy predating the payload opens the channel with nothing attached. That
// has to read as legacy rather than as an error, or every session through an
// older proxy would be refused.
func TestEmptyTunnelPayloadIsLegacy(t *testing.T) {
	for _, payload := range [][]byte{nil, {}, []byte("not ssh-marshalled")} {
		if got := ParseTunnelRequest(payload); got.Version != LegacyProtocol {
			t.Errorf("ParseTunnelRequest(%q) = %d, want %d", payload, got.Version, LegacyProtocol)
		}
	}
}

// The reason Extra exists: a later version must be able to add fields without
// the payload becoming unreadable to agents already in the field. This is the
// property that ssh.Unmarshal into a *changed struct* would not have, so it is
// worth pinning.
func TestTunnelRequestToleratesFutureFields(t *testing.T) {
	type futureExtension struct {
		Something string
		Another   uint32
	}
	future := ssh.Marshal(TunnelRequest{
		Version: ProtocolVersion + 7,
		Extra:   ssh.Marshal(futureExtension{"added later", 42}),
	})

	got := ParseTunnelRequest(future)
	if got.Version != ProtocolVersion+7 {
		t.Fatalf("version %d, want %d", got.Version, ProtocolVersion+7)
	}

	// And the extension is intact for a build that understands it.
	var ext futureExtension
	if err := ssh.Unmarshal(got.Extra, &ext); err != nil {
		t.Fatalf("extension did not survive: %v", err)
	}
	if ext.Something != "added later" || ext.Another != 42 {
		t.Errorf("extension came back as %+v", ext)
	}
}

// Demonstrates why the Extra field is not optional: adding a field directly to
// the struct breaks every peer compiled against the old shape. If this test
// ever fails, ssh.Unmarshal has become lenient and the design note in
// protocol.go should be revisited.
func TestAddingAFieldDirectlyWouldBreakOldAgents(t *testing.T) {
	type v2Request struct {
		Version uint32
		Extra   []byte
		Added   string
	}
	payload := ssh.Marshal(v2Request{Version: 2, Added: "new"})

	var asV1 TunnelRequest
	if err := ssh.Unmarshal(payload, &asV1); err == nil {
		t.Fatal("ssh.Unmarshal tolerated trailing fields; the Extra indirection may no longer be needed")
	}
}

func TestDescribeProtocol(t *testing.T) {
	if got := DescribeProtocol(LegacyProtocol); got != "pre-1" {
		t.Errorf("DescribeProtocol(0) = %q", got)
	}
	if got := DescribeProtocol(3); got != "v3" {
		t.Errorf("DescribeProtocol(3) = %q", got)
	}
}

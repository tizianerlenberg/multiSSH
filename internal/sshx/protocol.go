package sshx

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Versioning between the agent and the proxy.
//
// The agent is installed on machines that are, by design, rarely touched --
// that is the whole point of the tool -- so a protocol change has to be
// something both ends can *see*, rather than something that surfaces as an
// inexplicable failure months later. Two places carry a version:
//
//   - the SSH identification string, exchanged before anything else, so the
//     proxy can refuse an agent it cannot serve and say why in a banner the
//     agent prints;
//   - the tunnel channel's open payload, so the shape of a session can change
//     without changing the handshake.
//
// Version 1 is the first that carries any of this. An agent installed before
// it sends x/crypto's default identification and an empty tunnel payload; both
// read back as version 0, which the proxy still serves.

// ProtocolVersion is the revision this build speaks.
const ProtocolVersion = 1

// LegacyProtocol is what a peer predating the handshake reads back as.
const LegacyProtocol = 0

// RFC 4253 section 4.2 forbids whitespace and the minus sign in the software
// version, so the separators here are underscores rather than the dashes used
// everywhere else in this project.
const (
	agentVersionPrefix = "SSH-2.0-multissh_agent_"
	proxyVersionPrefix = "SSH-2.0-multissh_proxy_"
)

// AgentVersion is the identification string the agent announces itself with.
func AgentVersion() string { return agentVersionPrefix + strconv.Itoa(ProtocolVersion) }

// ProxyVersion is the identification string the proxy announces itself with.
func ProxyVersion() string { return proxyVersionPrefix + strconv.Itoa(ProtocolVersion) }

// ParseAgentVersion extracts the protocol version from an agent's
// identification string, returning LegacyProtocol for anything that does not
// carry one. It never reports an error: an unrecognised peer is old, not
// broken, and the caller decides whether that is acceptable.
func ParseAgentVersion(id []byte) int { return parseVersion(string(id), agentVersionPrefix) }

// ParseProxyVersion is the same for the proxy's identification string.
func ParseProxyVersion(id []byte) int { return parseVersion(string(id), proxyVersionPrefix) }

func parseVersion(id, prefix string) int {
	rest, ok := strings.CutPrefix(id, prefix)
	if !ok {
		return LegacyProtocol
	}
	// A comment may follow the version, separated by a space.
	rest, _, _ = strings.Cut(rest, " ")
	n, err := strconv.Atoi(rest)
	if err != nil || n < 0 {
		return LegacyProtocol
	}
	return n
}

// TunnelRequest is the payload the proxy sends when opening a tunnel channel
// toward an agent.
//
// Extra exists so that later versions can add fields without changing this
// struct's shape. ssh.Unmarshal rejects a payload that does not match the
// destination struct exactly -- both trailing bytes and missing ones -- so an
// added field would break every agent already in the field, which is precisely
// the situation this type exists to avoid. Anything new goes inside Extra as a
// further marshalled struct, which an older agent ignores intact.
type TunnelRequest struct {
	Version uint32
	Extra   []byte
}

// MarshalTunnelRequest builds the payload for the current protocol version.
func MarshalTunnelRequest() []byte {
	return ssh.Marshal(TunnelRequest{Version: ProtocolVersion})
}

// ParseTunnelRequest reads a tunnel payload. An empty or unreadable one comes
// from a proxy predating the payload and is reported as LegacyProtocol rather
// than as a failure, since the session it introduces is unchanged.
func ParseTunnelRequest(payload []byte) TunnelRequest {
	var t TunnelRequest
	if len(payload) == 0 || ssh.Unmarshal(payload, &t) != nil {
		return TunnelRequest{Version: LegacyProtocol}
	}
	return t
}

// DescribeProtocol renders a version for humans, since 0 means "did not say"
// rather than a real revision.
func DescribeProtocol(v int) string {
	if v == LegacyProtocol {
		return "pre-1"
	}
	return fmt.Sprintf("v%d", v)
}

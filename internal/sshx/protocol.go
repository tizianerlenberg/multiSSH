package sshx

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"
)

// The agent's identification string is attacker-controlled: any host can dial
// the agent endpoint and send whatever version string it likes. It cannot
// contain CR or LF (the SSH transport forbids them), but nothing stops an ESC,
// and the build and platform are printed straight into the operator's terminal
// in the listing. A crafted value could rewrite that display -- the very
// surface the host-key eye-check depends on. So both fields are constrained to
// exactly the shape a real agent sends, and anything else is dropped to empty,
// indistinguishable from an agent that sent nothing.
var (
	buildIDRe  = regexp.MustCompile(`^[0-9a-f]{1,32}$`) // a short hex SHA
	platformRe = regexp.MustCompile(`^[a-z0-9]{1,32}$`) // a GOOS name
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

// BuildIDLen is how much of a binary's SHA256 identifies it. Twelve hex
// characters is far more than enough to tell apart the handful of builds a
// proxy serves, and short enough to sit in a listing.
const BuildIDLen = 12

// AgentVersion is the identification string the agent announces itself with.
//
// The build ID rides here too, so the proxy learns which binary a machine is
// actually running without an extra round trip and without the agent having to
// be told at install time what it is. An empty build is omitted, which is what
// an agent that could not read its own executable sends.
func AgentVersion(build, platform string) string {
	v := agentVersionPrefix + strconv.Itoa(ProtocolVersion)
	if build != "" {
		v += "_" + build
		// Only after a build, so the fields stay positional. Anything that
		// cannot say what it is is simply older.
		if platform != "" {
			v += "_" + platform
		}
	}
	return v
}

// ProxyVersion is the identification string the proxy announces itself with.
func ProxyVersion() string { return proxyVersionPrefix + strconv.Itoa(ProtocolVersion) }

// ParseAgentVersion extracts the protocol version from an agent's
// identification string, returning LegacyProtocol for anything that does not
// carry one. It never reports an error: an unrecognised peer is old, not
// broken, and the caller decides whether that is acceptable.
func ParseAgentVersion(id []byte) int {
	proto, _, _ := parseVersion(string(id), agentVersionPrefix)
	return proto
}

// ParseAgentBuild extracts the build ID, empty when the agent did not send one.
func ParseAgentBuild(id []byte) string {
	_, build, _ := parseVersion(string(id), agentVersionPrefix)
	return build
}

// ParseAgentPlatform extracts the operating system the agent runs on, empty
// when it did not say. Knowing it matters because managing a target means
// sending it a command, and a shell snippet for one platform is line noise on
// another -- a POSIX loop pasted into PowerShell produces a page of parser
// errors and no update.
func ParseAgentPlatform(id []byte) string {
	_, _, platform := parseVersion(string(id), agentVersionPrefix)
	return platform
}

// ParseProxyVersion is the same for the proxy's identification string.
func ParseProxyVersion(id []byte) int {
	proto, _, _ := parseVersion(string(id), proxyVersionPrefix)
	return proto
}

func parseVersion(id, prefix string) (proto int, build, platform string) {
	rest, ok := strings.CutPrefix(id, prefix)
	if !ok {
		return LegacyProtocol, "", ""
	}
	// A comment may follow the version, separated by a space.
	rest, _, _ = strings.Cut(rest, " ")
	// "<protocol>[_<build>[_<platform>]]" -- positional, each part optional
	// from the right, so an older agent parses as far as it went.
	num, rest, _ := strings.Cut(rest, "_")
	n, err := strconv.Atoi(num)
	if err != nil || n < 0 {
		return LegacyProtocol, "", ""
	}
	build, platform, _ = strings.Cut(rest, "_")
	// Drop anything not of the expected shape: the values reach the operator's
	// terminal, and a control character there is an injection, not a build ID.
	if !buildIDRe.MatchString(build) {
		build = ""
	}
	if !platformRe.MatchString(platform) {
		platform = ""
	}
	return n, build, platform
}

// BuildIDOf reduces a full hex SHA256 to the short form used on the wire.
func BuildIDOf(hexSHA string) string {
	if len(hexSHA) < BuildIDLen {
		return hexSHA
	}
	return hexSHA[:BuildIDLen]
}

// BuildIDOfFile hashes a file and returns its short build ID. Used by the agent
// on its own executable, so a machine reports the binary it is really running
// rather than what someone recorded at install time.
func BuildIDOfFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return "", err
	}
	return BuildIDOf(hex.EncodeToString(sum.Sum(nil))), nil
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

// HostKeyRequestType is a global request the agent sends immediately after
// registering, telling the proxy which host key its embedded SSH server will
// present.
//
// The proxy cannot work this out for itself: the canonical name commits to the
// host key through a one-way hash, and a hash cannot be run backwards. Without
// being told, the proxy has nothing to show a user who wants to confirm, on
// first connect, that the key being offered is the right one -- and the name's
// own hash is no help there, being a different function in a different alphabet
// from the fingerprint ssh prints.
//
// An agent predating this sends nothing, and the listing simply has no host key
// to show for it.
const HostKeyRequestType = "hostkey@multissh"

// HostKeyReport carries the agent's host public key in SSH wire format.
type HostKeyReport struct {
	Key   []byte
	Extra []byte
}

// MarshalHostKeyReport builds the payload for a host key.
func MarshalHostKeyReport(key ssh.PublicKey) []byte {
	return ssh.Marshal(HostKeyReport{Key: key.Marshal()})
}

// ParseHostKeyReport reads one back, returning nil for anything unreadable.
func ParseHostKeyReport(payload []byte) ssh.PublicKey {
	var r HostKeyReport
	if len(payload) == 0 || ssh.Unmarshal(payload, &r) != nil {
		return nil
	}
	key, err := ssh.ParsePublicKey(r.Key)
	if err != nil {
		return nil
	}
	return key
}

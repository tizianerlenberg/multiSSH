// Spike 2: can the proxy open channels *toward* an already-connected agent,
// and multiplex several concurrent sessions over that one agent connection?
//
// This is the assumption v1 never satisfied: it gave each target a single raw
// socket, consumed entirely by one session, with no way to start a second and
// no cleanup when it died. Proves four things:
//
//  1. proxy (SSH server) can open a channel to the agent (SSH client)
//  2. many channels coexist concurrently over one agent connection
//  3. data flows bidirectionally on each
//  4. closing one channel leaves the others alive  <- the exact v1 failure
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

const tunnelChannelType = "tunnel@multissh"

// Payload the proxy sends when asking the agent for a new tunnel.
type tunnelRequest struct {
	Label  string
	ReqID  uint32
}

func mustSigner() ssh.Signer {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		log.Fatal(err)
	}
	return s
}

// ---------------------------------------------------------------- agent side

func runAgent(addr string, agentKey ssh.Signer, proxyHostKey ssh.PublicKey) {
	cfg := &ssh.ClientConfig{
		User:            "agent",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(agentKey)},
		HostKeyCallback: ssh.FixedHostKey(proxyHostKey),
		Timeout:         5 * time.Second,
	}

	raw, err := net.Dial("tcp", addr)
	if err != nil {
		log.Fatalf("agent dial: %v", err)
	}
	conn, chans, reqs, err := ssh.NewClientConn(raw, addr, cfg)
	if err != nil {
		log.Fatalf("agent handshake: %v", err)
	}
	client := ssh.NewClient(conn, chans, reqs)
	log.Printf("[agent] registered with proxy, awaiting tunnel requests")

	// Register interest in our custom channel type. Everything else the
	// standard client mux rejects for us.
	for nc := range client.HandleChannelOpen(tunnelChannelType) {
		var tr tunnelRequest
		if err := ssh.Unmarshal(nc.ExtraData(), &tr); err != nil {
			nc.Reject(ssh.ConnectionFailed, "bad payload")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			continue
		}
		go ssh.DiscardRequests(chReqs)
		log.Printf("[agent] accepted tunnel req=%d label=%q (this is where we would dial 127.0.0.1:22)", tr.ReqID, tr.Label)
		go func() {
			defer ch.Close()
			io.Copy(ch, ch) // stand-in for the local sshd
		}()
	}
}

// ---------------------------------------------------------------- proxy side

func runProxy(ln net.Listener, hostKey ssh.Signer, agentPub ssh.PublicKey, ready chan<- ssh.Conn) {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) != string(agentPub.Marshal()) {
				return nil, fmt.Errorf("unregistered agent key")
			}
			return nil, nil
		},
	}
	cfg.AddHostKey(hostKey)

	raw, err := ln.Accept()
	if err != nil {
		log.Fatalf("proxy accept: %v", err)
	}
	conn, chans, reqs, err := ssh.NewServerConn(raw, cfg)
	if err != nil {
		log.Fatalf("proxy handshake: %v", err)
	}
	go ssh.DiscardRequests(reqs)
	go func() {
		for nc := range chans {
			nc.Reject(ssh.Prohibited, "agents do not open channels")
		}
	}()
	log.Printf("[proxy] agent %q registered", conn.User())
	ready <- conn
}

// roundTrip writes a probe down the channel and reads the echo back.
func roundTrip(ch ssh.Channel, msg string) error {
	if _, err := ch.Write([]byte(msg)); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(ch, buf); err != nil {
		return fmt.Errorf("read: %w", err)
	}
	if string(buf) != msg {
		return fmt.Errorf("echo mismatch: sent %q got %q", msg, buf)
	}
	return nil
}

func main() {
	log.SetFlags(0)

	proxyHostKey := mustSigner()
	agentKey := mustSigner()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	ready := make(chan ssh.Conn, 1)
	go runProxy(ln, proxyHostKey, agentKey.PublicKey(), ready)
	go runAgent(addr, agentKey, proxyHostKey.PublicKey())

	agentConn := <-ready
	fail := func(format string, args ...any) {
		log.Printf("FAIL: "+format, args...)
		os.Exit(1)
	}

	// (1)+(2) open three concurrent tunnels over the one agent connection.
	var chans []ssh.Channel
	for i := 1; i <= 3; i++ {
		payload := ssh.Marshal(tunnelRequest{Label: fmt.Sprintf("target%d", i), ReqID: uint32(i)})
		ch, reqs, err := agentConn.OpenChannel(tunnelChannelType, payload)
		if err != nil {
			fail("proxy could not open channel %d toward agent: %v", i, err)
		}
		go ssh.DiscardRequests(reqs)
		chans = append(chans, ch)
	}
	log.Printf("PASS 1+2: three concurrent channels open over ONE agent connection")

	// (3) bidirectional data on each.
	for i, ch := range chans {
		if err := roundTrip(ch, fmt.Sprintf("hello-from-client-%d", i+1)); err != nil {
			fail("round trip on channel %d: %v", i+1, err)
		}
	}
	log.Printf("PASS 3: bidirectional data confirmed on all three")

	// (4) kill the middle one; the survivors must keep working. This is the
	// v1 bug reproduced as a test.
	if err := chans[1].Close(); err != nil {
		fail("closing channel 2: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	for _, i := range []int{0, 2} {
		if err := roundTrip(chans[i], fmt.Sprintf("still-alive-%d", i+1)); err != nil {
			fail("channel %d died when channel 2 closed: %v", i+1, err)
		}
	}
	log.Printf("PASS 4: closing one channel did NOT collapse the others")

	// A fresh tunnel after a close must also work (v1 hung here).
	payload := ssh.Marshal(tunnelRequest{Label: "target-reconnect", ReqID: 99})
	ch, reqs, err := agentConn.OpenChannel(tunnelChannelType, payload)
	if err != nil {
		fail("could not open a new channel after one closed: %v", err)
	}
	go ssh.DiscardRequests(reqs)
	if err := roundTrip(ch, "second-attempt-works"); err != nil {
		fail("round trip on post-close channel: %v", err)
	}
	log.Printf("PASS 5: new tunnel after a close works (v1 hung here)")

	log.Printf("\nALL CHECKS PASSED")
}

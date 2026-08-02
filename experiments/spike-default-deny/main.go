// Spike 3: what does x/crypto/ssh permit that you did NOT implement?
//
// Paramiko's ServerInterface base class refuses everything by default, so you
// harden by simply not overriding methods. This spike checks whether Go's
// lower-level API gives the same property.
//
// Implemented on purpose, and nothing else:
//   - session  -> print the target list
//   - direct-tcpip -> ONLY to a label in the registry
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

type directTCPIP struct {
	DestHost string
	DestPort uint32
	OrigHost string
	OrigPort uint32
}

// The only reachable destinations. Everything else is not a thing.
var registry = map[string]bool{"server1": true}

func main() {
	log.SetFlags(0)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		log.Fatal(err)
	}

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, nil
		},
		KeyboardInteractiveCallback: func(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:2224")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on 127.0.0.1:2224 (registry: server1)")
	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handle(c, cfg)
	}
}

func handle(c net.Conn, cfg *ssh.ServerConfig) {
	defer c.Close()
	conn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer conn.Close()

	// Global requests: tcpip-forward (ssh -R) arrives here. We must drain this
	// channel or the connection deadlocks; replying false is the refusal.
	go func() {
		for r := range reqs {
			log.Printf("GLOBAL REQ  type=%-28q wantReply=%v  -> replying FALSE", r.Type, r.WantReply)
			if r.WantReply {
				r.Reply(false, nil)
			}
		}
	}()

	for nc := range chans {
		switch nc.ChannelType() {
		case "session":
			ch, chReqs, err := nc.Accept()
			if err != nil {
				continue
			}
			go func() {
				for r := range chReqs {
					// exec / subsystem / x11-req / auth-agent-req all land here.
					ok := r.Type == "shell" || r.Type == "pty-req"
					log.Printf("SESSION REQ type=%-28q -> %v", r.Type, ok)
					if r.WantReply {
						r.Reply(ok, nil)
					}
					if r.Type == "shell" {
						fmt.Fprintf(ch, "\r\nregistered targets: server1\r\n\r\n")
						ch.Close()
					}
				}
			}()

		case "direct-tcpip":
			var d directTCPIP
			if err := ssh.Unmarshal(nc.ExtraData(), &d); err != nil {
				nc.Reject(ssh.ConnectionFailed, "bad payload")
				continue
			}
			if !registry[d.DestHost] {
				log.Printf("DIRECT-TCPIP host=%-20q port=%-5d -> REJECTED (not a registered label)", d.DestHost, d.DestPort)
				nc.Reject(ssh.ConnectionFailed, "no such target")
				continue
			}
			log.Printf("DIRECT-TCPIP host=%-20q port=%-5d -> ALLOWED", d.DestHost, d.DestPort)
			ch, chReqs, err := nc.Accept()
			if err != nil {
				continue
			}
			go ssh.DiscardRequests(chReqs)
			fmt.Fprintf(ch, "you reached the registered target\r\n")
			ch.Close()

		default:
			log.Printf("CHANNEL     type=%-28q -> REJECTED (not implemented)", nc.ChannelType())
			nc.Reject(ssh.UnknownChannelType, "not implemented")
		}
	}
}

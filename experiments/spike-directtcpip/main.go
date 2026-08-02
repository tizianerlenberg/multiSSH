// Spike: what does `ssh -J proxy user@target` actually send to the proxy?
//
// Answers three load-bearing questions for the multiSSH design:
//  1. Does the ssh client resolve the target hostname locally, or pass it through?
//  2. Do arbitrary (non-DNS) labels survive as the direct-tcpip destination?
//  3. Which username lands on the proxy vs. which is meant for the target?
//
// Throwaway code: accepts any credential, generates a fresh host key each run.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

// RFC 4254 section 7.2 direct-tcpip channel payload.
type directTCPIP struct {
	DestHost string
	DestPort uint32
	OrigHost string
	OrigPort uint32
}

func main() {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		log.Fatal(err)
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			log.Printf("AUTH pubkey     user=%q fp=%s type=%s client=%q",
				c.User(), ssh.FingerprintSHA256(key), key.Type(), c.ClientVersion())
			return nil, nil
		},
		KeyboardInteractiveCallback: func(c ssh.ConnMetadata, _ ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			log.Printf("AUTH kbd-inter  user=%q", c.User())
			return nil, nil
		},
	}
	config.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:2222")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("proxy spike listening on 127.0.0.1:2222")

	for {
		c, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handle(c, config)
	}
}

func handle(c net.Conn, config *ssh.ServerConfig) {
	defer c.Close()

	conn, chans, reqs, err := ssh.NewServerConn(c, config)
	if err != nil {
		log.Printf("handshake failed: %v", err)
		return
	}
	defer conn.Close()
	log.Printf("CONNECTED    user=%q version=%q", conn.User(), conn.ClientVersion())

	go func() {
		for r := range reqs {
			log.Printf("GLOBAL REQ   type=%q wantReply=%v len=%d", r.Type, r.WantReply, len(r.Payload))
			if r.WantReply {
				r.Reply(false, nil)
			}
		}
	}()

	for nc := range chans {
		log.Printf("CHANNEL      type=%q extraDataLen=%d", nc.ChannelType(), len(nc.ExtraData()))

		switch nc.ChannelType() {
		case "direct-tcpip":
			var d directTCPIP
			if err := ssh.Unmarshal(nc.ExtraData(), &d); err != nil {
				log.Printf("  !! unmarshal failed: %v", err)
				nc.Reject(ssh.ConnectionFailed, "bad payload")
				continue
			}
			log.Printf("  >> TARGET REQUESTED: host=%q port=%d (origin %s:%d)",
				d.DestHost, d.DestPort, d.OrigHost, d.OrigPort)
			nc.Reject(ssh.Prohibited, "spike: logged, not forwarding")

		case "session":
			ch, chReqs, err := nc.Accept()
			if err != nil {
				continue
			}
			go func() {
				for r := range chReqs {
					log.Printf("  SESSION REQ type=%q", r.Type)
					if r.WantReply {
						r.Reply(r.Type == "shell" || r.Type == "pty-req", nil)
					}
				}
			}()
			fmt.Fprintf(ch, "\r\nmultiSSH spike: you reached the proxy shell.\r\n")
			fmt.Fprintf(ch, "Registered targets would be listed here.\r\n\r\n")
			ch.Close()

		default:
			nc.Reject(ssh.UnknownChannelType, "unsupported")
		}
	}
	log.Printf("DISCONNECTED user=%q", conn.User())
}

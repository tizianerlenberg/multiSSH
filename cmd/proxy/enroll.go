package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
	"multissh/internal/sshx"
)

// Enrolment hands a machine its identity: the proxy signs the identity key it
// generated locally and derives its canonical name from its host key. Nothing
// is stored here, so this endpoint adds no state to back up.
//
// A password rather than a one-time token, with a lifetime chosen when it is
// created, because adding a machine has to stay easy enough that it actually
// gets done. The lifetime bounds the exposure instead of a ceremony at install
// time.

const (
	// enrolRateWindow/Burst bound guessing. Enrolment is rare and manual, so
	// this can be strict without being felt.
	enrolRateWindow = time.Minute
	enrolRateBurst  = 5

	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
)

// password is one enrolment credential. Stored hashed, with an expiry.
type password struct {
	Name    string    `json:"name"`
	Salt    string    `json:"salt"`
	Hash    string    `json:"hash"`
	Expires time.Time `json:"expires"` // zero means never
}

func (p password) expired() bool {
	return !p.Expires.IsZero() && time.Now().After(p.Expires)
}

func (p password) matches(candidate string) bool {
	salt, err := base64.RawStdEncoding.DecodeString(p.Salt)
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(p.Hash)
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(candidate), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return subtle.ConstantTimeCompare(got, want) == 1
}

func newPassword(name, secret string, lifetime time.Duration) (password, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return password{}, err
	}
	hash := argon2.IDKey([]byte(secret), salt, argonTime, argonMemory, argonThreads, argonKeyLen)

	p := password{
		Name: name,
		Salt: base64.RawStdEncoding.EncodeToString(salt),
		Hash: base64.RawStdEncoding.EncodeToString(hash),
	}
	if lifetime > 0 {
		p.Expires = time.Now().Add(lifetime)
	}
	return p, nil
}

func loadPasswords(path string) ([]password, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []password
	return out, json.Unmarshal(data, &out)
}

func savePasswords(path string, list []password) error {
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// limiter is a small fixed-window counter, keyed by client address.
type limiter struct {
	mu     sync.Mutex
	seen   map[string][]time.Time
	window time.Duration
	burst  int
}

func newLimiter(window time.Duration, burst int) *limiter {
	return &limiter{seen: make(map[string][]time.Time), window: window, burst: burst}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := time.Now().Add(-l.window)
	kept := l.seen[key][:0]
	for _, t := range l.seen[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.burst {
		l.seen[key] = kept
		return false
	}
	l.seen[key] = append(kept, time.Now())
	return true
}

type enrolRequest struct {
	Password string `json:"password"`
	Name     string `json:"name"`
	IdentKey string `json:"identity_key"` // authorized_keys form
	HostKey  string `json:"host_key"`
	Version  string `json:"version"`
	Platform string `json:"platform"`
}

type enrolResponse struct {
	Certificate string   `json:"certificate"`
	CA          string   `json:"ca"`
	Authorized  string   `json:"authorized_keys"`
	Proxies     []string `json:"proxies"`
	Canonical   string   `json:"canonical"`
	Friendly    string   `json:"friendly"`
}

// enroller answers POST /enroll.
type enroller struct {
	ca        ssh.Signer
	passwords []password
	usersFile string
	proxies   []string
	limit     *limiter
	validity  time.Duration
}

func (e *enroller) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	who := clientAddr(r)
	if !e.limit.allow(who) {
		http.Error(w, "too many attempts", http.StatusTooManyRequests)
		return
	}

	var req enrolRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	// Check every password even after a match, so timing does not reveal
	// which credential was used or how many exist.
	var ok bool
	var used string
	for _, p := range e.passwords {
		if p.matches(req.Password) && !p.expired() {
			ok, used = true, p.Name
		}
	}
	if !ok {
		logf("enrol refused from %s: bad or expired password", who)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	identPub, err := parseAuthorizedKey(req.IdentKey)
	if err != nil {
		http.Error(w, "bad identity key", http.StatusBadRequest)
		return
	}
	hostPub, err := parseAuthorizedKey(req.HostKey)
	if err != nil {
		http.Error(w, "bad host key", http.StatusBadRequest)
		return
	}

	name := strings.ToLower(strings.TrimSpace(req.Name))
	if !sshx.ValidFriendlyName(name) {
		http.Error(w, "name must be lowercase letters, digits and dashes, with no dot", http.StatusBadRequest)
		return
	}

	canonical, err := sshx.CanonicalName(name, hostPub)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cert, err := sshx.SignCert(e.ca, identPub, ssh.UserCert, canonical,
		[]string{canonical, name}, e.validity)
	if err != nil {
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}

	authorized, err := os.ReadFile(e.usersFile)
	if err != nil {
		http.Error(w, "no authorized keys configured", http.StatusInternalServerError)
		return
	}

	logf("enrolled %s (%s) with password %q from %s", canonical, req.Platform, used, who)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(enrolResponse{
		Certificate: string(ssh.MarshalAuthorizedKey(cert)),
		CA:          string(ssh.MarshalAuthorizedKey(e.ca.PublicKey())),
		Authorized:  string(authorized),
		Proxies:     e.proxies,
		Canonical:   canonical,
		Friendly:    name,
	})
}

func parseAuthorizedKey(s string) (ssh.PublicKey, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(s)))
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	return pub, nil
}

// clientAddr prefers the address a reverse proxy reports, since every request
// otherwise appears to come from loopback.
//
// The port must be stripped. RemoteAddr carries one, and every new connection
// gets a new port, so keying a rate limit on it counts each attempt separately
// and limits nothing whatsoever.
func clientAddr(r *http.Request) string {
	if f := r.Header.Get("X-Forwarded-For"); f != "" {
		first, _, _ := strings.Cut(f, ",")
		return strings.TrimSpace(first)
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// logf mirrors the package's logging style without importing log here twice.
func logf(format string, args ...any) { stdLogf(format, args...) }

// managePasswords creates, lists and deletes enrolment credentials. The secret
// is read from the terminal rather than a flag, since a password on the command
// line lands in shell history and in ps output.
func managePasswords(path, add, remove string, list bool, validity time.Duration) error {
	pws, err := loadPasswords(path)
	if err != nil {
		return err
	}

	switch {
	case list:
		if len(pws) == 0 {
			fmt.Println("no enrolment passwords")
			return nil
		}
		for _, p := range pws {
			when := "never expires"
			switch {
			case p.expired():
				when = "EXPIRED " + p.Expires.Format(time.RFC3339)
			case !p.Expires.IsZero():
				when = "expires " + p.Expires.Format(time.RFC3339)
			}
			fmt.Printf("  %-20s %s\n", p.Name, when)
		}
		return nil

	case remove != "":
		kept := pws[:0]
		found := false
		for _, p := range pws {
			if p.Name == remove {
				found = true
				continue
			}
			kept = append(kept, p)
		}
		if !found {
			return fmt.Errorf("no password named %q", remove)
		}
		fmt.Printf("removed %q\n", remove)
		return savePasswords(path, kept)

	default:
		secret, err := readSecret("enrollment password for " + add + ": ")
		if err != nil {
			return err
		}
		if len(secret) < 8 {
			return fmt.Errorf("use at least 8 characters")
		}
		p, err := newPassword(add, secret, validity)
		if err != nil {
			return err
		}
		for _, existing := range pws {
			if existing.Name == add {
				return fmt.Errorf("a password named %q already exists", add)
			}
		}
		if err := savePasswords(path, append(pws, p)); err != nil {
			return err
		}
		when := "never expires"
		if validity > 0 {
			when = "expires " + p.Expires.Format(time.RFC3339)
		}
		fmt.Printf("created %q, %s\n", add, when)
		return nil
	}
}

func readSecret(prompt string) (string, error) {
	if env := os.Getenv("MULTISSH_NEW_PASSWORD"); env != "" {
		return env, nil
	}
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return "", fmt.Errorf("no terminal to read a password from; set MULTISSH_NEW_PASSWORD")
	}
	defer tty.Close()
	fmt.Fprint(tty, prompt)
	secret, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(tty)
	return string(secret), err
}

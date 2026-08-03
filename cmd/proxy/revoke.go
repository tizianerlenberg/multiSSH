package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Revocation, and why it works on fingerprints.
//
// Certificates never expire by default, which is deliberate -- a machine
// switched off longer than its certificate lasts would otherwise lock itself
// out, in exactly the emergency this tool exists for. That trade is only
// honest if there is some other way to cut a machine off, and this is it.
//
// The handle is the SHA256 fingerprint of the agent's *identity key*, not the
// certificate serial. The proxy already computes it at authentication time and
// it survives re-issuing the certificate, whereas revoking by serial would
// need a name-to-serial map -- exactly the growing state the certificate
// design removed, and the thing whose loss used to mean re-enrolling every
// machine.
//
// Unlike friendly_labels and last_seen, this file is NOT advisory. Losing it
// un-revokes every entry, so it belongs with proxy_ca_key in whatever backup
// exists. That is the cost of holding no other state, and it is stated in the
// file's own header so it cannot be discovered too late.

// revocationSweep is how often the file is re-read and live agents matched
// against it. Revoking therefore takes effect within this long, on connections
// already established as well as on the next attempt.
const revocationSweep = 30 * time.Second

// revocations is the set of barred identity fingerprints, reloaded from disk so
// revoking does not require restarting the proxy and dropping every session.
type revocations struct {
	mu    sync.RWMutex
	path  string
	m     map[string]string // fingerprint -> note
	stamp string            // size and mtime, to skip re-reading an unchanged file
}

func openRevocations(path string) (*revocations, error) {
	r := &revocations{path: path, m: make(map[string]string)}
	if _, err := r.reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// reload re-reads the file if it has changed, reporting whether it did.
func (r *revocations) reload() (bool, error) {
	stamp := ""
	if fi, err := os.Stat(r.path); err == nil {
		stamp = fmt.Sprintf("%d/%d", fi.Size(), fi.ModTime().UnixNano())
	} else if !os.IsNotExist(err) {
		return false, err
	}

	r.mu.RLock()
	same := stamp == r.stamp
	r.mu.RUnlock()
	if same {
		return false, nil
	}

	m, err := readRevocations(r.path)
	if err != nil {
		return false, err
	}
	r.mu.Lock()
	r.m, r.stamp = m, stamp
	r.mu.Unlock()
	return true, nil
}

func readRevocations(path string) (map[string]string, error) {
	m := make(map[string]string)
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fp, note, _ := strings.Cut(line, " ")
		m[fp] = strings.TrimSpace(note)
	}
	return m, sc.Err()
}

// revoked reports whether a fingerprint is barred, and the note recorded with
// it. An empty note still counts: presence is the decision.
func (r *revocations) revoked(fp string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	note, ok := r.m[fp]
	return note, ok
}

func (r *revocations) count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.m)
}

// sweep drops any connected agent whose key has since been revoked. Checking
// only at authentication would leave a machine revoked today connected until it
// next reconnects, which for a healthy agent is never.
func (r *revocations) sweep(reg *registry) {
	if r.count() == 0 {
		return
	}
	for conn, fp := range reg.connections() {
		if note, yes := r.revoked(fp); yes {
			log.Printf("dropping revoked agent %s (%s)", fp, note)
			conn.Close()
		}
	}
}

// watch keeps the in-memory set current and enforces it against live
// connections.
func (r *revocations) watch(reg *registry) {
	t := time.NewTicker(revocationSweep)
	defer t.Stop()
	for range t.C {
		changed, err := r.reload()
		if err != nil {
			log.Printf("revocations: %v", err)
			continue
		}
		if changed {
			log.Printf("revocations reloaded: %d key(s) barred", r.count())
		}
		r.sweep(reg)
	}
}

// validFingerprint checks the shape of what OpenSSH prints. A typo here would
// revoke nothing while looking like it had worked, which for a security control
// is the worst possible outcome, so this refuses rather than guesses.
func validFingerprint(fp string) error {
	if !strings.HasPrefix(fp, "SHA256:") {
		return fmt.Errorf("expected a SHA256: fingerprint as shown by `ssh proxy` or in the proxy log, got %q", fp)
	}
	if body := strings.TrimPrefix(fp, "SHA256:"); len(body) != 43 {
		return fmt.Errorf("%q is not a full SHA256 fingerprint (want 43 characters after the prefix, got %d)", fp, len(body))
	}
	return nil
}

// manageRevocations implements -revoke, -unrevoke and -list-revoked.
func manageRevocations(path, add, remove string, list bool, note, ledgerPath string) error {
	m, err := readRevocations(path)
	if err != nil {
		return err
	}

	switch {
	case list:
		if len(m) == 0 {
			fmt.Println("no revoked keys")
			return nil
		}
		fps := make([]string, 0, len(m))
		for fp := range m {
			fps = append(fps, fp)
		}
		sort.Strings(fps)
		for _, fp := range fps {
			fmt.Printf("  %s  %s\n", fp, m[fp])
		}
		return nil

	case remove != "":
		if _, ok := m[remove]; !ok {
			return fmt.Errorf("%q is not revoked", remove)
		}
		delete(m, remove)
		if err := writeRevocations(path, m); err != nil {
			return err
		}
		fmt.Printf("un-revoked %s\n", remove)
		fmt.Printf("the machine can register again as soon as the proxy re-reads the file (within %s)\n", revocationSweep)
		return nil

	default:
		if err := validFingerprint(add); err != nil {
			return err
		}
		if _, already := m[add]; already {
			fmt.Printf("%s was already revoked\n", add)
			return nil
		}
		// A fingerprint no machine has ever presented is almost certainly a
		// mistyped one. The ledger is not a complete record -- a target that
		// never held a friendly name is absent -- so this warns rather than
		// refuses.
		if known, err := knownFingerprints(ledgerPath); err == nil && len(known) > 0 && !known[add] {
			fmt.Printf("warning: no machine in %s has that fingerprint; check for a typo\n", ledgerPath)
		}
		if note == "" {
			note = time.Now().UTC().Format("2006-01-02") + " revoked"
		}
		m[add] = note
		if err := writeRevocations(path, m); err != nil {
			return err
		}
		fmt.Printf("revoked %s (%s)\n", add, note)
		fmt.Printf("a running proxy picks this up and drops the machine within %s\n", revocationSweep)
		fmt.Printf("note: this bars the key, not the machine. Someone holding a valid enrolment\n")
		fmt.Printf("password could enrol it afresh under a new key, so remove that too if the\n")
		fmt.Printf("machine is out of your hands: -remove-password\n")
		return nil
	}
}

// knownFingerprints reads the friendly-name ledger for fingerprints the proxy
// has actually seen, purely to sanity-check a revocation.
func knownFingerprints(ledgerPath string) (map[string]bool, error) {
	l, err := openLedger(ledgerPath)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(l.m))
	for _, fp := range l.m {
		out[fp] = true
	}
	return out, nil
}

func writeRevocations(path string, m map[string]string) error {
	var b strings.Builder
	b.WriteString("# multiSSH revoked agent identity keys, one SHA256 fingerprint per line.\n")
	b.WriteString("#\n")
	b.WriteString("# NOT advisory, unlike friendly_labels and last_seen: losing this file\n")
	b.WriteString("# un-revokes every entry below. Back it up alongside proxy_ca_key.\n")
	b.WriteString("#\n")
	b.WriteString("# Edit with -revoke / -unrevoke; a running proxy re-reads it on its own.\n")

	fps := make([]string, 0, len(m))
	for fp := range m {
		fps = append(fps, fp)
	}
	sort.Strings(fps)
	for _, fp := range fps {
		fmt.Fprintf(&b, "%s %s\n", fp, m[fp])
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

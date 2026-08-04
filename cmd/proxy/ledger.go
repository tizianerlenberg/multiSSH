package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

// ledger binds friendly names to the machine that owns them.
//
// It is deliberately *advisory*. Losing it costs a convenient name and nothing
// else, because every target stays reachable under its canonical name, which is
// derived rather than recorded. That is the property the old list of registered
// agent keys lacked: losing that meant re-enrolling every machine, which is
// impossible in the situation this tool exists for. So this file never needs
// backing up, and the proxy remains restorable from the CA key alone.
type ledger struct {
	mu   sync.Mutex
	path string
	m    map[string]string // friendly name -> agent identity fingerprint
}

func openLedger(path string) (*ledger, error) {
	l := &ledger{path: path, m: make(map[string]string)}

	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return l, nil
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
		if name, fp, ok := strings.Cut(line, " "); ok {
			l.m[name] = strings.TrimSpace(fp)
		}
	}
	return l, sc.Err()
}

// claim decides whether name may be served for the machine identified by fp.
//
// An unheld name is bound on first sight, so a rebuilt proxy heals itself as
// machines come back rather than needing every friendly name re-asserted. The
// window in which that could bind the wrong machine is the minutes after a
// rebuild, and it is bounded: the canonical name is unaffected, and your own
// known_hosts entry catches a friendly name that moves.
func (l *ledger) claim(name, fp string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if owner, held := l.m[name]; held {
		return owner == fp
	}
	l.m[name] = fp
	if err := l.appendLine(name, fp); err != nil {
		// Not fatal: the binding still holds for this run.
		fmt.Fprintf(os.Stderr, "ledger: could not record %q: %v\n", name, err)
	}
	return true
}

func (l *ledger) appendLine(name, fp string) error {
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s %s\n", name, fp)
	return err
}

// forget drops a friendly name, so a machine reinstalled from scratch can
// claim it again.
//
// Without this, reinstalling is a trap: the new install generates a new
// identity key, the ledger still binds the name to the old one, and the
// machine comes back reachable under its canonical name only -- correct by the
// rules, and baffling if you do not know the rules.
func (l *ledger) forget(name string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, held := l.m[name]; !held {
		return false
	}
	delete(l.m, name)
	return l.rewrite() == nil
}

// rewrite replaces the file with the current bindings. The normal path only
// appends, so this is the one place the whole file is rendered.
func (l *ledger) rewrite() error {
	var b strings.Builder
	b.WriteString("# friendly name -> agent identity fingerprint.\n")
	b.WriteString("# Advisory: losing this costs a convenient name, never access.\n")
	names := make([]string, 0, len(l.m))
	for n := range l.m {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(&b, "%s %s\n", n, l.m[n])
	}
	return os.WriteFile(l.path, []byte(b.String()), 0o600)
}

// reload re-reads the file, so an edit made while the proxy runs takes effect
// without a restart that would drop every agent.
func (l *ledger) reload() error {
	fresh, err := openLedger(l.path)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.m = fresh.m
	return nil
}

package main

import (
	"bufio"
	"fmt"
	"os"
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

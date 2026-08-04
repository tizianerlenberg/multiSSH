package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// sightings records when each target was last connected.
//
// A rescue tool's real enemy is silent decay: an agent that quietly stopped
// months ago is discovered during the emergency it was meant to cover. The
// registry only knows who is here *now*, so without this there is no way to
// notice an absence. Advisory like the friendly-name ledger -- losing it costs
// history, never access.
type sightings struct {
	mu   sync.Mutex
	path string
	m    map[string]time.Time
}

func openSightings(path string) (*sightings, error) {
	s := &sightings{path: path, m: make(map[string]time.Time)}

	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return s, nil
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
		name, stamp, ok := strings.Cut(line, " ")
		if !ok {
			continue
		}
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(stamp)); err == nil {
			s.m[name] = t
		}
	}
	return s, sc.Err()
}

func (s *sightings) seen(name string) {
	s.mu.Lock()
	s.m[name] = time.Now().UTC()
	s.mu.Unlock()
	s.save()
}

// sighting is one target and when it was last connected.
type sighting struct {
	Name string
	When time.Time
}

// known returns every target ever seen, oldest sighting first, so the ones
// worth worrying about are at the top.
func (s *sightings) known() []sighting {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]sighting, 0, len(s.m))
	for n, t := range s.m {
		out = append(out, sighting{n, t})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].When.Before(out[j].When) })
	return out
}

// staleSince returns every target whose last sighting predates cutoff, oldest
// first.
//
// One gap worth naming: a machine that enrolled and never once connected is
// not here to be missed, because enrolment writes nothing to the proxy. The
// installer reports success from the target, so that case is visible there
// instead.
func (s *sightings) staleSince(cutoff time.Time) []sighting {
	var out []sighting
	for _, k := range s.known() {
		if k.When.Before(cutoff) {
			out = append(out, k)
		}
	}
	return out
}

func (s *sightings) save() {
	s.mu.Lock()
	defer s.mu.Unlock()

	var b strings.Builder
	b.WriteString("# target\tlast seen (UTC). Advisory: losing this costs history only.\n")
	names := make([]string, 0, len(s.m))
	for n := range s.m {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(&b, "%s %s\n", n, s.m[n].Format(time.RFC3339))
	}
	os.WriteFile(s.path, []byte(b.String()), 0o600)
}

// ago renders a duration the way a person reads it.
func ago(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// forget drops a target from the history, for a machine that is gone for good
// rather than merely absent.
func (s *sightings) forget(name string) bool {
	s.mu.Lock()
	_, known := s.m[name]
	if known {
		delete(s.m, name)
	}
	s.mu.Unlock()
	if known {
		s.save()
	}
	return known
}

// reload re-reads the file so an edit lands without a restart.
func (s *sightings) reload() error {
	fresh, err := openSightings(s.path)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m = fresh.m
	return nil
}

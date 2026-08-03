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

// known returns every target ever seen, oldest sighting first, so the ones
// worth worrying about are at the top.
func (s *sightings) known() []struct {
	Name string
	When time.Time
} {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]struct {
		Name string
		When time.Time
	}, 0, len(s.m))
	for n, t := range s.m {
		out = append(out, struct {
			Name string
			When time.Time
		}{n, t})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].When.Before(out[j].When) })
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

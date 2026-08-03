package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	_ "embed"

	"golang.org/x/crypto/ssh"
)

//go:embed scripts/install.sh
var installShTemplate string

// The proxy serves the installer and the agent binaries itself rather than
// pointing at a release host. It has to be reachable for the agent to work at
// all, so serving from here adds no failure mode -- and it can bake its own
// authority into the script, which removes the trust-on-first-use window for
// the agent's very first connect.

// distributor serves agent binaries from a directory and knows their hashes.
type distributor struct {
	dir     string
	mu      sync.RWMutex
	hashes  map[string]string // "linux-amd64" -> sha256
	version string
}

func newDistributor(dir string) *distributor {
	d := &distributor{dir: dir, hashes: map[string]string{}}
	d.scan()
	return d
}

// scan hashes whatever builds are present. Missing binaries are not fatal: the
// proxy still routes sessions, and the installer says plainly that there is no
// build for the platform asking.
func (d *distributor) scan() {
	entries, err := os.ReadDir(d.dir)
	if err != nil {
		return
	}
	h := map[string]string{}
	combined := sha256.New()
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.Contains(e.Name(), "-") {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	for _, name := range names {
		sum, err := hashFile(filepath.Join(d.dir, name))
		if err != nil {
			continue
		}
		h[name] = sum
		fmt.Fprintf(combined, "%s:%s\n", name, sum)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	d.hashes = h
	d.version = "none"
	if len(h) > 0 {
		d.version = hex.EncodeToString(combined.Sum(nil))[:12]
	}
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	sum := sha256.New()
	if _, err := io.Copy(sum, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

func (d *distributor) snapshot() (map[string]string, string) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make(map[string]string, len(d.hashes))
	for k, v := range d.hashes {
		out[k] = v
	}
	return out, d.version
}

// serveBinary hands over one build. The path element is matched against known
// builds rather than joined onto the directory, so nothing a client sends
// reaches the filesystem.
func (d *distributor) serveBinary(w http.ResponseWriter, r *http.Request) {
	want := strings.TrimPrefix(r.URL.Path, "/dist/")
	hashes, _ := d.snapshot()
	if _, ok := hashes[want]; !ok {
		http.Error(w, "no build for that platform", http.StatusNotFound)
		return
	}
	http.ServeFile(w, r, filepath.Join(d.dir, want))
}

// installScript renders the installer for this proxy: its address, its
// authority, and the checksums of the builds it is currently serving.
func installScript(d *distributor, caPub ssh.PublicKey, baseURL string, proxies []string) string {
	hashes, version := d.snapshot()

	pairs := make([]string, 0, len(hashes))
	for platform, sum := range hashes {
		pairs = append(pairs, platform+":"+sum)
	}
	sort.Strings(pairs)

	r := strings.NewReplacer(
		"__BASE_URL__", baseURL,
		"__PROXIES__", strings.Join(proxies, ","),
		"__CA__", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(caPub))),
		"__VERSION__", version,
		"__HASHES__", strings.Join(pairs, " "),
	)
	return r.Replace(installShTemplate)
}

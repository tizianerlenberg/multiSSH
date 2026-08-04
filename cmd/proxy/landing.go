package main

import (
	"html/template"
	"net/http"
	"strings"
)

// A page at / with the install commands and a button that copies them.
//
// The commands are long, exact, and typed on a machine that by definition has
// no convenient way to get text onto it -- that is the situation the whole
// tool exists for. Reading a wss:// URL off a screen and retyping it is how
// installs go wrong.
//
// Nothing here is secret. Everything on this page is already served
// unauthenticated at /install.sh and /install.ps1, and enrolment still needs
// the password, which is deliberately not shown.

var landingTemplate = template.Must(template.New("landing").Parse(`<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>multiSSH</title>
<style>
  :root { color-scheme: light dark; --fg:#111; --bg:#fff; --mut:#666; --line:#d8d8d8; --code:#f4f4f4; }
  @media (prefers-color-scheme: dark) {
    :root { --fg:#e6e6e6; --bg:#16181c; --mut:#9aa0a6; --line:#2c3038; --code:#20242b; }
  }
  body { margin:0 auto; padding:2.5rem 1.25rem 4rem; max-width:46rem; background:var(--bg); color:var(--fg);
         font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; }
  h1 { font-size:1.5rem; margin:0 0 .25rem; }
  h2 { font-size:1rem; margin:2rem 0 .5rem; text-transform:uppercase; letter-spacing:.06em; color:var(--mut); }
  p  { color:var(--mut); margin:.25rem 0 1rem; }
  .box { position:relative; border:1px solid var(--line); border-radius:8px; background:var(--code); }
  pre { margin:0; padding:1rem 5.5rem 1rem 1rem; overflow-x:auto; font:13px/1.55 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; }
  button { position:absolute; top:.55rem; right:.55rem; padding:.35rem .7rem; font:inherit; font-size:.8rem;
           border:1px solid var(--line); border-radius:6px; background:var(--bg); color:var(--fg); cursor:pointer; }
  button:hover { border-color:var(--mut); }
  button.done { color:#137333; border-color:#137333; }
  footer { margin-top:2.5rem; border-top:1px solid var(--line); padding-top:1rem; font-size:.85rem; color:var(--mut); }
  code { background:var(--code); padding:.1rem .3rem; border-radius:4px; font-size:.9em; }
</style>

<h1>multiSSH</h1>
<p>Run one of these on a machine to make it reachable through this proxy.
   You will be asked for an enrolment password.</p>

<h2>Linux &amp; macOS</h2>
<div class="box"><button>copy</button><pre>curl -fsSL {{.BaseURL}}/install.sh | sudo sh</pre></div>
<p>Without <code>sudo</code> it installs for your user only, and is reachable
   only while you are logged in.</p>

<h2>Windows</h2>
<div class="box"><button>copy</button><pre>irm {{.BaseURL}}/install.ps1 -OutFile $env:TEMP\ms.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\ms.ps1</pre></div>
<p>Run it in an <strong>Administrator</strong> PowerShell to install a machine-wide
   service, or an ordinary one to install for yourself. Saving to a file first
   is deliberate: piping into <code>iex</code> closes your window if anything
   goes wrong, and cannot take options.</p>

<h2>Then</h2>
{{if .UserHost}}<div class="box"><button>copy</button><pre>ssh {{.UserHost}}</pre></div>{{else}}<div class="box"><pre>ssh &lt;this proxy&gt;</pre></div>{{end}}
<p>Lists what is connected, and shows each target's host key so you can check it
   on first connect.</p>

<footer>
  {{.Builds}} agent build{{if ne .Builds 1}}s{{end}} available, version <code>{{.Version}}</code>.
  This page is public; enrolment still needs the password.
</footer>

<script>
for (const b of document.querySelectorAll('button')) {
  b.addEventListener('click', async () => {
    const text = b.parentElement.querySelector('pre').textContent;
    try { await navigator.clipboard.writeText(text); }
    catch { // clipboard API needs a secure context; select the text instead
      const r = document.createRange();
      r.selectNodeContents(b.parentElement.querySelector('pre'));
      getSelection().removeAllRanges(); getSelection().addRange(r);
      b.textContent = 'select + copy'; return;
    }
    b.textContent = 'copied'; b.classList.add('done');
    setTimeout(() => { b.textContent = 'copy'; b.classList.remove('done'); }, 1500);
  });
}
</script>
`))

// serveLanding renders the page. userHost is only a hint for the ssh example;
// the proxy has no reliable way to know the address and port a client reaches
// it on, since that side deliberately bypasses the reverse proxy.
func serveLanding(dist *distributor, baseURL, userHost string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		hashes, version := dist.snapshot()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		landingTemplate.Execute(w, struct {
			BaseURL  string
			UserHost string
			Builds   int
			Version  string
		}{
			BaseURL:  strings.TrimSuffix(baseURL, "/"),
			UserHost: userHost,
			Builds:   len(hashes),
			Version:  version,
		})
	}
}

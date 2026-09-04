# Operations

Installing targets, deploying and updating the proxy, managing who can log
in, and running behind a reverse proxy. See the [README](../README.md) for
the overview.

---

## Installing a target

The proxy serves a page at its own address with the install commands and a
button that copies them — worth having, because the machine you are installing
on is by definition one with no convenient way to get text onto it.


The proxy serves the installer and the agent builds itself. It has to be
reachable for the agent to work at all, so serving from it adds no failure mode
— and it can bake **its own authority into the script**, so the agent pins the
right one from its first connect and there is no trust-on-first-use window for
the agent-to-proxy hop.

```bash
# on the target
curl -fsSL https://multissh.example.com/install.sh | sudo sh          # linux, macos
irm https://multissh.example.com/install.ps1 | iex                    # windows, elevated
```

Re-running the installer on an enrolled machine updates it rather than
enrolling a second identity; `--reenroll` forces a fresh one.

### Update trust

There are two ways an agent's binary gets replaced, and they trust different
things.

**The trusted way — `deploy/update-agents.sh`, from your workstation.** For
Linux and macOS this **pushes the binary over the authenticated ssh session**,
encrypted end-to-end to the target's host key, and installs it without the
target fetching anything from the proxy. The proxy only relays ciphertext — the
same reason it is out of the trust chain for your interactive sessions — so it
cannot substitute a binary it never carries. **A proxy that has turned hostile
cannot push code to your machines this way.** No signing key, nothing extra to
back up: the trust anchor is the ssh user key already in the target's
`authorized_keys`. The one bootstrap it cannot cover is the *first* install,
which is trust-on-first-use in the proxy by necessity; every update after that
is proxy-independent.

**The proxy-trusting way — `manage.sh --update`, run on the target.** This
fetches the installer from the proxy over HTTPS and runs it as root, with the
hash baked into that same fetched script by the same server. So whatever can
serve or tamper with the primary's HTTPS response can run code as root on that
machine. This path still exists for convenience and is what **Windows** currently
uses (the pushed path is not yet proven on real Windows hardware). Prefer the
workstation sweep for anything you want to keep out of the proxy's reach.

Either way, updates are **operator-driven** — nothing is pushed on its own, and
the agent has no self-update path.

It asks two things — the machine's name, defaulting to the hostname, and the
enrollment password — shows every path it will touch, and takes one
confirmation. Answering `c` walks each setting. Scope follows reality: root
installs system-wide, anyone else installs for themselves.

**Private keys are generated on the target and never transmitted.** Only public
halves are sent for signing, which is what keeps the proxy out of the trust
chain for your *sessions* afterwards. Installation is a moment you trust the
proxy, since it serves the binary — and, being honest, so is **every update**,
which re-fetches the installer and runs it as root. That trust is not bounded to
install day; it is re-extended each time you update. See [Update trust](#update-trust).

The script and a manifest of what it installed are saved beside the agent:

```bash
sh /var/lib/multissh-agent/manage.sh --update      # binary only; keys untouched
sh /var/lib/multissh-agent/manage.sh --rollback    # back to the previous binary
sh /var/lib/multissh-agent/manage.sh --uninstall
```

**These are safe to run over the tunnel itself**, which matters because for a
machine behind NAT that is the only way to reach it. On Windows the restart is
handed to Task Scheduler as a one-shot task rather than performed in place: the
session is hosted by the process being restarted, so stopping it would kill the
update halfway through. The agent returns a few seconds after the command
finishes. See
[Updating agents](#updating-agents) for why that took some doing.

Piped from curl, options go after `--`:
`curl -fsSL … | sudo sh -s -- --uninstall`. Unattended installs read
`MULTISSH_PASSWORD` and friends, and the script detects the absence of a
terminal rather than hanging on a prompt.

### Managing enrolment passwords

```bash
multissh-proxy -passwords /var/lib/multissh/enrol_passwords.json -list-passwords
multissh-proxy -passwords ... -add-password laptops -password-validity 720h
multissh-proxy -passwords ... -remove-password laptops
systemctl reload multissh-proxy      # picks it up; no agent is disconnected
```

There is no "change" command: passwords are stored only as argon2id hashes, so
there is nothing to edit. Replace one by removing it and adding it again under
the same name. Names are create-only, and the clash is reported *before* you
are asked to type anything.

**The reload is not optional.** Passwords are held in memory, so until the
proxy re-reads the file a withdrawn password keeps working. Run it as root and
hand the file back: the password is read from your terminal and a service
account cannot open a terminal owned by you.

```bash
sudo multissh-proxy -passwords /var/lib/multissh/enrol_passwords.json -add-password laptops
sudo chown multissh:multissh /var/lib/multissh/enrol_passwords.json
sudo systemctl reload multissh-proxy
```

Passwords are argon2id-hashed with a lifetime chosen when created, `/enroll` is
rate limited, and enrolment writes nothing to the proxy — so none of this adds
anything to back up. A revoked identity key is refused at `/enroll` too, rather
than being handed a certificate that would then fail forever at connect time.

---

## Deploying the proxy

One command from your own machine, first time and every time after:

```bash
sh deploy/push.sh root@vps --public-url https://multissh.example.com   # first install
sh deploy/push.sh root@vps                                            # every update after
```

It builds all five platforms plus the proxy, ships them over ssh, and runs
`deploy/install-proxy.sh` on the far end, which creates the `multissh` system
user, the state directory and a hardened unit, then reports `/healthz`.

It finishes by reading `/healthz` and checking the `build` there against the
binary it just shipped, so a deployment is confirmed rather than assumed — a
command exiting zero is not evidence the new binary is the one running.

It is **safe to run against a live proxy**, and acts only on what changed:

| What changed | What happens |
|---|---|
| nothing | nothing |
| agent builds only | `systemctl reload` — **no agent loses its connection** |
| the proxy binary | a restart; agents reconnect on their own in a second or two |

The unit is written on first install and **never overwritten**, so flags you
edit on the server survive every later push. `install-proxy.sh` can also be run
by hand on the box; `push.sh` only builds, copies and calls it.

## Updating agents

```bash
sh deploy/update-agents.sh multissh          # every target reported OUTDATED
sh deploy/update-agents.sh multissh laptop   # just this one
sh deploy/update-agents.sh multissh --stop   # stop at the first failure
sh deploy/update-agents.sh multissh --yes    # do not ask about Windows
```

**Windows targets are asked about one at a time** and skipped unless confirmed,
including when there is no terminal to ask at. Updating one restarts it, and a
restart that does not take leaves the machine offline — which for a rescue tool
means losing the way back in. Linux and macOS restart through systemd or
launchd and have not shown that problem, so they go without asking.

Every step is bounded and a machine that does not answer is **skipped**, not
allowed to stall the sweep — unreachable targets are the normal state for this
tool, not an exception. The run reports what it could not do and exits
non-zero. The command sent depends on the target's platform, which the agent
reports: a POSIX snippet pasted into PowerShell is not a graceful failure, it
is a page of parser errors and no update.

Targets are updated **one at a time**, waiting for each to come back before
touching the next, and stopping at the first failure. That ordering is the
point: an update that goes wrong on a rescue tool takes away the very thing you
would use to fix it, so the blast radius of a bad build has to be one machine.

`ssh proxy` marks each target `current` or `OUTDATED`, and `/healthz` counts
them. The agent hashes **its own executable** at startup and reports that, so
what you see is the binary a machine is really running rather than what someone
recorded at install time — the two drift apart the moment an update half
finishes.

## Changing who can log in

The keys a target accepts are frozen at enrolment: removing someone from the
proxy's `users_authorized_keys` does **not** reach the machines, and re-enrolling
each one is impossible for a fleet you can only reach through this tool. The
lever is an operator-driven push, deliberately outside the proxy's hands — the
proxy is not in a position to rewrite who may log into your machines, so you are,
over the authenticated session:

```bash
sh deploy/authorize.sh multissh users_authorized_keys          # every connected target
sh deploy/authorize.sh multissh users_authorized_keys laptop   # just this one
sh deploy/authorize.sh multissh users_authorized_keys --yes    # approve every change
```

It reads each target's current key set, diffs it against the file you give, and
puts **each addition and removal to you one at a time**. Nothing is written
unless you approve a change, and it refuses to push an empty set — at two points,
so approving away every key cannot lock you out. The agent re-reads the file on
its next connection, so there is no restart and no window where the machine is
unreachable, which makes this safer than the update sweep. `KEYSFILE` is yours to
curate; nothing trusts the proxy to supply it.

## Noticing decay

The realistic failure mode is not a breach. It is an agent that quietly stopped
months ago, discovered during the emergency it was meant to cover.

- `ssh proxy` lists machines it has seen before but that are **not connected
  now**, oldest first, and marks with `!` anything past `-stale-after`
  (30 days by default).
- The same warning is logged at proxy startup.
- `/healthz` on the agent listener answers monitoring:

```json
{"status":"ok","connected":3,"known":5,"stale":1,"stale_after":"720h0m0s","outdated":1,"revoked":0,"protocol":1,"build":"a4e9348d8d24"}
```

It is **unauthenticated and deliberately anonymous** — counts only, no names and
no fingerprints. It shares a public hostname with the installer, and which
machines exist is itself worth something to an attacker. Names live in the
authenticated listing.

## Standby proxies

Verifying a certificate needs only the authority's public key; issuing one
needs the private key. A standby therefore runs on the public half alone: it
authenticates every agent and can enrol nothing, so the private key stays on
one machine while access survives losing it.

```bash
# once, on the primary: certify the standby's host key
./proxy -sign-proxy-host standby_host_key.pub

# on the standby: no private authority material at all
./proxy -ca proxy_ca.pub -host-key standby_host_key -host-cert standby_host_key-cert.pub
```

Agents hold **one** certificate, valid at every proxy, and connect to all of
them at once rather than failing over — which costs a connection each and
removes any failover delay.

Your `known_hosts` needs no changes either: target entries are keyed by the
target's name, not the proxy, so the same pin works through either route.

Losing the primary costs you *enrolment*, not access. Every target stays
reachable through a standby while you rebuild, and adding new machines is the
thing that can wait.

⚠️ Put standbys on a different provider **and a different domain**. Two
subdomains of one zone share a registrar and a DNS provider, either of which
can take out both at once.

## Deployment behind a reverse proxy

The intended production shape, on a single VPS also hosting other services on
their own subdomains:

```
        :22   ─────────────────────────────►  multiSSH proxy (users)   direct, bypasses Caddy
VPS
        :443  ──►  Caddy  ──┬──  multissh.example.com  ──►  127.0.0.1:8080
                            ├──  other.example.com     ──►  another service
                            └──  …
```

The agent transport is a WebSocket (`wss://`), which is ordinary HTTP/1.1 with
an `Upgrade` header, so Caddy's `reverse_proxy` carries it natively and it looks
like plain HTTPS to any firewall or DPI in between. **Implemented and tested
against real Caddy.**

Note that **peeking at the first bytes to demux SSH and TLS on one port does
not work here** — Caddy owns `:443` and routes on TLS SNI, and raw SSH has no
SNI. That trick only applies if multiSSH owns the port outright.

Two properties this gains:

- The agent listener binds **loopback only** and is never directly exposed.
- Caddy terminates TLS but sees **only ciphertext**, because the SSH transport
  runs inside the WebSocket. Terminating TLS at the reverse proxy reveals
  nothing.

The user-facing SSH listener stays on `:22` and bypasses Caddy, since an `ssh`
client cannot speak through it. Putting the client side on `:443` too would
need a `ProxyCommand` helper, which breaks "stock ssh client, nothing extra".

---

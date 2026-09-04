# Security

Trust model, what is and is not verified, and the gaps that are known and
open. See the [README](../README.md) for the overview.

---

## Security

### Trust model

The proxy is a **certificate authority**, but deliberately only for its own
business. It signs agent identities so it can authenticate them without
remembering anything, and it signs its own host key so agents can accept a
rebuilt proxy. It does **not** certify target host keys.

| Hop | Server identity | Who is allowed |
|---|---|---|
| you → proxy | host certificate signed by the CA (bare key also offered) | `users_authorized_keys` |
| agent → proxy | host certificate, agent pins the **CA** | identity certificate carrying the names |
| **you → target (E2E)** | **trust-on-first-use, proxy not involved** | agent's `agent_authorized_keys` |

**The proxy is not in the trust chain for your connections to targets**, and
that is on purpose. Were it to certify target host keys, a compromised proxy
could mint one for a machine it controls, route you there, and your client
would accept it in silence — pubkey auth would not leak your key, but you would
be typing into someone else's shell. Leaving targets on trust-on-first-use
means such a substitution trips the usual `HOST KEY CHANGED` warning.

A compromised proxy therefore cannot read your sessions and cannot impersonate
a target to you — a substituted host key trips the `HOST KEY CHANGED` warning.

It **can** do two things, and honesty about the second matters. It can deny
service. And it can **push code to your machines through the update path**:
`--update` fetches an installer from the proxy and runs it as root, with no
signature the target checks (see [Update trust](operations.md#update-trust)). So a proxy you
keep honest stays out of your machines; a proxy that turns hostile reaches them
at the next update. That is inherent to a reverse jump host — the thing that
serves the binary is trusted for it — and the way to bound it is documented
below rather than claimed away here.

### Two names per target

```
laptop.niwru7dfuvu5     canonical: derived from the target's own host key
laptop                  friendly: convenience, granted only when unclaimed
```

The canonical name embeds a hash of the target's host key **and of its own
label**, so it is unique by construction and needs no bookkeeping. More
usefully, **the name commits to the key your client verifies**: no other machine
can be given that name, because the string is derived from a key it does not
hold.

⚠️ The name's hash is **not** comparable by eye with what ssh prints. Both derive
from the same host key, but through different functions and different alphabets:

```
sha256(key)              base64  3kii8sLzg3y2UzY4nmFwhzllHFj7lwCUDA5EB83tesk   <- ssh prints this
sha256(domain|label|key) base32  p7tq2yx5krjg                                  <- the name uses this
```

To check the key on first connect, compare against the **host key** line in
`ssh proxy`, which is the same string in the same format ssh prints — or paste
it into ssh's `(yes/no/[fingerprint])` prompt and let ssh compare for you.

The label goes into the hash as well as in front of it. Hashing the host key
alone would leave the label free, so one machine could be presented under any
number of canonical names — each verifying perfectly — and `laptop` and
`backup-server` could be the same box with no way to tell.

Friendly names may not contain a dot; canonical names always do. That is the
whole of the namespace separation, so the two can never be confused.

The friendly name is the only ambiguous surface, so the proxy grants it only to
the machine that holds it, recorded in `friendly_labels`. A second machine
wanting the same name keeps its canonical name and the clash is logged rather
than silently resolved. That file is **advisory**: losing it costs a convenient
name, never access.

### Recovering the proxy

**Back up `proxy_ca_key` once.** Not after every enrollment — once, ever.

Rebuild the proxy on new hardware, restore that one file, and every target
reconnects on its own. A fresh host key is signed by the restored CA at
startup, so agents accept the replacement without being touched, and your own
`@cert-authority` line still matches. This is tested: the test deletes the
proxy's host key and every advisory record, restarts with only the CA key, and
watches the agent come back unaided *and be reachable*, not merely listed.

What each file costs you if it is lost:

| File | Losing it costs |
|---|---|
| `proxy_ca_key` | **everything** — every machine must be re-enrolled by hand |
| `revoked_keys` | **silently un-revokes every entry**; back this up too |
| `users_authorized_keys` | nothing you do not already have — your own public keys |
| `friendly_labels` | a convenient name, until the machine reconnects and reclaims it |
| `last_seen` | history, so decay is harder to notice for a while |
| `enrol_passwords.json` | the ability to enrol new machines until you make another |

```bash
# enrol a machine: the proxy signs its identity and derives its canonical
# name from its host key, storing nothing
./proxy -sign agent_identity.pub -sign-host-key agent_host_key.pub -sign-label laptop
./proxy -show-ca > proxy_ca.pub

# your known_hosts needs the authority only for the proxy itself; targets are
# pinned individually on first use, which is what keeps the proxy out of the
# trust chain
echo "@cert-authority multissh.example.com $(cat proxy_ca.pub)" >> ~/.ssh/known_hosts
```

Certificates never expire by default. For a rescue tool that is deliberate: a
machine switched off longer than its certificate lasts would otherwise lock
itself out. Use `-sign-validity` if you want expiry.

### Retiring a machine

Uninstalling the agent leaves the proxy holding two things about it: the
friendly name it claimed, and its place in the last-seen record.

```bash
multissh-proxy -forget winbox.bbbb        # canonical or friendly name
systemctl reload multissh-proxy
```

The name is the part that matters. **Reinstalling a machine generates a new
identity key**, the ledger still binds the name to the old one, and the machine
comes back reachable under its canonical name only — correct by the rules, and
baffling if you do not know the rules. Forget it first and the name is free
again.

This is housekeeping, not security: an uninstalled agent has no certificate
left to connect with. To bar a machine you do not physically control, use
[revocation](#revoking-a-machine).

### Revoking a machine

Because certificates do not expire, revocation is the only lever that removes a
machine's access, and the trade above is only honest if it works.

```bash
./proxy -revoke SHA256:2LnQxYd8… -revoke-note "stolen laptop"
./proxy -list-revoked
./proxy -unrevoke SHA256:2LnQxYd8…
```

The handle is the SHA256 fingerprint of the agent's **identity key**, shown by
`ssh proxy` and logged on every registration. Not the certificate serial:
fingerprints survive re-issuing a certificate, whereas serials would need a
name-to-serial map — exactly the growing state the certificate design removed.

A running proxy re-reads `revoked_keys` every 30 seconds and **drops matching
connections that are already established**, so revoking does not wait for the
machine to reconnect, and does not mean restarting the proxy and killing every
other session.

⚠️ **`revoked_keys` is the one file that is not advisory.** `friendly_labels`
and `last_seen` cost you a convenient name or some history; losing *this* one
silently un-revokes every entry. Back it up with `proxy_ca_key`. The file says
so in its own header.

⚠️ Revocation bars a **key**, not a machine. Anyone still holding a valid
enrolment password can enrol the same machine afresh under a new key. If the
hardware is genuinely out of your hands, `-remove-password` too.

### Verified by test

`go test ./...` runs everything in this first list. The end-to-end tests build
the real proxy and agent binaries and run them over loopback, including a real
PTY, so they check the shipped programs rather than a rehearsal of them.
`-short` skips those and leaves the unit tests. A second list, *Checked by hand*,
follows — read the boundary between them, because the difference is the point.

The routing and identity boundaries:

- **`ssh -L` reaches nothing** — routing is a map lookup, so the client-supplied
  host is never dialled and the client-supplied port is ignored. This matters:
  `-L` and `-J` are byte-identical on the wire, so that lookup *is* the
  security boundary, not merely routing
- an unregistered label is rejected; `exec` and non-`sftp` subsystems are refused
- a reconnecting agent cannot be deregistered by the ghost connection it
  replaced
- the proxy survives being destroyed: with only `proxy_ca_key` restored and a
  brand new host key, the agent re-registers unaided
- `sftp` moves files in both directions through the tunnel (`scp` rides the same
  subsystem)

The authentication boundaries, several added after an external audit found the
first of them:

- an agent presenting a certificate from **any other authority** is refused —
  the proxy verifies the signing CA, not just that the certificate is
  self-consistent (this was a real bypass; the test fails against the old code)
- a proxy **host** certificate cannot be used as an **agent** credential
- rate limits are charged to the real client: `X-Forwarded-For` is trusted only
  from a `-trusted-proxies` peer, and its rightmost, unforgeable entry is used
- a certificate principal carrying a control character cannot reach the log or
  the last-seen file; a build/platform string carrying a terminal escape cannot
  reach the listing
- a build file whose name is not `<os>-<arch>` never reaches the rendered
  installer
- the revocation list, passwords and host key are written atomically; a
  malformed revocation line fails closed
- a revoked agent cannot register, and un-revoking lets it back in
- failed ssh handshakes are counted per source and refused past a threshold
- an agent below the configured protocol floor is refused, and told why

The operational properties:

- `/healthz` reports without naming a single target
- a withdrawn enrolment password stops working on reload, and a corrupt
  password file leaves the previous set in force rather than disabling enrolment
- publishing a new agent build and reloading with `SIGHUP` disconnects no agent,
  and the listing flips to `OUTDATED`
- the agent's inner handshake is bounded, so a tunnel opened and left silent is
  closed rather than held
- `authorize.sh` adds and removes login keys and refuses to push an empty set
- several regressions are frozen against their original shapes, including two
  that were invisible in exactly the configuration first tested — one build
  served, one request made — and only appeared in the shape a real deployment
  takes

### Checked by hand, not automated

These held when last exercised by hand but are **not** in `go test`, so treat
them as claims backed by a person, not a machine. Some resist automation for
reasons the end-to-end package explains; the rest are simply not automated yet.

- session teardown leaves no orphan after `kill -9` of the client, and a frozen
  agent (`SIGSTOP`) is evicted within ~30s
- the proxy drops a silent *unauthenticated* client after 30s (the *agent's*
  inner-handshake equivalent **is** tested)
- reconnect backoff resets after a healthy session
- X11 and agent forwarding are refused (only `exec`/`subsystem` refusal is tested)
- the installer works over real TLS through real Caddy (Caddy appears only in a
  comment and the manual walkthrough)
- the Windows and macOS install paths on real hardware — both have been run
  and work, but only by hand: in `go test` the installers are covered by
  assertions against their rendered text and nothing more

### Reading the commit history

Commit messages from the hardening pass reference identifiers like `H4`, `M2`
or `M15`. Those come from a security review of this codebase whose findings are
not published as a document: the high ones are closed, and the ones deliberately
left open are the **Known gaps** below, described there in full. The identifiers
are kept in the messages so that a commit can still be traced to the finding it
answers, not because a separate report is being withheld.

### Before exposing it publicly

This has run on a LAN against a handful of agents on Linux, Windows and macOS,
but not at scale or under hostile traffic; treat internet exposure as
lightly tested rather than proven. Connection caps exist (`-max-user-connections`,
`-max-agent-connections`, enforced before the handshake) and failed handshakes
and `/enroll` attempts are rate limited per source — but the source is only
trustworthy behind a reverse proxy listed in `-trusted-proxies` (default
loopback), so set that correctly if you front it with anything else.

What is genuinely *not* there: **no per-user access control** — any key in
`users_authorized_keys` reaches every registered target — and the **unsigned
update path** described under [Update trust](operations.md#update-trust).

---

## Known gaps

| | Issue | Impact |
|---|---|---|
| 🔴 | The agent is **not code signed**. On Windows with Smart App Control enforced it can be blocked from starting, which shows up only as scheduled task result `0x800704C7` and an agent that never reconnects. | The installer strips the Mark of the Web and warns when Smart App Control is on. A real fix needs a code-signing certificate. |
| 🟡 | Windows: a machine-wide install is a real service; a user install is a scheduled task, because creating a service needs rights a user does not have. | The user-scope agent restarts three times on failure and stops when you log out. |
| 🟡 | `wss://` to a bare IP does not override TLS SNI, so `-proxy-host` alone is not enough to bypass DNS over TLS. | Works for `ws://` behind a TLS-terminating reverse proxy; direct `wss://` needs a resolvable name. |
| 🟡 | Processes a session starts survive disconnect, on both platforms. | Deliberate on Unix, as under a normal sshd. On Windows a Job Object would fix it, but it killed the self-update halfway through and had to come out; the way back is to move the restart out of the session. |
| 🟡 | Everyone with a user key reaches every target. No ACLs. | Fine for one operator; wrong the moment a second key is added for someone else. |
| 🟡 | Proxy configuration is entirely flags, held in the systemd unit. | `install-proxy.sh` writes the unit once and never overwrites it, so changes are edited on the server. |
| 🟡 | Agents are never updated automatically. | A sweep is something you run; nothing happens on its own. Deliberate — an automatic update that goes wrong takes out every machine at once. |
| 🟡 | **The on-target `manage.sh --update` trusts the proxy** (fetches and runs an installer from it as root), and **Windows** updates this way. | The Linux/macOS workstation sweep (`update-agents.sh`) pushes the binary over the authenticated session instead, so a hostile proxy cannot inject code there. Windows and the on-box path remain proxy-trusting — see [Update trust](operations.md#update-trust). |
| 🟡 | Revocation is **per-proxy**: `-revoke` on the primary does not reach a standby, which enforces its own list. | Matters only if you run standbys. Until then, moot; when you do, copy `revoked_keys` across as part of revoking. |
| ⚪ | A machine that enrolled but never once connected is invisible to the proxy — enrolment writes nothing there. | The installer reports success on the target instead. |

# Development

Building, the checks CI runs, and how the protocol version is handled.
See the [README](../README.md) for the overview.

---

## Protocol versioning

The agent runs on machines nobody touches; that is the entire point. So a
protocol change has to be something both ends can *see*, rather than something
that surfaces as an inexplicable failure months later.

- The version rides in the SSH identification string, exchanged before
  anything else. `-min-agent-protocol` refuses agents below a floor, and the
  proxy sends a **banner** saying so, which the agent prints to its own log —
  rather than leaving an unattributed authentication failure.
- The floor defaults to accepting everything, including agents installed before
  any of this existed. Refusing an old agent strands a machine, so that stays a
  decision taken deliberately rather than one a proxy upgrade makes for you.
- The tunnel channel carries a versioned payload with a reserved `Extra` field.
  New fields go *inside* it, because `ssh.Unmarshal` rejects a payload that does
  not match its struct exactly — so adding a field directly would break every
  agent already in the field. There is a test that fails if that ever stops
  being true.

---

## Development

```bash
sh deploy/check.sh       # everything CI runs, including shellcheck and pwsh
go test ./...            # unit tests plus end-to-end, ~20s
go test -short ./...     # unit tests only
sh deploy/build.sh dist  # every platform
```

Run `deploy/check.sh` before pushing. Two of CI's checks need tools that are on
neither a development machine nor the proxy — `shellcheck` and a PowerShell
parse — so they are easy to push and forget. The script runs both through a
container, or says plainly that it skipped them.

Deployment lives in `deploy/`: `push.sh` (build and ship to the proxy host),
`install-proxy.sh` (run there, idempotent), `update-agents.sh` (roll a build
out to targets one at a time), and `authorize.sh` (push a curated login-key set
to targets, each change confirmed).

CI runs `gofmt`, `go vet`, `go test -race`, a cross-compile of all five
platforms, `sh -n` and `shellcheck` over the installer, and a PowerShell parse
check of `install.ps1` — the last of these because the Windows path has never
been run on real hardware, so a parse is the only guard it has.

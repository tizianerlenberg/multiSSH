# Security policy

multiSSH is a tool for reaching machines that cannot accept inbound
connections. A flaw in it is a flaw in someone's remote access, so reports are
welcome and will be taken seriously.

This is a personal project maintained by one person. There is no company behind
it, no bounty, and no response-time guarantee.

## Reporting a vulnerability

Please report privately, not as a public issue:

**[Open a private security advisory](../../security/advisories/new)** on this
repository. That keeps the report between you and the maintainer until there is
a fix.

Useful in a report: what an attacker has to start with, what they end up with,
and the smallest sequence that shows it. A proof of concept helps but is not
required if the reasoning is clear.

## Scope

In scope: the proxy, the agent, the installers (`install.sh`, `install.ps1`),
and the deployment scripts under `deploy/`.

Out of scope: OpenSSH itself, and the operator's own configuration, unless the
documentation told them to configure it that way.

## Already known

Some weaknesses are known, documented, and open on purpose. Please read
[docs/security.md](docs/security.md) before reporting; the **Known gaps** table
lists them with their impact.

The two that account for most of what a reader will notice:

- **The on-target update path trusts the proxy.** `manage.sh --update`, and all
  Windows updates, fetch an installer from the proxy and run it as root. A
  hostile proxy can therefore run code on a target. The workstation sweep
  (`deploy/update-agents.sh`) avoids this by pushing the binary over the
  authenticated ssh session instead.
- **There is no per-user access control.** Any key in `users_authorized_keys`
  reaches every registered target.

Both are recorded rather than hidden, and a report that sharpens the impact of
either is still worth sending.

## What is verified, and how

[docs/security.md](docs/security.md) separates the properties covered by
`go test` from those only checked by hand. That distinction is deliberate:
treat the second list as claims backed by a person, not by a machine.

# Design notes

Why a few things are shaped the way they are. Background rather than
instruction; nothing here is needed to run the tool.

See the [README](../README.md) for the overview.

---

## Why updating over the tunnel needed care

The installer used to stop the agent before moving the new binary into place.
Driven over the agent's own tunnel — which for a machine behind NAT is the only
way to reach it — that stop killed the update script too, because systemd tears
down the whole cgroup it was running in. The binary was never replaced, the
unit stayed stopped, and systemd would not restart it because it had been
stopped deliberately. **One update and the machine was gone for good.** This
was reproduced on a real systemd install, twice; `setsid` and `nohup` do not
help, as they escape the process-group kill but not the cgroup kill.

The stop was only there because a running executable cannot be overwritten in
place — `ETXTBSY`. But `rename(2)` has no such restriction: the running process
keeps its own inode and the new file simply takes the name. So the binary is
downloaded, verified, and swapped atomically, and *only then* is anything
restarted — by which point the update is already committed. If the script is
killed before that, the old agent is still running and the next restart picks
up the new binary. There is no window in which the machine has neither.

`--uninstall` is ordered the same way, for the same reason.

The outgoing binary is kept as `.prev`, so `--rollback` works, over the tunnel,
without the proxy.

Separately: the saved `manage.sh --update` could never update anything. The
proxy generates the installer per request with its current version baked in;
the saved copy froze that value and compared it against the manifest, which was
written from the same value. Always equal, so it reported `already current`
forever. It now asks the proxy for the script it is serving now — which it had
to reach anyway to download a binary from.

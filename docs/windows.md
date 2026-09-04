# Windows

What an install actually gives you on Windows, and how the two
scopes differ. See the [README](../README.md) for the overview.

---

### What you get on Windows

The agent runs as a scheduled task under **SYSTEM**, so the machine is
reachable before anyone logs in — which is the whole point for a rescue tool.
The shell you get is PowerShell running as SYSTEM, and that is a genuinely
different account from yours, not merely an elevated one:

- **No user profile.** `$HOME`, `%LOCALAPPDATA%` and `HKCU` are SYSTEM's, under
  `C:\Windows\System32\config\systemprofile`, not yours.
- **Per-user apps are missing.** `winget` in particular is an app execution
  alias in `%LOCALAPPDATA%\Microsoft\WindowsApps`, which is on *your* PATH and
  not on SYSTEM's — so it is "not recognized" in the session while working fine
  in your own PowerShell. The same goes for scoop, pyenv, and anything else
  installed per user.
- **No network identity of yours.** SYSTEM authenticates to other machines as
  the *computer* account, so mapped drives and shares behave differently.
- More privilege locally than an administrator, less reach outward.

If you would rather have a session as **yourself**, install a second agent in
user scope. Both can run side by side — the SYSTEM one is the rescue path, the
user one is the comfortable one, and they keep separate directories, keys and
scheduled tasks:

```powershell
# in a NORMAL (unelevated) PowerShell -- no flag needed
irm https://multissh.example.com/install.ps1 -OutFile $env:TEMP\ms.ps1
powershell -ExecutionPolicy Bypass -File $env:TEMP\ms.ps1
```

Scope follows elevation, as it does on Linux: an elevated shell installs for
the machine, anyone else installs for themselves. The confirmation prompt names
the scope it picked and why, so `-Scope` is only for overriding it — installing
for yourself *from* an elevated shell, say.

When the other scope is already installed, the suggested name avoids the one it
holds — `winbox-user` beside `winbox` — because both agents can ask for a
friendly name but only one can have it, and the loser is reachable under its
canonical name alone. The user-scope agent is **not reachable while you are
logged out**, which is the trade.

There is no `sudo -u` on Windows to switch between them from inside a session:
`runas` wants the password typed at a real console, and `Start-Process
-Credential` detaches the process so its output never comes back. Two agents is
the workable answer.

`whoami` says `nt authority\system`. To check what you are:

```powershell
whoami
[Security.Principal.WindowsIdentity]::GetCurrent().Name
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
  ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
```

For `winget` specifically, the package payload is present machine-wide even
though the alias is not, so it can be called by full path:

```powershell
$w = (Get-ChildItem 'C:\Program Files\WindowsApps' -Filter winget.exe -Recurse `
        -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
& $w list
```

Microsoft does not support running `winget` as SYSTEM, and it may still fail on
source registration even when found. `--scope machine` installs are the ones
most likely to work. MSI installers and `Add-AppxProvisionedPackage` do not
have this problem.

**The username is ignored by both hops.** The proxy does not use it (the target
is chosen by hostname), and the agent's embedded server does not switch users —
it runs the shell as whoever the agent runs as. So `ssh -J proxy root@laptop`
on a user-scope install silently gives you a *non-root* shell. Write whatever
you like; only your key matters.

`scp` and `sftp` work, which matters because getting a file *off* a machine
that is half broken is a large part of what a rescue tool is for:

```bash
scp -J proxy user@laptop:/etc/ssh/sshd_config .     # rescue a file
sftp -J proxy user@laptop                           # or browse
```

⚠️ **Do not quote the remote path.** In SFTP mode the path is taken literally,
not passed through a shell, so quotes become part of the filename:

```bash
scp -J proxy file.txt 'winbox:C:/Users/Some Name/Downloads/file.txt'    # right
scp -J proxy file.txt 'winbox:"C:\Users\Some Name\Downloads\file.txt"'  # wrong
```

Backslashes work as well as forward slashes on Windows. Quote the whole
argument once, against your *local* shell, and stop there. Relative paths land
in the agent's working directory, which is often not writable — use an absolute
one.

Only the `sftp` subsystem is served; the embedded server is not a general
subsystem host. On Windows the files are reached as SYSTEM or as you,
[depending on scope](#what-you-get-on-windows).

---

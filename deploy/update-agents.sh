#!/bin/sh
# Roll a new agent build out to targets, one machine at a time.
#
#   sh deploy/update-agents.sh multissh            # every outdated target
#   sh deploy/update-agents.sh multissh laptop     # just these
#   sh deploy/update-agents.sh multissh --all      # including ones already current
#   sh deploy/update-agents.sh multissh --yes      # do not ask about Windows
#
# Linux and macOS targets are updated the trusted way: the binary is **pushed**
# from here over the authenticated ssh session -- encrypted end-to-end to the
# target's host key, which the proxy only relays -- and installed without the
# target fetching anything from the proxy. So an update survives a proxy that
# has turned hostile: it cannot substitute a binary it never carries. The binary
# comes from a local build directory (deploy/build.sh writes it; push.sh leaves
# it in ./dist), set with MULTISSH_DIST. Run this after push.sh, with the same
# build, so the listing's "current" marker still means what it says.
#
# The installer is pushed with it, and it is that copy which runs. Handing the
# work to the target's own saved manage.sh does not work: that copy is frozen
# at install time, so an agent installed before the pushed path existed does
# not understand MULTISSH_UPDATE_FROM, ignores the binary just pushed to it,
# and falls through to downloading from the proxy -- where it checks what it
# gets against its install-time hash and dies with a checksum mismatch. Older
# the agent, more certain the failure, which is the wrong way round for a tool
# whose job is reaching machines that have been left alone. Pushing the
# installer makes the update independent of how old the target is, and keeps
# the promise this path is built on: the code that runs came from here, not
# from the proxy.
#
# Windows still updates the old way -- the target fetches from the proxy -- which
# trusts the proxy for that hop. That path is unverified on real hardware here;
# until it is, it stays as it was, and is asked about one machine at a time.
#
# Windows targets are asked about one at a time and skipped unless confirmed.
# Updating one restarts it, and if that restart does not take, the machine goes
# offline -- which for a rescue tool means losing the way back in. Linux and
# macOS restart through systemd or launchd and have not shown that problem.
#
# The argument is however you reach the proxy with a stock ssh client: a Host
# alias from ~/.ssh/config, or user@host.
#
# One machine at a time, waiting for each to come back before touching the
# next. An update that goes wrong on a rescue tool takes away the thing you
# would use to fix it, so the blast radius of a bad build has to be one machine
# -- and you find out on that one rather than on all of them.
#
# A machine that does not answer is skipped rather than allowed to stop the
# sweep: unreachable targets are the normal state for this tool, not an
# exception, so the run reports them at the end and carries on.
#
#   MULTISSH_DIST      directory of local agent builds to push      (default dist)
#   MULTISSH_INSTALLER installer to push and run on the target
#                      (default cmd/proxy/scripts/install.sh in this checkout)
#   MULTISSH_WAIT      seconds to wait for a machine to come back  (default 120)
#   MULTISSH_TIMEOUT   seconds to allow the update command itself   (default 90)
#   MULTISSH_DEADLINE  seconds for the whole sweep                  (default 1800)
#   MULTISSH_STOP      set to 1 to stop at the first failure instead of skipping
#   MULTISSH_YES       set to 1 to update Windows targets without asking
set -eu

[ $# -ge 1 ] || { echo "usage: sh deploy/update-agents.sh <proxy> [name...] [--all] [--stop] [--yes]" >&2; exit 2; }
PROXY=$1; shift

ALL=
NAMES=
STOP=${MULTISSH_STOP:-}
ASSUME_YES=${MULTISSH_YES:-}
for arg in "$@"; do
    case "$arg" in
        --all)  ALL=1 ;;
        --stop) STOP=1 ;;
        -y|--yes) ASSUME_YES=1 ;;
        -*)     echo "unknown option: $arg" >&2; exit 2 ;;
        *)      NAMES="$NAMES $arg" ;;
    esac
done

SSH=${MULTISSH_SSH:-ssh}
SFTP=${MULTISSH_SFTP:-sftp}
DIST=${MULTISSH_DIST:-dist}
# Resolved against this script rather than the working directory, because the
# whole point is to push a known-good installer and the caller may be standing
# anywhere.
SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
INSTALLER=${MULTISSH_INSTALLER:-$SCRIPT_DIR/../cmd/proxy/scripts/install.sh}
WAIT_SECONDS=${MULTISSH_WAIT:-120}
CMD_TIMEOUT=${MULTISSH_TIMEOUT:-90}
# How long a target may sit connected-but-outdated before that counts as a
# verdict rather than something still in progress.
STALE_VERDICT=${MULTISSH_STALE_VERDICT:-45}
DEADLINE=$(( $(date +%s) + ${MULTISSH_DEADLINE:-1800} ))

# Every ssh here is bounded. Without this a target that accepted the connection
# and then stopped answering -- a laptop closing its lid mid-update, which is
# exactly the population this tool serves -- hangs the sweep indefinitely.
# -T and -n are the important ones, and their absence is what made this look
# broken. Run from a terminal, ssh with no command allocates a pseudo-terminal
# and puts *your* terminal into raw mode. The sweep then hung, and Ctrl-C did
# not stop it -- in raw mode the interrupt is passed to the far end as a byte
# instead of becoming a signal locally, so the only way out was to close the
# window. -T asks for no terminal and -n takes stdin away entirely, which is
# what a script wants in any case: nothing here is interactive.
SSHOPTS="-T -n -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=10 -o ServerAliveCountMax=3"

have_timeout=
command -v timeout >/dev/null 2>&1 && have_timeout=1
run_bounded() { # run_bounded SECONDS COMMAND...
    _t=$1; shift
    if [ -n "$have_timeout" ]; then
        timeout "$_t" "$@"
    else
        "$@"
    fi
}

listing() { run_bounded 30 $SSH $SSHOPTS "$PROXY" 2>/dev/null | tr -d '\r' || true; }

# targets extracts "<canonical> <platform> <state>" from the ONLINE section and
# nothing else.
#
# Bounded on both sides deliberately. An earlier version matched any indented
# line containing a dot, which swept up prose from the CONNECT section further
# down and solemnly tried to update a machine called "you." -- the sentence
# ended in a full stop.
targets() {
    listing | awk '
        /^ ONLINE \(/      { inside = 1; next }
        /^ [A-Z]+/         { inside = 0 }
        !inside            { next }
        # "<friendly> <canonical> <platform> v1 <state>", friendly possibly
        # blank. The canonical name is the field carrying a dot.
        {
            name = ""; state = ""; platform = ""
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^[a-z0-9][a-z0-9-]*\.[a-z2-7]+$/) name = $i
                else if ($i == "OUTDATED" || $i == "current") state = $i
                else if ($i ~ /^(linux|windows|darwin|freebsd|openbsd)$/) platform = $i
            }
            if (name != "") print name, (platform == "" ? "unknown" : platform), state
        }'
}

# The command is passed as an argument to ssh, not fed to its stdin.
#
# With no command, ssh asks for a shell, and a shell is interactive: PowerShell
# opens a prompt, echoes what arrives on stdin, and waits for more. It never
# runs the script and never exits, so the update simply hung. It appeared to
# work on Linux only because the update restarted the agent and killed the
# session out from under itself.
#
# The payload is base64 so that neither shell has to survive the other's
# quoting on the way through ssh: what crosses is [A-Za-z0-9+/=] and nothing
# else.
b64() { printf '%s' "$1" | base64 | tr -d '\n'; }

# Where the agent's state directory may be. MULTISSH_AGENT_DIRS overrides it,
# which a custom install path needs and the tests use.
POSIX_DIRS='${MULTISSH_AGENT_DIRS:-/var/lib/multissh-agent:$HOME/.config/multissh-agent:/Library/Application Support/multissh-agent}'

# detect_osarch asks the target what it is, so the right local binary is chosen.
# uname is on every POSIX target; Windows has no business here.
detect_osarch() { # detect_osarch NAME -> "<os>-<arch>" or empty
    _u=$(run_bounded "$CMD_TIMEOUT" $SSH $SSHOPTS -J "$PROXY" \
        -o StrictHostKeyChecking=accept-new "authorize@$1" 'uname -sm' 2>/dev/null | tr -d '\r')
    case "$_u" in
        Linux\ x86_64)  echo linux-amd64 ;;
        Linux\ aarch64) echo linux-arm64 ;;
        Linux\ arm64)   echo linux-arm64 ;;
        Darwin\ x86_64) echo darwin-amd64 ;;
        Darwin\ arm64)  echo darwin-arm64 ;;
        *)              echo "" ;;
    esac
}

# push_files sends the local files to temp paths on the target over sftp --
# a raw channel, no PTY to corrupt the bytes, and end-to-end encrypted so the
# proxy relays ciphertext it cannot alter. One session for both, so a target
# that goes away mid-push does not leave one half of the pair behind.
push_files() { # push_files NAME LOCALBIN REMOTEBIN LOCALINSTALLER REMOTEINSTALLER
    printf 'put %s %s\nput %s %s\n' "$2" "$3" "$4" "$5" | run_bounded "$CMD_TIMEOUT" \
        $SFTP -J "$PROXY" -o BatchMode=yes -o ConnectTimeout=15 \
        -o StrictHostKeyChecking=accept-new -b - "authorize@$1" >/dev/null 2>&1
}

# posix_push_update runs the pushed installer against the pushed binary, with
# no re-fetch, so no proxy-supplied code runs and no proxy download happens.
# Both temp files are removed whether or not the update succeeds -- when the
# script gets that far. A successful update ends in a restart, and driven over
# the agent's own tunnel that restart tears down the cgroup this snippet runs
# in, so the trailing rm is not reached on exactly the runs that work. Clearing
# any earlier pair on the way in is what actually keeps /tmp from filling up,
# one leaked binary per update; the two paths in flight are skipped by name.
#
# The state directory is still found the same way, but by its manifest rather
# than by manage.sh: the manifest is what --update actually needs, and it
# records where this install put things. Reading M_STATE and M_BIN from it and
# passing them on is what lets the pushed installer, which is running from
# /tmp and cannot guess, act on a non-default install path.
posix_push_update() { # posix_push_update REMOTEBIN REMOTEINSTALLER
    _snip='for f in /tmp/multissh-agent.update.* /tmp/multissh-install.update.*; do
    [ -e "$f" ] || continue
    [ "$f" = "'"$1"'" ] || [ "$f" = "'"$2"'" ] || rm -f "$f"
done
IFS=:; found=; rc=1
for d in '"$POSIX_DIRS"'; do
    if [ -f "$d/manifest" ]; then
        found=1
        M_STATE=; M_BIN=
        . "$d/manifest"
        [ -n "$M_STATE" ] || M_STATE=$d
        [ -n "$M_BIN" ] || M_BIN=$d/multissh-agent
        MULTISSH_UPDATE_FROM="'"$1"'" MULTISSH_NO_REFETCH=1 \
        MULTISSH_STATE_DIR="$M_STATE" MULTISSH_PREFIX="$(dirname "$M_BIN")" \
            sh "'"$2"'" --update -y
        rc=$?
        break
    fi
done
rm -f "'"$1"'" "'"$2"'"
[ -n "$found" ] || { echo "no multissh-agent install found on this machine" >&2; exit 1; }
exit $rc'
    printf "echo %s | base64 -d | sh" "$(b64 "$_snip")"
}

WINDOWS_UPDATE='$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
foreach ($d in @("$env:ProgramData\multiSSH", "$env:LOCALAPPDATA\multiSSH\state")) {
    $m = Join-Path $d "manage.ps1"
    if (Test-Path $m) { & ([scriptblock]::Create((Get-Content $m -Raw))) -Update -Yes; exit 0 }
}
Write-Host "no multissh-agent install found on this machine"
exit 1'

# windows_update_command is the old, proxy-fetch path, kept only for Windows.
windows_update_command() {
    printf "\$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'));Invoke-Expression \$s" \
        "$(b64 "$WINDOWS_UPDATE")"
}

# confirm asks before touching a Windows target.
#
# The prompt reads the terminal directly rather than stdin: stdin may be a
# pipe, and in any case nothing else here is interactive. With no terminal at
# all the answer is no -- an unattended run must not decide on its own to risk
# a machine.
# /dev/tty exists as a device node whether or not there is a controlling
# terminal behind it, so testing for the file says nothing. Opening it is the
# only real test, and doing that quietly keeps the failure from leaking out as
# "No such device or address".
have_tty() {
    { : >/dev/tty; } 2>/dev/null
}

confirm() { # confirm NAME
    if [ -n "$ASSUME_YES" ]; then
        return 0
    fi
    if ! have_tty; then
        return 1
    fi
    printf 'update %s? A Windows restart that does not take leaves it offline. [y/N]: ' "$1" > /dev/tty
    read -r _answer < /dev/tty || _answer=
    case "$_answer" in
        y|Y|yes|YES) return 0 ;;
        *)           return 1 ;;
    esac
}

matches() { # matches CANONICAL
    if [ -z "$NAMES" ]; then
        return 0
    fi
    _base=${1%%.*}
    for want in $NAMES; do
        if [ "$want" = "$1" ] || [ "$want" = "$_base" ]; then
            return 0
        fi
    done
    return 1
}

# Interrupting has to say what happened. Pressing ^C used to print nothing at
# all, leaving no way to tell which machines had already been done.
DONE=
FAILED=
SKIPPED=
summary() {
    echo
    if [ -n "$DONE" ];    then echo "updated:$DONE"; fi
    if [ -n "$SKIPPED" ]; then echo "skipped:$SKIPPED"; fi
    if [ -n "$FAILED" ];  then echo "did not update:$FAILED" >&2; fi
    return 0
}
trap 'echo; echo "interrupted." >&2; summary; exit 130' INT TERM

# Checked before anything is touched. Discovering the installer is missing one
# machine into a sweep would leave the run half-done for no reason.
[ -f "$INSTALLER" ] || {
    echo "no installer at $INSTALLER" >&2
    echo "run this from the multiSSH checkout, or set MULTISSH_INSTALLER" >&2
    exit 2
}

echo "==> asking $PROXY what is connected"
ALL_TARGETS=$(targets)
if [ -z "$ALL_TARGETS" ]; then
    echo "no targets connected"
    exit 0
fi

TODO=
OLDIFS=$IFS
IFS='
'
for line in $ALL_TARGETS; do
    IFS=$OLDIFS
    # shellcheck disable=SC2086
    set -- $line
    name=$1; platform=$2; state=${3:-}
    if matches "$name"; then
        if [ -n "$ALL" ] || [ "$state" = OUTDATED ] || [ -z "$state" ]; then
            TODO="$TODO $name/$platform"
        fi
    fi
    IFS='
'
done
IFS=$OLDIFS

if [ -z "$TODO" ]; then
    echo "everything connected is already current"
    exit 0
fi

echo "will update:"
for entry in $TODO; do
    if [ "${entry#*/}" = windows ]; then
        echo "    ${entry%/*}  (${entry#*/}, will ask first)"
    else
        echo "    ${entry%/*}  (${entry#*/})"
    fi
done
echo

for entry in $TODO; do
    name=${entry%/*}
    platform=${entry#*/}

    if [ "$(date +%s)" -ge "$DEADLINE" ]; then
        echo "==> $name" >&2
        echo "    skipped: the sweep has run past its overall deadline." >&2
        FAILED="$FAILED $name"
        continue
    fi
    echo "==> $name"

    if [ "$platform" = windows ]; then
        if ! confirm "$name"; then
            if have_tty; then
                echo "    skipped."
            else
                echo "    skipped: Windows targets are only updated when confirmed," >&2
                echo "    and there is no terminal to ask at. Pass --yes to override." >&2
            fi
            SKIPPED="$SKIPPED $name"
            continue
        fi
    fi

    if [ "$platform" = unknown ]; then
        echo "    skipped: this agent is too old to say what platform it is on." >&2
        echo "    Update it by hand, or re-run the installer on it." >&2
        FAILED="$FAILED $name"
        continue
    fi

    # ConPTY / a Unix PTY prepend setup and echo bytes; strip them rather than
    # print them. Reused for both paths below.
    strip_pty() { tr -d '\r' | sed -e 's/\x1b\][^\x07]*\x07//g' -e 's/\x1b\[[0-9;?]*[a-zA-Z]//g' -e 's/^/    /'; }

    if [ "$platform" = windows ]; then
        # The old path: the target fetches from the proxy. Left as-is until the
        # pushed path is proven on real Windows.
        if ! run_bounded "$CMD_TIMEOUT" \
                $SSH $SSHOPTS -J "$PROXY" -o StrictHostKeyChecking=accept-new \
                "update@$name" "$(windows_update_command)" 2>&1 | strip_pty; then
            echo "    (command ended early -- checking whether it took anyway)"
        fi
    else
        # The trusted path: detect the architecture, push the matching local
        # binary over sftp, then have the target install it without touching
        # the proxy.
        osarch=$(detect_osarch "$name")
        if [ -z "$osarch" ]; then
            echo "    could not determine this machine's architecture; skipped" >&2
            FAILED="$FAILED $name"; continue
        fi
        localbin="$DIST/$osarch"
        if [ ! -f "$localbin" ]; then
            echo "    no local binary at $localbin to push -- build with deploy/build.sh" >&2
            echo "    or set MULTISSH_DIST; skipped" >&2
            FAILED="$FAILED $name"; continue
        fi
        remote="/tmp/multissh-agent.update.$$"
        remote_installer="/tmp/multissh-install.update.$$"
        echo "    pushing $osarch binary ($(wc -c <"$localbin") bytes) and installer"
        if ! push_files "$name" "$localbin" "$remote" "$INSTALLER" "$remote_installer"; then
            echo "    could not push the binary and installer over sftp; skipped" >&2
            FAILED="$FAILED $name"; continue
        fi
        if ! run_bounded "$CMD_TIMEOUT" \
                $SSH $SSHOPTS -J "$PROXY" -o StrictHostKeyChecking=accept-new \
                "update@$name" "$(posix_push_update "$remote" "$remote_installer")" 2>&1 | strip_pty; then
            echo "    (command ended early -- checking whether it took anyway)"
        fi
    fi

    # Progress with numbers on it. A row of dots for two minutes is
    # indistinguishable from a hang, which is how a slow failure came to look
    # like a broken script.
    started=$(date +%s)
    until_ts=$(( started + WAIT_SECONDS ))
    ok=
    stale_since=
    while :; do
        now=$(date +%s)
        [ "$now" -lt "$until_ts" ] || break
        state=$(targets | awk -v n="$name" '$1 == n { print $3 }')
        if [ "$state" = current ]; then ok=1; break; fi

        # Present but still on the old build is a different answer from absent,
        # and a conclusive one: the machine is up, it just did not restart into
        # the new binary. Waiting the full period for that to change is time
        # spent learning nothing.
        if [ "$state" = OUTDATED ]; then
            [ -n "$stale_since" ] || stale_since=$now
            if [ $(( now - stale_since )) -ge "$STALE_VERDICT" ]; then break; fi
        else
            stale_since=
        fi
        elapsed=$(( now - started ))
        if [ "$state" = OUTDATED ]; then
            what="back, still on the old build"
        else
            what="waiting for it to come back"
        fi
        # Rewriting one line is for a terminal. Piped to a file or a log, a
        # carriage return is just a character, so say it once and be quiet.
        if [ -t 1 ]; then
            printf '\r    %s (%ss of %ss)   ' "$what" "$elapsed" "$WAIT_SECONDS"
        elif [ "$elapsed" -eq 0 ]; then
            printf '    %s...\n' "$what"
        fi
        sleep 3
    done
    if [ -t 1 ]; then
        printf '\r                                                              \r'
    fi

    if [ -n "$ok" ]; then
        echo "    now current"
        DONE="$DONE $name"
    elif [ -n "$stale_since" ]; then
        echo "    it is connected but still running the old build: the new binary" >&2
        echo "    was installed and the restart did not take effect." >&2
        echo "    On Windows check whether the restart task ran:" >&2
        echo "      Get-ScheduledTaskInfo -TaskName 'multiSSH agent restart'" >&2
        FAILED="$FAILED $name"
    else
        echo "    did NOT come back current within ${WAIT_SECONDS}s" >&2
        echo "    the previous binary is still on that machine: --rollback" >&2
        FAILED="$FAILED $name"
        if [ -n "$STOP" ]; then
            echo
            echo "stopping here (--stop); the remaining machines were left alone." >&2
            exit 1
        fi
    fi
done

summary
if [ -n "$FAILED" ]; then
    echo "(re-run to try them again; nothing was left half-applied)" >&2
    exit 1
fi
echo "all done"

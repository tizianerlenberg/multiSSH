#!/bin/sh
# Roll a new agent build out to targets, one machine at a time.
#
#   sh deploy/update-agents.sh multissh            # every outdated target
#   sh deploy/update-agents.sh multissh laptop     # just these
#   sh deploy/update-agents.sh multissh --all      # including ones already current
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
#   MULTISSH_WAIT     seconds to wait for a machine to come back   (default 180)
#   MULTISSH_TIMEOUT  seconds to allow the update command itself   (default 120)
#   MULTISSH_STOP     set to 1 to stop at the first failure instead of skipping
set -eu

[ $# -ge 1 ] || { echo "usage: sh deploy/update-agents.sh <proxy> [name...] [--all] [--stop]" >&2; exit 2; }
PROXY=$1; shift

ALL=
NAMES=
STOP=${MULTISSH_STOP:-}
for arg in "$@"; do
    case "$arg" in
        --all)  ALL=1 ;;
        --stop) STOP=1 ;;
        -*)     echo "unknown option: $arg" >&2; exit 2 ;;
        *)      NAMES="$NAMES $arg" ;;
    esac
done

SSH=${MULTISSH_SSH:-ssh}
WAIT_SECONDS=${MULTISSH_WAIT:-180}
CMD_TIMEOUT=${MULTISSH_TIMEOUT:-120}

# Every ssh here is bounded. Without this a target that accepted the connection
# and then stopped answering -- a laptop closing its lid mid-update, which is
# exactly the population this tool serves -- hangs the sweep indefinitely.
SSHOPTS="-o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=10 -o ServerAliveCountMax=3"

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

# The saved installer lives beside the agent keys, and the command to run it
# depends entirely on what shell is at the other end. A POSIX loop sent to a
# Windows target is not a failure that degrades gracefully: PowerShell parses
# it and prints a page of syntax errors while updating nothing.
update_command() { # update_command PLATFORM
    case "$1" in
        windows)
            cat <<'PS'
$ErrorActionPreference='Stop'
$dirs = @("$env:ProgramData\multiSSH", "$env:LOCALAPPDATA\multiSSH\state")
foreach ($d in $dirs) {
  $m = Join-Path $d 'manage.ps1'
  if (Test-Path $m) { & ([scriptblock]::Create((Get-Content $m -Raw))) -Update -Yes; exit 0 }
}
Write-Host 'no multissh-agent install found on this machine'; exit 1
PS
            ;;
        *)
            cat <<'SH'
for d in /var/lib/multissh-agent "$HOME/.config/multissh-agent" "/Library/Application Support/multissh-agent"; do
    if [ -f "$d/manage.sh" ]; then exec sh "$d/manage.sh" --update -y; fi
done
echo "no multissh-agent install found on this machine" >&2
exit 1
SH
            ;;
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
for entry in $TODO; do echo "    ${entry%/*}  (${entry#*/})"; done
echo

FAILED=
DONE=
for entry in $TODO; do
    name=${entry%/*}
    platform=${entry#*/}
    echo "==> $name"

    if [ "$platform" = unknown ]; then
        echo "    skipped: this agent is too old to say what platform it is on." >&2
        echo "    Update it by hand, or re-run the installer on it." >&2
        FAILED="$FAILED $name"
        continue
    fi

    if ! update_command "$platform" | run_bounded "$CMD_TIMEOUT" \
            $SSH $SSHOPTS -J "$PROXY" -o StrictHostKeyChecking=accept-new \
            "update@$name" 2>&1 | sed 's/^/    /'; then
        # The agent restarts as the last thing it does, so the session is very
        # often cut off mid-sentence. Whether this worked is decided by the
        # machine coming back, not by an exit status from a command that
        # expected to be killed.
        echo "    (command ended early -- checking whether it took anyway)"
    fi

    printf '    waiting for it to come back'
    deadline=$(( $(date +%s) + WAIT_SECONDS ))
    ok=
    while [ "$(date +%s)" -lt "$deadline" ]; do
        sleep 3
        printf '.'
        state=$(targets | awk -v n="$name" '$1 == n { print $3 }')
        if [ "$state" = current ]; then ok=1; break; fi
    done
    echo

    if [ -n "$ok" ]; then
        echo "    now current"
        DONE="$DONE $name"
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

echo
[ -n "$DONE" ] && echo "updated:$DONE"
if [ -n "$FAILED" ]; then
    echo "did not update:$FAILED" >&2
    echo "(re-run to try them again; nothing was left half-applied)" >&2
    exit 1
fi
echo "all done"

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
#   MULTISSH_WAIT      seconds to wait for a machine to come back  (default 120)
#   MULTISSH_TIMEOUT   seconds to allow the update command itself   (default 90)
#   MULTISSH_DEADLINE  seconds for the whole sweep                  (default 1800)
#   MULTISSH_STOP      set to 1 to stop at the first failure instead of skipping
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
WAIT_SECONDS=${MULTISSH_WAIT:-120}
CMD_TIMEOUT=${MULTISSH_TIMEOUT:-90}
DEADLINE=$(( $(date +%s) + ${MULTISSH_DEADLINE:-1800} ))

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

POSIX_UPDATE='for d in /var/lib/multissh-agent "$HOME/.config/multissh-agent" "/Library/Application Support/multissh-agent"; do
    if [ -f "$d/manage.sh" ]; then exec sh "$d/manage.sh" --update -y; fi
done
echo "no multissh-agent install found on this machine" >&2
exit 1'

WINDOWS_UPDATE='$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
foreach ($d in @("$env:ProgramData\multiSSH", "$env:LOCALAPPDATA\multiSSH\state")) {
    $m = Join-Path $d "manage.ps1"
    if (Test-Path $m) { & ([scriptblock]::Create((Get-Content $m -Raw))) -Update -Yes; exit 0 }
}
Write-Host "no multissh-agent install found on this machine"
exit 1'

update_command() { # update_command PLATFORM
    case "$1" in
        windows)
            printf "\$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'));Invoke-Expression \$s" \
                "$(b64 "$WINDOWS_UPDATE")"
            ;;
        *)
            printf "echo %s | base64 -d | sh" "$(b64 "$POSIX_UPDATE")"
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

# Interrupting has to say what happened. Pressing ^C used to print nothing at
# all, leaving no way to tell which machines had already been done.
DONE=
FAILED=
summary() {
    echo
    [ -n "$DONE" ]   && echo "updated:$DONE"
    [ -n "$FAILED" ] && echo "did not update:$FAILED" >&2
    return 0
}
trap 'echo; echo "interrupted." >&2; summary; exit 130' INT TERM

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

    if [ "$platform" = unknown ]; then
        echo "    skipped: this agent is too old to say what platform it is on." >&2
        echo "    Update it by hand, or re-run the installer on it." >&2
        FAILED="$FAILED $name"
        continue
    fi

    # The agent always allocates a pseudo-terminal, even for a command, so
    # Windows sends ConPTY setup sequences before anything readable. Strip
    # them rather than print them.
    if ! run_bounded "$CMD_TIMEOUT" \
            $SSH $SSHOPTS -J "$PROXY" -o StrictHostKeyChecking=accept-new \
            "update@$name" "$(update_command "$platform")" 2>&1 |
            sed -e 's/\x1b\][^\x07]*\x07//g' -e 's/\x1b\[[0-9;?]*[a-zA-Z]//g' -e 's/^/    /'; then
        # The agent restarts as the last thing it does, so the session is very
        # often cut off mid-sentence. Whether this worked is decided by the
        # machine coming back, not by an exit status from a command that
        # expected to be killed.
        echo "    (command ended early -- checking whether it took anyway)"
    fi

    # Progress with numbers on it. A row of dots for two minutes is
    # indistinguishable from a hang, which is how a slow failure came to look
    # like a broken script.
    started=$(date +%s)
    until_ts=$(( started + WAIT_SECONDS ))
    ok=
    while :; do
        now=$(date +%s)
        [ "$now" -lt "$until_ts" ] || break
        state=$(targets | awk -v n="$name" '$1 == n { print $3 }')
        if [ "$state" = current ]; then ok=1; break; fi
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

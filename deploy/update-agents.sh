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
# One at a time, waiting for each machine to come back before touching the
# next, and stopping at the first failure. That ordering is the point. An
# update that goes wrong on a rescue tool takes away the thing you would use to
# fix it, so the blast radius of a bad build has to be one machine -- and you
# find out on that one rather than on all of them.
set -eu

[ $# -ge 1 ] || { echo "usage: sh deploy/update-agents.sh <proxy> [name...] [--all]" >&2; exit 2; }
PROXY=$1; shift

ALL=
NAMES=
for arg in "$@"; do
    case "$arg" in
        --all) ALL=1 ;;
        -*)    echo "unknown option: $arg" >&2; exit 2 ;;
        *)     NAMES="$NAMES $arg" ;;
    esac
done

SSH=${MULTISSH_SSH:-ssh}
WAIT_SECONDS=${MULTISSH_WAIT:-120}

# listing asks the proxy what it has. `ssh proxy` serves this on a shell
# request, so there is no command to run and nothing to quote.
listing() { $SSH "$PROXY" 2>/dev/null | tr -d '\r'; }

# targets extracts "<canonical> <state>" from the connected section only. The
# "not connected" section below it also holds canonical names, and those
# machines cannot be updated because they are not here.
targets() {
    listing | awk '
        /not connected/ { exit }
        /^   [a-z0-9]/ {
            name = ""; state = ""
            for (i = 1; i <= NF; i++) {
                if ($i ~ /\./ && $i !~ /^SHA256:/) name = $i
                if ($i == "OUTDATED" || $i == "current") state = $i
            }
            if (name != "") print name, state
        }'
}

# The saved installer lives beside the agent's keys. Both default locations are
# tried because the scope depends on whether the install ran as root, and the
# script itself works out the rest.
UPDATE_CMD='for d in /var/lib/multissh-agent "$HOME/.config/multissh-agent" "/Library/Application Support/multissh-agent"; do
    if [ -f "$d/manage.sh" ]; then exec sh "$d/manage.sh" --update -y; fi
done
echo "no multissh-agent install found on this machine" >&2; exit 1'

# matches reports whether a target was asked for, by either of its names.
#
# Written with explicit if/then rather than `test && return`: under `set -e` a
# bare test that comes out false is a non-zero statement and takes the whole
# script down with it. That is the same shape as the bug that once made the
# installer abort silently, so it is not repeated here.
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
    name=$1
    state=${2:-}
    if matches "$name"; then
        if [ -n "$ALL" ] || [ "$state" = OUTDATED ] || [ -z "$state" ]; then
            TODO="$TODO $name"
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
for name in $TODO; do echo "    $name"; done
echo

FAILED=
for name in $TODO; do
    echo "==> $name"
    if ! $SSH -J "$PROXY" -o StrictHostKeyChecking=accept-new "update@$name" "$UPDATE_CMD" 2>&1 | sed 's/^/    /'; then
        echo "    update command failed" >&2
        FAILED=$name
        break
    fi

    # The agent restarts as the last step, so the session above may well have
    # been cut off mid-sentence. Success is the machine coming back, not the
    # exit status of a command that expected to be killed.
    printf '    waiting for it to come back'
    deadline=$(( $(date +%s) + WAIT_SECONDS ))
    ok=
    while [ "$(date +%s)" -lt "$deadline" ]; do
        sleep 3
        printf '.'
        state=$(targets | awk -v n="$name" '$1 == n { print $2 }')
        case "$state" in
            current) ok=1; break ;;
            OUTDATED) ;;                 # back, but still on the old binary
            *) ;;                        # not back yet
        esac
    done
    echo
    if [ -n "$ok" ]; then
        echo "    now current"
    else
        echo "    did NOT come back current within ${WAIT_SECONDS}s" >&2
        echo "    the previous binary is still on that machine: --rollback" >&2
        FAILED=$name
        break
    fi
done

if [ -n "$FAILED" ]; then
    echo
    echo "stopped at $FAILED; the remaining machines were left alone." >&2
    exit 1
fi

echo
echo "all done"

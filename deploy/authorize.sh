#!/bin/sh
# Push an updated set of login keys to targets, one machine at a time, with
# every change approved by hand.
#
#   sh deploy/authorize.sh multissh users_authorized_keys           # every connected target
#   sh deploy/authorize.sh multissh users_authorized_keys laptop    # just these
#   sh deploy/authorize.sh multissh users_authorized_keys --yes     # approve every change
#
# The keys a target accepts are fixed at enrolment and never change on their
# own: removing someone from the proxy's own users file does not reach the
# machines. This is the lever for that, kept deliberately manual -- the proxy is
# not in a position to rewrite who may log into your machines, so you are, over
# the authenticated session, with each addition and removal shown and confirmed.
#
# KEYSFILE is an authorized_keys file: the set you want the targets to accept.
# Ordinarily a copy of the proxy's own users_authorized_keys, but it is yours to
# curate -- nothing here trusts the proxy to supply it.
#
# For each target the current set is read, compared with KEYSFILE, and every key
# to be added or removed is put to you one at a time. Nothing is written unless
# you approve at least one change, and the agent re-reads the file on its next
# connection, so no restart and no window with the machine unreachable.
#
# The PROXY argument is however you reach the proxy with a stock ssh client: a
# Host alias from ~/.ssh/config, or user@host.
#
#   MULTISSH_YES       set to 1 to approve every change without asking
#   MULTISSH_TIMEOUT   seconds to allow a single read or write   (default 45)
#   MULTISSH_DEADLINE  seconds for the whole sweep               (default 1800)
set -eu

[ $# -ge 2 ] || { echo "usage: sh deploy/authorize.sh <proxy> <keysfile> [name...] [--yes]" >&2; exit 2; }
PROXY=$1; KEYSFILE=$2; shift 2

[ -f "$KEYSFILE" ] || { echo "no such keys file: $KEYSFILE" >&2; exit 2; }

ASSUME_YES=${MULTISSH_YES:-}
NAMES=
for arg in "$@"; do
    case "$arg" in
        -y|--yes) ASSUME_YES=1 ;;
        -*)       echo "unknown option: $arg" >&2; exit 2 ;;
        *)        NAMES="$NAMES $arg" ;;
    esac
done

SSH=${MULTISSH_SSH:-ssh}
CMD_TIMEOUT=${MULTISSH_TIMEOUT:-45}
DEADLINE=$(( $(date +%s) + ${MULTISSH_DEADLINE:-1800} ))

WORK=$(mktemp -d "${TMPDIR:-/tmp}/multissh-authorize.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

# The same bounded, non-interactive ssh update-agents.sh uses, and for the same
# reasons: -T -n keep a target that stops answering from hanging the sweep and
# from putting the local terminal into raw mode.
SSHOPTS="-T -n -o BatchMode=yes -o ConnectTimeout=15 -o ServerAliveInterval=10 -o ServerAliveCountMax=3"

have_timeout=
command -v timeout >/dev/null 2>&1 && have_timeout=1
run_bounded() { # run_bounded SECONDS COMMAND...
    _t=$1; shift
    if [ -n "$have_timeout" ]; then timeout "$_t" "$@"; else "$@"; fi
}

b64() { base64 | tr -d '\n'; }

listing() { run_bounded 30 $SSH $SSHOPTS "$PROXY" 2>/dev/null | tr -d '\r' || true; }

# targets extracts "<canonical> <platform>" from the ONLINE section only, the
# same parse update-agents.sh uses so the two agree on what is reachable.
targets() {
    listing | awk '
        /^ ONLINE \(/ { inside = 1; next }
        /^ [A-Z]+/    { inside = 0 }
        !inside       { next }
        {
            name = ""; platform = ""
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^[a-z0-9][a-z0-9-]*\.[a-z2-7]+$/) name = $i
                else if ($i ~ /^(linux|windows|darwin|freebsd|openbsd)$/) platform = $i
            }
            if (name != "") print name, (platform == "" ? "unknown" : platform)
        }'
}

matches() { # matches CANONICAL
    if [ -z "$NAMES" ]; then return 0; fi
    _base=${1%%.*}
    for want in $NAMES; do
        if [ "$want" = "$1" ] || [ "$want" = "$_base" ]; then return 0; fi
    done
    return 1
}

# The agent's state directory holds agent_authorized_keys. The search list is
# the installer's defaults per platform; MULTISSH_AGENT_DIRS overrides it, which
# a custom install path needs and the tests use.
POSIX_DIRS='${MULTISSH_AGENT_DIRS:-/var/lib/multissh-agent:$HOME/.config/multissh-agent:/Library/Application Support/multissh-agent}'

posix_read='IFS=:; found=
for d in '"$POSIX_DIRS"'; do
    if [ -f "$d/agent_authorized_keys" ]; then cat "$d/agent_authorized_keys"; found=1; break; fi
done
[ -n "$found" ] || { echo "no multissh-agent install found" >&2; exit 1; }'

windows_read='foreach ($d in @("$env:ProgramData\multiSSH", "$env:LOCALAPPDATA\multiSSH\state")) {
    $f = Join-Path $d "agent_authorized_keys"
    if (Test-Path $f) { Get-Content $f -Raw; exit 0 }
}
Write-Host "no multissh-agent install found"; exit 1'

read_command() { # read_command PLATFORM
    case "$1" in
        windows) printf "\$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'));Invoke-Expression \$s" "$(printf '%s' "$windows_read" | b64)" ;;
        *)       printf "echo %s | base64 -d | sh" "$(printf '%s' "$posix_read" | b64)" ;;
    esac
}

# The new content is handed over base64-encoded, so nothing but [A-Za-z0-9+/=]
# crosses the wire and neither shell has to survive the other's quoting. Written
# through a temporary file and renamed, so a dropped connection mid-write cannot
# leave a truncated authorized_keys that locks everyone out.
write_command() { # write_command PLATFORM CONTENT_B64
    _plat=$1; _b64=$2
    case "$_plat" in
        windows)
            _ps='$b = "'"$_b64"'"
foreach ($d in @("$env:ProgramData\multiSSH", "$env:LOCALAPPDATA\multiSSH\state")) {
    $f = Join-Path $d "agent_authorized_keys"
    if (Test-Path $f) {
        [IO.File]::WriteAllBytes("$f.new", [Convert]::FromBase64String($b))
        Move-Item -Force "$f.new" $f
        Write-Host "written"; exit 0
    }
}
Write-Host "no multissh-agent install found"; exit 1'
            printf "\$s=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('%s'));Invoke-Expression \$s" "$(printf '%s' "$_ps" | b64)"
            ;;
        *)
            _sh='IFS=:; done=
for d in '"$POSIX_DIRS"'; do
    if [ -d "$d" ] && [ -f "$d/agent_authorized_keys" ]; then
        printf %s "'"$_b64"'" | base64 -d > "$d/agent_authorized_keys.new" &&
            mv "$d/agent_authorized_keys.new" "$d/agent_authorized_keys" && done=1 && break
    fi
done
[ -n "$done" ] || { echo "no multissh-agent install found" >&2; exit 1; }
echo written'
            printf "echo %s | base64 -d | sh" "$(printf '%s' "$_sh" | b64)"
            ;;
    esac
}

# A key's identity is its type and blob, columns one and two. The comment is
# ignored, so the same key with a different trailing label is not a change.
identity() { awk 'NF && $1 !~ /^#/ { print $1" "$2 }'; }

# line_for prints the full authorized_keys line for one "type blob" identity,
# preferring the KEYSFILE's copy (with its comment) over the target's.
line_for() { # line_for IDENTITY CURRENTFILE
    awk -v id="$1" 'NF && $1 !~ /^#/ && ($1" "$2)==id { print; exit }' "$KEYSFILE" && return 0
    awk -v id="$1" 'NF && $1 !~ /^#/ && ($1" "$2)==id { print; exit }' "$2"
}

# fingerprint renders one "type blob" line the way ssh-keygen does, for display.
fingerprint() { # fingerprint "type blob"
    if command -v ssh-keygen >/dev/null 2>&1; then
        _fp=$(printf '%s\n' "$1" | ssh-keygen -lf - 2>/dev/null | awk '{ print $2" "$NF }')
        [ -n "$_fp" ] && { printf '%s\n' "$_fp"; return 0; }
    fi
    printf '%s...\n' "$(printf '%s' "$1" | cut -d' ' -f2 | cut -c1-24)"
}

ask() { # ask PROMPT ; yes -> 0
    if [ -n "$ASSUME_YES" ]; then return 0; fi
    { : >/dev/tty; } 2>/dev/null || return 1   # no terminal -> no
    printf '%s [y/N]: ' "$1" > /dev/tty
    read -r _a < /dev/tty || _a=
    case "$_a" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

DONE=; SKIPPED=; FAILED=; UNCHANGED=
summary() {
    echo
    [ -n "$DONE" ]      && echo "updated:$DONE"
    [ -n "$UNCHANGED" ] && echo "already matching:$UNCHANGED"
    [ -n "$SKIPPED" ]   && echo "skipped:$SKIPPED"
    [ -n "$FAILED" ]    && echo "failed:$FAILED" >&2
    return 0
}
trap 'echo; echo "interrupted." >&2; summary; rm -rf "$WORK"; exit 130' INT TERM

echo "==> asking $PROXY what is connected"
ALL_TARGETS=$(targets)
[ -n "$ALL_TARGETS" ] || { echo "no targets connected"; exit 0; }

identity < "$KEYSFILE" | sort -u > "$WORK/want"
[ -s "$WORK/want" ] || { echo "$KEYSFILE has no keys in it; refusing to push an empty set" >&2; exit 2; }

OLDIFS=$IFS
IFS='
'
for line in $ALL_TARGETS; do
    IFS=$OLDIFS
    # shellcheck disable=SC2086
    set -- $line
    name=$1; platform=${2:-unknown}
    IFS='
'
    matches "$name" || continue

    if [ "$(date +%s)" -ge "$DEADLINE" ]; then
        echo "==> $name" >&2
        echo "    skipped: past the overall deadline" >&2
        FAILED="$FAILED $name"; continue
    fi
    echo "==> $name"

    if [ "$platform" = unknown ]; then
        echo "    skipped: this agent is too old to say what platform it is on" >&2
        FAILED="$FAILED $name"; continue
    fi

    if ! run_bounded "$CMD_TIMEOUT" \
            $SSH $SSHOPTS -J "$PROXY" -o StrictHostKeyChecking=accept-new \
            "authorize@$name" "$(read_command "$platform")" 2>/dev/null | tr -d '\r' > "$WORK/current"; then
        echo "    could not read the current keys; skipped" >&2
        FAILED="$FAILED $name"; continue
    fi
    if [ ! -s "$WORK/current" ]; then
        echo "    could not read the current keys; skipped" >&2
        FAILED="$FAILED $name"; continue
    fi
    identity < "$WORK/current" | sort -u > "$WORK/have"

    comm -23 "$WORK/want" "$WORK/have" > "$WORK/add"      # wanted, not present
    comm -13 "$WORK/want" "$WORK/have" > "$WORK/remove"   # present, not wanted

    if [ ! -s "$WORK/add" ] && [ ! -s "$WORK/remove" ]; then
        echo "    already matches"
        UNCHANGED="$UNCHANGED $name"; continue
    fi

    # Begin from what is there; apply only approved changes.
    cp "$WORK/have" "$WORK/keep"
    changed=
    while IFS= read -r k; do
        [ -n "$k" ] || continue
        if ask "  add    $(fingerprint "$k")?"; then
            printf '%s\n' "$k" >> "$WORK/keep"; changed=1
        fi
    done < "$WORK/add"
    while IFS= read -r k; do
        [ -n "$k" ] || continue
        if ask "  remove $(fingerprint "$k")?"; then
            grep -vxF "$k" "$WORK/keep" > "$WORK/keep.tmp" || true
            mv "$WORK/keep.tmp" "$WORK/keep"; changed=1
        fi
    done < "$WORK/remove"

    if [ -z "$changed" ]; then
        echo "    no change approved; left as is"
        SKIPPED="$SKIPPED $name"; continue
    fi

    # Render approved identities to full lines, deduplicated, KEYSFILE comment
    # preferred.
    : > "$WORK/render"
    sort -u "$WORK/keep" | while IFS= read -r id; do
        [ -n "$id" ] || continue
        line_for "$id" "$WORK/current"
    done | awk '!seen[$1" "$2]++' > "$WORK/render"

    if [ ! -s "$WORK/render" ]; then
        echo "    every key was removed; refusing to push an empty set (would lock everyone out)" >&2
        FAILED="$FAILED $name"; continue
    fi

    if ! run_bounded "$CMD_TIMEOUT" \
            $SSH $SSHOPTS -J "$PROXY" -o StrictHostKeyChecking=accept-new \
            "authorize@$name" "$(write_command "$platform" "$(b64 < "$WORK/render")")" >/dev/null 2>&1; then
        echo "    write failed; the previous keys are unchanged" >&2
        FAILED="$FAILED $name"; continue
    fi
    echo "    updated ($(grep -c . "$WORK/render") key(s); takes effect on next connection)"
    DONE="$DONE $name"
done
IFS=$OLDIFS

summary
[ -z "$FAILED" ] || { echo "(re-run to try the failures again; nothing was left half-applied)" >&2; exit 1; }
echo "all done"

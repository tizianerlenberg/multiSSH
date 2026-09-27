#!/bin/sh
# Clear out machines the proxy still remembers but that are gone: walk every
# target that is not connected right now and decide on each one by hand.
#
#   sh deploy/forget.sh multissh server@vps            # every target not connected
#   sh deploy/forget.sh multissh server@vps --stale    # only those past -stale-after
#
# The counterpart to uninstalling an agent. The machine is gone, but the proxy
# still holds its friendly name and its last-seen entry, so the listing keeps
# showing it -- and a reinstall under the same name comes back reachable only
# under its canonical name, because the old binding refuses the new key.
#
# Two addresses, because two different things are asked:
#   PROXY  how you reach the proxy's ssh listener with a stock client (a Host
#          alias from ~/.ssh/config, or user@host -p port) -- read for the listing
#   ADMIN  a login on the machine the proxy runs on, with sudo -- where
#          `multissh-proxy -forget` is run and the proxy is reloaded
#
# Nothing is changed until you have gone through the whole list: the chosen
# names are shown once more, then forgotten in one ssh session, followed by a
# single reload. Connected targets are never offered. Forgetting does not revoke
# anything; a machine that comes back simply shows up again.
#
#   MULTISSH_STATE_DIR  the proxy's working directory  (default /var/lib/multissh)
#   MULTISSH_BIN        the proxy binary               (default /usr/local/bin/multissh-proxy)
#   MULTISSH_RUNAS      the proxy's service account    (default multissh)
#   MULTISSH_SERVICE    the systemd unit               (default multissh-proxy)
set -eu

[ $# -ge 2 ] || { echo "usage: sh deploy/forget.sh <proxy> <admin> [--stale]" >&2; exit 2; }
PROXY=$1; ADMIN=$2; shift 2

ONLY_STALE=
for arg in "$@"; do
    case "$arg" in
        --stale) ONLY_STALE=1 ;;
        *)       echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

SSH=${MULTISSH_SSH:-ssh}
STATE_DIR=${MULTISSH_STATE_DIR:-/var/lib/multissh}
BIN=${MULTISSH_BIN:-/usr/local/bin/multissh-proxy}
RUNAS=${MULTISSH_RUNAS:-multissh}
SERVICE=${MULTISSH_SERVICE:-multissh-proxy}

# Answers come from the terminal, not stdin, so this also works piped.
[ -r /dev/tty ] || { echo "needs a terminal to ask on" >&2; exit 2; }

# The NOT CONNECTED section of the listing, one "<mark> <name> <last seen...>"
# per line. The mark is "!" past -stale-after, otherwise blank -- so it is
# normalised to "-" here to keep the fields aligned.
missing=$($SSH -T -n -o BatchMode=yes -o ConnectTimeout=15 "$PROXY" 2>/dev/null | tr -d '\r' | awk '
    /^ NOT CONNECTED \(/ { inside = 1; next }
    /^ [A-Z]/            { inside = 0 }
    inside && /last seen/ {
        mark = "-"; name = $1
        if ($1 == "!") { mark = "!"; name = $2 }
        sub(/.*last seen /, "")
        print mark, name, $0
    }') || true

if [ -n "$ONLY_STALE" ]; then
    missing=$(printf '%s\n' "$missing" | awk '$1 == "!"')
fi

if [ -z "$missing" ]; then
    echo "nothing to clear: every target the proxy knows is connected${ONLY_STALE:+ or recent}."
    exit 0
fi

total=$(printf '%s\n' "$missing" | wc -l | tr -d ' ')
echo "$total target(s) not connected. Enter forgets, s skips, q stops asking."
echo

chosen=
i=0
while IFS= read -r line; do
    i=$((i + 1))
    mark=${line%% *}; rest=${line#* }
    name=${rest%% *}; seen=${rest#* }
    # Names go into a remote command line: accept only what the proxy issues.
    case "$name" in
        *[!A-Za-z0-9._-]*|'') echo "  skipping odd name: $name" >&2; continue ;;
    esac
    flag=; [ "$mark" = "!" ] && flag="  (stale)"
    printf '[%d/%d] %s  last seen %s%s  forget? [Enter/s/q] ' "$i" "$total" "$name" "$seen" "$flag"
    read -r answer </dev/tty || answer=q
    case "$answer" in
        '')     chosen="$chosen $name" ;;
        q|Q)    break ;;
        *)      ;;
    esac
done <<EOF
$missing
EOF

if [ -z "$chosen" ]; then
    echo; echo "nothing chosen, nothing changed."
    exit 0
fi

echo
echo "about to forget on $ADMIN:"
for n in $chosen; do echo "  $n"; done
printf 'go ahead? [y/N] '
read -r answer </dev/tty || answer=
case "$answer" in y|Y|yes) ;; *) echo "nothing changed."; exit 0 ;; esac

# One session for everything, with a terminal so sudo may ask for a password.
# Run as the service account (through runuser, so a sudoers entry that only
# covers root is enough), which is also the only one allowed into its
# state directory: -forget rewrites the ledger and the last-seen
# file, and written as root they would no longer be readable by the proxy.
# shellcheck disable=SC2086 # $chosen is a validated, space-separated list
$SSH -t "$ADMIN" "for n in $chosen; do echo \"== \$n\"; sudo runuser -u '$RUNAS' -- sh -c 'cd \"\$1\" && exec \"\$2\" -forget \"\$3\"' _ '$STATE_DIR' '$BIN' \"\$n\" | grep -v -e 'reload the proxy' -e 'systemctl reload' -e '^\$' || true; done && sudo systemctl reload '$SERVICE' && echo && echo 'reloaded $SERVICE'"

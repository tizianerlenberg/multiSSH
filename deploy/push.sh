#!/bin/sh
# Build everything and deploy it to the proxy host, from a development machine.
#
#   sh deploy/push.sh root@multissh.example.com --public-url https://multissh.example.com
#   sh deploy/push.sh root@multissh.example.com          # subsequent updates
#
# Safe to run against a live proxy. Only what actually changed is acted on: a
# new proxy binary restarts the service, new agent builds are picked up with a
# reload that costs nobody their connection, and an unchanged tree does nothing.
#
# --public-url is required the first time only; after that the unit on the
# server holds the configuration and this will not overwrite it.
set -eu

REPO=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
[ $# -ge 1 ] || { echo "usage: sh deploy/push.sh [user@]host [--public-url URL] [...]" >&2; exit 2; }
HOST=$1; shift

SSH=${MULTISSH_SSH:-ssh}
SUDO=${MULTISSH_SUDO:-sudo}
REMOTE_TMP=${MULTISSH_REMOTE_TMP:-/tmp/multissh-push}

echo "==> building"
sh "$REPO/deploy/build.sh" "$REPO/dist" >/dev/null
echo "    $(ls "$REPO/dist" | tr '\n' ' ')and the proxy"

echo "==> shipping to $HOST:$REMOTE_TMP"
# tar over ssh rather than rsync or scp -r: rsync is not on every minimal VPS
# image, and this preserves the executable bits without a second chmod pass.
$SSH "$HOST" "rm -rf $REMOTE_TMP && mkdir -p $REMOTE_TMP"
tar -C "$REPO" -cf - multissh-proxy dist deploy/install-proxy.sh |
    $SSH "$HOST" "tar -C $REMOTE_TMP -xf - && mv $REMOTE_TMP/deploy/install-proxy.sh $REMOTE_TMP/ && rmdir $REMOTE_TMP/deploy"

echo "==> installing"
# The arguments are forwarded verbatim, so --public-url and friends work the
# same whether typed here or on the server.
$SSH -t "$HOST" "$SUDO sh $REMOTE_TMP/install-proxy.sh $*"

echo "==> cleaning up"
$SSH "$HOST" "rm -rf $REMOTE_TMP"

# The proxy's own report, fetched through the host rather than from here: the
# agent listener is bound to loopback and is not meant to be reachable outside.
# Confirms the shipped binary is the one now running, rather than trusting that
# a command exited zero.
echo "==> health"
WANT=$(sha256sum "$REPO/multissh-proxy" 2>/dev/null | cut -c1-12 ||
       shasum -a 256 "$REPO/multissh-proxy" | cut -c1-12)
GOT=$($SSH "$HOST" 'curl -fsS http://127.0.0.1:8080/healthz 2>/dev/null' || true)
if [ -z "$GOT" ]; then
    echo "    (could not read /healthz; check -agent-addr and that the proxy is up)"
    exit 1
fi
echo "    $GOT"
case "$GOT" in
    *"\"build\":\"$WANT\""*)
        echo "    running the build just shipped ($WANT)" ;;
    *'"build"'*)
        # It reports a build and it is not ours: the restart did not take.
        echo "    WARNING: the proxy reports a different build than the one shipped ($WANT)" >&2 ;;
    *)
        # No build field at all, so it is older than build reporting -- which
        # is expected exactly once, on the push that introduces it.
        echo "    note: this proxy predates build reporting and cannot confirm its version;" >&2
        echo "          the next push will be able to" >&2 ;;
esac

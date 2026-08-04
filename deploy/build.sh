#!/bin/sh
# Cross-compile the agent for every platform the proxy will offer, plus the
# proxy itself. Runnable from anywhere.
set -eu

# Resolve the output directory before moving, so a relative argument still
# means what the caller meant, then work from the repository root: the go
# build lines below name packages relative to it, and push.sh calls this from
# wherever the developer happens to be standing.
OUT=${1:-dist}
case "$OUT" in
    /*) ;;
    *)  OUT=$(pwd)/$OUT ;;
esac
cd "$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"

mkdir -p "$OUT"

for target in linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64; do
    os=${target%-*}
    arch=${target#*-}
    name=$target
    echo "  $name"

    # Windows gets the GUI subsystem. A console-subsystem binary launched by
    # Task Scheduler as the logged-in user pops a console window on their
    # desktop -- which they can close, killing the agent. With -H windowsgui
    # no console is allocated at all, and the agent logs to the file the
    # installer points -log at instead.
    ldflags="-s -w"
    if [ "$os" = windows ]; then
        ldflags="$ldflags -H windowsgui"
    fi

    GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags "$ldflags" -o "$OUT/$name" ./cmd/agent
done

echo "  multissh-proxy"
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o multissh-proxy ./cmd/proxy

echo
echo "agent builds are in $OUT/ -- point the proxy at it with -dist $OUT"

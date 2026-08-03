#!/bin/sh
# Cross-compile the agent for every platform the proxy will offer, plus the
# proxy itself. Run from the repository root.
set -eu
OUT=${1:-dist}
mkdir -p "$OUT"

for target in linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64; do
    os=${target%-*}
    arch=${target#*-}
    name=$target
    echo "  $name"
    GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$OUT/$name" ./cmd/agent
done

echo "  multissh-proxy"
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o multissh-proxy ./cmd/proxy

echo
echo "agent builds are in $OUT/ -- point the proxy at it with -dist $OUT"

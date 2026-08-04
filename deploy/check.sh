#!/bin/sh
# Run everything CI runs, here.
#
#   sh deploy/check.sh
#
# This exists because CI was red for a day and nobody noticed. Two of its
# checks -- shellcheck and a PowerShell parse -- need tools that are on neither
# the development machine nor the proxy, so they were pushed and forgotten, and
# the one automated guard on the platform that cannot be tested locally sat
# broken behind a failing step that ran before it.
#
# Containers cover the two missing tools. Without a container runtime those
# checks are skipped and say so, rather than passing silently.
set -eu

cd "$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"

fail=0
step() { printf '\n== %s\n' "$1"; }
bad()  { printf '   FAILED\n'; fail=1; }

RUNNER=
for r in podman docker; do
    if command -v "$r" >/dev/null 2>&1; then RUNNER=$r; break; fi
done

step "gofmt"
unformatted=$(gofmt -l cmd internal e2e)
if [ -n "$unformatted" ]; then printf '%s\n' "$unformatted"; bad; else echo "   clean"; fi

step "go vet"
go vet ./... || bad

step "go test"
go test -count=1 -timeout 12m ./... || bad

step "sh -n"
for f in cmd/proxy/scripts/install.sh deploy/*.sh; do
    sh -n "$f" || { echo "   $f"; bad; }
done
echo "   parsed"

step "shellcheck"
if [ -z "$RUNNER" ]; then
    echo "   SKIPPED: no podman or docker, and shellcheck is not installed locally"
elif command -v shellcheck >/dev/null 2>&1; then
    shellcheck --shell=sh --severity=warning cmd/proxy/scripts/install.sh deploy/*.sh || bad
else
    "$RUNNER" run --rm -v "$PWD:/src:z" -w /src docker.io/koalaman/shellcheck:stable \
        --shell=sh --severity=warning cmd/proxy/scripts/install.sh deploy/*.sh || bad
fi

step "install.ps1 parses"
# The rendered script, not the template: the placeholders are substituted with
# real values, and a quoting mistake in that substitution would only show here.
if [ -z "$RUNNER" ]; then
    echo "   SKIPPED: no podman or docker, and pwsh is not installed locally"
else
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/dist"
    head -c 512 /dev/urandom > "$tmp/dist/windows-amd64"
    echo "# none" > "$tmp/users_authorized_keys"
    go build -o "$tmp/proxy" ./cmd/proxy
    ( cd "$tmp" && ./proxy -user-addr 127.0.0.1:0 -agent-addr 127.0.0.1:18099 \
        -public-url https://example.invalid -dist dist >/dev/null 2>&1 & echo $! > "$tmp/pid" )
    sleep 2
    curl -fsS http://127.0.0.1:18099/install.ps1 -o "$tmp/install.ps1" || bad
    kill "$(cat "$tmp/pid")" 2>/dev/null || true

    if [ -s "$tmp/install.ps1" ]; then
        "$RUNNER" run --rm -v "$tmp:/w:z" mcr.microsoft.com/powershell:latest \
            pwsh -NoProfile -Command '
              $e = $null
              [System.Management.Automation.Language.Parser]::ParseFile("/w/install.ps1", [ref]$null, [ref]$e) | Out-Null
              if ($e) { $e | ForEach-Object { Write-Host "   $_" }; exit 1 }
              Write-Host "   parsed"' || bad
    else
        echo "   could not render install.ps1"; bad
    fi
fi

step "cross-compile"
out=$(mktemp -d)
sh deploy/build.sh "$out" >/dev/null && echo "   $(ls "$out" | tr '\n' ' ')"
rm -rf "$out"

printf '\n'
if [ "$fail" -ne 0 ]; then
    echo "SOMETHING FAILED -- do not push"
    exit 1
fi
echo "all checks passed"

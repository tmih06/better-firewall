#!/usr/bin/env bash
# scripts/ci/check.sh — static checks for better-firewall. Safe: no root, no
# namespace, no network mutation. Suitable for any developer machine and CI.
#
# Usage:
#   scripts/ci/check.sh            run every check below
#   scripts/ci/check.sh NAME... run a subset: fmt modtidy vet staticcheck vuln
#                                  actionlint shellcheck
# Tool versions are pinned by the CI workflow (.github/workflows/ci.yml).
# For local runs install them yourself, e.g.:
#   go install honnef.co/go/tools/cmd/staticcheck@2026.2.1
#   go install golang.org/x/vuln/cmd/govulncheck@v1.8.0
#   go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
#   go install github.com/zricethezav/gitleaks/v8@v8.30.1
#   apt-get install shellcheck            (or your distro's package)
set -euo pipefail

cd "$(dirname "$0")/../.."

log() { printf '[check] %s\n' "$*"; }
die() { printf '[check] FATAL: %s\n' "$*" >&2; exit 1; }

need() {
    command -v "$1" >/dev/null 2>&1 || \
        die "missing '$1' ($2) — install it or run the corresponding CI job"
}

check_fmt() {
    need go gofmt
    log "gofmt -l ."
    local unformatted
    unformatted="$(gofmt -l .)"
    if [ -n "$unformatted" ]; then
        printf '[check] unformatted files (run gofmt -w):\n%s\n' "$unformatted" >&2
        return 1
    fi
}

check_modtidy() {
    need go
    log "go.mod/go.sum tidiness"
    local modfile sumfile changed=0
    modfile="$(mktemp ./.bfw-modtidy.XXXXXX.mod)"
    sumfile="${modfile%.mod}.sum"
    if ! cp go.mod "$modfile" || ! cp go.sum "$sumfile"; then
        rm -f "$modfile" "$sumfile"
        return 1
    fi
    if ! go mod tidy -modfile="$modfile"; then
        rm -f "$modfile" "$sumfile"
        return 1
    fi
    if ! cmp -s go.mod "$modfile"; then
        diff -u go.mod "$modfile" || true
        changed=1
    fi
    if ! cmp -s go.sum "$sumfile"; then
        diff -u go.sum "$sumfile" || true
        changed=1
    fi
    rm -f "$modfile" "$sumfile"
    if [ "$changed" -ne 0 ]; then
        printf '[check] go.mod/go.sum are not tidy; run go mod tidy\n' >&2
        return 1
    fi
}


check_vet() {
    need go
    log "go vet ./..."
    go vet ./...
}

check_staticcheck() {
    need staticcheck "https://staticcheck.dev — go install honnef.co/go/tools/cmd/staticcheck@<pin>"
    log "staticcheck ./..."
    staticcheck ./...
}

check_vuln() {
    need govulncheck "go install golang.org/x/vuln/cmd/govulncheck@<pin>"
    log "govulncheck ./... (module + stdlib vulnerability scan)"
    govulncheck ./...
}

check_actionlint() {
    need actionlint "go install github.com/rhysd/actionlint/cmd/actionlint@<pin>"
    shopt -s nullglob
    local workflows=(.github/workflows/*.yml .github/workflows/*.yaml)
    if [ "${#workflows[@]}" -eq 0 ]; then
        log "no workflows found; skipping actionlint"
        return 0
    fi
    log "actionlint ${workflows[*]}"
    actionlint "${workflows[@]}"
}

check_shellcheck() {
    need shellcheck "apt-get install shellcheck"
    shopt -s nullglob globstar
    local scripts=(scripts/**/*.sh)
    if [ "${#scripts[@]}" -eq 0 ]; then
        log "no shell scripts under scripts/; skipping shellcheck"
        return 0
    fi
    log "shellcheck ${scripts[*]}"
    shellcheck "${scripts[@]}"
}

main() {
    local checks=("$@")
    if [ "${#checks[@]}" -eq 0 ]; then
        checks=(fmt modtidy vet staticcheck actionlint shellcheck vuln)
    fi
    local name
    for name in "${checks[@]}"; do
        case "$name" in
            fmt|modtidy|vet|staticcheck|vuln|actionlint|shellcheck) "check_$name" ;;
            *) die "unknown check '$name' (valid: fmt modtidy vet staticcheck vuln actionlint shellcheck)" ;;
        esac
    done
    log "all requested checks passed"
}

main "$@"

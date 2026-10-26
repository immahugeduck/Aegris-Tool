#!/usr/bin/env bash
# Installs the scanners Aegris uses, pinned to exact versions and checked
# against known SHA-256 checksums so a tampered download fails loudly.
# Linux x86_64 (GitHub's ubuntu-latest runners). Re-running is safe.
set -euo pipefail

GITLEAKS_VERSION=8.21.2
GITLEAKS_SHA256=5bc41815076e6ed6ef8fbecc9d9b75bcae31f39029ceb55da08086315316e3ba
OSV_VERSION=1.9.2
OSV_SHA256=d6af4b67fa5de658598bd2d445efb99e90d1734b3146962418719c4350ecb74b
SEMGREP_VERSION=1.182.1

BIN="${AEGRIS_BIN:-$HOME/.local/bin}"
mkdir -p "$BIN"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

fetch() {  # url sha256 dest
  curl -fsSL --retry 3 -o "$3" "$1"
  echo "$2  $3" | sha256sum -c --quiet - || { echo "checksum mismatch for $1" >&2; exit 1; }
}

if ! "$BIN/gitleaks" version 2>/dev/null | grep -q "$GITLEAKS_VERSION"; then
  fetch "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
    "$GITLEAKS_SHA256" "$TMP/gitleaks.tgz"
  tar -xzf "$TMP/gitleaks.tgz" -C "$TMP" gitleaks
  install -m 0755 "$TMP/gitleaks" "$BIN/gitleaks"
fi

if ! "$BIN/osv-scanner" --version 2>/dev/null | grep -q "$OSV_VERSION"; then
  fetch "https://github.com/google/osv-scanner/releases/download/v${OSV_VERSION}/osv-scanner_linux_amd64" \
    "$OSV_SHA256" "$TMP/osv-scanner"
  install -m 0755 "$TMP/osv-scanner" "$BIN/osv-scanner"
fi

python3 -m pip install --quiet --disable-pip-version-check "semgrep==${SEMGREP_VERSION}"

if [ -n "${GITHUB_PATH:-}" ]; then
  echo "$BIN" >> "$GITHUB_PATH"
fi
export PATH="$BIN:$PATH"
gitleaks version
osv-scanner --version | head -1
semgrep --version

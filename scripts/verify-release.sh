#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 <tag>"
  echo "Example: $0 v1.0.0"
  exit 1
fi

TAG="$1"
REPO="holder-bot/core-security"
BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"

if ! command -v cosign >/dev/null 2>&1; then
  echo "cosign is required. Install: brew install cosign"
  exit 1
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

cd "$WORKDIR"

curl -fsSLO "${BASE_URL}/core-security-${TAG}.tar.gz"
curl -fsSLO "${BASE_URL}/core-security-${TAG}.tar.gz.sha256"
curl -fsSLO "${BASE_URL}/core-security-${TAG}.tar.gz.sig"
curl -fsSLO "${BASE_URL}/core-security-${TAG}.tar.gz.pem"

EXPECTED_SHA=$(awk '{print $1}' "core-security-${TAG}.tar.gz.sha256")
ACTUAL_SHA=$(shasum -a 256 "core-security-${TAG}.tar.gz" | awk '{print $1}')

if [ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]; then
  echo "Checksum mismatch"
  echo "Expected: $EXPECTED_SHA"
  echo "Actual:   $ACTUAL_SHA"
  exit 1
fi

cosign verify-blob \
  --signature "core-security-${TAG}.tar.gz.sig" \
  --certificate "core-security-${TAG}.tar.gz.pem" \
  --certificate-identity-regexp '^https://github.com/holder-bot/core-security/.github/workflows/release-sign.yml@refs/tags/.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "core-security-${TAG}.tar.gz"

echo "Release ${TAG} verified successfully"

#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

FILES=$(find near/src rust-wasm/src rust-signer/src rust-signer-external/src policy frontend-lib \
  -type f | LC_ALL=C sort)

if [ -z "$FILES" ]; then
  echo "No files found to hash" >&2
  exit 1
fi

printf '%s\n' "$FILES" | xargs shasum -a 256 > .oss-manifest.txt
shasum -a 256 .oss-manifest.txt | awk '{print $1}' > .oss-digest.txt

echo "Generated .oss-manifest.txt and .oss-digest.txt"
echo "OSS digest: $(cat .oss-digest.txt)"

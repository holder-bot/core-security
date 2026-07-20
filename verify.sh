#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${1:-https://holder.bot}"
BASE_URL="${BASE_URL%/}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

./scripts/generate-oss-manifest.sh >/dev/null
LOCAL_DIGEST=$(cat .oss-digest.txt)

REMOTE_DIGEST=$(curl -fsS "$BASE_URL/api/verify/oss" | \
  sed -n 's/.*"oss_digest"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')

if [ -z "$REMOTE_DIGEST" ]; then
  echo "Could not parse oss_digest from $BASE_URL/api/verify/oss"
  exit 1
fi

echo "Local digest:  $LOCAL_DIGEST"
echo "Remote digest: $REMOTE_DIGEST"

if [ "$LOCAL_DIGEST" != "$REMOTE_DIGEST" ]; then
  echo "Verification failed: digest mismatch"
  exit 1
fi

echo "Verification successful: digests match"

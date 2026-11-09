#!/usr/bin/env bash
# Write deploy/quickstart/.env from the example. Existing files are kept.
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
example="$root/deploy/quickstart/.env.example"
target="$root/deploy/quickstart/.env"

if [[ -f "$target" ]]; then
  echo "deploy/quickstart/.env already exists; leaving it unchanged" >&2
  exit 0
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required to generate quickstart secrets" >&2
  exit 1
fi

for key in YABANIN_SESSION_KEY YABANIN_CACHE_HMAC_SECRET YABANIN_ENCRYPTION_KEY; do
  if ! grep -q "^${key}=" "$example"; then
    echo "missing ${key} in deploy/quickstart/.env.example" >&2
    exit 1
  fi
done

session=$(openssl rand -hex 32)
hmac=$(openssl rand -hex 32)
enc=$(openssl rand -hex 32)

umask 077
tmp=$(mktemp "${TMPDIR:-/tmp}/yabanin-quickstart.XXXXXX")
sed \
  -e "s/^YABANIN_SESSION_KEY=.*/YABANIN_SESSION_KEY=${session}/" \
  -e "s/^YABANIN_CACHE_HMAC_SECRET=.*/YABANIN_CACHE_HMAC_SECRET=${hmac}/" \
  -e "s/^YABANIN_ENCRYPTION_KEY=.*/YABANIN_ENCRYPTION_KEY=${enc}/" \
  "$example" >"$tmp"
mv "$tmp" "$target"
chmod 600 "$target"
echo "wrote deploy/quickstart/.env (mode 600)"

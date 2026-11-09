#!/usr/bin/env bash
# Seed the quickstart database via the canonical `yabanin seed` one-shot and
# print the API key and admin password once. This is the single seeding path;
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$root"

env_file="$root/deploy/quickstart/.env"
if [[ ! -f "$env_file" ]]; then
  echo "missing deploy/quickstart/.env; run scripts/quickstart/init-env.sh first" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1091
source "$env_file"
set +a

if ! command -v openssl >/dev/null 2>&1; then
  echo "openssl is required to generate the quickstart admin password" >&2
  exit 1
fi

# QS_COMPOSE_FILE lets the regression suite point the seed at a rewritten
# scratch copy of the compose file (QS_PRIMARY_NET override) without editing
# the shipped file. The explicit --project-directory keeps .env resolution
# anchored to deploy/quickstart for any compose file location; it is a no-op
# for the default (the file already lives in that directory).
compose=(docker compose -f "${QS_COMPOSE_FILE:-deploy/quickstart/docker-compose.yml}" \
  --project-directory deploy/quickstart --profile seed)

email=${QS_ADMIN_EMAIL:-admin@localhost}
password=$(openssl rand -hex 16)

set +e
seed_out=$(printf '%s\n' "$password" | "${compose[@]}" run -T --rm seed \
  --admin-email "$email" --admin-password-stdin 2>&1)
seed_code=$?
set -e
if [[ "$seed_code" -ne 0 ]]; then
  printf '%s\n' "$seed_out" >&2
  exit "$seed_code"
fi

printf '%s\n' "$seed_out"

if printf '%s' "$seed_out" | grep -q 'root admin created'; then
  echo "Admin password (shown once, store it now): ${password}"
else
  echo "Admin user ${email} already exists; a new password was not issued." >&2
fi

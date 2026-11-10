#!/usr/bin/env bash
# One-command quickstart demo: configure, build, start, and seed the local
# stand, then point the operator at the dashboard, gateway, and credentials.
# This only chains the documented steps (init-env.sh, compose build/up,
# seed.sh); no credentials are generated or echoed here — they come from
# seed.sh's own output.
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$root"

usage() {
  cat <<'EOF'
usage: scripts/quickstart/demo.sh [--fresh]

Bring the quickstart demo up and print the dashboard URL, gateway URL, and
where the API key and admin password appear.

  --fresh  DESTRUCTIVE: wipe the demo database, keys, and logs
           (compose down -v) first so seed re-issues the credentials.
  -h       Show this help.
EOF
}

fresh=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --fresh) fresh=1 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "unknown flag: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

bash scripts/quickstart/init-env.sh

# The summary reports the configured admin email; seed.sh reads the same file.
set -a
# shellcheck disable=SC1091
source deploy/quickstart/.env
set +a

compose=(docker compose -f deploy/quickstart/docker-compose.yml --profile mock --profile ui)

if [[ "$fresh" -eq 1 ]]; then
  # Demo data is disposable by design; -v drops the DB volume so the seed
  # after `up` issues a fresh key and password instead of "already exists".
  echo "DESTRUCTIVE: wiping demo database, keys, and logs (compose down -v)" >&2
  "${compose[@]}" down -v
fi

# Layer cache makes re-runs fast; the Dockerfile requires SOURCE_DATE_EPOCH
# for reproducible builds (docs/quickstart.md step 3).
"${compose[@]}" build --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"

"${compose[@]}" up -d --no-build --wait

# seed.sh streams the API key and admin password on stdout; the operator must
# see them live, so tee only keeps a working copy that tells a first-run
# issuance ("shown once") apart from the "already exists" note on later runs.
seed_log=$(mktemp "${TMPDIR:-/tmp}/yabanin-quickstart-demo.XXXXXX")
trap 'rm -f "$seed_log"' EXIT
bash scripts/quickstart/seed.sh | tee "$seed_log"

dashboard_url="http://127.0.0.1:${QS_DASHBOARD_PORT:-3000}"
gateway_url="http://127.0.0.1:${QS_GATEWAY_PORT:-8082}"
login_email=${QS_ADMIN_EMAIL:-admin@localhost}

cat <<EOF

Quickstart demo is up.
  Dashboard: ${dashboard_url}
  Gateway:   ${gateway_url}
  Login:     ${login_email}
EOF

if grep -q 'Admin password (shown once' "$seed_log"; then
  cat <<'EOF'
  The gateway API key and admin password are the two "(shown once, store it
  now)" lines printed above; store them now. Smoke-check the gateway with:

    bash scripts/quickstart/smoke.sh "$YABANIN_API_KEY"

  ($YABANIN_API_KEY must hold the key from the lines above when you run it.)
EOF
else
  cat <<'EOF'
  Seeding is idempotent: the admin user and API key already exist, so the
  credentials were issued on the first run and are not re-displayed. Use the
  ones saved earlier; seeding is not a password reset. To re-issue
  credentials, rerun with --fresh (this wipes the demo database and keys).
EOF
fi

#!/usr/bin/env bash
# Build the checkout, seed the gateway and verify the dashboard end to end.
set -euo pipefail
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
if [[ "${1:-}" != --help && "${1:-}" != -h ]]; then
  bash "$root/scripts/quickstart/init-env.sh"
  set -a
  # shellcheck disable=SC1091
  source "$root/deploy/quickstart/.env"
  set +a
fi
exec python3 "$root/scripts/quickstart/showcase/stand.py" "$@"

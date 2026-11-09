#!/usr/bin/env bash
# Smoke the quickstart gateway. Argument: the API key printed by seed.sh.
set -euo pipefail

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
cd "$root"

key=${1:-}
if [[ -z "$key" ]]; then
  echo "usage: scripts/quickstart/smoke.sh KEY" >&2
  exit 1
fi

env_file="$root/deploy/quickstart/.env"
if [[ -f "$env_file" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$env_file"
  set +a
fi

model=${QS_MODEL:-mock-model}
compose=(docker compose -f deploy/quickstart/docker-compose.yml --profile mock)
base=${QS_BASE:-http://127.0.0.1:8082}

if ! curl -fsS "$base/healthz" >/dev/null; then
  echo "gateway /healthz failed" >&2
  exit 1
fi

models=$(curl -fsS "$base/v1/models" -H "Authorization: Bearer ${key}")
if ! printf '%s' "$models" | grep -q "$model"; then
  echo "GET /v1/models did not contain ${model}" >&2
  exit 1
fi

body=$(curl -fsS "$base/v1/chat/completions" \
  -H "Authorization: Bearer ${key}" \
  -H "Content-Type: application/json" \
  -d "{\"model\":\"${model}\",\"stream\":false,\"messages\":[{\"role\":\"user\",\"content\":\"ping\"}]}")

python3 - "$body" <<'PY'
import json, sys
data = json.loads(sys.argv[1])
content = data["choices"][0]["message"]["content"]
if not isinstance(content, str) or not content.strip():
    raise SystemExit("chat completion content is empty")
PY

sleep 5
count=0
for _ in 1 2 3 4 5 6; do
  count=$("${compose[@]}" exec -T postgres \
    psql -U yabanin -d yabanin -tA \
    -c "SELECT count(*) FROM request_logs WHERE request_id IS NOT NULL")
  count=${count//[[:space:]]/}
  if [[ "${count}" =~ ^[0-9]+$ ]] && [[ "$count" -ge 1 ]]; then
    echo "smoke ok (${count} request log rows)"
    exit 0
  fi
  sleep 2
done

echo "loggerd did not write a request_logs row with request_id" >&2
exit 1

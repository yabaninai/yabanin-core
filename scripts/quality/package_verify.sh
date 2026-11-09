#!/usr/bin/env bash
# NEXT-24: local packaging verification (build without push).
# Every Docker resource belongs to this run and is verified absent on exit.
set -euo pipefail
cd "$(dirname "$0")/../.."

if ! command -v docker >/dev/null 2>&1 || ! docker info >/dev/null 2>&1; then
  echo "FAIL: Docker daemon unavailable; packaging verification cannot run" >&2
  exit 1
fi

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$-${RANDOM}${RANDOM}"
OUT="artifacts/package-verify/$RUN_ID"
LABEL_KEY="io.yabanin.package-verify.run"
OWNER_LABEL="$LABEL_KEY=$RUN_ID"
IMAGE="yabanin-package-verify:$RUN_ID"
NETWORK="yabanin-package-verify-$RUN_ID"
mkdir -p "$OUT"

declare -a OWNED_NAMES=("")
declare -a OWNED_IDS=("")
declare -a OWNED_ANON_VOLUMES=("")
cleanup_failed=0
record_cleanup_failure() {
  cleanup_failed=1
  printf 'FAIL: cleanup: %s\n' "$1" >&2
  printf 'FAIL: cleanup: %s\n' "$1" >>"$OUT/cleanup.log" 2>/dev/null || true
}

cleanup() {
  local status=$?
  # Bash inherits EXIT traps in command-substitution subshells. Only the
  # verifier's top-level shell owns resources or may run this cleanup.
  if [ "${BASH_SUBSHELL:-0}" -gt 0 ]; then return "$status"; fi
  trap - EXIT INT TERM HUP
  set +e
  local name id label remaining

  # First remove by the exact IDs returned by this run, after rechecking label.
  for id in "${OWNED_IDS[@]}"; do
    [ -n "$id" ] || continue
    label=$(docker inspect --format '{{ index .Config.Labels "io.yabanin.package-verify.run" }}' "$id" 2>/dev/null)
    if [ "$label" = "$RUN_ID" ]; then
      if ! docker rm -fv "$id" >/dev/null 2>&1; then
        record_cleanup_failure "failed to remove owned container id=$id"
      fi
    fi
  done

  # A run can be interrupted after Docker creates a container but before the
  # client returns its ID. Resolve only the run's pre-registered exact names.
  for name in "${OWNED_NAMES[@]}"; do
    [ -n "$name" ] || continue
    if ! id=$(docker ps -aq --filter "name=^/$name$" 2>/dev/null); then
      record_cleanup_failure "could not enumerate owned container name=$name"
      continue
    fi
    if [ -n "$id" ]; then
      label=$(docker inspect --format '{{ index .Config.Labels "io.yabanin.package-verify.run" }}' "$id" 2>/dev/null)
      if [ "$label" = "$RUN_ID" ] && ! docker rm -fv "$id" >/dev/null 2>&1; then
        record_cleanup_failure "failed to remove owned container name=$name id=$id"
      fi
    fi
  done

  # The unique label is a final exact-ownership sweep and a leak assertion.
  remaining=$(docker ps -aq --filter "label=$OWNER_LABEL" 2>/dev/null)
  if [ $? -ne 0 ]; then
    record_cleanup_failure "could not enumerate owned containers"
  elif [ -n "$remaining" ]; then
    while IFS= read -r id; do
      [ -n "$id" ] || continue
      label=$(docker inspect --format '{{ index .Config.Labels "io.yabanin.package-verify.run" }}' "$id" 2>/dev/null)
      if [ "$label" = "$RUN_ID" ] && ! docker rm -fv "$id" >/dev/null 2>&1; then
        record_cleanup_failure "failed to remove owned container id=$id during final sweep"
      fi
    done <<<"$remaining"
  fi

  # PostgreSQL and Redis images declare anonymous data volumes. Their exact
  # mount names were recorded from the owned containers before cleanup; Docker
  # removes anonymous (never named) volumes with `rm -v`. Verify each name is
  # absent from a successful volume inventory before reporting clean.
  if [ "${#OWNED_ANON_VOLUMES[@]}" -gt 1 ]; then
    local volumes volume
    if ! volumes=$(docker volume ls -q); then
      record_cleanup_failure "could not enumerate volumes to verify anonymous volume cleanup"
    else
      for volume in "${OWNED_ANON_VOLUMES[@]}"; do
        [ -n "$volume" ] || continue
        if grep -Fqx "$volume" <<<"$volumes"; then
          record_cleanup_failure "owned anonymous volume remains: $volume"
        fi
      done
    fi
  fi
  if ! remaining=$(docker ps -aq --filter "label=$OWNER_LABEL" 2>/dev/null); then
    record_cleanup_failure "could not verify owned containers were removed"
  elif [ -n "$remaining" ]; then
    record_cleanup_failure "owned containers remain: $remaining"
  fi

  label=$(docker network inspect --format '{{ index .Labels "io.yabanin.package-verify.run" }}' "$NETWORK" 2>/dev/null)
  if [ "$label" = "$RUN_ID" ]; then
    if ! docker network rm "$NETWORK" >/dev/null 2>&1; then
      record_cleanup_failure "failed to remove owned network name=$NETWORK"
    fi
  fi
  remaining=$(docker network ls -q --filter "label=$OWNER_LABEL" 2>/dev/null)
  if [ $? -ne 0 ]; then
    record_cleanup_failure "could not enumerate owned networks"
  elif [ -n "$remaining" ]; then
    while IFS= read -r id; do
      [ -n "$id" ] || continue
      label=$(docker network inspect --format '{{ index .Labels "io.yabanin.package-verify.run" }}' "$id" 2>/dev/null)
      if [ "$label" = "$RUN_ID" ] && ! docker network rm "$id" >/dev/null 2>&1; then
        record_cleanup_failure "failed to remove owned network id=$id"
      fi
    done <<<"$remaining"
  fi
  if ! remaining=$(docker network ls -q --filter "label=$OWNER_LABEL" 2>/dev/null); then
    record_cleanup_failure "could not verify owned networks were removed"
  elif [ -n "$remaining" ]; then
    record_cleanup_failure "owned networks remain: $remaining"
  fi

  label=$(docker image inspect --format '{{ index .Config.Labels "io.yabanin.package-verify.run" }}' "$IMAGE" 2>/dev/null)
  if [ "$label" = "$RUN_ID" ]; then
    if ! docker image rm "$IMAGE" >/dev/null 2>&1; then
      record_cleanup_failure "failed to remove owned image tag=$IMAGE"
    fi
  fi
  if [ -n "${DASH_IMAGE:-}" ]; then
    label=$(docker image inspect --format '{{ index .Config.Labels "io.yabanin.package-verify.run" }}' "$DASH_IMAGE" 2>/dev/null)
    if [ "$label" = "$RUN_ID" ]; then
      if ! docker image rm "$DASH_IMAGE" >/dev/null 2>&1; then
        record_cleanup_failure "failed to remove owned image tag=$DASH_IMAGE"
      fi
    fi
  fi
  remaining=$(docker image ls -q --no-trunc --filter "label=$OWNER_LABEL" 2>/dev/null)
  if [ $? -ne 0 ]; then
    record_cleanup_failure "could not enumerate owned images"
  elif [ -n "$remaining" ]; then
    while IFS= read -r id; do
      [ -n "$id" ] || continue
      label=$(docker image inspect --format '{{ index .Config.Labels "io.yabanin.package-verify.run" }}' "$id" 2>/dev/null)
      if [ "$label" = "$RUN_ID" ] && ! docker image rm "$id" >/dev/null 2>&1; then
        record_cleanup_failure "failed to remove owned image id=$id"
      fi
    done <<<"$remaining"
  fi
  if ! remaining=$(docker image ls -q --no-trunc --filter "label=$OWNER_LABEL" 2>/dev/null); then
    record_cleanup_failure "could not verify owned images were removed"
  elif [ -n "$remaining" ]; then
    record_cleanup_failure "owned images remain: $remaining"
  fi

  if [ "$cleanup_failed" = 1 ]; then status=1; fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

fail=0
run_once() {
  local name=$1 output=$2 timeout=${3:-45} id running code
  shift 3
  OWNED_NAMES+=("$name")
  if ! id=$(docker run -d --name "$name" --label "$OWNER_LABEL" "$@"); then
    echo "FAIL: could not start owned container $name" >&2
    return 1
  fi
  OWNED_IDS+=("$id")
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if ! running=$(docker inspect --format '{{.State.Running}}' "$id" 2>/dev/null); then
      echo "FAIL: cannot inspect owned container $name" >&2
      return 1
    fi
    [ "$running" = true ] || break
    sleep 0.2
  done
  if [ "$running" = true ]; then
    echo "FAIL: owned container $name did not exit within ${timeout}s" >&2
    return 1
  fi
  if ! docker logs "$id" >"$output" 2>&1; then
    echo "FAIL: cannot collect output for $name" >&2
    return 1
  fi
  if ! code=$(docker inspect --format '{{.State.ExitCode}}' "$id") || [[ ! "$code" =~ ^[0-9]+$ ]]; then
    echo "FAIL: cannot determine exit status for $name" >&2
    return 1
  fi
  return "$code"
}

require_nonempty() {
  if [ ! -s "$1" ]; then
    echo "FAIL: expected nonempty evidence file: $1" >&2
    fail=1
  fi
}

# The std Dockerfile fails the build loudly without SOURCE_DATE_EPOCH
# (reproducible image recipe, same pattern as scripts/deploy-public-stand.sh):
# default to the last commit time, let an explicit caller value win, reject a
# non-integer value before any docker work starts.
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH=$(git log -1 --pretty=format:%ct 2>/dev/null || true)
fi
case "${SOURCE_DATE_EPOCH:-}" in
  '' | *[!0-9]*)
    echo "FAIL: SOURCE_DATE_EPOCH must be an integer unix timestamp (got: '${SOURCE_DATE_EPOCH:-}')" >&2
    exit 1
    ;;
esac

echo "== building unified image"
docker build -q --label "$OWNER_LABEL" --build-arg "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" -t "$IMAGE" . >"$OUT/build.log" 2>&1

# (contract acceptance-gap 1). Build gate lives here, not in a separate
# script, so the Docker budget and label-ownership cleanup stay in one place.
echo "== building dashboard image"
DASH_IMAGE="yabanin-package-verify-dashboard:$RUN_ID"
if ! docker build -q --label "$OWNER_LABEL" -f web/dashboard/Dockerfile -t "$DASH_IMAGE" . >"$OUT/dashboard-build.log" 2>&1; then
  echo "FAIL: dashboard image build failed; see $OUT/dashboard-build.log" >&2
  exit 1
fi
if ! docker image inspect --format='{{.Id}}' "$DASH_IMAGE" >"$OUT/dashboard-image-id.txt" 2>/dev/null; then
  echo "FAIL: dashboard image id inventory failed" >&2
  exit 1
fi

# dashboard deliverable image. vite currently emits none, so green means the
# deliverable is map-free; any future *.map in the image fails this gate.
echo "== dashboard deliverable contents (sourcemaps fail closed)"
if ! run_once "pkgverify-dashboard-$RUN_ID" "$OUT/dashboard-sourcemaps.txt" 45 \
  --entrypoint /bin/sh "$DASH_IMAGE" -c 'find /usr/share/nginx/html -name "*.map" -print'; then
  code=$?
  echo "FAIL: dashboard sourcemap probe exited $code; see $OUT/dashboard-sourcemaps.txt" >&2
  fail=1
fi
if [ -s "$OUT/dashboard-sourcemaps.txt" ]; then
  echo "FAIL: sourcemaps present in dashboard deliverable:" >&2
  sed 's/^/    /' "$OUT/dashboard-sourcemaps.txt" >&2
  fail=1
fi

echo "== non-root runtime user"
UID_NAME="pkgverify-uid-$RUN_ID"
if run_once "$UID_NAME" "$OUT/runtime-uid.txt" 45 --entrypoint id "$IMAGE" -u; then
  uid=$(tr -d '\r\n' <"$OUT/runtime-uid.txt")
  if [ -z "$uid" ] || [ "$uid" = 0 ]; then
    echo "FAIL: invalid runtime uid: ${uid:-empty}" >&2
    fail=1
  else
    echo "  runtime uid=$uid"
  fi
else
  code=$?
  echo "FAIL: runtime user probe exited $code" >&2
  fail=1
fi
require_nonempty "$OUT/runtime-uid.txt"

echo "== service subcommand matrix"
marker_for() {
  case "$1" in
    gateway)  echo "invalid gateway config" ;;
    admin)    echo "YABANIN_PG_URI is required" ;;
    loggerd)  echo "invalid loggerd config" ;;
    mcp)      echo "YABANIN_PARTNER_API_KEY" ;;
    migrate)  echo "pg_uri is required for migrate" ;;
  esac
}
for sub in gateway admin loggerd mcp migrate; do
  name="pkgverify-route-$sub-$RUN_ID"
  output="$OUT/route-$sub.log"
  if run_once "$name" "$output" 45 --entrypoint /app/yabanin "$IMAGE" "$sub"; then
    code=0
  else
    code=$?
  fi
  marker=$(marker_for "$sub")
  if [ "$code" -ne 0 ] && grep -q "$marker" "$output"; then
    echo "  ✓ $sub (dispatched, config-validated)"
  else
    echo "FAIL: $sub route probe exit=$code, expected marker: $marker" >&2
    fail=1
  fi
done

PG_PASSWORD=$(openssl rand -hex 24)
PG_USER="pkgverify"
PG_DB="pkgverify"
PG_URI="postgres://${PG_USER}:${PG_PASSWORD}@postgres:5432/${PG_DB}?sslmode=disable"
HMAC_SECRET=$(openssl rand -hex 32)

echo "== private disposable database and cache"
NETWORK=$(printf 'yabanin-package-verify-%s' "$RUN_ID")
if ! NETWORK_ID=$(docker network create --label "$OWNER_LABEL" "$NETWORK"); then
  echo "FAIL: could not create owned network $NETWORK" >&2
  exit 1
fi
PG_NAME="pkgverify-pg-$RUN_ID"
OWNED_NAMES+=("$PG_NAME")
if ! POSTGRES_ID=$(docker run -d --network "$NETWORK_ID" --network-alias postgres --name "$PG_NAME" \
  --label "$OWNER_LABEL" -e POSTGRES_USER="$PG_USER" -e POSTGRES_PASSWORD="$PG_PASSWORD" \
  -e POSTGRES_DB="$PG_DB" pgvector/pgvector:pg16); then
  echo "FAIL: could not start owned PostgreSQL container" >&2
  exit 1
fi
OWNED_IDS+=("$POSTGRES_ID")
REDIS_NAME="pkgverify-redis-$RUN_ID"
OWNED_NAMES+=("$REDIS_NAME")
if ! REDIS_ID=$(docker run -d --network "$NETWORK_ID" --network-alias redis --name "$REDIS_NAME" \
  --label "$OWNER_LABEL" redis:7-alpine); then
  echo "FAIL: could not start owned Redis container" >&2
  exit 1
fi
OWNED_IDS+=("$REDIS_ID")

wait_dependency() {
  local id=$1 name=$2 deadline=$((SECONDS + 90)) state
  while (( SECONDS < deadline )); do
    if ! state=$(docker inspect --format '{{.State.Running}}' "$id" 2>/dev/null); then
      echo "FAIL: cannot inspect $name readiness" >&2
      return 1
    fi
    if [ "$state" = true ]; then
      if [ "$name" = postgres ] && docker exec "$id" pg_isready -U "$PG_USER" -d "$PG_DB" >/dev/null 2>&1; then return 0; fi
      if [ "$name" = redis ] && docker exec "$id" redis-cli ping 2>/dev/null | grep -q PONG; then return 0; fi
    else
      echo "FAIL: $name stopped before readiness" >&2
      return 1
    fi
    sleep 1
  done
  echo "FAIL: $name did not become ready within 90 seconds" >&2
  return 1
}
wait_dependency "$POSTGRES_ID" postgres
printf 'PostgreSQL ready via pg_isready\n' >"$OUT/postgres-readiness.txt"
wait_dependency "$REDIS_ID" redis
printf 'Redis ready via PING/PONG\n' >"$OUT/redis-readiness.txt"

record_anonymous_volumes() {
  local id=$1 service=$2 file=$3 names volume
  if ! docker inspect --format '{{json .Mounts}}' "$id" >"$file"; then
    echo "FAIL: cannot record $service mount provenance" >&2
    return 1
  fi
  if ! names=$(python3 - "$file" <<'PY'
import json
import sys

mounts = json.load(open(sys.argv[1], encoding="utf-8"))
volumes = [mount for mount in mounts if mount.get("Type") == "volume"]
if not volumes or any(not mount.get("Name") for mount in volumes):
    raise SystemExit("expected named volume IDs in image-declared mounts")
for mount in volumes:
    print(mount["Name"])
PY
  ); then
    echo "FAIL: invalid $service volume provenance; see $file" >&2
    return 1
  fi
  [ -n "$names" ] || { echo "FAIL: $service has no volume provenance" >&2; return 1; }
  while IFS= read -r volume; do
    [ -n "$volume" ] && printf '%s\t%s\n' "$service" "$volume" >>"$OUT/owned-anonymous-volumes.txt"
  done <<<"$names"
  while IFS= read -r volume; do
    [ -n "$volume" ] && OWNED_ANON_VOLUMES+=("$volume")
  done <<<"$names"
}
record_anonymous_volumes "$POSTGRES_ID" postgres "$OUT/postgres-mounts.json"
record_anonymous_volumes "$REDIS_ID" redis "$OUT/redis-mounts.json"

echo "== apply migrations and start gateway"
MIGRATE_NAME="pkgverify-migrate-$RUN_ID"
if run_once "$MIGRATE_NAME" "$OUT/migrate.log" 120 --network "$NETWORK_ID" \
  --entrypoint /app/yabanin -e YABANIN_PG_URI="$PG_URI" -e YABANIN_REGION=us "$IMAGE" migrate; then
  printf 'Migration command exited 0\n' >"$OUT/migration-result.txt"
else
  code=$?
  echo "FAIL: migrations exited $code; see $OUT/migrate.log" >&2
  exit 1
fi
GATEWAY_NAME="pkgverify-gateway-$RUN_ID"
OWNED_NAMES+=("$GATEWAY_NAME")
if ! GATEWAY_ID=$(docker run -d --network "$NETWORK_ID" --name "$GATEWAY_NAME" \
  --label "$OWNER_LABEL" -e YABANIN_PG_URI="$PG_URI" \
  -e YABANIN_REDIS_ADDR="redis:6379" \
  -e YABANIN_CACHE_HMAC_SECRET="$HMAC_SECRET" -e YABANIN_GATEWAY_LISTEN="0.0.0.0:8082" \
  -e YABANIN_LOG_LEVEL=warn "$IMAGE" gateway); then
  echo "FAIL: could not start owned gateway container" >&2
  exit 1
fi
OWNED_IDS+=("$GATEWAY_ID")
ok=0
for _ in $(seq 1 60); do
  if docker exec "$GATEWAY_ID" wget -q -O- http://127.0.0.1:8082/healthz >"$OUT/healthz.json" 2>/dev/null; then
    if grep -q '"status":"ok"' "$OUT/healthz.json" && grep -q '"redis":"up"' "$OUT/healthz.json"; then ok=1; break; fi
  fi
  if [ "$(docker inspect --format '{{.State.Running}}' "$GATEWAY_ID" 2>/dev/null || true)" != true ]; then break; fi
  sleep 1
done
if [ "$ok" != 1 ]; then
  if ! docker logs "$GATEWAY_ID" >"$OUT/container-gateway.log" 2>&1; then
    echo "FAIL: unable to collect gateway log" >&2
  fi
  echo "FAIL: gateway /healthz did not report status=ok and redis=up" >&2
  { grep -viE kms "$OUT/container-gateway.log" || true; } | tail -8 | sed 's/^/    /'
  fail=1
else
  echo "  ✓ gateway /healthz reports status=ok and redis=up"
fi

echo "== dependency + license inventory (SBOM-lite)"
VERSION_NAME="pkgverify-image-info-$RUN_ID"
OWNED_NAMES+=("$VERSION_NAME")
if VERSION_ID=$(docker create --name "$VERSION_NAME" --label "$OWNER_LABEL" "$IMAGE"); then
  OWNED_IDS+=("$VERSION_ID")
  if ! docker cp "$VERSION_ID:/app/yabanin" "$OUT/yabanin"; then
    echo "FAIL: could not extract the built gateway binary for version inventory" >&2
    fail=1
  elif ! go version -m "$OUT/yabanin" >"$OUT/version.txt" 2>"$OUT/version.stderr"; then
    echo "FAIL: Go build metadata inventory failed; see $OUT/version.stderr" >&2
    fail=1
  fi
  require_nonempty "$OUT/version.txt"
else
  echo "FAIL: could not create owned metadata container" >&2
  fail=1
fi
if ! go list -m all >"$OUT/go-modules.txt" 2>"$OUT/go-modules.stderr"; then
  echo "FAIL: go module inventory failed; see $OUT/go-modules.stderr" >&2
  fail=1
fi
require_nonempty "$OUT/go-modules.txt"
for p in web/dashboard web/site sdks/node services/subscription-bridge; do
  [ -f "$p/package.json" ] || continue
  inventory="$OUT/npm-$(echo "$p" | tr / -).json"
  if ! npm --prefix "$p" ls --omit=dev --json >"$inventory" 2>"$OUT/npm-$(echo "$p" | tr / -).stderr"; then
    echo "FAIL: npm inventory failed for $p" >&2
    fail=1
  fi
  require_nonempty "$inventory"
done
if ! docker image inspect --format='{{.Id}}' "$IMAGE" >"$OUT/image-id.txt"; then
  echo "FAIL: image id inventory failed" >&2
  fail=1
fi
require_nonempty "$OUT/image-id.txt"

# that ship — sdks/node npm tarball, docker save layers and history of both
# built images, package-manager caches — not just the source tree. Docker and
# npm are proven present at this point, so a scanner SKIP (77) is a wired
# inconsistency and fails this gate rather than reading as a pass.
echo "== delivered-bytes scan (npm tarball + image layers/history/caches)"
scan_code=0
bash scripts/quality/scan_delivered_bytes.sh --out "$OUT/bytes-scan" \
  --npm-pack sdks/node \
  --image "$IMAGE" --profile root \
  --image "$DASH_IMAGE" --profile dashboard || scan_code=$?
if [ "$scan_code" -ne 0 ]; then
  if [ "$scan_code" -eq 77 ]; then
    echo "FAIL: delivered-bytes scan skipped although docker/npm are required here; see $OUT/bytes-scan/report.txt" >&2
  else
    echo "FAIL: delivered-bytes scan exited $scan_code; see $OUT/bytes-scan/report.txt" >&2
  fi
  fail=1
fi

echo "  inventory: $OUT (image binary Go build metadata, Go modules, production npm trees, image id, dashboard image id + sourcemap probe, delivered-bytes scan)"
if [ "$fail" = 1 ]; then echo "FAIL: packaging verification"; exit 1; fi
echo "packaging verification: clean; evidence=$OUT"

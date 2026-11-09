#!/usr/bin/env bash
# N11-P02-T05: negative test — local fsync is NOT replicated RPO=0 storage.
#
# Card T05 forbids presenting local-disk fsync as replicated zero-RPO
# durability. This drill PROVES the negative on the bundled single-node
# postgres model (the Helm chart's bundled.postgres): acknowledged rows
# vanish with the volume. Exit 0 = negative CONFIRMED (rows lost).
#
# Never reads the shared stand lock; uses /tmp/opencode/n11p02-fsync.lock.
set -euo pipefail

LOCK=/tmp/opencode/n11p02-fsync.lock
PROJ=n11p02-fsync
CTR=n11p02-fsync-pg
VOL=n11p02-fsync-pgdata
IMG=pgvector/pgvector:pg16
CF=/tmp/opencode/n11p02-fsync-compose.yml

cat > "$CF" <<'YML'
services:
  pg:
    image: pgvector/pgvector:pg16
    container_name: n11p02-fsync-pg
    volumes:
      - n11p02-fsync-pgdata:/var/lib/postgresql/data
    environment:
      POSTGRES_USER: drill
      POSTGRES_PASSWORD: drill
      POSTGRES_DB: drill
volumes:
  n11p02-fsync-pgdata:
    # explicit name: compose would otherwise prefix the project (n11p02-fsync_…)
    name: n11p02-fsync-pgdata
YML

exec 9>"$LOCK"
flock -w 30 9 || { echo "FAIL lock: could not acquire $LOCK within 30s"; exit 1; }

cleanup() {
  docker compose -p "$PROJ" -f "$CF" down -v >/dev/null 2>&1 || true
  docker volume rm -f "$VOL" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== T05 negative_fsync_test: acknowledged writes on a local volume are lost with the volume"

# Fresh start on a named volume — the bundled-postgres model.
docker compose -p "$PROJ" -f "$CF" down -v >/dev/null 2>&1 || true
docker volume rm -f "$VOL" >/dev/null 2>&1 || true
docker compose -p "$PROJ" -f "$CF" up -d >/dev/null

for _ in $(seq 1 60); do
  if docker exec "$CTR" pg_isready -U drill -d drill >/dev/null 2>&1; then break; fi
  sleep 1
done
docker exec "$CTR" pg_isready -U drill -d drill >/dev/null 2>&1 \
  || { echo "FAIL readiness: postgres never became ready"; exit 1; }

# Acknowledge rows through the DEFAULT durability (fsync=on,
# synchronous_commit=on): this is exactly what "local fsync" means on a
# single node. No standby exists — there is nothing to replicate to.
docker exec -i "$CTR" psql -U drill -d drill -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
CREATE TABLE drill_accounting(id int primary key, payload text);
INSERT INTO drill_accounting VALUES (1,'acknowledged-fsync-row-1'),(2,'acknowledged-fsync-row-2');
SQL
GOT=$(docker exec "$CTR" psql -U drill -d drill -Atc \
  "SELECT count(*) FROM drill_accounting")
[ "$GOT" = "2" ] || { echo "FAIL seed: expected 2 rows, got $GOT"; exit 1; }
echo "  2 acknowledged rows committed with fsync=on, synchronous_commit=on (no standby: nothing replicated)"

# Destroy the node AND its volume — the failure mode the bundled
# single-replica statefulset cannot survive (node/PV loss).
docker rm -f "$CTR" >/dev/null
docker volume rm "$VOL" >/dev/null
echo "  container removed, named volume destroyed"

# Fresh start on a NEW volume: everything must be gone. If any row
# survived, local fsync somehow replicated — that would invalidate the
# documentation contract and must fail this drill.
docker compose -p "$PROJ" -f "$CF" up -d >/dev/null
for _ in $(seq 1 60); do
  if docker exec "$CTR" pg_isready -U drill -d drill >/dev/null 2>&1; then break; fi
  sleep 1
done
AFTER=$(docker exec "$CTR" psql -U drill -d drill -Atc \
  "SELECT count(*) FROM drill_accounting" 2>/dev/null || echo "table-missing")

if [ "$AFTER" = "table-missing" ] || [ "$AFTER" = "0" ]; then
  echo "  PASS negative-confirmed: acknowledged rows GONE after volume loss ($AFTER rows survive)"
  echo "  => local fsync is NOT replicated RPO=0 storage; bundled postgres needs the HA path (I41/I44)"
  exit 0
fi
echo "  FAIL negative-not-confirmed: '$AFTER' rows survived volume destruction — fsync replicated??"
exit 1

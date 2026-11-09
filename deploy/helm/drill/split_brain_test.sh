#!/usr/bin/env bash
# N11-P02-T05: split-brain exclusion drill — a network-partitioned
# ex-primary must not accept acknowledged writes, and after healing it
# must rejoin as a REPLICA (fenced, never a second writer).
#
# Topology: the 3-node raft drill cluster. We partition the CURRENT
# primary away from the other two members, verify:
#   (1) a quorum of the remaining two elects a new primary (service kept),
#   (2) the partitioned ex-primary refuses/loses any acknowledged write
#       attempt (strict synchronous mode: no sync standby reachable =>
#       no acknowledged commit),
#   (3) after healing, the ex-primary is a follower on the new timeline.
# Exit 0 only if all three hold.
#
# Partition gate (REVISE F-1, review 2026-11-03): the network partition is
# gated on the SAME physical quorum proof the failover drill uses, plus a
# settle window — NOT merely pg_stat_replication streaming=2. streaming=2
# is the FIRST moment the gate could pass and lands the partition inside
# the clone-settling window (observed: partition seconds after a standby
# finished its basebackup clone; survivors then deferred promotion to each
# other — "i am not the healthiest node" — for >120 s and check (1) failed
# 3/3 under fleet-normal load while the system itself was correct; the
# settled-cluster control promoted at t+36 s). Gate = exactly one primary
# + two replicas (REST roles) AND 2 streaming wal senders with exactly one
# NAMED sync standby AND canary rows physically present on BOTH standbys
# AND that whole state holding continuously for SETTLE_S before the
# partition fires.
#
# Never reads the shared stand lock; uses /tmp/opencode/n11p02-sb.lock.
set -euo pipefail

LOCK=/tmp/opencode/n11p02-sb.lock
CF_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE="docker compose -f $CF_DIR/docker-compose.drill.yml"
CLUSTER_TIMEOUT_S=240    # includes first-boot basebackup clone (~90 s observed)
SETTLE_S=20              # quorum state must hold CONTINUOUSLY this long
                         # (>4 patroni loop_wait cycles) before the partition
ELECTION_BUDGET_S=240    # >=180 s per review F-1 (6x ttl=30); observed
                         # deferral loops outlasted the old 120 s budget
HEAL_BUDGET_S=300        # ex-primary postgres is STOPPED at demotion; rejoin
                         # needs restart + possible pg_rewind/basebackup clone

exec 9>"$LOCK"
flock -w 30 9 || { echo "FAIL lock: could not acquire $LOCK within 30s"; exit 1; }

for tool in docker python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "FAIL env: $tool missing"; exit 2; }
done
docker compose version >/dev/null 2>&1 || { echo "FAIL env: docker compose plugin missing"; exit 2; }

KEEP_DRILL="${KEEP_DRILL:-0}"
cleanup() {
  # heal network membership even on failure paths
  docker network connect n11p02-drill-net n11p02-drill-node-a >/dev/null 2>&1 || true
  docker network connect n11p02-drill-net n11p02-drill-node-b >/dev/null 2>&1 || true
  docker network connect n11p02-drill-net n11p02-drill-node-c >/dev/null 2>&1 || true
  if [ "$KEEP_DRILL" != "1" ]; then
    $COMPOSE down -v >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "== T05 split_brain_test: partitioned ex-primary must not write; fencing after heal"

$COMPOSE down -v >/dev/null 2>&1 || true
$COMPOSE up -d >/dev/null

# --- wait for a healthy, SETTLED 3-member cluster (T04-style physical
# quorum gate — see the partition-gate note in the header)
python3 - "$CLUSTER_TIMEOUT_S" "$SETTLE_S" <<'PY'
import subprocess, sys, time

timeout, settle = int(sys.argv[1]), int(sys.argv[2])
deadline = time.monotonic() + timeout
settled_since = None
last = ""

def run(args):
    return subprocess.run(args, capture_output=True, text=True)

def probe(node, endpoint):
    # /primary answers 200 only on the leader, /replica only on a standby
    # (the bare / endpoint 503s on replicas — do not use it for role probes)
    return run(["docker", "exec", f"n11p02-drill-node-{node}",
                "wget", "-q", "-O-", f"http://127.0.0.1:8008/{endpoint}"]).returncode == 0

def leader():
    ls = [n for n in "abc" if probe(n, "primary")]
    if len(ls) != 1:
        return None
    for n in "abc":
        if n != ls[0] and not probe(n, "replica"):
            return None
    return ls[0]

def ensure_rows(p):
    # Idempotent seed of the isolation row (1) + readiness canary (998),
    # both quorum-path writes. statement_timeout bounds a strict-mode commit
    # that transiently cannot reach a sync standby (clone window): the
    # statement aborts server-side, nothing hangs, the loop simply retries.
    r = run(["docker", "exec", f"n11p02-drill-node-{p}", "psql", "-h", "127.0.0.1",
             "-U", "drill_app", "-d", "drill", "-v", "ON_ERROR_STOP=1", "-c",
             "SET statement_timeout='5s';"
             "CREATE TABLE IF NOT EXISTS drill_accounting("
             "id int primary key, payload text, acked_at timestamptz default now());"
             "INSERT INTO drill_accounting(id,payload) VALUES "
             "(1,'pre-partition-ack'),(998,'readiness-canary') ON CONFLICT (id) DO NOTHING"])
    return r.returncode == 0

def quorum_path(p):
    # 2 streaming wal senders, exactly ONE of them the named sync standby
    # (pg_stat_replication rows have no trailing colon — endswith(":sync"),
    # not ":sync:" in ln; same parsing as failover_drill.sh)
    stat = run(["docker", "exec", f"n11p02-drill-node-{p}", "psql", "-h", "127.0.0.1",
                "-U", "postgres", "-d", "drill", "-Atc",
                "SELECT application_name||':'||state||':'||sync_state FROM pg_stat_replication"])
    if stat.returncode != 0:
        return False
    streaming = [ln for ln in stat.stdout.strip().splitlines() if ":streaming:" in ln]
    sync = [ln for ln in streaming if ln.endswith(":sync")]
    return len(streaming) == 2 and len(sync) == 1

def rows_on_both_standbys(p):
    # PHYSICAL proof: rows 1 (isolation datum) + 998 (canary) must be
    # replayed and readable on BOTH standbys — sync assignment alone is
    # not proof (it was already assigned in the failing run while the
    # clone had just finished)
    seen = 0
    for n in "abc":
        if n == p:
            continue
        q = run(["docker", "exec", f"n11p02-drill-node-{n}", "psql", "-h", "127.0.0.1",
                 "-U", "drill_app", "-d", "drill", "-Atc",
                 "SELECT count(*) FROM drill_accounting WHERE id IN (1,998)"])
        if q.returncode == 0 and q.stdout.strip() == "2":
            seen += 1
    return seen == 2

while time.monotonic() < deadline:
    p = leader()
    ok = bool(p) and ensure_rows(p) and quorum_path(p) and rows_on_both_standbys(p)
    state = f"primary={'node-' + p if p else '?'} physical_quorum={'ok' if ok else 'no'}"
    if state != last:
        print(f"  {state}")
        last = state
    if ok:
        now = time.monotonic()
        if settled_since is None:
            settled_since = now
            print(f"  physical quorum verified (rows 1+998 on BOTH standbys, 2 streaming, "
                  f"one named sync); holding {settle}s before partition")
        elif now - settled_since >= settle:
            print("  cluster settled: quorum path held continuously; partition gate OPEN")
            sys.exit(0)
    else:
        settled_since = None
    time.sleep(2)
print("FAIL cluster: no settled 3-member cluster with a verified physical quorum path in time")
sys.exit(1)
PY

primary_of() {
  local n
  for n in a b c; do
    if docker exec "n11p02-drill-node-$n" wget -q -O- http://127.0.0.1:8008/primary >/dev/null 2>&1; then
      echo "$n"; return 0
    fi
  done
  return 1
}

P=$(primary_of) || { echo "FAIL: no primary found"; exit 1; }
echo "  cluster settled; partitioning node-$P (current primary) away from survivors"
T_PART=$SECONDS

# --- partition: disconnect ONLY the primary from the drill network
docker network disconnect n11p02-drill-net "n11p02-drill-node-$P"

# --- (1) survivors elect a new primary (budget ELECTION_BUDGET_S >= 180 s)
NEWP=""
for _ in $(seq 1 $((ELECTION_BUDGET_S / 2))); do
  for n in a b c; do
    [ "$n" = "$P" ] && continue
    if docker exec "n11p02-drill-node-$n" wget -q -O- http://127.0.0.1:8008/primary >/dev/null 2>&1; then
      NEWP=$n; break
    fi
  done
  [ -n "$NEWP" ] && break
  sleep 2
done
[ -n "$NEWP" ] || { echo "FAIL quorum: survivors failed to elect a new primary"; exit 1; }
echo "  survivors elected node-$NEWP (quorum kept service; elected t+$((SECONDS - T_PART))s after partition)"

# --- (2) partitioned ex-primary must NOT acknowledge a write.
# Patroni expires the leader lock after the TTL and DEMOTES (often stops)
# the partitioned postgres — that is fencing, not data loss: a stopped or
# read-only server cannot acknowledge anything. Data presence is only
# asserted when the server is accepting connections.
if docker exec "n11p02-drill-node-$P" pg_isready -h 127.0.0.1 >/dev/null 2>&1; then
  HAVE=$(docker exec "n11p02-drill-node-$P" psql -h 127.0.0.1 -U drill_app -d drill -Atc \
    "SELECT count(*) FROM drill_accounting WHERE id=1" 2>/dev/null || echo "0")
  [ "$HAVE" = "1" ] || { echo "FAIL isolation: ex-primary up but lost pre-partition data"; exit 1; }
  echo "  ex-primary up: pre-partition data present; asserting write refusal"
else
  echo "  ex-primary postgres stopped while partitioned (patroni demotion) — cannot acknowledge writes"
fi
# synchronous_mode_strict: no reachable sync standby => no commit ack; the
# commit would hang, so bound it with timeout: a hang is as much a refusal
# to acknowledge as an error.
if docker exec "n11p02-drill-node-$P" timeout 10 psql -h 127.0.0.1 -U drill_app -d drill -Atc \
     "INSERT INTO drill_accounting(id,payload) VALUES (78,'split-brain-attempt') \
      ON CONFLICT (id) DO NOTHING RETURNING id" >/dev/null 2>&1; then
  echo "FAIL split-brain: partitioned ex-primary ACKNOWLEDGED a write (fencing broken)"
  exit 1
fi
  echo "  PASS isolation-write: partitioned ex-primary did not acknowledge any write (fencing held)"

# --- (3) heal: reconnect, ex-primary must rejoin as REPLICA (fenced).
# The ex-primary's postgres was stopped by the demotion; rejoining needs a
# restart plus pg_rewind or a fresh basebackup (timeline diverged), so the
# budget is generous on purpose — a heal timeout would be a false negative.
docker network connect n11p02-drill-net "n11p02-drill-node-$P"
REPLICA=""
for _ in $(seq 1 $((HEAL_BUDGET_S / 2))); do
  if docker exec "n11p02-drill-node-$P" wget -q -O- http://127.0.0.1:8008/replica >/dev/null 2>&1; then
    FOLLOW=$(docker exec "n11p02-drill-node-$P" psql -h 127.0.0.1 -U postgres -d drill -Atc \
      "SELECT pg_is_in_recovery()" 2>/dev/null || echo "")
    [ "$FOLLOW" = "t" ] && REPLICA=1 && break
  fi
  sleep 2
done
if [ -z "$REPLICA" ]; then
  echo "FAIL heal: ex-primary did not rejoin as read-only replica within ${HEAL_BUDGET_S}s"
  exit 1
fi
PRIMARIES=0
for n in a b c; do
  docker exec "n11p02-drill-node-$n" wget -q -O- http://127.0.0.1:8008/primary >/dev/null 2>&1 && PRIMARIES=$((PRIMARIES+1))
done
[ "$PRIMARIES" = "1" ] || { echo "FAIL topology-after-heal: $PRIMARIES writable primaries"; exit 1; }

echo "  PASS heal-fencing: node-$P rejoined as replica (pg_is_in_recovery=t, /replica 200), never promoted itself"
echo "  PASS topology: exactly one writable primary (node-$NEWP) after split-brain + heal"
echo "DRILL RESULT: PASS (split-brain excluded; fencing observed)"
exit 0

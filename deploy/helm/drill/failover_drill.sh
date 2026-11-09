#!/usr/bin/env bash
# N11-P02-T04 — multi-node failover drill (HA-TOPOLOGY.md contract, I42/I43/I44).
#
# What it proves, on one docker host, with Patroni (raft DCS) as the reference
# HA manager:
#   1. three failure domains form ONE 3-member cluster (single primary, one
#      synchronous standby — the quorum path — and one async standby);
#   2. killing the primary's whole container ("node loss incl. primary DB",
#      I42) → a surviving node is elected, restores the quorum path and
#      ACCEPTS a new acknowledged accounting write within 60 s of the failure
#      (I43);
#   3. accounting RPO=0 holds across the failover (every acknowledged row
#      survives; I44), while the async history path is reported honestly
#      (bounded loss, not zero-loss);
#   4. the failed node rejoins as a FENCED replica (never a second writer).
#
# Honest scope (see README.md): one docker host, docker kill as the failure
# injection, stateless tiers excluded, raft DCS in-container. Timing numbers
# are local observations, not SLAs.
#
# Exit codes: 0 all phases pass; 1 contract assertion failed; 2 environment.
set -euo pipefail
cd "$(dirname "$0")"

LOCK=/tmp/opencode/n11p02-drill.lock
COMPOSE="docker compose -f docker-compose.drill.yml"
FAIL_BUDGET_S=60        # I43: new requests accepted within 60 s of failure
CLUSTER_TIMEOUT_S=240   # includes first-boot basebackup clone (~90 s observed)
REJOIN_TIMEOUT_S=180
KEEP="${KEEP_DRILL:-0}"

exec 9>"$LOCK"
flock -n 9 || { echo "SKIP: another drill is running ($LOCK)"; exit 2; }

for tool in docker python3; do
  command -v "$tool" >/dev/null 2>&1 || { echo "FAIL env: $tool missing"; exit 2; }
done
docker compose version >/dev/null 2>&1 || { echo "FAIL env: docker compose plugin missing"; exit 2; }

phase() { printf '\n== %s\n' "$*"; }

teardown() {
  [ "$KEEP" = "1" ] && { echo "== teardown skipped (KEEP_DRILL=1)"; return; }
  $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
  docker rm -f n11p02-drill-node-a n11p02-drill-node-b n11p02-drill-node-c >/dev/null 2>&1 || true
}
trap teardown EXIT

# ---------------------------------------------------------------------------
phase "preflight"
$COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
$COMPOSE build 2>&1 | tail -1

# ---------------------------------------------------------------------------
phase "cluster-up (wait: 1 primary + 2 replicas + quorum path restored)"
$COMPOSE up -d
python3 - "$CLUSTER_TIMEOUT_S" <<'PY'
import json, subprocess, sys, time
timeout = int(sys.argv[1])
deadline = time.monotonic() + timeout
last = ""

def probe(node, endpoint):
    # /primary answers 200 only on the leader, /replica only on a standby
    # (the bare / endpoint 503s on replicas — do not use it for role probes)
    return subprocess.run(["docker", "exec", f"n11p02-drill-node-{node}",
                           "wget", "-q", "-O-", f"http://127.0.0.1:8008/{endpoint}"],
                          capture_output=True).returncode == 0

def roles():
    out = {}
    for n in "abc":
        out[n] = ("primary" if probe(n, "primary") else
                  "replica" if probe(n, "replica") else "starting")
    return out

while time.monotonic() < deadline:
    r = roles()
    summary = str(r)
    if summary != last:
        print(f"  roles: {summary}")
        last = summary
    leaders = [n for n, role in r.items() if role == "primary"]
    if len(leaders) == 1 and list(r.values()).count("replica") == 2:
        # A standby answering /replica 200 is NOT proof of a healthy quorum
        # path: patroni reports the DCS role while a standby is still
        # cloning, and synchronous_mode_strict transiently clears
        # synchronous_standby_names during that window (observed: a commit
        # acked only locally, lost at promotion). Require REAL streaming
        # replication to both standbys with one named sync standby.
        p = leaders[0]
        stat = subprocess.run(
            ["docker", "exec", f"n11p02-drill-node-{p}", "psql", "-h", "127.0.0.1",
             "-U", "postgres", "-d", "drill", "-Atc",
             "SELECT application_name||':'||state||':'||sync_state FROM pg_stat_replication"],
            capture_output=True, text=True)
        rows = [ln for ln in stat.stdout.strip().splitlines() if ln]
        streaming = [ln for ln in rows if ":streaming:" in ln]
        # endswith(":sync"), not ":sync:" in ln — pg_stat_replication rows have
        # no trailing colon ("node-b:streaming:sync" does NOT contain ":sync:")
        sync = [ln for ln in streaming if ln.endswith(":sync")]
        if len(streaming) == 2 and len(sync) == 1:
            subprocess.run(
                ["docker", "exec", f"n11p02-drill-node-{p}", "psql", "-h", "127.0.0.1",
                 "-U", "drill_app", "-d", "drill", "-c",
                 "CREATE TABLE IF NOT EXISTS drill_accounting(id int primary key, "
                 "payload text, acked_at timestamptz default now())"],
                capture_output=True, text=True)
            canary = subprocess.run(
                ["docker", "exec", f"n11p02-drill-node-{p}", "psql", "-h", "127.0.0.1",
                 "-U", "drill_app", "-d", "drill", "-Atc",
                 "INSERT INTO drill_accounting(id,payload) VALUES (998,'readiness-canary') "
                 "ON CONFLICT (id) DO NOTHING RETURNING id"],
                capture_output=True, text=True)
            # psql -c prints a trailing "INSERT 0 1" command tag after the
            # RETURNING row; compare the first line, not the whole stdout
            if canary.returncode == 0 and canary.stdout.splitlines()[0:1] == ["998"]:
                # wait (bounded) for the canary to be replayed on BOTH standbys
                for _ in range(15):
                    seen = 0
                    for n in "abc":
                        if n == p:
                            continue
                        q = subprocess.run(
                            ["docker", "exec", f"n11p02-drill-node-{n}", "psql", "-h", "127.0.0.1",
                             "-U", "drill_app", "-d", "drill", "-Atc",
                             "SELECT count(*) FROM drill_accounting WHERE id=998"],
                            capture_output=True, text=True)
                        if q.returncode == 0 and q.stdout.strip() == "1":
                            seen += 1
                    if seen == 2:
                        print("  quorum path verified: both standbys streaming, one named sync, "
                              "canary row physically present on both standbys")
                        sys.exit(0)
                    time.sleep(2)
    time.sleep(3)
print("FAIL cluster-up: no healthy 3-member cluster with a verified quorum path in time")
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
echo "  current primary: node-$P"

# ---------------------------------------------------------------------------
phase "seed (quorum-path accounting rows + async history rows)"
# -i is REQUIRED: docker exec does not forward stdin without it, so a heredoc
# would reach psql as empty input — psql exits 0 having run NOTHING.
docker exec -i "n11p02-drill-node-$P" psql -h 127.0.0.1 -U drill_history -d drill -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
CREATE TABLE IF NOT EXISTS drill_history(id int primary key, payload text, acked_at timestamptz default now());
INSERT INTO drill_history(id, payload) VALUES (1,'seed-hist-1'),(2,'seed-hist-2');
SQL
docker exec -i "n11p02-drill-node-$P" psql -h 127.0.0.1 -U drill_app -d drill -v ON_ERROR_STOP=1 <<'SQL' >/dev/null
INSERT INTO drill_accounting(id, payload) VALUES (1,'seed-acc-1'),(2,'seed-acc-2');
SQL
echo "  seeded 2 accounting + 2 history rows on node-$P; settling replication 6 s"
sleep 6

# The kill is gated on the seed being PHYSICALLY present on both standbys:
# a commit that merely returned is not proof — synchronous_mode_strict can
# transiently clear the sync target (clone/completion window) and ack a
# commit locally. Killing before verified replication would measure an
# async window, not the quorum contract.
SEEDED=$(python3 - "$P" <<'PY'
import subprocess, sys, time
p = sys.argv[1]
last = {}
for _ in range(30):
    ok = 0
    for n in "abc":
        if n == p:
            continue
        q = subprocess.run(
            ["docker", "exec", f"n11p02-drill-node-{n}", "psql", "-h", "127.0.0.1",
             "-U", "drill_app", "-d", "drill", "-Atc",
             "SELECT string_agg(id::text, ',' ORDER BY id) FROM drill_accounting"],
            capture_output=True, text=True)
        last[n] = f"rc={q.returncode} out={q.stdout.strip()!r} err={q.stderr.strip()[:80]}"
        if q.returncode == 0 and q.stdout.strip() == "1,2,998":
            ok += 1
    if ok == 2:
        print("PASS seed-verified: rows 1,2,998 present on both standbys")
        sys.exit(0)
    time.sleep(2)
print("FAIL seed-verified: seed rows never reached both standbys (quorum path not honest)")
for n, d in last.items():
    print(f"  DETAIL {n}: {d}")
sys.exit(1)
PY
) || true
echo "  $SEEDED"
echo "$SEEDED" | grep -q "^PASS" || exit 1

# ---------------------------------------------------------------------------
phase "kill-primary (node loss incl. primary DB, I42) + timed recovery probe"
# Python result goes through a file: a failing command substitution plus
# `set -e` would otherwise swallow the diagnostic output.
PROBE_LOG=$(mktemp /tmp/opencode/n11p02-failover-probe.XXXXXX.log)
if python3 - "$P" "$FAIL_BUDGET_S" >"$PROBE_LOG" <<'PY'

import json, subprocess, sys, time
p, budget = sys.argv[1], float(sys.argv[2])

def run(args):
    return subprocess.run(args, capture_output=True, text=True)

# t0 = the moment the kill signal is issued (monotonic, single clock).
t0 = time.monotonic()
r = run(["docker", "kill", f"n11p02-drill-node-{p}"])
if r.returncode != 0:
    print(f"FAIL kill: {r.stderr.strip()[:120]}"); sys.exit(1)

survivors = [n for n in "abc" if n != p]
deadline = t0 + budget
new_primary = None
first_ok = None

# Recovery loop: discover the promoted primary via its readiness-gated REST
# endpoint (what a K8s Service would do), require the quorum path (synchronous
# standby) to be back, then require ONE new acknowledged accounting write.
while time.monotonic() < deadline:
    for n in survivors:
        if run(["docker", "exec", f"n11p02-drill-node-{n}",
                "wget", "-q", "-O-", "http://127.0.0.1:8008/primary"]).returncode != 0:
            continue
        sync = run(["docker", "exec", f"n11p02-drill-node-{n}", "psql", "-h", "127.0.0.1",
                    "-U", "postgres", "-d", "drill", "-Atc", "SHOW synchronous_standby_names"])
        if sync.returncode != 0 or not sync.stdout.strip():
            continue  # strict mode: no ack without a sync standby (quorum path)
        r = run(["docker", "exec", f"n11p02-drill-node-{n}", "psql", "-h", "127.0.0.1",
                 "-U", "drill_app", "-d", "drill", "-Atc",
                 "INSERT INTO drill_accounting(id,payload) VALUES (10,'post-failover-request') "
                 "ON CONFLICT (id) DO NOTHING RETURNING id"])
        if r.returncode == 0 and r.stdout.splitlines()[0:1] == ["10"]:
            new_primary, first_ok = n, time.monotonic() - t0
    if new_primary:
        break
    time.sleep(1)

if not new_primary:
    print(f"FAIL recovery: no acknowledged write within {budget:.0f}s of primary loss")
    sys.exit(1)
print(f"PASS recovery: node-{new_primary} accepted a new acknowledged accounting write "
      f"at t+{first_ok:.1f}s (budget {budget:.0f}s)")
print(f"DETAIL primary_lost={p} promoted={new_primary} seconds={first_ok:.1f}")
sys.exit(0)
PY
then
  RESULT="PASS"
else
  RESULT="FAIL"
fi
echo "  $(cat "$PROBE_LOG")"
NEWP=$(grep -o "promoted=[a-c]" "$PROBE_LOG" | cut -d= -f2 || true)
rm -f "$PROBE_LOG"
[ "$RESULT" = "PASS" ] || exit 1

# ---------------------------------------------------------------------------
phase "rpo-accounting (I44: acknowledged rows survive; quorum path)"
ACC=$(docker exec "n11p02-drill-node-$NEWP" psql -h 127.0.0.1 -U drill_app -d drill -Atc \
  "SELECT count(*)||'|'||coalesce(string_agg(payload, ',' ORDER BY id),'') FROM drill_accounting")
COUNT=${ACC%%|*}; PAYLOADS=${ACC#*|}
# Expected: seeds 1,2 + readiness canary 998 (all quorum-acked pre-kill)
# + probe row 10 (quorum-acked post-failover).
if [ "$COUNT" = "4" ] && [ "$PAYLOADS" = "seed-acc-1,seed-acc-2,post-failover-request,readiness-canary" ]; then
  echo "  PASS rpo-accounting: 4/4 acknowledged rows on promoted node-$NEWP (zero loss, RPO=0 held)"
else
  echo "  FAIL rpo-accounting: got count=$COUNT payloads=[$PAYLOADS], expected seeds+canary+probe"
  exit 1
fi
SYNC=$(docker exec "n11p02-drill-node-$NEWP" psql -h 127.0.0.1 -U postgres -d drill -Atc \
  "SHOW synchronous_standby_names")
[ -n "$SYNC" ] || { echo "  FAIL rpo-accounting: no synchronous standby on new primary"; exit 1; }
echo "  quorum path restored on node-$NEWP (synchronous_standby_names=$SYNC)"

# ---------------------------------------------------------------------------
phase "rpo-history (I44 default: async path, loss bounded — reported honestly)"
HIST=$(docker exec "n11p02-drill-node-$NEWP" psql -h 127.0.0.1 -U drill_history -d drill -Atc \
  "SELECT count(*)||'|'||coalesce(string_agg(id::text, ',' ORDER BY id),'') FROM drill_history")
HCOUNT=${HIST%%|*}; HIDS=${HIST#*|}
if [ "$HCOUNT" -gt 0 ] && echo "$HIDS" | tr ',' '\n' | grep -qv -E '^(1|2)$'; then
  echo "  FAIL rpo-history: phantom history rows detected [$HIDS]"
  exit 1
fi
echo "  INFO rpo-history: $HCOUNT/2 rows survived ($((2 - HCOUNT)) lost). Async path: loss is bounded by "
echo "       contract (<=60 s window), NOT guaranteed zero. No false success status is claimed."
[ "$HCOUNT" -le 2 ] || { echo "  FAIL rpo-history invariant"; exit 1; }

# ---------------------------------------------------------------------------
phase "rejoin-fencing (failed node returns as replica, never a second writer)"
docker start "n11p02-drill-node-$P" >/dev/null
python3 - "$P" "$REJOIN_TIMEOUT_S" <<'PY'
import json, subprocess, sys, time
p, timeout = sys.argv[1], int(sys.argv[2])
deadline = time.monotonic() + timeout

def probe(endpoint):
    return subprocess.run(["docker", "exec", f"n11p02-drill-node-{p}",
                           "wget", "-q", "-O-", f"http://127.0.0.1:8008/{endpoint}"],
                          capture_output=True).returncode == 0

while time.monotonic() < deadline:
    if probe("primary"):
        print(f"FAIL rejoin-fencing: node-{p} came back as a SECOND primary")
        sys.exit(1)
    if probe("replica"):
        print(f"PASS rejoin-fencing: node-{p} rejoined as replica (fenced)")
        sys.exit(0)
    time.sleep(3)
print(f"FAIL rejoin-fencing: node-{p} did not rejoin within {timeout}s")
sys.exit(1)
PY

# ---------------------------------------------------------------------------
phase "final-topology"
ROLES=$(python3 - <<'PY'
import subprocess
out = []

def probe(node, endpoint):
    return subprocess.run(["docker", "exec", f"n11p02-drill-node-{node}",
                           "wget", "-q", "-O-", f"http://127.0.0.1:8008/{endpoint}"],
                          capture_output=True).returncode == 0

for n in "abc":
    role = ("primary" if probe(n, "primary") else
            "replica" if probe(n, "replica") else "down")
    out.append(f"node-{n}={role}")
print(" ".join(out))
PY
)
echo "  $ROLES"
NPRIM=$(echo "$ROLES" | grep -o "primary" | wc -l)
[ "$NPRIM" = "1" ] || { echo "  FAIL final-topology: $NPRIM primaries"; exit 1; }
echo "  PASS final-topology: exactly one writable primary"

echo ""
echo "DRILL RESULT: PASS (all phases)"
exit 0

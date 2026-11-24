#!/usr/bin/env bash
# `make migrate-up` acceptance gate.
#
# Contract: the target applies migrations through the ledger-aware
# cmd/yabanin-migrate runner — nonzero exit on failure, no success message,
# and no migration applied after a failed one.
#
# M0 structural: the recipe invokes ./yabanin-migrate, never raw psql SQL replay.
# M1 fault (no DB): missing YABANIN_REGION exits nonzero before DB contact.
# M2 fault (no DB): unreachable PostgreSQL exits nonzero.
# M3 ledger (DB): clean run applies the chain; repeat succeeds without
#    reapplying (schema_migrations unchanged via independent psql reads).
# M4 fault propagation (DB): a disposable source fixture injects an
#    intentionally failing migration mid-chain plus a later marker, then runs
#    the actual `make migrate-up` from the fixture against a separate
#    disposable database: nonzero exit, no success message, marker unapplied
#    (independent SQL oracle). The candidate source is never modified.
#
# Fail closed: without YABANIN_TEST_PG_URI (a disposable PostgreSQL) the gate
# ends INCOMPLETE/nonzero. --allow-no-db runs only the light controls M0-M2.
#
# Usage: bash scripts/migrate_up_gate.sh [--allow-no-db]
set -euo pipefail
cd "$(dirname "$0")/.."

ALLOW_NO_DB=0
case "${1:-}" in
  "") ;;
  --allow-no-db) ALLOW_NO_DB=1 ;;
  *) echo "usage: migrate_up_gate.sh [--allow-no-db]" >&2; exit 2 ;;
esac

fail=0
pass() { echo "PASS: $1"; }
bad() { echo "FAIL: $1" >&2; fail=1; }
run_target() { # run_target <cwd> <pg-uri> <region>  (sets rc/out)
  out="$(timeout 300 make -C "$1" migrate-up YABANIN_PG_URI="$2" YABANIN_REGION="$3" 2>&1)" && rc=0 || rc=$?
}
ledger_of() { # ledger_of <pg-uri> -> independent oracle "count:maxversion"
  psql "$1" -tAc 'SELECT COUNT(*)||CHR(58)||COALESCE(MAX(version),0) FROM public.schema_migrations'
}

# M0: structural dry run (no compilation, no database contact).
plan="$(make -n migrate-up 2>&1)" || bad "M0: make -n migrate-up failed: $plan"
if grep -q './yabanin-migrate' <<< "$plan" && ! grep -q 'migrations/\*\.sql' <<< "$plan" && ! grep -qE 'psql .* -f ' <<< "$plan"; then
  pass "M0: migrate-up invokes the ledger-aware ./yabanin-migrate runner (no raw psql SQL loop)"
else
  bad "M0: migrate-up must call ./yabanin-migrate and never replay migrations/*.sql via psql"
fi

# M1: missing region must be refused by the runner itself (nonzero, no DB touch).
run_target "$PWD" 'postgres://127.0.0.1:9/yabanin?sslmode=disable' ''
if [ "$rc" -ne 0 ] && grep -q 'YABANIN_REGION is required' <<< "$out"; then
  pass "M1: missing YABANIN_REGION exits nonzero naming the requirement (rc=$rc)"
else
  bad "M1: missing YABANIN_REGION must exit nonzero with the runner's requirement (rc=$rc): $out"
fi

# M2: unreachable PostgreSQL must propagate failure (nonzero, bounded time).
run_target "$PWD" 'postgres://127.0.0.1:9/yabanin?sslmode=disable' 'sg'
if [ "$rc" -ne 0 ]; then
  pass "M2: unreachable PostgreSQL exits nonzero, no later steps (rc=$rc)"
else
  bad "M2: unreachable PostgreSQL must fail migrate-up (rc=0)"
fi

if [ -z "${YABANIN_TEST_PG_URI:-}" ]; then
  if [ "$ALLOW_NO_DB" -eq 1 ]; then
    echo "SKIP: M3/M4 DB-gated acceptance controls (--allow-no-db: ledger behavior unverified)"
  else
    echo "FAIL: M3/M4 require YABANIN_TEST_PG_URI (disposable PostgreSQL); default is fail closed; use --allow-no-db for light M0-M2 only" >&2
    echo "== RESULT: INCOMPLETE" >&2
    exit 1
  fi
else
  command -v psql >/dev/null 2>&1 || { echo "FAIL: psql (the independent SQL oracle) is missing" >&2; exit 1; }

  # M3: clean apply + repeat no-reapply on the disposable database. The
  # no-reapply oracle is the independent ledger read alone (row count and max
  # version unchanged); the runner's "applied N" line is ledger-row accounting
  # (COUNT(*) over the single-row schema_migrations ledger), never a per-run
  # delta, so it must not gate the repeat check.
  ledger_read() { ledger_of "$YABANIN_TEST_PG_URI"; }
  run_target "$PWD" "$YABANIN_TEST_PG_URI" 'sg'
  ledger1="$(ledger_read)" || bad "M3: independent ledger read failed: $ledger1"
  if [ "$rc" -eq 0 ] && [ -n "$ledger1" ]; then
    pass "M3: clean migrate-up applied the chain (ledger count:maxversion = $ledger1)"
    run_target "$PWD" "$YABANIN_TEST_PG_URI" 'sg'
    ledger2="$(ledger_read)"
    if [ "$rc" -eq 0 ] && [ "$ledger2" = "$ledger1" ]; then
      pass "M3: repeat run succeeded with the ledger unchanged — no reapply (count:maxversion = $ledger2)"
    else
      bad "M3: repeat must succeed with the ledger unchanged (rc=$rc, before=$ledger1, after=$ledger2): $out"
    fi
  else
    bad "M3: clean migrate-up must succeed on a disposable database (rc=$rc): $out"
  fi

  # M4: disposable source fixture (detached worktree at HEAD + two injected
  # migrations) against its own disposable database on the provided instance.
  fixture="$(mktemp -d "${TMPDIR:-/tmp}/p3-migrate-gate-XXXXXX")"
  m4_db="p3_migrate_gate_m4_$$"
  m4_uri="${YABANIN_TEST_PG_URI%/*}/$m4_db"
  cleanup_m4() {
    git worktree remove --force "$fixture/src" >/dev/null 2>&1 || rm -rf "$fixture/src"
    psql "$YABANIN_TEST_PG_URI" -c "DROP DATABASE IF EXISTS \"$m4_db\"" >/dev/null 2>&1 || true
    rm -rf "$fixture"
  }
  trap cleanup_m4 EXIT

  psql "$YABANIN_TEST_PG_URI" -c "DROP DATABASE IF EXISTS \"$m4_db\"" >/dev/null
  if ! psql "$YABANIN_TEST_PG_URI" -c "CREATE DATABASE \"$m4_db\"" >/dev/null; then
    bad "M4: cannot create the disposable fixture database \"$m4_db\" (need CREATEDB on YABANIN_TEST_PG_URI)"
  elif ! git worktree add --detach "$fixture/src" HEAD >/dev/null 2>&1; then
    bad "M4: cannot create the disposable source fixture worktree at HEAD"
  else
    emb="$fixture/src/pkg/migrate/migrations"
    maxv="$(ls "$emb" | sed -nE 's/^([0-9]+)_.*/\1/p' | sort -n | tail -1)"
    failv=$((10#$maxv + 1)); markv=$((10#$maxv + 2))  # 10#: leading zeros are octal in bash arithmetic
    failsql="$emb/$(printf '%04d' "$failv")_gate_fail.up.sql"
    marksql="$emb/$(printf '%04d' "$markv")_gate_marker.up.sql"
    printf '%s\n' 'SELECT 1/0;' > "$failsql"
    printf '%s\n' 'CREATE TABLE public.p3_gate_marker (id int);' > "$marksql"
    cp "$failsql" "$marksql" "$fixture/src/migrations/"

    run_target "$fixture/src" "$m4_uri" 'sg'
    if [ "$rc" -eq 0 ]; then
      bad "M4: intentional failing migration must exit nonzero (rc=0): $out"
    elif grep -q '✓ applied' <<< "$out"; then
      bad "M4: failed run must print no success message: $out"
    else
      marker_absent="$(psql "$m4_uri" -tAc "SELECT to_regclass('public.p3_gate_marker') IS NULL")"
      ledger4="$(ledger_of "$m4_uri")"
      dirty="$(psql "$m4_uri" -tAc "SELECT COALESCE(BOOL_OR(dirty), false) FROM public.schema_migrations WHERE version = $failv")"
      if [ "$marker_absent" != "t" ]; then
        bad "M4: later marker migration was applied despite the mid-chain failure (p3_gate_marker exists)"
      elif [ "${ledger4##*:}" != "$failv" ]; then
        bad "M4: ledger must stop at the failing version $failv, got ${ledger4##*:} (proves the chain actually ran, not a refused connection)"
      elif [ "$dirty" != "t" ]; then
        bad "M4: failing migration must be recorded dirty in the ledger for investigation"
      else
        pass "M4: mid-chain failure exits nonzero (rc=$rc), no success message, marker unapplied, ledger dirty at $failv"
      fi
    fi
  fi
fi

if [ "$fail" -ne 0 ]; then
  echo "== RESULT: FAIL" >&2
  exit 1
fi
echo "== RESULT: PASS"

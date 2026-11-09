#!/usr/bin/env bash
# Regression test for scripts/dr/backup_compose.sh.
#
# Defect: the script's `set -euo pipefail` line is rejected by the runtime
# shell of the compose backup sidecar (busybox ash: "set: Illegal option
# -o pipefail", abort, exit 2). The nightly 02:00 UTC cron job
# (`sh /app/backup.sh`, deploy/docker-compose.prod.yml) therefore never
# produces a backup at all — proven live by deploy/ops-verify-single-host.sh
# against the pinned postgres:16-alpine image.
#
# Fix under test: strict mode WITHOUT the unsupported option — `set -eu` —
# which busybox ash and dash both honor. The script's only pipeline (the
# PGPASSWORD extraction, `echo | sed`) cannot fail its echo leg, so dropping
# pipefail loses no abort coverage.
#
# Harness pattern follows deploy/ops-verify-single-host.sh: [ok]/[FAIL]/
# [skip: reason] lines, skips never counted as success, exit non-zero iff a
# FAIL exists. pg_dump is injected via PATH (ok/fail modes); the hardcoded
# /run/secrets/pg_uri read is served by a cat stub so the test runs
# unprivileged. The pipefail-rejecting shell is PROBED (dash first — it
# reproduces the pinned sidecar's rejection on this host); a host whose
# /bin/sh accepts -o pipefail must not be mistaken for the runtime class.
#
# Usage: scripts/dr/backup_compose_test.sh
# Docker-free and hermetic; exit 0 = all cases green.
set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")" && pwd)/backup_compose.sh"
PASS=0; FAIL=0; SKIP=0

ok()   { PASS=$((PASS+1)); echo "  [ok] $*"; }
fail() { FAIL=$((FAIL+1)); echo "  [FAIL] $*"; }
skip() { SKIP=$((SKIP+1)); echo "  [skip: $*]"; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/backup_compose_test.XXXXXX")"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

# --- stubs (PATH-injected; real binaries stay reachable after the stub dir) -
mkdir -p "$TMP/bin"
cat > "$TMP/bin/cat" <<'EOF'
#!/bin/sh
# stub cat: serve the hardcoded sidecar secret path from the test env
if [ "$1" = "/run/secrets/pg_uri" ]; then
  printf '%s\n' "$BACKUP_TEST_PG_URI"
  exit 0
fi
exec /bin/cat "$@"
EOF
cat > "$TMP/bin/pg_dump" <<'EOF'
#!/bin/sh
# stub pg_dump: honors -f <path>; BACKUP_TEST_PG_DUMP_MODE=fail simulates a
# mid-write crash (partial dump left, non-zero exit) — the failing stage.
out=""
prev=""
for a in "$@"; do
  [ "$prev" = "-f" ] && out="$a"
  prev="$a"
done
if [ "${BACKUP_TEST_PG_DUMP_MODE:-ok}" = "fail" ]; then
  [ -n "$out" ] && printf 'PARTIAL-DATA' > "$out"
  echo "pg_dump: error: injected failure (BACKUP_TEST_PG_DUMP_MODE=fail)" >&2
  exit 1
fi
[ -n "$out" ] && printf 'PGDMP-CUSTOM-FORMAT-SIMULATED\n' > "$out"
exit 0
EOF
chmod +x "$TMP/bin/cat" "$TMP/bin/pg_dump"

# --- runtime-shell selection: first available shell that REJECTS -o pipefail
RT_NAME=""; RT_CMD=()
if command -v dash >/dev/null 2>&1 && ! dash -c 'set -euo pipefail' >/dev/null 2>&1; then
  RT_NAME="dash"; RT_CMD=(dash)
elif [ -x /bin/sh ] && ! /bin/sh -c 'set -euo pipefail' >/dev/null 2>&1; then
  RT_NAME="/bin/sh"; RT_CMD=(/bin/sh)
elif command -v busybox >/dev/null 2>&1 && ! busybox sh -c 'set -euo pipefail' >/dev/null 2>&1; then
  RT_NAME="busybox sh"; RT_CMD=(busybox sh)
fi

# run_script <case-dir> <mode:ok|fail> [shell...] — runs the script with the
# stub PATH; prints nothing, returns the script's exit code via RUN_RC and
# points RUN_LOG/RUN_BACKUP_DIR at the case artifacts.
RUN_RC=0; RUN_LOG=""; RUN_BACKUP_DIR=""
run_script() {
  local dir="$1" mode="$2"; shift 2
  RUN_BACKUP_DIR="$dir/backups"
  mkdir -p "$RUN_BACKUP_DIR"
  RUN_LOG="$dir/run.log"
  if BACKUP_DIR="$RUN_BACKUP_DIR" \
     BACKUP_TEST_PG_URI="postgres://backup_test:pw@postgres:5432/yabanin" \
     BACKUP_TEST_PG_DUMP_MODE="$mode" \
     PATH="$TMP/bin:$PATH" \
     "$@" "$SCRIPT" >"$RUN_LOG" 2>&1; then
    RUN_RC=0
  else
    RUN_RC=$?
  fi
}

echo "== backup_compose_test (script: $SCRIPT)"

echo "=== case 0: syntax (bash -n) ==="
if bash -n "$SCRIPT" 2>"$TMP/syntax.err"; then
  ok "bash -n clean"
else
  fail "bash -n: $(cat "$TMP/syntax.err")"
fi

echo "=== case A: nightly path completes under the pipefail-rejecting runtime shell (the F1 defect) ==="
if [ -n "$RT_NAME" ]; then
  run_script "$TMP/a" ok "${RT_CMD[@]}"
  if [ "$RUN_RC" -eq 0 ]; then
    ok "script exits 0 under $RT_NAME (was: abort at 'set -euo pipefail', exit 2)"
  else
    fail "script exits $RUN_RC under $RT_NAME: $(tail -1 "$RUN_LOG")"
  fi
  if compgen -G "$RUN_BACKUP_DIR/pg_*.dump.gz" > /dev/null && gzip -t "$RUN_BACKUP_DIR"/pg_*.dump.gz 2>/dev/null; then
    ok "dump produced and gzip-valid under $RT_NAME"
  else
    fail "no valid pg_*.dump.gz under $RT_NAME"
  fi
  if grep -q "Backup complete" "$RUN_LOG"; then
    ok "completion marker printed under $RT_NAME"
  else
    fail "completion marker missing under $RT_NAME"
  fi
else
  skip "no pipefail-rejecting shell available (dash//bin/sh/busybox all accept -o pipefail); static case E still pins the invariant"
fi

echo "=== case B: failing stage aborts under the runtime shell — non-zero exit, no partial artifact ==="
if [ -n "$RT_NAME" ]; then
  run_script "$TMP/b" fail "${RT_CMD[@]}"
  if [ "$RUN_RC" -ne 0 ]; then
    ok "non-zero exit ($RUN_RC) on injected pg_dump failure under $RT_NAME"
  else
    fail "exit 0 on injected pg_dump failure under $RT_NAME (silent partial backup)"
  fi
  if compgen -G "$RUN_BACKUP_DIR/pg_*.dump.gz" > /dev/null; then
    fail "partial artifact pg_*.dump.gz exists after failure under $RT_NAME"
  else
    ok "no pg_*.dump.gz artifact after failure under $RT_NAME"
  fi
  if grep -q "Backup complete" "$RUN_LOG"; then
    fail "'Backup complete' printed despite failed stage under $RT_NAME"
  else
    ok "no completion marker after failure under $RT_NAME"
  fi
else
  skip "no pipefail-rejecting shell available for the runtime-shell abort case"
fi

echo "=== case C: failing stage aborts under bash (direct invocation) ==="
run_script "$TMP/c" fail bash
if [ "$RUN_RC" -ne 0 ]; then
  ok "non-zero exit ($RUN_RC) on injected pg_dump failure under bash"
else
  fail "exit 0 on injected pg_dump failure under bash (silent partial backup)"
fi
if compgen -G "$RUN_BACKUP_DIR/pg_*.dump.gz" > /dev/null; then
  fail "partial artifact pg_*.dump.gz exists after failure under bash"
else
  ok "no pg_*.dump.gz artifact after failure under bash"
fi
if grep -q "Backup complete" "$RUN_LOG"; then
  fail "'Backup complete' printed despite failed stage under bash"
else
  ok "no completion marker after failure under bash"
fi

echo "=== case D: bash happy path unchanged (behavior-identical guard) ==="
run_script "$TMP/d" ok bash
if [ "$RUN_RC" -eq 0 ]; then
  ok "script exits 0 under bash"
else
  fail "script exits $RUN_RC under bash on the happy path"
fi
if compgen -G "$RUN_BACKUP_DIR/pg_*.dump.gz" > /dev/null && gzip -t "$RUN_BACKUP_DIR"/pg_*.dump.gz 2>/dev/null; then
  ok "dump produced and gzip-valid under bash"
else
  fail "no valid pg_*.dump.gz under bash"
fi

echo "=== case E: strict mode is busybox-safe — exactly 'set -eu', no -o pipefail ==="
setline="$(grep '^set ' "$SCRIPT" | head -1 || true)"
if [ "$setline" = "set -eu" ]; then
  ok "set line is the F1 prescription 'set -eu' (strict, busybox-safe)"
else
  fail "set line is not 'set -eu' (got: '$setline'); busybox ash rejects '-o pipefail' and strictness must keep -e/-u"
fi

echo ""
echo "backup_compose_test: $PASS ok / $FAIL FAIL / $SKIP skip"
[ "$FAIL" -eq 0 ]

#!/usr/bin/env bash
# preview1_recovery.sh — retained product shell: Preview1 -> candidate upgrade
# and rollback rehearsal on an isolated named retained volume.
#
# FROZEN CASE REGISTRY (stable IDs; do not renumber without owner review):
#   QS-UPGRADE-P1   actual Preview1 source (7b85b18963ce764aea1f9631a7d47104b09550aa)
#                   on an isolated retained volume: two seeded orgs with
#                   distinct real API keys, per-org API-key ownership plus
#                   GLOBAL-registry model routing, real request
#                   history (explicit X-Request-ID identities), a positive
#                   GLOBAL-registry routing control (the seed service inserts
#                   BOTH model names into the GLOBAL models_registry — not
#                   org_custom_models — so a request for the other org's
#                   seeded name is served by global routing; model_used is
#                   NOT asserted because global routing may select any
#                   enabled global model), a third org1 API key minted
#                   locally and stored INACTIVE through the real api_keys
#                   table with its CORRECT sha256 hash (so only the inactive
#                   state can cause its denial), S3b-shaped
#                   fixture rows inserted through Preview1's real tables, the
#                   ACTUAL Preview1 view set and values recorded as the
#                   baseline (not assumed), protected pre-upgrade backup taken
#                   after writers are stopped, then candidate
#                   3a73e8e08b532df2b51a5fb47f19fbdbdff2f045 migrate/start on
#                   the SAME volume; old keys keep working, frozen identities
#                   and routing are retained, the inactive key stays denied
#                   with exact HTTP 401, zero provider hits and zero ledger
#                   effects (observed at the provider through an instrumented
#                   mock: MOCK_REQUEST_LOG=1, one method/path entry per
#                   received request, never headers, bodies or secrets), an
#                   expected-negative control re-runs the SAME denial oracle
#                   with an ACTIVE key and must fail with HTTP 200, and the
#                   seven managed
#                   beta views (pkg/feedback MetricsViewNames) show the frozen
#                   fixture values computed from retained rows.
#   QS-ROLLBACK-P1  protected backup restore: post-backup marker request with
#                   an explicit X-Request-ID awaited in the ledger, stop
#                   writers, restore into a recreated empty database with the
#                   documented pg_restore --dbname --exit-on-error --no-owner
#                   --no-acl form, actual Preview1 startup on the restored
#                   data (container image digest must equal the recorded
#                   Preview1 image); ledger counts equal the backup-time
#                   snapshot BEFORE any new request, the marker's exact ID is
#                   absent, frozen identities are restored, old keys work
#                   again (each adding exactly its own known ID), roles/
#                   grants/RLS/ownership match the pre-upgrade snapshot after
#                   the documented db-app-role boundary re-provisions them,
#                   and the view set/values/app-role read match the recorded
#                   ACTUAL Preview1 baseline. Controls on disposable targets
#                   only: NC-R1 a corrupt dump must fail the restore loudly;
#                   NC-R2 a restore without the bootstrap boundary must deny
#                   app-role reads with SQLSTATE 42501. The documented restore
#                   deliberately does not carry cluster roles or ACLs; never
#                   claim --no-owner/--no-acl preserved privileges — the
#                   assertions below compare behavior against independent
#                   snapshots instead.
#
# `down -v` IS NOT ROLLBACK and never runs on the retained volume during the
# cases; the volume is kept as evidence. QS_RECOVERY_PURGE=1 (separate,
# explicit) is the only path that removes harness-owned resources, after the
# verdicts have been recorded.
#
# MODES: `all` (default) runs upgrade then rollback in one invocation and
# reuses the in-memory minted keys; `upgrade` runs only the upgrade case and
# LEAVES the candidate stack up on the retained volume; `rollback` resumes
# against a prior `upgrade` run's protected state and REQUIRES
# QS_RECOVERY_RESUME=1 plus QS_RECOVERY_KEY1/QS_RECOVERY_KEY2 from that run
# (the protected seed transcripts hold the minted-once lines; the locally
# minted inactive control key is re-read from its own 0600 protected file).
# Keys are never printed or written outside 0600 files; the inactive control
# key is logged only as its sha256 fingerprint. A fresh run requires a
# nonexistent RUNTMP so prior evidence can never be overwritten silently.
#
# EXECUTION GATE: this file is committed in a source-only phase. The Docker
# legs require QS_RECOVERY_EXECUTE=1 AND (per owner instruction) a full green
# S1..S12 run on the candidate plus explicit execution authorization. Without
# the env the script prints this registry and exits 3. Every Go/Docker/
# integration call must be made through scripts/agents/heavy-lease.sh from the
# coordination repository; the harness cannot verify its caller, so lease
# discipline is on the operator. The preserved existing quickstart stack owns
# the pinned 10.207.0.0/24 subnet; this harness NEVER stops or rebuilds it,
# never rebuilds or retags the shared yabanin-quickstart:local image, and
# instead rewrites its isolated compose copies onto a verified-free scratch
# subnet with its own ports, images, project and volume.
#
# Fixtures (seed transcripts, keys, passwords, dumps, snapshots) live under
# $RUNTMP outside every Git worktree; directories 0700, files 0600. Keys are
# fingerprinted (sha256), never written to logs; seed transcripts stay in
# protected files because the minting line contains the plaintext key.

set -euo pipefail
umask 077

CANDIDATE_COMMIT=3a73e8e08b532df2b51a5fb47f19fbdbdff2f045
PREVIEW1_COMMIT=7b85b18963ce764aea1f9631a7d47104b09550aa
PROJECT="${QS_RECOVERY_PROJECT:-qs-p1recovery}"
RETAINED_VOLUME="${PROJECT}_pg_data"
TAG_P1="${PROJECT}:preview1"
TAG_CAND="${PROJECT}:candidate"
TAG_MOCK="${PROJECT}:mock"
GW_PORT="${QS_GATEWAY_PORT:-18097}"
ADM_PORT="${QS_ADMIN_PORT:-18098}"
QS_BASE="http://127.0.0.1:${GW_PORT}"
RUNTMP="${QS_RECOVERY_TMPDIR:-/tmp/opencode/qs-p1recovery}"

# Frozen dataset (independent literals; the reviewed S3b contract values).
FIX_ORG='77777777-7777-4777-8777-777777777777'
FIX_MODEL='mock-model'
FIX_PROVIDER='qs-fixture-provider'
ORG1_SLUG='p1-recovery-one'
ORG2_SLUG='p1-recovery-two'
ORG1_MODEL='p1r-one-model'
ORG2_MODEL='p1r-two-model'
ADMIN_EMAIL='p1recov-admin@localhost'
EXP_VIEWS="beta_cache_hit_rate_daily
beta_dau_daily
beta_latency_daily
beta_onboarding_ttfq
beta_provider_distribution
beta_provider_errors
beta_requests_daily"

CURRENT_CASE=registry
CURRENT_STEP=init

fail() {
  echo "QS-RECOVERY: FAIL (${CURRENT_CASE}/${CURRENT_STEP}): $*" >&2
  echo "  (stack left as-is for diagnosis; this harness never cleans up on failure)" >&2
  exit 1
}
step() { printf '== %s %s: %s\n' "$CURRENT_CASE" "$CURRENT_STEP" "$*"; }
case_start() { CURRENT_CASE=$1; CURRENT_STEP=start; step "case begin"; }
cs() { CURRENT_STEP=$1; }
note() { printf '   %s\n' "$*"; }

sha_file() { sha256sum "$1" | cut -d' ' -f1; }
fingerprint() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }

project_name_ok() {
  # project_name_ok NAME: recovery project names become docker objects
  # (volume, network, containers, image tags); only this strict lowercase
  # subset is accepted so a bad QS_RECOVERY_PROJECT fails before ANY docker
  # object is named or created. Default remains qs-p1recovery.
  [[ "$1" =~ ^[a-z0-9][a-z0-9_-]*$ ]]
}

wait_healthz() {
  local i
  for i in $(seq 1 90); do
    curl -fsS "$QS_BASE/healthz" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

send_chat() {
  # send_chat KEY MODEL REQID -> HTTP code; carries an explicit X-Request-ID so
  # the row identity is known exactly. Retries only transport failures (code
  # 000); a real HTTP response is final.
  local code tries=0
  while :; do
    code=$(curl -s -o /dev/null -w '%{http_code}' -X POST \
      -H "Authorization: Bearer $1" -H 'Content-Type: application/json' -H "X-Request-ID: $3" \
      -d "{\"model\":\"$2\",\"messages\":[{\"role\":\"user\",\"content\":\"p1recovery\"}]}" \
      "$QS_BASE/v1/chat/completions")
    [[ "$code" != "000" ]] && { printf '%s' "$code"; return 0; }
    tries=$((tries+1)); [[ $tries -ge 10 ]] && { echo "send_chat: transport failures persisted for $3" >&2; return 1; }
    sleep 1
  done
}

await_reqid() {
  # await_reqid QFN REQID: bounded wait for the exact request row; request
  # logging may be asynchronous. X-Request-ID propagation (pkg/requestid) is
  # thereby proven live, not assumed.
  local i
  for i in $(seq 1 30); do
    [[ "$($1 "SELECT count(*) FROM request_logs WHERE request_id = '$2'")" == "1" ]] && return 0
    sleep 1
  done
  return 1
}

chat_ok() {
  # chat_ok QFN KEY MODEL REQID LABEL: one completed 200 request whose exact
  # ID lands in the ledger exactly once.
  local code
  code=$(send_chat "$2" "$3" "$4") || fail "$5: send failed"
  [[ "$code" == "200" ]] || fail "$5: HTTP $code (expected 200)"
  await_reqid "$1" "$4" || fail "$5: row for request_id $4 never appeared — X-Request-ID propagation broken"
}

assert_pg_runtime() {
  # assert_pg_runtime QFN LABEL EXPECTED_MAJOR: verify the LIVE server binary
  # and the migrated extension catalog after each actual startup.
  # SHOW server_version_num must sit in the compose-recorded supported family
  # and must equal EXPECTED_MAJOR when given (empty only for the UP1 baseline
  # call that defines it). pg_extension.extversion for 'vector' must be
  # nonempty: migration 0001_init creates the extension, so availability alone
  # would mask a broken migration (recorded only as supplementary evidence).
  # A failed query is a failure, never absence. Prints the observed major.
  local qf="$1" label="$2" want="$3" v major ext avail
  v=$("$qf" "SHOW server_version_num") || fail "$label: SHOW server_version_num query failed"
  [[ "$v" =~ ^[0-9]{6}$ ]] || fail "$label: server_version_num not parseable [$v]"
  major=${v:0:2}
  [[ "$major" == "$PG_MAJ" ]] || fail "$label: live server major $major != compose pg${PG_MAJ} family"
  if [[ -n "$want" ]]; then
    [[ "$major" == "$want" ]] || fail "$label: live server major $major != preview1's recorded $want (cross-major binary/data mixing)"
  fi
  ext=$("$qf" "SELECT extversion FROM pg_extension WHERE extname = 'vector'") \
    || fail "$label: vector extversion query failed"
  [[ -n "$ext" ]] \
    || fail "$label: vector extension NOT installed in the migrated database (0001_init creates it; availability is not installation)"
  avail=$("$qf" "SELECT default_version FROM pg_available_extensions WHERE name = 'vector'") \
    || fail "$label: vector availability query failed"
  printf '   %s\n' "$label: live postgres server_version_num $v (pg${major}); vector extversion ${ext} (available ${avail:-none})" >&2
  echo "pg_${label}_server_version_num $v" >> "$RECORD"
  echo "pg_${label}_vector_extversion $ext" >> "$RECORD"
  echo "pg_${label}_vector_available ${avail:-none}" >> "$RECORD"
  printf '%s' "$major"
}

assert_container_image() {
  # assert_container_image CONTAINER EXPECTED_ID LABEL: the RUNNING container
  # must be the exact recorded image — inspecting a reference before `up`
  # does not prove what actually runs. A failed inspect is a failure, not a
  # mismatch verdict.
  local img
  img=$(docker inspect "$1" --format '{{.Image}}') || fail "$3: docker inspect $1 failed"
  [[ "$img" == "$2" ]] || fail "$3: container $1 image $img != expected $2"
}

provision_phase_env() {
  # provision_phase_env SRCARCHIVE PHASE1DIR PHASE2DIR: the quickstart compose
  # files declare env_file: .env (project-directory relative); preflight must
  # exist before the first compose call. Secrets are generated ONCE through
  # the REAL product init-env.sh inside the extracted Preview1 archive and
  # installed with IDENTICAL bytes into BOTH phase dirs — identical bytes are
  # what make retained-key behavior observable; differing phase secrets would
  # rehearse a silent re-key instead of the upgrade. If phase envs already
  # exist (resume re-runs preflight) they are the authority and are NEVER
  # regenerated or overwritten — a missing archive env must not re-key the
  # retained volume. Secret values are never printed; the sha256 fingerprint
  # on stdout is the identity evidence.
  local src="$1" envf="$1/deploy/quickstart/.env"
  if [[ -s "$2/.env" || -s "$3/.env" ]]; then
    [[ -s "$2/.env" && -s "$3/.env" ]] || fail "phase env: only one phase .env exists (refusing to invent the missing half)"
    cmp -s "$2/.env" "$3/.env" || fail "phase env: phase .env bytes differ (retained-key rehearsal invalid)"
    [[ ! -s "$envf" ]] || cmp -s "$envf" "$2/.env" \
      || fail "phase env: archive .env differs from the installed phase .env"
    chmod 600 "$2/.env" "$3/.env"
    sha_file "$2/.env"; return 0
  fi
  bash "$src/scripts/quickstart/init-env.sh" >&2 || fail "phase env: init-env.sh failed inside $src"
  [[ -s "$envf" ]] || fail "phase env: init-env.sh left no $envf"
  cp "$envf" "$2/.env" || fail "phase env: could not install $2/.env"
  cp "$envf" "$3/.env" || fail "phase env: could not install $3/.env"
  chmod 600 "$2/.env" "$3/.env"
  cmp -s "$2/.env" "$3/.env" || fail "phase env: phase .env bytes differ (retained-key rehearsal invalid)"
  sha_file "$2/.env"
}

require_phase_env() {
  # require_phase_env PHASE1DIR PHASE2DIR IDENTITYFILE: rollback resume must
  # REUSE the prior upgrade run's phase .env verbatim — the retained volume's
  # data was encrypted/session-keyed with exactly those secrets. Both files
  # must exist, be byte-identical, and match the fingerprint recorded at
  # upgrade time. Never regenerates, never rewrites; prints the fingerprint.
  local f1="$1/.env" f2="$2/.env" want got m1 m2
  [[ -s "$f1" && -s "$f2" ]] || fail "resume: phase .env missing under $1 or $2 (secrets are never regenerated on resume)"
  m1=$(stat -c %a "$f1"); m2=$(stat -c %a "$f2")
  [[ "$m1$m2" == "600600" ]] || fail "resume: phase .env mode drift (${m1}/${m2}, want 600/600)"
  cmp -s "$f1" "$f2" || fail "resume: phase .env bytes differ"
  want=$(sed -n 's/^phase_env_sha256 //p' "$3" | head -1)
  [[ -n "$want" ]] || fail "resume: no phase_env_sha256 recorded in $3"
  got=$(sha_file "$f1")
  [[ "$got" == "$want" ]] || fail "resume: phase .env differs from the upgrade run's recorded secrets ($got != $want)"
  printf '%s' "$got"
}

require_phase_images() {
  # require_phase_images TAG COMPOSEFILE LABEL: invariant half of the PF3
  # app-image rewrite — zero shared yabanin-quickstart:local refs remain
  # (checked FIRST: any surviving shared ref would run fleet-built bytes and
  # is the actual safety violation), then exactly three TAG refs. Validates
  # partially rewritten files too, so a defective correction fails as a
  # shared-image invariant violation, never as a silent pass.
  local tag="$1" f="$2" lbl="$3" tagged shared
  shared=$(grep -c 'image: yabanin-quickstart:local' "$f" || true)
  [[ "$shared" -eq 0 ]] || fail "$lbl compose: $shared shared yabanin-quickstart:local ref(s) remain (shared-image invariant violated)"
  tagged=$(grep -c "image: ${tag}\$" "$f" || true)
  [[ "$tagged" -eq 3 ]] || fail "$lbl compose: expected 3 refs to $tag, found $tagged"
}

rewrite_phase_images() {
  # rewrite_phase_images TAG COMPOSEFILE LABEL: the archived quickstart
  # compose references the shared mutable yabanin-quickstart:local image for
  # exactly three services (migrate, seed, yabanin). Preflight pins all three
  # to THIS phase's source-rebuilt tag so compose can never silently run
  # whatever the fleet last built under the shared tag (the r3 UP1 failure:
  # container 6998f57d != archived 3171a922). Immutable postgres/redis refs
  # and the mock override are never touched. Precheck: exactly three shared
  # refs (archive shape guard); postcheck: the invariant above.
  local tag="$1" f="$2" lbl="$3" n
  n=$(grep -c 'image: yabanin-quickstart:local' "$f" || true)
  [[ "$n" -eq 3 ]] \
    || fail "$lbl compose: expected 3 shared yabanin-quickstart:local app refs, found $n (archive shape changed; refusing to guess)"
  sed -i "s#image: yabanin-quickstart:local\$#image: ${tag}#" "$f"
  require_phase_images "$tag" "$f" "$lbl"
}

# Compose invocations for the two phases of the SAME project (same project
# name => same retained <project>_pg_data volume). Each phase file is paired
# with the instrumented-mock override (same reviewed harness-commit mock image
# for both phases; only the application images differ). P1C/CDC are FULL
# executable command arrays — external tools like timeout(1) cannot exec a
# shell function (the r4 seed failure) — and always carry --profile mock so
# the instrumented provider mock runs with every phase invocation. The seed
# profile is NEVER default: it is added only at the explicit seed_run so no
# unintended seed service runs during ordinary UP/rollback and changes
# org/key/provider facts. psql helpers always run with ON_ERROR_STOP so a
# failed statement is a nonzero exit, multi-statement fixture SQL included.
P1C=(docker compose --project-name "$PROJECT" --project-directory "$RUNTMP/preview1" --profile mock -f "$RUNTMP/preview1/docker-compose.yml" -f "$RUNTMP/preview1/mock-instrumented.yml")
CDC=(docker compose --project-name "$PROJECT" --project-directory "$RUNTMP/candidate" --profile mock -f "$RUNTMP/candidate/docker-compose.yml" -f "$RUNTMP/candidate/mock-instrumented.yml")
p1c()   { "${P1C[@]}" "$@"; }
cdc()   { "${CDC[@]}" "$@"; }
p1q()   { p1c exec -T postgres psql -U yabanin -d yabanin -v ON_ERROR_STOP=1 -tA -c "$1"; }
cndq()  { cdc exec -T postgres psql -U yabanin -d yabanin -v ON_ERROR_STOP=1 -tA -c "$1"; }
p1adm() { p1c exec -T postgres psql -U yabanin -d postgres -v ON_ERROR_STOP=1 -tA -c "$1"; }
cdcadm(){ cdc exec -T postgres psql -U yabanin -d postgres -v ON_ERROR_STOP=1 -tA -c "$1"; }
p1app() { p1c exec -T postgres psql -U yabanin_app -d yabanin -v ON_ERROR_STOP=1 -v VERBOSITY=verbose -tA -c "$1"; }
cndapp(){ cdc exec -T postgres psql -U yabanin_app -d yabanin -v ON_ERROR_STOP=1 -v VERBOSITY=verbose -tA -c "$1"; }

MOCK_CONTAINER="${PROJECT}-mock-openai-1"
GW_CONTAINER="${PROJECT}-yabanin-1"

mock_hits() {
  # Provider-side observation: count of received chat-completions requests in
  # the instrumented mock's log (docker logs reset when its container is
  # recreated, so assertions are always within one container lifetime).
  # Fail-closed: a missing/dead mock or a Docker error must never become a
  # fake zero that could make a denial look valid; only a genuinely empty log
  # counts as zero. Entries are the exact method+path lines only — never
  # headers, bodies or secrets.
  local logs
  [[ "$(docker inspect "$MOCK_CONTAINER" --format '{{.State.Running}}')" == "true" ]] \
    || fail "provider observation unavailable: mock container $MOCK_CONTAINER is not running"
  logs=$(docker logs "$MOCK_CONTAINER" 2>&1) \
    || fail "provider observation unavailable: docker logs $MOCK_CONTAINER failed"
  awk 'index($0, "mock-request POST /v1/chat/completions") { n++ } END { print n + 0 }' <<<"$logs"
}

mock_delta_one() { # mock_delta_one H0 LABEL — provider hits grew by exactly one
  local h1; h1=$(mock_hits)
  [[ "$h1" == "$(( $1 + 1 ))" ]] || fail "$2: provider hits $1 -> $h1 (expected exactly +1)"
}

extract_key() { sed -n 's/.*API key (shown once, store it now): \(yb_[0-9a-fA-F]*\).*/\1/p' "$1"; }

count_req() { # count_req QFN ORG -> request_logs rows for org
  "$1" "SELECT count(*) FROM request_logs WHERE org_id = '$2'"
}

snapshot_history() {
  # snapshot_history QFN ORG1 ORG2 OUT: per-org counts plus org-tagged stable
  # request identities. A snapshot that captured no identities, or whose ID
  # lines do not account for every counted row, is INVALID — a vacuous
  # snapshot must fail, never pass by regex dropping IDs.
  local q=$1 o1=$2 o2=$3 out=$4 ids total
  {
    echo "count|org1|$("$q" "SELECT count(*) FROM request_logs WHERE org_id = '$o1'")"
    echo "count|org2|$("$q" "SELECT count(*) FROM request_logs WHERE org_id = '$o2'")"
    echo "count|fixture|$("$q" "SELECT count(*) FROM request_logs WHERE org_id = '$FIX_ORG'")"
    "$q" "SELECT org_id::text || '|' || request_id FROM request_logs WHERE org_id IN ('$o1','$o2','$FIX_ORG') ORDER BY 1,2";
  } > "$out"
  chmod 600 "$out"
  ids=$(grep -cE '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\|..*$' "$out" || true)
  total=$(awk -F'|' '/^count\|/{s+=$3} END{print s+0}' "$out")
  [[ "$ids" == "$total" && "$total" -gt 0 ]] \
    || fail "history snapshot invalid: $ids parseable identity lines for $total counted rows — identities must be non-empty and complete"
}

assert_history_retained() {
  # assert_history_retained QFN SNAP LABEL: every frozen org|request_id pair
  # from the backup-time snapshot still exists, associated with the same org.
  # Deliberately independent of per-org totals: new requests may add rows but
  # never remove or re-associate frozen ones.
  local q=$1 snap=$2 label=$3 current missing
  [[ -s "$snap" ]] || { echo "$label: snapshot missing" >&2; return 1; }
  current=$("$q" "SELECT org_id::text || '|' || request_id FROM request_logs WHERE org_id IN ('${ORG1_ID}','${ORG2_ID}','$FIX_ORG')")
  missing=$(comm -23 <(grep -vE '^count\|' "$snap" | sort -u) <(printf '%s\n' "$current" | sort -u))
  [[ -z "$missing" ]] || { echo "$label: frozen request identities lost or re-associated: $(printf '%s' "$missing" | tr '\n' ' ')" >&2; return 1; }
  return 0
}

snapshot_acl() {
  # Canonical roles/grants/policies/ownership snapshot with stable ordering.
  # Grants include grantor; ownership covers tables AND views via the
  # owner-aware catalog (pg_class/pg_namespace — information_schema.tables
  # exposes no owner column) so a restore that changed owners cannot pass.
  local q=$1 out=$2
  {
    "$q" "SELECT 'role', rolname FROM pg_roles WHERE rolname IN ('yabanin','yabanin_app') ORDER BY 2"
    "$q" "SELECT 'grant', grantor, grantee, table_name, privilege_type FROM information_schema.role_table_grants WHERE grantee IN ('yabanin','yabanin_app') ORDER BY 2,3,4,5"
    "$q" "SELECT 'owner', c.relname AS table_name, CASE c.relkind WHEN 'r' THEN 'BASE TABLE' WHEN 'v' THEN 'VIEW' WHEN 'm' THEN 'MATERIALIZED VIEW' WHEN 'p' THEN 'PARTITIONED TABLE' ELSE c.relkind::text END AS table_type, pg_get_userbyid(c.relowner) AS owner FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'public' AND c.relkind IN ('r','v','m','p') ORDER BY 2"
    "$q" "SELECT 'policy', tablename, policyname FROM pg_policies WHERE schemaname = 'public' ORDER BY 2,3"
    "$q" "SELECT 'rls', tablename, rowsecurity::int FROM pg_tables WHERE schemaname = 'public' AND rowsecurity ORDER BY 2";
  } > "$out"
  chmod 600 "$out"
}

snapshot_routing() {
  local q=$1 o1=$2 o2=$3 out=$4
  "$q" "SELECT org_id, model_name, provider, upstream_url FROM org_custom_models WHERE org_id IN ('$o1','$o2','$FIX_ORG') ORDER BY 1,2" > "$out"
  chmod 600 "$out"
}

view_names() { # view_names QFN -> managed-view set actually present
  "$1" "SELECT table_name FROM information_schema.views WHERE table_schema='public' AND table_name LIKE 'beta_%' ORDER BY 1"
}

vv() { # vv QFN LABEL SQL — one name|value line; name|MISSING if the view is absent or errors
  local got
  if got=$("$1" "$3" 2>/dev/null); then printf '%s\n' "$got"; else echo "$2|MISSING"; fi
}

view_values() {
  # view_values QFN OUT: the ACTUAL per-view values as name|value lines
  # (name|MISSING when a view is absent on this stack). Used to record the
  # Preview1 baseline as-is and to compare candidate/rollback stacks.
  local q=$1 out=$2
  {
    vv "$q" dau      "SELECT 'dau', active_users || '/' || requests FROM beta_dau_daily WHERE org_id = '$FIX_ORG'"
    vv "$q" requests "SELECT 'requests', requests || '/' || errors FROM beta_requests_daily WHERE org_id = '$FIX_ORG'"
    vv "$q" ttfq     "SELECT 'ttfq', (onboarded_at - '$FIX_T0'::timestamptz) = interval '0' AND (first_request_at - ('$FIX_T0'::timestamptz + interval '90 seconds')) = interval '0' AND round(seconds_to_first_request::numeric) = 90 FROM beta_onboarding_ttfq WHERE org_id = '$FIX_ORG'"
    vv "$q" provider "SELECT 'provider', provider || '/' || byok::int || '/' || requests FROM beta_provider_distribution WHERE org_id = '$FIX_ORG'"
    vv "$q" errors   "SELECT 'errors', requests || '/' || errors || '/' || round(error_rate::numeric, 4)::text FROM beta_provider_errors WHERE org_id = '$FIX_ORG'"
    vv "$q" latency  "SELECT 'latency', p50_ms::int || '/' || p95_ms::int || '/' || requests FROM beta_latency_daily WHERE org_id = '$FIX_ORG'"
    vv "$q" cache    "SELECT 'cache', hits || '/' || requests || '/' || round(hit_rate::numeric, 4)::text FROM beta_cache_hit_rate_daily WHERE org_id = '$FIX_ORG'";
  } > "$out"
  chmod 600 "$out"
}

app_read_outcome() { # app_read_outcome APPFN -> 'app_read|ok|N' or 'app_read|DENIED'
  local got
  if got=$("$1" "SELECT count(*) FROM beta_dau_daily WHERE org_id = '$FIX_ORG'" 2>/dev/null); then
    echo "app_read|ok|$got"
  else
    echo "app_read|DENIED"
  fi
}

FROZEN_VIEW_VALUES="dau|3/3
requests|3/1
ttfq|t
provider|${FIX_PROVIDER}/1/3
errors|3/1/0.3333
latency|200/290/3
cache|1/3/0.3333"

print_registry() {
  sed -n '/^# FROZEN CASE REGISTRY/,/^# `down -v`/p' "$0" | sed '$d'
}

seed_run() {
  # seed_run OUT SEED_ARGS...: runs the product seed service (preview1 phase
  # only) with bounded time; the full transcript stays in a 0600 file because
  # the minting line contains the plaintext key and must never reach a log.
  # Parse failures reference the file's sha256, not its content.
  local out=$1; shift
  if ! timeout 300 "${P1C[@]}" --profile seed run --rm -T seed "$@" < "$RUNTMP/admin-password" > "$out" 2>&1; then
    fail "seed run failed; transcript kept protected at $out (sha256 $(sha_file "$out"))"
  fi
  chmod 600 "$out"
}

global_model_ok() {
  # global_model_ok QFN KEY MODEL LABEL: POSITIVE global-registry routing
  # control. The seed service inserts both model names into the GLOBAL
  # models_registry (not org_custom_models), so this is NOT a private-model
  # isolation probe and is never described as a denial: ordinary global
  # routing may legitimately select a different enabled global model, so
  # model_used is NOT asserted. Observed contract: HTTP 200 with a unique
  # explicit request ID that lands in the ledger exactly once, exactly one
  # provider hit, exactly one new org1 ledger row, org2 ledger unchanged.
  local code h0 h1 l1_0 l1_1 l2_0 l2_1 reqid
  reqid="qs-p1r-glb-$(date +%s%N)"
  h0=$(mock_hits)
  l1_0=$("$1" "SELECT count(*) FROM request_logs WHERE org_id = '${ORG1_ID}'")
  l2_0=$("$1" "SELECT count(*) FROM request_logs WHERE org_id = '${ORG2_ID}'")
  code=$(send_chat "$2" "$3" "$reqid") || fail "$4: send failed"
  [[ "$code" == "200" ]] || fail "$4: global-registry request not served (HTTP $code)"
  await_reqid "$1" "$reqid" || fail "$4: row for request_id $reqid never appeared — X-Request-ID propagation broken"
  h1=$(mock_hits)
  l1_1=$("$1" "SELECT count(*) FROM request_logs WHERE org_id = '${ORG1_ID}'")
  l2_1=$("$1" "SELECT count(*) FROM request_logs WHERE org_id = '${ORG2_ID}'")
  [[ "$h1" == "$((h0 + 1))" ]] || fail "$4: provider hits $h0 -> $h1 (expected exactly +1)"
  [[ "$l1_1" == "$((l1_0 + 1))" ]] || fail "$4: org1 ledger $l1_0 -> $l1_1 (expected exactly +1)"
  [[ "$l2_1" == "$l2_0" ]] || fail "$4: org2 ledger changed ($l2_0 -> $l2_1)"
  note "$4: served by global routing, provider hit +1, org1 ledger +1, org2 unchanged (global registry control, not private-model isolation)"
}

load_inactive_key() {
  # Read-or-create the locally minted inactive control key. The plaintext is
  # stored ONLY in the 0600 protected file (resume re-reads it), never
  # printed, never written to the DB, and logged only as its sha256
  # fingerprint, which is recorded once and verified against drift on resume.
  # The file's mode is verified to be 0600 BEFORE it is read — a protected
  # fixture that loosened its mode is refused rather than trusted.
  local fp rec mode
  if [[ -e "$INACTIVE_KEY_FILE" ]]; then
    mode=$(stat -c%a "$INACTIVE_KEY_FILE")
    [[ "$mode" == "600" ]] \
      || fail "inactive control key file is mode $mode, not 0600 — refusing to read it"
    [[ -s "$INACTIVE_KEY_FILE" ]] || fail "inactive control key file is empty"
    key3=$(<"$INACTIVE_KEY_FILE")
  else
    key3="yb_$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
    printf '%s' "$key3" > "$INACTIVE_KEY_FILE"
    chmod 600 "$INACTIVE_KEY_FILE"
  fi
  [[ "$key3" =~ ^yb_[0-9a-f]{32}$ ]] \
    || fail "inactive control key malformed in $INACTIVE_KEY_FILE (sha256 $(sha_file "$INACTIVE_KEY_FILE"))"
  fp=$(fingerprint "$key3")
  rec=$(sed -n 's/^inactive_key_fingerprint //p' "$RECORD" | head -1)
  if [[ -n "$rec" ]]; then
    [[ "$rec" == "$fp" ]] || fail "inactive control key fingerprint drift vs the recorded upgrade-run value"
  else
    echo "inactive_key_fingerprint $fp" >> "$RECORD"
  fi
}

assert_inactive_key() {
  # assert_inactive_key QFN LABEL: the fixture row exists exactly once AND
  # the full binding is intact — deterministic id, the CORRECT sha256 hash of
  # the protected plaintext, org1 ownership, an org1-owned team and
  # active=false. Only with every binding column correct can the 401 observed
  # by denied_key_ok have exactly one cause: the inactive state. A wrong
  # hash/org/team would also 401 (unknown or foreign key) and would prove
  # nothing, so each is asserted separately with its own diagnostic. Checked
  # on preview1 (UP4), after the candidate migrate (UP9) and after the
  # rollback restore (RB5).
  local n row hash_ok org_ok act team_ok
  n=$("$1" "SELECT count(*) FROM api_keys WHERE id = '${INACTIVE_KEY_ID}'")
  [[ "$n" == 1 ]] || fail "$2: inactive api_keys row missing or duplicated [$n]"
  row=$("$1" "SELECT (key_hash = '$(fingerprint "$key3")'), (org_id = '${ORG1_ID}'::uuid), active,
    (team_id IN (SELECT id FROM organizations_teams WHERE org_id = '${ORG1_ID}'::uuid))
    FROM api_keys WHERE id = '${INACTIVE_KEY_ID}'")
  IFS='|' read -r hash_ok org_ok act team_ok <<<"$row"
  [[ "$hash_ok" == "t" ]] || fail "$2: inactive api_keys key_hash is not the correct hash of the protected plaintext"
  [[ "$org_ok" == "t" ]] || fail "$2: inactive api_keys row is not owned by org1"
  [[ "$act" == "f" ]] || fail "$2: inactive api_keys row is not active=false [$act]"
  [[ "$team_ok" == "t" ]] || fail "$2: inactive api_keys team is not an org1-owned team"
}

install_inactive_key() {
  # install_inactive_key QFN: insert the inactive control row through the
  # REAL api_keys table — deterministic id, only the sha256 hash of the
  # protected plaintext, org1 ownership and one of org1's REAL teams from
  # organizations_teams — with active=false. Callers must run
  # assert_inactive_key immediately afterwards: ON CONFLICT DO NOTHING could
  # otherwise leave a stale conflicting row that the full binding check
  # rejects loudly instead of silently proving the wrong thing.
  local team
  team=$("$1" "SELECT id::text FROM organizations_teams WHERE org_id = '${ORG1_ID}' ORDER BY created_at LIMIT 1")
  [[ -n "$team" ]] || fail "inactive fixture: org1 has no team in organizations_teams"
  "$1" "INSERT INTO api_keys (id, key_hash, org_id, team_id, name, active)
    VALUES ('${INACTIVE_KEY_ID}', '$(fingerprint "$key3")', '${ORG1_ID}'::uuid, '${team}'::uuid,
            'p1 recovery inactive control key', false)
    ON CONFLICT (id) DO NOTHING" >/dev/null \
    || fail "inactive fixture: insert into api_keys failed"
}

denied_key_ok() {
  # denied_key_ok QFN KEY MODEL LABEL: real authorization negative. The key's
  # api_keys row carries its CORRECT sha256 hash, org1 ownership and an
  # org1-owned team but active=false, and it has never been used positively
  # (no cache can vouch for it), so the observed contract — exact HTTP 401,
  # zero provider hits, zero org1 ledger change and zero rows carrying the
  # denied request's exact ID — is behavioral evidence of the inactive-state
  # denial, not a DB-flag or source-text check.
  local code h0 h1 led0 led1 rid rows
  rid="qs-p1r-deny-$(date +%s%N)"
  # the request ID is emitted BEFORE the send: request IDs are not secrets,
  # and on the intentional HTTP 200 path of the active-key control this is
  # the only place the ID is recorded for the effect accounting below.
  note "$4: request_id $rid"
  h0=$(mock_hits)
  led0=$("$1" "SELECT count(*) FROM request_logs WHERE org_id = '${ORG1_ID}'")
  code=$(send_chat "$2" "$3" "$rid") || fail "$4: send failed"
  [[ "$code" == "401" ]] || fail "$4: inactive key not denied (HTTP $code)"
  h1=$(mock_hits)
  led1=$("$1" "SELECT count(*) FROM request_logs WHERE org_id = '${ORG1_ID}'")
  [[ "$h1" == "$h0" ]] || fail "$4: provider saw $((h1 - h0)) extra requests despite the 401 denial"
  [[ "$led1" == "$led0" ]] || fail "$4: org1 ledger changed across the denial ($led0 -> $led1)"
  rows=$("$1" "SELECT count(*) FROM request_logs WHERE request_id = '${rid}'")
  [[ "$rows" == 0 ]] || fail "$4: $rows ledger rows carry the denied request ID"
  note "$4: denied (HTTP 401), provider hits $h0 -> $h1, org1 ledger unchanged, no row for the denied request"
}

run_active_key_negative() {
  # run_active_key_negative QFN KEY MODEL LOGFILE LABEL: isolated
  # expected-negative control proving the denial oracle itself has teeth.
  # The SAME denied_key_ok runs in a subshell with an ACTIVE key and MUST
  # fail with HTTP 200 in its captured log — failing for any other reason
  # (e.g. setup breakage) is rejected. The control's OWN effect is then
  # MEASURED, not assumed: provider hits and the org1 ledger are captured
  # before the subshell and must each have grown by exactly one afterwards,
  # and exactly one request_logs row must carry the rid the helper emitted
  # before its send (parsed back from the protected log; a missing, ambiguous
  # or empty rid is rejected; the row is AWAITED via await_reqid before the
  # +1 assertions because the ledger write is asynchronous). The log is kept
  # as expected-negative evidence. An unexpected inactive-key failure
  # elsewhere is never swallowed here.
  local h0 h1 l0 l1 rid rows nrid
  h0=$(mock_hits)
  l0=$("$1" "SELECT count(*) FROM request_logs WHERE org_id = '${ORG1_ID}'")
  if ( denied_key_ok "$1" "$2" "$3" "$5 (expected-negative: ACTIVE key must fail this oracle)" ) >"$4" 2>&1; then
    fail "$5: active-key control unexpectedly PASSED the inactive-key oracle"
  fi
  grep -q 'HTTP 200' "$4" \
    || fail "$5: active-key control failed for the wrong reason: $(head -c 200 "$4")"
  rid=$(sed -n 's/.*request_id \(qs-p1r-deny-[0-9]\{1,\}\).*/\1/p' "$4" | head -1)
  [[ "$rid" =~ ^qs-p1r-deny-[0-9]+$ ]] \
    || fail "$5: no parseable request ID in the expected-negative log"
  nrid=$(grep -c 'request_id qs-p1r-deny-[0-9]\{1,\}' "$4")
  [[ "$nrid" == 1 ]] || fail "$5: expected exactly one request ID in the log, found $nrid (ambiguous control)"
  await_reqid "$1" "$rid" \
    || fail "$5: the active key's row for request_id $rid never appeared — X-Request-ID propagation broken"
  h1=$(mock_hits)
  l1=$("$1" "SELECT count(*) FROM request_logs WHERE org_id = '${ORG1_ID}'")
  [[ "$h1" == "$((h0 + 1))" ]] \
    || fail "$5: active-key control did not make exactly one provider hit ($h0 -> $h1)"
  [[ "$l1" == "$((l0 + 1))" ]] \
    || fail "$5: active-key control did not add exactly one org1 ledger row ($l0 -> $l1)"
  rows=$("$1" "SELECT count(*) FROM request_logs WHERE request_id = '${rid}'")
  [[ "$rows" == 1 ]] \
    || fail "$5: expected exactly one ledger row carrying the control's request_id $rid, found $rows"
  chmod 600 "$4"
  note "$5: expected-negative OK, measured: HTTP 200, provider hits $h0 -> $h1, org1 ledger $l0 -> $l1, exactly one row for request_id $rid"
}

# ---------------------------------------------------------------- gate + guards

if [[ "${QS_RECOVERY_EXECUTE:-0}" != "1" ]]; then
  print_registry
  echo "QS-RECOVERY: execution not enabled (source-only phase; set QS_RECOVERY_EXECUTE=1" \
       "only after S1..S12 green on the candidate and owner authorization)" >&2
  exit 3
fi

[[ $# -le 1 && "${1:-all}" =~ ^(all|upgrade|rollback)$ ]] || fail "usage: $0 [all|upgrade|rollback]"
MODE=${1:-all}
RESUME="${QS_RECOVERY_RESUME:-0}"
project_name_ok "$PROJECT" \
  || fail "invalid QS_RECOVERY_PROJECT [$PROJECT] (want ^[a-z0-9][a-z0-9_-]*\$)"

for t in docker ss curl sha256sum timeout sed grep awk comm stat tar date head od git python3 openssl cmp cp; do
  command -v "$t" >/dev/null 2>&1 || fail "required tool missing: $t (port/subnet checks must fail, not silently skip)"
done

root=$(git rev-parse --show-toplevel 2>/dev/null) || fail "not run from a Git worktree"
HARNESS_HEAD=$(git -C "$root" rev-parse HEAD)
git -C "$root" diff --quiet || fail "worktree has unstaged changes to tracked files"
git -C "$root" diff --cached --quiet || fail "worktree has staged changes"
git -C "$root" cat-file -e "$PREVIEW1_COMMIT^{commit}" || fail "Preview1 commit $PREVIEW1_COMMIT not present"
git -C "$root" cat-file -e "$CANDIDATE_COMMIT^{commit}" || fail "candidate commit $CANDIDATE_COMMIT not present"
note "harness head $HARNESS_HEAD (recorded, not asserted equal to the candidate)"

BACKUP="$RUNTMP/protected/pre-upgrade.dump"
RECORD="$RUNTMP/protected/pre-upgrade-record.txt"
IDENTITY="$RUNTMP/protected/identity.txt"
HIST_PRE="$RUNTMP/protected/history-backup-time.txt"
ACL_PRE="$RUNTMP/protected/acl-pre-upgrade.txt"
ROUTING_PRE="$RUNTMP/protected/routing-pre-upgrade.txt"
VIEWS_P1="$RUNTMP/protected/view-values-preview1.txt"
VIEWS_P1_SET="$RUNTMP/protected/view-set-preview1.txt"
VIEWS_P1_APP="$RUNTMP/protected/view-appread-preview1.txt"
RECOVERY_POINT="$RUNTMP/protected/recovery-point.txt"
# Inactive-key authorization fixture: plaintext lives ONLY in this 0600 file
# (read back on rollback resume), the DB stores only its sha256 hash, and the
# deterministic id keeps the row identifiable across backup/migrate/restore.
INACTIVE_KEY_FILE="$RUNTMP/protected/inactive-key.txt"
INACTIVE_KEY_ID="77777777-7777-4777-8777-777777770004"
ORG1_ID='' ORG2_ID='' FIX_T0=''

if [[ "$RESUME" == "1" ]]; then
  [[ "$MODE" == rollback ]] || fail "QS_RECOVERY_RESUME=1 supports only mode rollback"
  [[ -d "$RUNTMP" && -s "$BACKUP" && -s "$RECORD" ]] \
    || fail "resume: no prior upgrade evidence under $RUNTMP (need $BACKUP and $RECORD)"
  note "resume from protected state under $RUNTMP (prior evidence read-only; new lines go to $IDENTITY)"
  require_phase_env "$RUNTMP/preview1" "$RUNTMP/candidate" "$IDENTITY" >/dev/null \
    || fail "resume: phase .env reuse check failed (never regenerated)"
  note "resume: phase .env verified against the upgrade run's recorded fingerprint"
else
  [[ "$MODE" != rollback ]] || fail "mode rollback requires QS_RECOVERY_RESUME=1 (a prior upgrade run's protected state)"
  [[ ! -e "$RUNTMP" ]] \
    || fail "$RUNTMP already exists — prior evidence must never be overwritten; inspect it and either run a reviewed QS_RECOVERY_RESUME=1 rollback or move it aside deliberately"
  mkdir -p "$RUNTMP/preview1" "$RUNTMP/candidate" "$RUNTMP/protected" "$RUNTMP/src-preview1" "$RUNTMP/src-candidate"
fi
chmod 700 "$RUNTMP" "$RUNTMP/protected" "$RUNTMP/preview1" "$RUNTMP/candidate"
if git -C "$RUNTMP" rev-parse --show-toplevel >/dev/null 2>&1; then
  fail "RUNTMP $RUNTMP resolves inside a Git worktree; fixtures must live outside Git"
fi

# ---------------------------------------------------------------- preflight

cs PF1
if [[ "$RESUME" == "1" ]]; then
  step "resume preflight: prior project running; scratch endpoints derived from the live stack"
  docker compose ls --all --format '{{.Name}}' 2>/dev/null | grep -qx "$PROJECT" \
    || fail "resume: compose project $PROJECT is not up (an upgrade-only run leaves the candidate stack running)"
  SUBNET=$(docker network inspect "${PROJECT}_default" --format '{{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null || true)
  MOCK_IP=$(grep -m1 -oE 'ipv4_address:[[:space:]]*[0-9.]+' "$RUNTMP/candidate/docker-compose.yml" 2>/dev/null | grep -oE '[0-9.]+$' || true)
  [[ -n "$SUBNET" && -n "$MOCK_IP" ]] || fail "resume: could not derive the live scratch subnet / mock ip"
  note "resume on scratch subnet $SUBNET mock ip $MOCK_IP"
else
  step "preflight: isolated project, volume and ports free; scratch subnet chosen and verified"
  docker compose ls --all --format '{{.Name}}' 2>/dev/null | grep -qx "$PROJECT" \
    && fail "compose project $PROJECT already exists; a previous run still owns it (inspect and remove deliberately — this harness never cleans prior-run or foreign resources on its own)"
  docker volume ls --format '{{.Name}}' | grep -qx "$RETAINED_VOLUME" \
    && fail "retained volume $RETAINED_VOLUME already exists"
  for p in "$GW_PORT" "$ADM_PORT"; do
    if ss -ltn "sport = :$p" 2>/dev/null | grep -q LISTEN; then fail "port $p busy"; fi
  done
  held_subnets=$(for nid in $(docker network ls --format '{{.Name}}'); do
    docker network inspect "$nid" --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null
  done)
  SUBNET='' MOCK_IP=''
  for cand in 10.207.201.0/24 10.207.202.0/24 10.207.203.0/24 10.207.204.0/24; do
    if ! grep -qF "$cand" <<<"$held_subnets"; then
      SUBNET=$cand; MOCK_IP="${cand%0/*}9"; break
    fi
  done
  [[ -n "$SUBNET" ]] || fail "no free scratch subnet available (10.207.201-204 all held)"
  note "scratch subnet $SUBNET mock ip $MOCK_IP (existing 10.207.0.0/24 stack untouched)"
fi

cs PF2
step "preflight: exact archived sources for both app images (never the shared :local image)"
git -C "$root" archive "$PREVIEW1_COMMIT" | tee "$RUNTMP/src-preview1.tar" | tar -x -C "$RUNTMP/src-preview1"
git -C "$root" archive "$CANDIDATE_COMMIT" | tee "$RUNTMP/src-candidate.tar" | tar -x -C "$RUNTMP/src-candidate"
PRE_TAR_SHA=$(sha_file "$RUNTMP/src-preview1.tar"); PRE_TREE_SHA=$(git -C "$root" rev-parse "$PREVIEW1_COMMIT^{tree}")
CAND_TAR_SHA=$(sha_file "$RUNTMP/src-candidate.tar"); CAND_TREE_SHA=$(git -C "$root" rev-parse "$CANDIDATE_COMMIT^{tree}")
{
  echo "harness_head $HARNESS_HEAD"
  echo "preview1_commit $PREVIEW1_COMMIT"; echo "preview1_tree $PRE_TREE_SHA"; echo "preview1_archive_tar_sha256 $PRE_TAR_SHA"
  echo "candidate_commit $CANDIDATE_COMMIT"; echo "candidate_tree $CAND_TREE_SHA"; echo "candidate_archive_tar_sha256 $CAND_TAR_SHA"
  echo "run_started_utc $(date -u +%FT%TZ)";
} > "$IDENTITY"
note "preview1 tree ${PRE_TREE_SHA} (tar ${PRE_TAR_SHA})"
note "candidate tree ${CAND_TREE_SHA} (tar ${CAND_TAR_SHA})"
note "images are source-rebuilt from these exact trees; the module zip identity (go.sum h1:CvRyFnznqtqNToTB5UxUg2XLDQvYyeX3LGTiT43IsWw=) certifies the pin but is not the image bytes"

cs PF3
step "preflight: phase compose copies rewritten onto the scratch subnet + instrumented mock override"
for phase in preview1 candidate; do
  if [[ "$phase" == preview1 ]]; then src_commit=$PREVIEW1_COMMIT; phase_tag=$TAG_P1; else src_commit=$CANDIDATE_COMMIT; phase_tag=$TAG_CAND; fi
  git -C "$root" show "${src_commit}:deploy/quickstart/docker-compose.yml" > "$RUNTMP/$phase/docker-compose.yml"
  git -C "$root" show "${src_commit}:deploy/quickstart/bootstrap-app-role.sql" > "$RUNTMP/$phase/bootstrap-app-role.sql"
  rewrite_phase_images "$phase_tag" "$RUNTMP/$phase/docker-compose.yml" "$phase"
  sed -i "s#10\.207\.0\.0/24#${SUBNET}#g; s#10\.207\.0\.9#${MOCK_IP}#g" "$RUNTMP/$phase/docker-compose.yml"
  if grep -q '10\.207\.0\.' "$RUNTMP/$phase/docker-compose.yml"; then
    fail "$phase compose still references the occupied 10.207.0.0/24 after rewrite"
  fi
  cat > "$RUNTMP/$phase/mock-instrumented.yml" <<EOF
services:
  mock-openai:
    image: ${TAG_MOCK}
    environment:
      MOCK_REQUEST_LOG: "1"
EOF
  chmod 600 "$RUNTMP/$phase/mock-instrumented.yml"
  note "$phase compose sha256 $(sha_file "$RUNTMP/$phase/docker-compose.yml") bootstrap sha256 $(sha_file "$RUNTMP/$phase/bootstrap-app-role.sql") override sha256 $(sha_file "$RUNTMP/$phase/mock-instrumented.yml")"
done
# Postgres image references: the SAME supported major family (pg16) is
# required across phases; immutable digests MAY differ (an ordinary pin
# refresh between the two commits is exactly what this rehearsal must
# exercise). The helper rejects pg15/other majors, non-pgvector images,
# unpinned or malformed references and ambiguous families BEFORE any volume
# exists. Never a convenience tag, never a retag.
pgref1=$(grep -m1 'image: pgvector' "$RUNTMP/preview1/docker-compose.yml" | awk '{print $2}')
pgref2=$(grep -m1 'image: pgvector' "$RUNTMP/candidate/docker-compose.yml" | awk '{print $2}')
PGREF_OUT=$(python3 "$root/scripts/quality/pg_image_refs.py" "$pgref1" "$pgref2" 2>"$RUNTMP/pf3-pgref.err") \
  || fail "postgres image references not compatible: $(cat "$RUNTMP/pf3-pgref.err")"
PG_MAJ=$(sed -n 's/^major=//p' <<<"$PGREF_OUT")
[[ -n "$PG_MAJ" ]] || fail "pg image refs helper returned no major"
{ echo "postgres_ref_preview1 $pgref1"; echo "postgres_ref_candidate $pgref2"
  echo "postgres_major $PG_MAJ"; } >> "$IDENTITY"
note "postgres refs share supported major pg${PG_MAJ}; distinct immutable digests allowed (pin refresh rehearsed)"

cs PF4
step "preflight: build both isolated app images from the archives + the instrumented mock from the harness commit"
P1_EPOCH=$(git -C "$root" log -1 --format=%ct "$PREVIEW1_COMMIT")
CAND_EPOCH=$(git -C "$root" log -1 --format=%ct "$CANDIDATE_COMMIT")
DOCKER_BUILDKIT=1 docker build --build-arg "SOURCE_DATE_EPOCH=${P1_EPOCH}" -t "$TAG_P1" -f "$RUNTMP/src-preview1/Dockerfile" "$RUNTMP/src-preview1" >/dev/null \
  || fail "preview1 image build failed"
DOCKER_BUILDKIT=1 docker build --build-arg "SOURCE_DATE_EPOCH=${CAND_EPOCH}" -t "$TAG_CAND" -f "$RUNTMP/src-candidate/Dockerfile" "$RUNTMP/src-candidate" >/dev/null \
  || fail "candidate image build failed"
MOCK_TREE_SHA=$(git -C "$root" rev-parse --quiet --verify "${HARNESS_HEAD}:deploy/mock-provider" 2>/dev/null) \
  || fail "harness commit does not contain deploy/mock-provider"
DOCKER_BUILDKIT=1 docker build -t "$TAG_MOCK" -f "$root/deploy/mock-provider/Dockerfile" "$root/deploy/mock-provider" >/dev/null \
  || fail "instrumented mock image build failed (worktree is clean, so this equals the harness-commit source)"
PRE_IMAGE_ID=$(docker image inspect "$TAG_P1" --format '{{.Id}}')
CAND_IMAGE_ID=$(docker image inspect "$TAG_CAND" --format '{{.Id}}')
MOCK_IMAGE_ID=$(docker image inspect "$TAG_MOCK" --format '{{.Id}}')
{ echo "preview1_image_id $PRE_IMAGE_ID"; echo "candidate_image_id $CAND_IMAGE_ID"
  echo "mock_image_id $MOCK_IMAGE_ID"; echo "mock_provider_tree $MOCK_TREE_SHA"; } >> "$IDENTITY"
# Obtain the EXACT immutable postgres images (pull by full reference only);
# record their actual image IDs as identity evidence for both phases.
for pgref in "$pgref1" "$pgref2"; do
  docker image inspect "$pgref" --format '{{.Id}}' >/dev/null 2>&1 \
    || docker pull --quiet "$pgref" >/dev/null \
    || fail "could not obtain the immutable postgres image $pgref (never a convenience tag)"
done
PG1_IMAGE_ID=$(docker image inspect "$pgref1" --format '{{.Id}}')
PG2_IMAGE_ID=$(docker image inspect "$pgref2" --format '{{.Id}}')
{ echo "postgres_image_id_preview1 $PG1_IMAGE_ID"; echo "postgres_image_id_candidate $PG2_IMAGE_ID"; } >> "$IDENTITY"
note "postgres image ids: preview1 ${PG1_IMAGE_ID} candidate ${PG2_IMAGE_ID}"
note "image ids: preview1 ${PRE_IMAGE_ID} candidate ${CAND_IMAGE_ID} mock ${MOCK_IMAGE_ID} (mock tree ${MOCK_TREE_SHA})"

cs PF5
step "preflight: phase .env secrets via the real Preview1 init-env.sh (identical bytes across phases)"
PHASE_ENV_SHA=$(provision_phase_env "$RUNTMP/src-preview1" "$RUNTMP/preview1" "$RUNTMP/candidate") \
  || fail "phase env provisioning failed"
echo "phase_env_sha256 $PHASE_ENV_SHA" >> "$IDENTITY"
note "phase .env installed into both project dirs (mode 600, identical bytes; contents never printed)"

export QS_GATEWAY_PORT="$GW_PORT" QS_ADMIN_PORT="$ADM_PORT" QS_UPSTREAM_URL="http://${MOCK_IP}:8081"

# ================================================================ QS-UPGRADE-P1

case_upgrade() {
  case_start QS-UPGRADE-P1
  {
    echo "record_started_utc $(date -u +%FT%TZ)"
    echo "harness_head $HARNESS_HEAD";
  } > "$RECORD"
  chmod 600 "$RECORD"

  cs UP1
  step "preview1 stack up on the isolated retained volume; ACTUAL view set recorded"
  "${P1C[@]}" up -d --no-build --wait >/dev/null || fail "preview1 up --wait failed"
  wait_healthz || fail "preview1 gateway never became healthy"
  run_image=$(docker inspect "$GW_CONTAINER" --format '{{.Image}}')
  [[ "$run_image" == "$PRE_IMAGE_ID" ]] || fail "preview1 container is not the archived image ($run_image != $PRE_IMAGE_ID)"
  P1_PG_MAJOR=$(assert_pg_runtime p1q up1 "")
  assert_container_image "${PROJECT}-postgres-1" "$PG1_IMAGE_ID" "UP1 preview1 postgres"
  assert_container_image "${PROJECT}-migrate-1" "$PRE_IMAGE_ID" "UP1 preview1 migrate"
  P1_MIGRATE_HEAD=$(p1q "SELECT max(version) FROM schema_migrations")
  [[ -n "$P1_MIGRATE_HEAD" ]] || fail "preview1 schema_migrations empty"
  p1_views=$(view_names p1q)
  printf '%s\n' "$p1_views" > "$VIEWS_P1_SET"; chmod 600 "$VIEWS_P1_SET"
  p1_view_n=$(grep -c . "$VIEWS_P1_SET" || true)
  note "preview1 migrate head $P1_MIGRATE_HEAD; actual managed-view count ${p1_view_n} (recorded as the rollback baseline — shipping views.go does not prove this stack provisioned them)"
  { echo "preview1_migrate_head $P1_MIGRATE_HEAD"
    echo "preview1_view_set_sha256 $(sha_file "$VIEWS_P1_SET")"; } >> "$RECORD"

  cs UP2
  step "seed org1 through the product seed service (real key #1)"
  admin_pw=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
  printf '%s\n' "$admin_pw" > "$RUNTMP/admin-password"; chmod 600 "$RUNTMP/admin-password"
  seed_run "$RUNTMP/protected/seed-org1.out" --admin-email "$ADMIN_EMAIL" --admin-password-stdin \
    --org-name "P1 Recovery One" --model "$ORG1_MODEL"
  key1=$(extract_key "$RUNTMP/protected/seed-org1.out")
  [[ "$key1" =~ ^yb_ ]] || fail "org1 key not minted (transcript sha256 $(sha_file "$RUNTMP/protected/seed-org1.out"))"
  ORG1_ID=$(p1q "SELECT id::text FROM organizations WHERE slug = '$ORG1_SLUG'")
  [[ -n "$ORG1_ID" ]] || fail "org1 slug $ORG1_SLUG not created by seed"
  note "org1 ${ORG1_ID} key1 fingerprint sha256:$(fingerprint "$key1")"
  echo "key1_fingerprint $(fingerprint "$key1")" >> "$RECORD"; echo "org1 $ORG1_ID" >> "$RECORD"

  cs UP3
  step "seed org2 with a distinct org name (real key #2, distinct by construction)"
  seed_run "$RUNTMP/protected/seed-org2.out" --admin-email "$ADMIN_EMAIL" --admin-password-stdin \
    --org-name "P1 Recovery Two" --model "$ORG2_MODEL"
  key2=$(extract_key "$RUNTMP/protected/seed-org2.out")
  [[ "$key2" =~ ^yb_ ]] || fail "org2 key not minted (transcript sha256 $(sha_file "$RUNTMP/protected/seed-org2.out"))"
  [[ "$key1" != "$key2" ]] || fail "keys are not distinct"
  ORG2_ID=$(p1q "SELECT id::text FROM organizations WHERE slug = '$ORG2_SLUG'")
  [[ -n "$ORG2_ID" ]] || fail "org2 slug $ORG2_SLUG not created by seed"
  note "org2 ${ORG2_ID} key2 fingerprint sha256:$(fingerprint "$key2")"
  echo "key2_fingerprint $(fingerprint "$key2")" >> "$RECORD"; echo "org2 $ORG2_ID" >> "$RECORD"

  cs UP4
  step "real request history (explicit request IDs, provider-observed), global-registry routing control and inactive-key denial"
  h=$(mock_hits)
  chat_ok p1q "$key1" "$ORG1_MODEL" qs-p1r-up1-a "UP4 org1 request 1"
  mock_delta_one "$h" "UP4 org1 request 1"
  [[ $(count_req p1q "$ORG1_ID") == 1 ]] || fail "org1 ledger not exactly 1 after the first request"
  h=$(mock_hits)
  chat_ok p1q "$key1" "$ORG1_MODEL" qs-p1r-up1-b "UP4 org1 request 2"
  mock_delta_one "$h" "UP4 org1 request 2"
  [[ $(count_req p1q "$ORG1_ID") == 2 ]] || fail "org1 ledger not exactly 2 after the second request"
  h=$(mock_hits)
  chat_ok p1q "$key2" "$ORG2_MODEL" qs-p1r-up2-a "UP4 org2 request"
  mock_delta_one "$h" "UP4 org2 request"
  [[ $(count_req p1q "$ORG2_ID") == 1 ]] || fail "org2 ledger not exactly 1 after its request"
  # POSITIVE control: both seeded names live in the GLOBAL models_registry,
  # so org1's key requesting ORG2_MODEL is served by global routing (this is
  # not a private-model isolation probe; see global_model_ok).
  global_model_ok p1q "$key1" "$ORG2_MODEL" "UP4 global-registry routing"
  # Inactive-key fixture: minted locally (never used positively), stored
  # through the real api_keys table with the CORRECT hash so only the
  # inactive state can deny it; binding asserted immediately after insert.
  load_inactive_key
  install_inactive_key p1q
  assert_inactive_key p1q "UP4 inactive fixture"
  note "inactive control key fingerprint sha256:$(fingerprint "$key3") id ${INACTIVE_KEY_ID} (active=false; plaintext never printed)"
  denied_key_ok p1q "$key3" "$ORG1_MODEL" "UP4 inactive-key denial"
  run_active_key_negative p1q "$key1" "$ORG1_MODEL" "$RUNTMP/protected/negctl-up4.log" "UP4 active-key negative control"

  cs UP5
  step "fixture rows inserted through preview1's real tables (S3b-frozen shape)"
  FIX_T0=$(p1q "SELECT date_trunc('hour', now())::text")
  [[ -n "$FIX_T0" ]] || fail "FIX_T0 not obtained"
  p1q "DELETE FROM request_logs WHERE org_id = '$FIX_ORG';
DELETE FROM org_custom_models WHERE org_id = '$FIX_ORG';
DELETE FROM organizations WHERE id = '$FIX_ORG';
INSERT INTO organizations (id, name, slug, created_at) VALUES ('$FIX_ORG', 'qs-p1recovery-fixture', 'qs-p1recovery-fixture', '$FIX_T0');
INSERT INTO org_custom_models (org_id, model_name, provider, upstream_url) VALUES ('$FIX_ORG', '$FIX_MODEL', '$FIX_PROVIDER', 'http://fixture.invalid');
INSERT INTO request_logs (id, org_id, model_requested, model_used, status_code, duration_ms, error, created_at, updated_at, request_id, cache_hit_type, user_id, home_region) VALUES
  (987770101, '$FIX_ORG', '$FIX_MODEL', '$FIX_MODEL', 200, 200, NULL, '$FIX_T0'::timestamptz + interval '90 seconds', '$FIX_T0'::timestamptz + interval '90 seconds', 'qs-p1r-fix-1', NULL, '77777777-7777-4777-8777-777777000001', 'qs'),
  (987770102, '$FIX_ORG', '$FIX_MODEL', '$FIX_MODEL', 200, 200, NULL, '$FIX_T0'::timestamptz + interval '150 seconds', '$FIX_T0'::timestamptz + interval '150 seconds', 'qs-p1r-fix-2', 'exact', '77777777-7777-4777-8777-777777000002', 'qs'),
  (987770103, '$FIX_ORG', '$FIX_MODEL', '$FIX_MODEL', 500, 300, 'fixture error', '$FIX_T0'::timestamptz + interval '180 seconds', '$FIX_T0'::timestamptz + interval '180 seconds', 'qs-p1r-fix-3', NULL, '77777777-7777-4777-8777-777777000003', 'qs')" >/dev/null \
    || fail "fixture insert into preview1 tables failed"
  gotfix=$(count_req p1q "$FIX_ORG")
  [[ "$gotfix" == 3 ]] || fail "fixture history [$gotfix] != 3"
  echo "fix_t0 $FIX_T0" >> "$RECORD"

  cs UP6
  step "preview1 ACTUAL behavior baseline recorded: view values, app-role read, ACL, routing"
  view_values p1q "$VIEWS_P1"
  app_read_outcome p1app > "$VIEWS_P1_APP"; chmod 600 "$VIEWS_P1_APP"
  if ! diff <(printf '%s\n' "$FROZEN_VIEW_VALUES") "$VIEWS_P1" >/dev/null; then
    note "preview1 view baseline differs from the frozen candidate values (recorded as-is; rollback must reproduce THIS baseline, whatever it is)"
  fi
  note "preview1 app-role view read outcome: $(cat "$VIEWS_P1_APP")"
  snapshot_acl p1q "$ACL_PRE"
  snapshot_routing p1q "$ORG1_ID" "$ORG2_ID" "$ROUTING_PRE"
  [[ -s "$ACL_PRE" && -s "$ROUTING_PRE" ]] || fail "pre-upgrade snapshots empty"

  cs UP7
  step "protected pre-upgrade backup after stopping fixture writers"
  p1c stop yabanin >/dev/null || fail "could not stop the gateway writer before the frozen snapshot"
  p1c exec -T postgres pg_dump -U yabanin -d yabanin -Fc > "$RUNTMP/protected/pre-upgrade.dump.work" \
    || fail "pg_dump failed"
  mv "$RUNTMP/protected/pre-upgrade.dump.work" "$BACKUP"; chmod 600 "$BACKUP"
  [[ -s "$BACKUP" ]] || fail "backup empty"
  BACKUP_SHA=$(sha_file "$BACKUP")
  snapshot_history p1q "$ORG1_ID" "$ORG2_ID" "$HIST_PRE"
  { echo "backup_sha256 $BACKUP_SHA"; echo "backup_taken_utc $(date -u +%FT%TZ)"
    echo "history_snapshot $HIST_PRE"; echo "acl_snapshot $ACL_PRE"
    echo "routing_snapshot $ROUTING_PRE"; echo "views_baseline $VIEWS_P1"; } >> "$RECORD"
  note "backup sha256 ${BACKUP_SHA} bytes $(stat -c%s "$BACKUP")"

  cs UP8
  step "swap: preview1 down (NO -v; volume retained) -> candidate up on the same volume"
  p1c down >/dev/null || fail "preview1 down failed"
  docker volume ls --format '{{.Name}}' | grep -qx "$RETAINED_VOLUME" \
    || fail "retained volume vanished after down"
  cdc up -d --no-build --wait >/dev/null || fail "candidate up --wait failed"
  wait_healthz || fail "candidate gateway never became healthy"
  run_image=$(docker inspect "$GW_CONTAINER" --format '{{.Image}}')
  [[ "$run_image" == "$CAND_IMAGE_ID" ]] || fail "candidate container is not the archived image ($run_image != $CAND_IMAGE_ID)"
  cand_head=$(cndq "SELECT max(version) FROM schema_migrations")
  [[ -n "$cand_head" ]] || fail "candidate schema_migrations empty"
  assert_pg_runtime cndq up8 "$P1_PG_MAJOR" >/dev/null
  assert_container_image "${PROJECT}-postgres-1" "$PG2_IMAGE_ID" "UP8 candidate postgres"
  assert_container_image "${PROJECT}-migrate-1" "$CAND_IMAGE_ID" "UP8 candidate migrate"
  note "candidate migrate head $cand_head (preview1 recorded $P1_MIGRATE_HEAD)"
  echo "candidate_migrate_head $cand_head" >> "$RECORD"

  cs UP9
  step "frozen identities retained (before any new request); routing + inactive-key denial retained; old keys still work"
  assert_history_retained cndq "$HIST_PRE" "UP9" || fail "frozen request identities not retained across the upgrade"
  snapshot_routing cndq "$ORG1_ID" "$ORG2_ID" "$RUNTMP/protected/routing-post-upgrade.txt"
  diff "$ROUTING_PRE" "$RUNTMP/protected/routing-post-upgrade.txt" \
    || fail "routing rows changed across the upgrade"
  # the revoked state must survive the candidate migrate: full binding intact,
  # the SAME behavioral denial, then the oracle's own expected-negative proof.
  assert_inactive_key cndq "UP9 inactive fixture retained"
  denied_key_ok cndq "$key3" "$ORG1_MODEL" "UP9 inactive-key denial (candidate)"
  n1=$(sed -n 's/^count|org1|//p' "$HIST_PRE"); n2=$(sed -n 's/^count|org2|//p' "$HIST_PRE")
  h=$(mock_hits)
  chat_ok cndq "$key1" "$ORG1_MODEL" qs-p1r-post1-a "UP9 old key1"
  mock_delta_one "$h" "UP9 old key1"
  h=$(mock_hits)
  chat_ok cndq "$key2" "$ORG2_MODEL" qs-p1r-post2-a "UP9 old key2"
  mock_delta_one "$h" "UP9 old key2"
  [[ $(count_req cndq "$ORG1_ID") == $((n1 + 1)) ]] || fail "org1 ledger not exactly backup+1 after one new request"
  [[ $(count_req cndq "$ORG2_ID") == $((n2 + 1)) ]] || fail "org2 ledger not exactly backup+1 after one new request"
  # expected-negative AFTER the exact-count checks: this control adds one
  # real org1 provider hit + ledger row (intentionally accepted here).
  run_active_key_negative cndq "$key1" "$ORG1_MODEL" "$RUNTMP/protected/negctl-up9.log" "UP9 active-key negative control"

  cs UP10
  step "seven managed views with the frozen fixture values (candidate contract)"
  cand_views=$(view_names cndq)
  diff <(printf '%s\n' "$EXP_VIEWS") <(printf '%s\n' "$cand_views") || fail "candidate view set differs from the seven managed views"
  view_values cndq "$RUNTMP/protected/view-values-candidate.txt"
  diff <(printf '%s\n' "$FROZEN_VIEW_VALUES") "$RUNTMP/protected/view-values-candidate.txt" \
    || fail "candidate view values differ from the frozen fixture values"
  appn=$(cndapp "SELECT count(*) FROM beta_dau_daily WHERE org_id = '$FIX_ORG'")
  [[ "$appn" == 1 ]] || fail "app role cannot read the migrated views [$appn]"

  cs UP11
  step "roles/grants/RLS/ownership: nothing from the pre-upgrade snapshot is lost"
  snapshot_acl cndq "$RUNTMP/protected/acl-post-upgrade.txt"
  lost=$(comm -23 <(sort -u "$ACL_PRE") <(sort -u "$RUNTMP/protected/acl-post-upgrade.txt"))
  [[ -z "$lost" ]] || fail "ACL entries lost across the upgrade: $(printf '%s' "$lost" | tr '\n' ';')"
  note "acl pre sha256 $(sha_file "$ACL_PRE") post sha256 $(sha_file "$RUNTMP/protected/acl-post-upgrade.txt") (growth allowed, loss is not)"
  echo "QS-UPGRADE-P1: PASS"
  if [[ "$MODE" == upgrade ]]; then
    note "candidate stack LEFT UP on the retained volume for a possible rollback resume"
    note "a resume needs: QS_RECOVERY_RESUME=1 QS_RECOVERY_KEY1=... QS_RECOVERY_KEY2=... (keys live only in the protected seed transcripts)"
  fi
}

# ================================================================ QS-ROLLBACK-P1

case_rollback() {
  case_start QS-ROLLBACK-P1
  [[ -s "$BACKUP" && -s "$RECORD" ]] || fail "rollback needs the upgrade case's backup and record (run upgrade first)"
  BACKUP_SHA=$(sed -n 's/^backup_sha256 //p' "$RECORD" | head -1)
  ORG1_ID=$(sed -n 's/^org1 //p' "$RECORD" | head -1)
  ORG2_ID=$(sed -n 's/^org2 //p' "$RECORD" | head -1)
  FIX_T0=$(sed -n 's/^fix_t0 //p' "$RECORD" | head -1)
  [[ -n "$BACKUP_SHA" && -n "$ORG1_ID" && -n "$ORG2_ID" && -n "$FIX_T0" ]] || fail "pre-upgrade record incomplete"
  if [[ "$MODE" == "all" ]]; then
    [[ -n "${key1:-}" && -n "${key2:-}" ]] || fail "mode all: the upgrade phase did not mint keys in this invocation"
  else
    key1="${QS_RECOVERY_KEY1:?mode rollback needs QS_RECOVERY_KEY1 (the org1 key minted once in the upgrade run; see the protected seed transcript)}"
    key2="${QS_RECOVERY_KEY2:?mode rollback needs QS_RECOVERY_KEY2 (the org2 key minted once in the upgrade run)}"
  fi
  # the inactive control key is re-read from its 0600 protected file (mode
  # verified before reading; fingerprint checked against the recorded value)
  load_inactive_key

  cs RB1
  step "post-backup marker: one more real org1 request with an explicit awaited request ID"
  MARKER_ID="qs-p1r-marker-$(date +%s)"
  chat_ok cndq "$key1" "$ORG1_MODEL" "$MARKER_ID" "RB1 marker"
  note "marker request_id ${MARKER_ID} (row present pre-restore, must be absent after restore)"

  cs RB2
  step "protected backup verified against the recorded sha256"
  got_sha=$(sha_file "$BACKUP")
  [[ "$got_sha" == "$BACKUP_SHA" ]] || fail "protected backup digest drift [$got_sha] != [$BACKUP_SHA]"

  cs RB3
  step "stop writers; restore into a recreated empty database (documented pg_restore form)"
  cdc stop yabanin >/dev/null || fail "could not stop the gateway writer"
  cdcadm "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'yabanin' AND pid <> pg_backend_pid()" >/dev/null \
    || fail "could not quiesce connections to yabanin"
  cdc exec -T postgres psql -U yabanin -d postgres -v ON_ERROR_STOP=1 -c "DROP DATABASE yabanin WITH (FORCE)" >/dev/null \
    || fail "drop database failed (administered from the postgres database)"
  cdc exec -T postgres psql -U yabanin -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE yabanin OWNER yabanin" >/dev/null \
    || fail "create empty database failed"
  docker cp "$BACKUP" "${PROJECT}-postgres-1:/tmp/restore.dump" || fail "backup copy into container failed"
  cdc exec -T postgres pg_restore -U yabanin --dbname=yabanin --exit-on-error --no-owner --no-acl /tmp/restore.dump \
    || fail "pg_restore of the protected backup failed"
  note "restored without ownership/ACLs; the documented db-app-role boundary re-provisions them at startup (asserted in RB6)"

  cs RB4
  step "candidate down (NO -v); actual preview1 startup on the restored data"
  cdc down >/dev/null || fail "candidate down failed"
  docker volume ls --format '{{.Name}}' | grep -qx "$RETAINED_VOLUME" \
    || fail "retained volume vanished during rollback"
  p1c up -d --no-build --wait >/dev/null || fail "preview1 up on restored volume failed"
  wait_healthz || fail "restored preview1 gateway never became healthy"
  run_image=$(docker inspect "$GW_CONTAINER" --format '{{.Image}}')
  [[ "$run_image" == "$PRE_IMAGE_ID" ]] || fail "restored stack is not the Preview1 image ($run_image != $PRE_IMAGE_ID)"
  P1_MIGRATE_HEAD=${P1_MIGRATE_HEAD:-$(sed -n 's/^preview1_migrate_head //p' "$RECORD" | head -1)}
  P1_PG_MAJOR=${P1_PG_MAJOR:-$(sed -n 's/^pg_up1_server_version_num //p' "$RECORD" | head -1 | cut -c1-2)}
  [[ -n "$P1_PG_MAJOR" ]] || fail "resume: preview1 postgres major missing from $RECORD"
  PG_MAJ=${PG_MAJ:-$(sed -n 's/^postgres_major //p' "$IDENTITY" | head -1)}
  PG1_IMAGE_ID=${PG1_IMAGE_ID:-$(sed -n 's/^postgres_image_id_preview1 //p' "$IDENTITY" | head -1)}
  [[ -n "$PG_MAJ" && -n "$PG1_IMAGE_ID" ]] || fail "resume: postgres identity missing from $IDENTITY"
  assert_pg_runtime p1q rb4 "$P1_PG_MAJOR" >/dev/null
  assert_container_image "${PROJECT}-postgres-1" "$PG1_IMAGE_ID" "RB4 rollback postgres"
  assert_container_image "${PROJECT}-migrate-1" "$PRE_IMAGE_ID" "RB4 rollback migrate"
  rb_head=$(p1q "SELECT max(version) FROM schema_migrations")
  [[ "$rb_head" == "$P1_MIGRATE_HEAD" ]] || fail "restored migrate head [$rb_head] != preview1's [$P1_MIGRATE_HEAD]"

  cs RB5
  step "restored ledger equals the backup-time snapshot BEFORE any new request; marker absent; keys still work"
  n1=$(sed -n 's/^count|org1|//p' "$HIST_PRE"); n2=$(sed -n 's/^count|org2|//p' "$HIST_PRE"); nf=$(sed -n 's/^count|fixture|//p' "$HIST_PRE")
  r1=$(count_req p1q "$ORG1_ID"); r2=$(count_req p1q "$ORG2_ID"); rf=$(count_req p1q "$FIX_ORG")
  [[ "$r1" == "$n1" ]] || fail "org1 ledger [$r1] != backup-time [$n1] BEFORE any new request (marker present?)"
  [[ "$r2" == "$n2" ]] || fail "org2 ledger [$r2] != backup-time [$n2]"
  [[ "$rf" == "$nf" ]] || fail "fixture ledger [$rf] != backup-time [$nf]"
  marker=$(p1q "SELECT count(*) FROM request_logs WHERE request_id = '${MARKER_ID}' AND org_id = '$ORG1_ID'")
  [[ "$marker" == 0 ]] || fail "post-backup marker $MARKER_ID present after restore"
  assert_history_retained p1q "$HIST_PRE" "RB5" || fail "backup-time request identities not restored"
  # the revoked state must ALSO survive backup + restore: full binding intact
  # on the restored preview1 data, and the SAME behavioral denial (zero-delta
  # checks, so the exact ledger counts below remain valid).
  assert_inactive_key p1q "RB5 inactive fixture restored"
  denied_key_ok p1q "$key3" "$ORG1_MODEL" "RB5 inactive-key denial (restored preview1)"
  h=$(mock_hits)
  R1_ID="qs-p1r-rbk1-$(date +%s)"
  chat_ok p1q "$key1" "$ORG1_MODEL" "$R1_ID" "RB5 old key1"
  mock_delta_one "$h" "RB5 old key1"
  h=$(mock_hits)
  R2_ID="qs-p1r-rbk2-$(date +%s)"
  chat_ok p1q "$key2" "$ORG2_MODEL" "$R2_ID" "RB5 old key2"
  mock_delta_one "$h" "RB5 old key2"
  [[ $(count_req p1q "$ORG1_ID") == $((n1 + 1)) ]] || fail "org1 ledger not exactly backup+1 after one validated request"
  [[ $(count_req p1q "$ORG2_ID") == $((n2 + 1)) ]] || fail "org2 ledger not exactly backup+1 after one validated request"

  cs RB6
  step "roles/grants/RLS/ownership + routing + ACTUAL preview1 view baseline reproduced"
  snapshot_acl p1q "$RUNTMP/protected/acl-post-rollback.txt"
  diff "$ACL_PRE" "$RUNTMP/protected/acl-post-rollback.txt" \
    || fail "restored ACL/ownership differs from the pre-upgrade snapshot (the documented bootstrap must re-provision exactly the recorded grants)"
  snapshot_routing p1q "$ORG1_ID" "$ORG2_ID" "$RUNTMP/protected/routing-post-rollback.txt"
  diff "$ROUTING_PRE" "$RUNTMP/protected/routing-post-rollback.txt" || fail "routing rows not restored"
  view_names p1q > "$RUNTMP/protected/view-set-post-rollback.txt"
  diff "$VIEWS_P1_SET" "$RUNTMP/protected/view-set-post-rollback.txt" \
    || fail "view set after rollback differs from preview1's ACTUAL recorded set"
  view_values p1q "$RUNTMP/protected/view-values-post-rollback.txt"
  diff "$VIEWS_P1" "$RUNTMP/protected/view-values-post-rollback.txt" \
    || fail "view values after rollback differ from the recorded ACTUAL preview1 baseline"
  app_read_outcome p1app > "$RUNTMP/protected/view-appread-post-rollback.txt"
  diff "$VIEWS_P1_APP" "$RUNTMP/protected/view-appread-post-rollback.txt" \
    || fail "app-role view-read behavior after rollback differs from the recorded preview1 outcome"

  cs RB7
  step "recovery point recorded"
  {
    echo "recovery_point_backup_sha256 $BACKUP_SHA"
    echo "restored_to preview1 $PREVIEW1_COMMIT image $PRE_IMAGE_ID"
    echo "marker_absent request_id ${MARKER_ID} org1 ledger $r1 == backup-time $n1"
    echo "rollback_completed_utc $(date -u +%FT%TZ)";
  } | tee "$RECOVERY_POINT"
  chmod 600 "$RECOVERY_POINT"

  cs RB8
  step "control NC-R1 (disposable target): corrupt dump fails the restore loudly"
  head -c 2048 "$BACKUP" > "$RUNTMP/protected/corrupt.dump"
  printf 'garbage-not-a-dump' >> "$RUNTMP/protected/corrupt.dump"; chmod 600 "$RUNTMP/protected/corrupt.dump"
  p1adm "CREATE DATABASE qs_nc1_scratch OWNER yabanin" >/dev/null
  docker cp "$RUNTMP/protected/corrupt.dump" "${PROJECT}-postgres-1:/tmp/corrupt.dump" >/dev/null
  if p1c exec -T postgres pg_restore -U yabanin --dbname=qs_nc1_scratch --exit-on-error --no-owner --no-acl /tmp/corrupt.dump >/dev/null 2>"$RUNTMP/protected/nc1.err"; then
    fail "NC-R1: corrupt restore SUCCEEDED — a corrupt backup must never restore"
  fi
  grep -qiE 'error|invalid|corrupt|unexpected' "$RUNTMP/protected/nc1.err" \
    || fail "NC-R1: restore failed but without a visible diagnostic"
  p1adm "DROP DATABASE qs_nc1_scratch WITH (FORCE)" >/dev/null
  note "NC-R1 visible failure: $(head -c 200 "$RUNTMP/protected/nc1.err" | tr '\n' ' ')"

  cs RB9
  step "control NC-R2 (disposable target): restored data without the bootstrap boundary denies app-role reads"
  p1adm "CREATE DATABASE qs_nc2_scratch OWNER yabanin" >/dev/null
  docker cp "$BACKUP" "${PROJECT}-postgres-1:/tmp/nc2.dump" >/dev/null
  p1c exec -T postgres pg_restore -U yabanin --dbname=qs_nc2_scratch --exit-on-error --no-owner --no-acl /tmp/nc2.dump >/dev/null \
    || fail "NC-R2 setup: scratch restore failed"
  if p1c exec -T postgres psql -U yabanin_app -d qs_nc2_scratch -v ON_ERROR_STOP=1 -v VERBOSITY=verbose -tA \
       -c "SELECT count(*) FROM request_logs WHERE org_id = '$ORG1_ID'" >"$RUNTMP/protected/nc2.out" 2>&1; then
    fail "NC-R2: app-role read SUCCEEDED on a target without the bootstrap grants"
  fi
  grep -q '42501' "$RUNTMP/protected/nc2.out" || fail "NC-R2: denial not SQLSTATE 42501: $(head -c 200 "$RUNTMP/protected/nc2.out")"
  note "NC-R2 visible denial on the un-bootstrapped target: $(grep -m1 42501 "$RUNTMP/protected/nc2.out" | head -c 120)"
  p1adm "DROP DATABASE qs_nc2_scratch WITH (FORCE)" >/dev/null
  echo "QS-ROLLBACK-P1: PASS"
}

# ---------------------------------------------------------------- run + teardown

if [[ "$MODE" != rollback ]]; then case_upgrade; fi
if [[ "$MODE" != upgrade ]]; then case_rollback; fi

if [[ "$MODE" != upgrade ]]; then
  step "verdict: retained volume ${RETAINED_VOLUME} kept as evidence (down -v is not rollback)"
  p1c down >/dev/null 2>&1 || cdc down >/dev/null 2>&1 || true
  if [[ "${QS_RECOVERY_PURGE:-0}" == "1" ]]; then
    step "QS_RECOVERY_PURGE=1: removing harness-owned project + volume after recorded verdicts"
    p1c down -v --remove-orphans >/dev/null 2>&1 || true
  fi
fi
echo "QS-RECOVERY: DONE mode=$MODE"

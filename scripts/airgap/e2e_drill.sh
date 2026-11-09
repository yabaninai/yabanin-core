#!/usr/bin/env bash
#
# Proves the package criterion "чистая установка и первый запрос к локальной
# модели без egress" on one docker host:
#
#   Phase A (connected build machine):  build the hardened image + the drill
#     local-model stand-in, push everything a connected host would pull into
#     a local registry, then run scripts/airgap/build_bundle.sh against that
#     registry → yabanin-airgap-<tag>.tar.gz (+ manifest, SBOMs, digests).
#   Phase B (transfer):                 only the bundle tarball (+ the drill
#     local-model tar, clearly marked DRILL-ONLY) cross into workdir/offline.
#   Phase C (air-gap machine):          scripts/airgap/load_bundle.sh —
#     manifest.sha256 tamper check, docker load, retag+push to the offline
#     registry.
#   Phase D (zero-egress run):          docker compose stack on an INTERNAL
#     docker network (no external route, no external DNS): postgres + redis
#     + migrate + local-model + gateway.
#   Phase E (assertions):               while the stack serves on the
#     internal network: external DNS resolution FAILS, external TCP FAILS,
#     and the FIRST request to the local model via the gateway returns 200
#     with the local model's deterministic answer — i.e. the request was
#     served with zero external DNS/network calls (the path does not exist).
#   Phase F (license grace evidence):   the ratified fixed 7-day grace
#     (Active / Expired-degraded / HardExpired, no phone-home) as executable
#     proof via the pkg/license tests.
#
# Local model: the drill uses deploy/mock-provider (OpenAI-compatible
# /v1/chat/completions) as the LOCAL stand-in — same service shape as the
# production vLLM path (deploy/onprem/vllm-*-values.yaml, models_registry
# row 'local-vllm-llama3-70b', provider 'vllm'). A GPU vLLM drill is a
# cluster exercise; see docs/ops/runbooks/airgap-first-request.md.
#
# Limitation (documented, honest): one docker daemon plays both the
# connected and the air-gap machine. The air-gap property is enforced by
# the INTERNAL network in Phase D/E, not by daemon isolation.
#
# Usage: scripts/airgap/e2e_drill.sh [work-dir] [--keep] [--down]
#   --keep  keep containers/network/registry after the drill (debugging)
#   --down  only tear down a previous run and exit
# Evidence: <work-dir>/evidence-drill.txt (every step, PASS/FAIL + exit codes).
set -euo pipefail
cd "$(dirname "$0")/../.."

WORK="${1:-dist/airgap-drill}"
KEEP=0
DOWN_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --keep) KEEP=1 ;;
    --down) DOWN_ONLY=1 ;;
  esac
done

TAG="${DRILL_TAG:-r057drill}"
REG="${DRILL_REGISTRY:-localhost:5001}"
PROJ="yabanin-airgap-drill"
NET="yabanin-airgap-drill-net"
LOCALMODEL_TAR="yabanin-drill-localmodel.tar"
FALLBACK_KEY="${DRILL_FALLBACK_KEY:-drill-egress-key}"
MODEL_NAME="local-vllm-llama3-70b"
HMAC_SECRET="${DRILL_HMAC_SECRET:-$(openssl rand -hex 32 2>/dev/null || echo drill-hmac-secret-not-for-production-use)}"

mkdir -p "$WORK"
evidence="$WORK/evidence-drill.txt"
: > "$evidence"
step() { echo "[$(date -u +%H:%M:%SZ)] $1" | tee -a "$evidence"; }
pass() { step "   PASS: $1"; }
die()  { step "   FAIL: $1"; step "DRILL FAILED — containers kept for debugging (rerun with --down to clean)"; exit 1; }

compose() { docker compose -p "$PROJ" "$@"; }

down_all() {
  if [ -f "$WORK/drill-compose.yml" ]; then
    compose -f "$WORK/drill-compose.yml" down -v --remove-orphans >/dev/null 2>&1 || true
  else
    docker rm -f "$PROJ" >/dev/null 2>&1 || true
  fi
  docker network rm "$NET" >/dev/null 2>&1 || true
  docker rm -f "$PROJ-registry" >/dev/null 2>&1 || true
  step "teardown complete (project $PROJ, network $NET, registry $PROJ-registry)"
}

[ "$DOWN_ONLY" = "1" ] && { down_all; exit 0; }

# Dockerfile.hardened fails the build loudly without SOURCE_DATE_EPOCH (it
# stamps image timestamps for reproducible rebuilds, same recipe as
# scripts/release/release-artifacts.sh): default to the last commit time,
# let an explicit caller value win, reject a non-integer value before any
# docker work starts.
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH=$(git log -1 --pretty=format:%ct 2>/dev/null || true)
fi
case "$SOURCE_DATE_EPOCH" in
  '' | *[!0-9]*)
    echo "FAIL: SOURCE_DATE_EPOCH must be an integer unix timestamp (got: '$SOURCE_DATE_EPOCH')" >&2
    exit 2
    ;;
esac

command -v docker >/dev/null 2>&1 || { echo "FAIL: docker required" >&2; exit 2; }
docker compose version >/dev/null 2>&1 || { echo "FAIL: docker compose v2 required" >&2; exit 2; }
command -v go >/dev/null 2>&1 || { echo "FAIL: go required (license grace evidence)" >&2; exit 2; }
# A08: format-2 bundles must be SIGNED — the installer refuses unsigned new
# bundles, so the drill generates an ephemeral cosign key-pair and installs
# against its public key (never a key found inside the bundle).
command -v cosign >/dev/null 2>&1 || { echo "FAIL: cosign required (A08: load_bundle.sh installs only signed format-2 bundles)" >&2; exit 2; }

step "=== R057 air-gap e2e drill (tag=$TAG registry=$REG work=$WORK) ==="
step "single-daemon simulation: connected vs air-gap roles share one docker daemon;"
step "the zero-egress property is enforced by the INTERNAL network (phase D/E)."

# ---------------------------------------------------------------- Phase A ---
step "A1. offline registry ($REG) as docker container"
if ! docker ps --format '{{.Names}}' | grep -qx "$PROJ-registry"; then
  docker rm -f "$PROJ-registry" >/dev/null 2>&1 || true
  docker run -d --name "$PROJ-registry" -p 5001:5000 registry:2 \
    || die "cannot start registry:2 (connected phase needs docker hub access)"
fi
pass "registry up ($PROJ-registry -> $REG)"

step "A2. build hardened yabanin image (Dockerfile.hardened)"
docker build -q -f Dockerfile.hardened --build-arg "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}" \
  -t "yabanin:$TAG" . >/dev/null || die "image build failed"
for svc in gateway loggerd admin; do
  docker tag "yabanin:$TAG" "$REG/yabanin-$svc:$TAG"
  docker push "$REG/yabanin-$svc:$TAG" >/dev/null || die "push yabanin-$svc failed"
done
pass "built+pushed yabanin-gateway/-loggerd/-admin:$TAG (unified binary, subcommand-selected)"

step "A3. third-party images pinned as in scripts/airgap/images.txt"
docker pull pgvector/pgvector:pg16 >/dev/null || die "pull pgvector failed"
docker pull redis:7-alpine >/dev/null || die "pull redis failed"
docker tag pgvector/pgvector:pg16 "$REG/pgvector/pgvector:pg16" && docker push "$REG/pgvector/pgvector:pg16" >/dev/null || die "push pgvector failed"
docker tag redis:7-alpine "$REG/redis:7-alpine" && docker push "$REG/redis:7-alpine" >/dev/null || die "push redis failed"
pass "pgvector/pgvector:pg16 + redis:7-alpine in registry"

step "A4. drill local-model stand-in (deploy/mock-provider — DRILL-ONLY, not in images.txt)"
docker build -q -f deploy/mock-provider/Dockerfile -t "yabanin-drill-localmodel:$TAG" deploy/mock-provider >/dev/null \
  || die "localmodel build failed"
docker save "yabanin-drill-localmodel:$TAG" -o "$WORK/$LOCALMODEL_TAR" || die "localmodel save failed"
pass "saved $LOCALMODEL_TAR (transferred separately from the vendor bundle)"

step "A5. build_bundle.sh against the local registry (signed inventory manifest, A08)"
# Ephemeral drill key-pair: the PRIVATE key signs on the connected build side
# and never crosses into workdir/offline; only the public key is used on the
# install side as the external trust root for --pubkey.
COSIGN_PASSWORD="${DRILL_COSIGN_PASSWORD:-}"
export COSIGN_PASSWORD
DRILL_KEY_PREFIX="$WORK/drill-cosign"
if [ ! -f "$DRILL_KEY_PREFIX.key" ]; then
  cosign generate-key-pair --output-key-prefix "$DRILL_KEY_PREFIX" >>"$evidence" 2>&1 \
    || die "cosign generate-key-pair failed"
fi
RELEASE_STRICT=0 REGISTRY_PREFIX="$REG/" TAG="$TAG" COSIGN_KEY="$DRILL_KEY_PREFIX.key" \
  bash scripts/airgap/build_bundle.sh "$TAG" "$WORK/bundle" >>"$evidence" 2>&1 \
  || die "build_bundle.sh failed"
BUNDLE_TAR="$WORK/bundle/yabanin-airgap-$TAG.tar.gz"
[ -f "$BUNDLE_TAR" ] || die "bundle tarball missing"
[ -f "$WORK/bundle/manifest.sha256.sig" ] || [ -f "$WORK/bundle/manifest.sha256.sig.bundle" ] \
  || die "bundle has no signed inventory manifest (A08: manifest.sha256.sig/.sig.bundle required)"
pass "bundle built with signed inventory manifest (manifest.sha256.sig; image digests + registry refs signed too)"
step "   bundle: $BUNDLE_TAR ($(du -h "$BUNDLE_TAR" | cut -f1))"

# ---------------------------------------------------------------- Phase B ---
step "B1. transfer simulation: ONLY the bundle + the drill local-model tar cross over"
mkdir -p "$WORK/offline"
cp "$BUNDLE_TAR" "$WORK/offline/" || die "transfer copy failed"
cp "$WORK/$LOCALMODEL_TAR" "$WORK/offline/" || die "transfer copy failed"
rm -rf "$WORK/bundle/yabanin-airgap-$TAG.tar.gz"
pass "offline side receives: $(basename "$BUNDLE_TAR"), $LOCALMODEL_TAR"

# ---------------------------------------------------------------- Phase C ---
step "C1. load_bundle.sh — signed-manifest verification (external --pubkey),"
step "    manifest tamper check + docker load + push to $REG"
# The offline side receives ONLY the bundle; the trust root is the drill
# public key from the connected side (independent channel, C-11).
WORKDIR="$WORK/offline/loaded" bash scripts/airgap/load_bundle.sh \
  --pubkey "$DRILL_KEY_PREFIX.pub" "$WORK/offline/$(basename "$BUNDLE_TAR")" "$REG" >>"$evidence" 2>&1 \
  || die "load_bundle.sh failed (A08 pre-install verification or load step)"
pass "bundle signature+manifest verified, loaded into $REG"

step "C2. load drill local-model into the registry"
docker load -i "$WORK/offline/$LOCALMODEL_TAR" >/dev/null || die "localmodel load failed"
docker tag "yabanin-drill-localmodel:$TAG" "$REG/yabanin-drill-localmodel:$TAG"
docker push "$REG/yabanin-drill-localmodel:$TAG" >/dev/null || die "localmodel push failed"
pass "local-model stand-in loaded"

# ---------------------------------------------------------------- Phase D ---
step "D1. INTERNAL docker network (no external route, no external DNS)"
# Rerun hygiene: tear down any previous drill project first (it holds the
# network; `network rm` alone fails while containers are attached).
if [ -f "$WORK/drill-compose.yml" ]; then
  compose -f "$WORK/drill-compose.yml" down -v --remove-orphans >/dev/null 2>&1 || true
fi
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create --internal "$NET" >/dev/null || die "internal network create failed"
pass "network $NET created with --internal"

step "D2. compose stack (postgres, redis, migrate, localmodel, gateway)"
cat > "$WORK/drill-compose.yml" <<YAML
name: $PROJ
services:
  postgres:
    image: $REG/pgvector/pgvector:pg16
    environment:
      POSTGRES_USER: yabanin
      POSTGRES_PASSWORD: drill-pg
      POSTGRES_DB: yabanin
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U yabanin -d yabanin"]
      interval: 2s
      timeout: 5s
      retries: 60
    networks: [$NET]
  redis:
    image: $REG/redis:7-alpine
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 2s
      timeout: 5s
      retries: 60
    networks: [$NET]
  migrate:
    image: $REG/yabanin-gateway:$TAG
    command: ["migrate"]
    restart: "no"
    environment:
      YABANIN_PG_URI: postgres://yabanin:drill-pg@postgres:5432/yabanin?sslmode=disable
      YABANIN_REGION: onprem
    networks: [$NET]
    depends_on:
      postgres:
        condition: service_healthy
  localmodel:
    image: $REG/yabanin-drill-localmodel:$TAG
    environment:
      MOCK_PROVIDER_PORT: "8081"
    networks: [$NET]
  gateway:
    image: $REG/yabanin-gateway:$TAG
    command: ["gateway"]
    environment:
      YABANIN_PG_URI: postgres://yabanin:drill-pg@postgres:5432/yabanin?sslmode=disable
      YABANIN_REGION: onprem
      YABANIN_REDIS_ADDR: redis:6379
      YABANIN_CACHE_HMAC_SECRET: "$HMAC_SECRET"
      YABANIN_GATEWAY_LISTEN: ":8082"
      YABANIN_FALLBACK_KEY: "$FALLBACK_KEY"
    networks: [$NET]
    depends_on:
      migrate:
        condition: service_completed_successfully
      redis:
        condition: service_healthy
networks:
  $NET:
    external: true
    name: $NET
YAML
compose -f "$WORK/drill-compose.yml" up -d --quiet-pull >>"$evidence" 2>&1 || die "compose up failed"

step "D3. wait for migrate (must exit 0)"
# `compose ps -q` lists only running containers — the one-shot migrate exits
# fast, so --all is required or the id lookup misses it entirely.
mig_id="$(compose -f "$WORK/drill-compose.yml" ps -q --all migrate | head -1)"
[ -n "$mig_id" ] || die "migrate container not found"
mig_ok=0
for _ in $(seq 1 60); do
  read -r st ec <<< "$(docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' "$mig_id" 2>/dev/null || echo starting -1)"
  if [ "$st" = "exited" ]; then
    [ "$ec" = "0" ] && mig_ok=1
    break
  fi
  sleep 2
done
[ "$mig_ok" = 1 ] || die "migrate did not exit 0 (state=$st exit=$ec; docker logs $mig_id)"
pass "migrations applied offline"

step "D4. bootstrap the app role (IMP-88: gateway pools SET ROLE yabanin_app)"
compose -f "$WORK/drill-compose.yml" exec -T postgres psql -U yabanin -d yabanin \
  < deploy/quickstart/bootstrap-app-role.sql >>"$evidence" 2>&1 \
  || die "app-role bootstrap failed (without it the resolver degrades to fallback-only)"
pass "yabanin_app role provisioned (deploy/quickstart/bootstrap-app-role.sql)"

step "D5. enable the local model row + seed the drill identity (install-guide step 6 shape)"
# auth_mode=header with a wired DB resolver is fail-closed for unknown keys,
# so the drill request uses a real api_keys row (sha256 hash) with org,
# team, credits and a team budget — the same objects the admin UI would
# create. All seeded BEFORE the first request: the budget enforcer caches
# a no-budget deny, so seeding after a request would poison the drill.
API_KEY="${DRILL_API_KEY:-drill-$(openssl rand -hex 12 2>/dev/null || echo fixedkey)}"
step "   drill api key: $API_KEY (drill-only credential)"
compose -f "$WORK/drill-compose.yml" exec -T postgres psql -U yabanin -d yabanin -v key="$API_KEY" <<'SQL' >>"$evidence" 2>&1 \
  || die "models_registry/api_keys seed failed"
UPDATE models_registry SET enabled=true, upstream_url='http://localmodel:8081'
  WHERE model_name='local-vllm-llama3-70b';
INSERT INTO organizations (name, slug) VALUES ('drill-org','drill-org')
  ON CONFLICT DO NOTHING;
INSERT INTO organizations_teams (org_id, slug, name)
  SELECT id, 'drill-team', 'drill-team' FROM organizations WHERE slug='drill-org'
  ON CONFLICT DO NOTHING;
INSERT INTO api_keys (key_hash, org_id, name, team_id)
  SELECT encode(sha256(:'key'::bytea),'hex'), o.id, 'airgap drill key', t.id
  FROM organizations o, organizations_teams t
  WHERE o.slug='drill-org' AND t.slug='drill-team' AND t.org_id=o.id
  ON CONFLICT DO NOTHING;
INSERT INTO org_credits (org_id, balance_cents, remainder_micro_usd, reserved_micro_usd)
  SELECT id, 100000, 0, 0 FROM organizations WHERE slug='drill-org'
  ON CONFLICT DO NOTHING;
INSERT INTO team_budgets (team_id, monthly_limit_usd, hard_limit)
  SELECT t.id, 1000, true FROM organizations_teams t, organizations o
  WHERE o.slug='drill-org' AND t.slug='drill-team' AND t.org_id=o.id
  ON CONFLICT DO NOTHING;
SQL
pass "models_registry: $MODEL_NAME -> http://localmodel:8081 enabled; org/team/key/credits/budget seeded"

step "D6. restart the gateway (it started before the role existed and logged"
step "    'resolver will use fallback only')"
compose -f "$WORK/drill-compose.yml" restart gateway >>"$evidence" 2>&1 || die "gateway restart failed"

step "D7. wait for gateway /healthz (in-network probe; published ports do not"
step "    exist on --internal networks — everything stays inside the drill net)"
gw_ok=0
for _ in $(seq 1 60); do
  if docker run --rm --network "$NET" redis:7-alpine wget -qO- -T 3 http://gateway:8082/healthz >>"$evidence" 2>&1; then gw_ok=1; break; fi
  sleep 2
done
[ "$gw_ok" = 1 ] || die "gateway never became healthy (in-network probe)"
pass "gateway healthy on the internal network"

# ---------------------------------------------------------------- Phase E ---
step "E1. zero-egress assertion: EXTERNAL DNS must fail on the drill network"
if docker run --rm --network "$NET" redis:7-alpine nslookup example.com >/dev/null 2>&1; then
  die "external DNS resolved on the internal network — egress isolation NOT proven"
fi
pass "nslookup example.com FAILED (no external DNS path)"

step "E2. zero-egress assertion: in-network DNS still works (isolation, not breakage)"
if ! docker run --rm --network "$NET" redis:7-alpine nslookup gateway >/dev/null 2>&1; then
  die "in-network service DNS failed — the network is broken, not isolated"
fi
pass "nslookup gateway OK (service discovery intact)"

step "E3. zero-egress assertion: external TCP must fail on the drill network"
if docker run --rm --network "$NET" redis:7-alpine wget -T 3 -t 1 -q -O /dev/null http://1.1.1.1/ >/dev/null 2>&1; then
  die "external TCP connect succeeded on the internal network — egress isolation NOT proven"
fi
pass "wget http://1.1.1.1/ FAILED (no external route)"

step "E4. FIRST REQUEST to the local model through the gateway (in-network probe)"
first_body="$WORK/first-request.json"
code="$(docker run --rm --network "$NET" redis:7-alpine wget -qO- \
  --header="Authorization: Bearer $API_KEY" \
  --header="Content-Type: application/json" \
  --post-data="{\"model\":\"$MODEL_NAME\",\"messages\":[{\"role\":\"user\",\"content\":\"first air-gap request\"}],\"max_tokens\":32}" \
  http://gateway:8082/v1/chat/completions 2>/dev/null || true)"
if [ -z "$code" ]; then
  die "first request returned empty body"
fi
printf '%s\n' "$code" > "$first_body"
grep -q "Mock response to: first air-gap request" "$first_body" \
  || die "first request answer is not the local model's deterministic output: $code"
grep -q "\"model\":\"$MODEL_NAME\"" "$first_body" || die "answer does not echo the local model name: $code"
pass "HTTP 200 from gateway -> local model, deterministic answer verified"
step "   body: $code"

# ---------------------------------------------------------------- Phase F ---
step "F1. license grace — ratified FIXED 7-day grace (R057 D1), executable evidence"
step "   posture: Active before expiry; ExpiresAt passed but within 7d -> degraded"
step "   (Expired=true, HardExpired=false, still serves); past 7d -> HardExpired ->"
step "   rate-limited; Verify() is pure offline Ed25519 — no phone-home exists."
if go test ./pkg/license/ -run 'TestVerify_(ValidToken|TamperedPayload_Rejected|ExpiredInGrace_Allowed|HardExpired_Rejected)' -count=1 >>"$evidence" 2>&1; then
  pass "pkg/license grace tests green (7d degraded window, hard-expire rejection)"
else
  die "pkg/license grace tests failed"
fi

step "=== DRILL PASSED: bundle -> load -> first request to a local model, zero egress ==="
step "evidence: $evidence"

if [ "$KEEP" = "1" ]; then
  step "--keep: stack left running (teardown: $0 --down)"
else
  down_all
fi

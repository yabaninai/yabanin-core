# Release evidence (Preview 2)

`scripts/release/release_evidence.py` binds machine-verifiable release facts
to the exact source tree, keeps known gaps as failures, and never produces or
fakes human approval. `scripts/release/dashboard_evidence.py` records the
dashboard asset facts it consumes. Both are stdlib-only and self-contained:
they reuse `scripts/quality/license_check.py` (forbidden markers, source
fingerprint) and consume the quickstart service model from the local Docker Compose CLI.
The config command reads every profile with interpolation and service environment
file resolution disabled. It requires no daemon, running containers or pull.

## What is proven

- **Containers**: every digest-pinned quickstart service image and every
  digest-pinned Dockerfile `FROM` base must have an evidence record keyed by
  that exact index digest, with a bound version and a notice text whose
  SHA-256 is verified and which must not hit any forbidden marker. Redis must
  be the fixed `redis:7.2-alpine` pin resolving to 7.2.17 (BSD-3-Clause,
  upstream `COPYING` SHA-256 `97f0a15b...`); the original restricted 7.4.12
  finding (RSALv2/SSPLv1, both markers forbidden) is retained as a negative
  control and must keep failing. The alpine runtime-base record is bound to
  the committed `scripts/release/image-os-notices` corpus whose MANIFEST pins
  the same index digest; the pgvector extension version is bound to the
  locally pinned upstream `vector.control` bytes (hash-bound against the
  fixed pin) -- the image-filesystem extraction itself stays pending until
  a hash-bound collection record carrying the pinned image's
  index->manifest->config chain is produced by an actual docker run; the distroless
  base of `Dockerfile.hardened` is resolved from the registry with its lack
  of revision metadata recorded as a gap.
- **Assets**: every file under `web/dashboard/dist` is enumerated and hashed
  two-way (missing and phantom entries both fail). Every emitted JS chunk
  must be twin-bound to a sourcemapped build by the map's own relative path:
  the only accepted equivalence is the single final
  `//# sourceMappingURL=<name>` comment line at EOF (exactly one marker in
  the file, nothing after it but one optional trailing LF, restored to the
  code's own trailing LF) - appended payload after that comment, empty
  names, mid-file or missing markers are hard failures, never silently
  stripped. Contributing npm packages are recorded with the legal files
  available in `node_modules`, and lucide-react (ISC, Feather/MIT
  attribution in its LICENSE) is proven present in the chunk graph. The
  `--astra-*` design tokens are bound from `design/astra-tokens.css`
  through the real `@import` in `web/dashboard/src/index.css` into the
  emitted CSS, with exactly one recorded minifier equivalence
  (`--astra-duration: 140ms` emitted as `.14s`); no broad value waiver.
- **Provenance**: every path added since the frozen task base is bound to
  its introducing commit, author and DCO signoff, two-way (missing and
  stale/phantom rows both fail). DCO signoff presence is recorded as a fact
  and is explicitly not proof of employer rights.
- **Distribution**: the five release binaries are bound through
  `dist/release/SHA256SUMS`, and each binary's `image-notices` payload is
  verified exhaustively via its `inventory.json`: the recorded
  `binary_sha256` must equal the actual binary, every listed legal file
  must exist as a regular file confined to the payload directory with a
  matching SHA-256, project `LICENSE`/`NOTICE`, the Go toolchain `LICENSE`
  and linked-module notices are required, and any unlisted payload file is
  rejected (empty payload directories cannot pass). `dist/release/NOTICE`
  must be byte-identical to the current root `NOTICE`, and the
  identifier-only `THIRD-PARTY-NOTICES.md` draft is hash-bound.
- **Dashboard packages**: the contributing package set is bound to the
  sourcemap chunk origins in both directions; each record needs a concrete
  version and at least one hash-bound legal text, and an empty or deleted
  `contributing_packages` array fails.
- **NOTICE**: the root `NOTICE` must carry the Apache-2.0 statement for
  project-authored code exactly once, reference `LICENSING.md`, and contain
  neither the removed `enterprise/LICENSE` reference nor the absent-dated
  D1 wording.

## Freshness and review state

Verification binds HEAD to the HEAD recorded in the evidence itself; an
explicitly passed `--expected-head` is an additional assertion on the same
value, never a substitute for the evidence's own binding (and the
top-level `head`, when retained, must agree with `freshness.head`). There
is no hardcoded acceptance commit, so a reviewed follow-up commit
regenerates the evidence instead of failing forever.
`dist/release/recipe.json` must record the current HEAD *and* its content
sha256 must equal the recorded `distribution.recipe_sha256`, so a recipe
mutation that keeps the commit id still fails; the dirty/untracked source
sets must match the evidence. Acceptance
state requires a clean tree: a verification run on a dirty working
snapshot is labeled `REVIEW-ONLY` and fails. The expected workflow is:
commit first, then build and generate, then verify.

## Known gaps stay failures

A documented gap is not a pass. `verify` reports `PENDING gap: ...` lines
(exit code 1) while any of these remain:

- the quickstart image check requires the engine's OCI index digest for each
  built image and a matching BuildKit provenance receipt. The verifier checks
  the exact commit, platform, effective Compose build context, Dockerfile and
  pinned base images. The same Core receipt covers yabanin, seed and migrate.
  Dashboard and mock-openai each require their own image and receipt. A
  missing build record is pending. A claimed build with missing or mismatched
  receipt bytes fails verification. See [retaining receipts](#retaining-quickstart-build-receipts).
- the actual notice bytes under `/usr/share/licenses/yabanin/` in the built
  Core image are unbound (requires an image-bound content manifest; paths
  are EXACTLY confined -- a sibling directory is not accepted);
- the mock-provider Alpine proof requires the final image's installed APK
  database, delivered notices and matching source companion. The verifier
  replays the selected OCI image layers and checks these inputs against the
  committed mock-provider manifest. Missing proof stays pending. See
  [retaining the mock-provider proof](#retaining-the-mock-provider-proof);
- dashboard npm package notices do not accompany the built output (the
  nginx stage ships `dist/` only; closing requires a product change mapping
  emitted npm code and assets to full notices, including Lucide's ISC and
  applicable Feather-derived MIT attribution). A bound delivery requires
  EVERY contributing package covered, the delivered files INSIDE
  `web/dashboard/dist/`, and each file's bytes equal to the package's
  RECORDED legal-file bytes;
- the pgvector `vector.control` image-filesystem extraction stays pending:
  the local hash-bound observation is recorded, but a bound closure needs
  a hash-bound `extension_collection` record whose collected `image_id`
  equals the pinned image's config digest at the pinned resolution
  platform (`linux/amd64`) -- the generation text keeps the extraction
  claim explicitly pending until then;
- the node/ICU classification stays **open** pending the exact final nginx
  image inspection (see the scope-boundary section below). When that
  inspection CONFIRMS retained occurrences, they are HARD failures, never
  pending;
- the linked module set re-derivation requires a go toolchain on PATH;
  without it the inventory module list stays generator-bound (honest
  PENDING line per binary).

These are required Preview2 blockers and are never reclassified as
out-of-scope. Closing these machine probes is **not exhaustive** for
ownership and distribution of the five host binaries: the human scoped
inventory review remains pending (`reviews` placeholders are not
approvals).

## Preview2 scope boundary

Preview2 acceptance scope is install/provider/request/inspect/recovery;
the acceptance artifact is the standard Compose quickstart plus the five
host binaries. Everything outside that scope is surfaced as an explicit
out-of-scope note or a pending gap, never silently accepted. This boundary
is a scoping fact, not a readiness or approval claim.

- **Out-of-scope, unassessed: `Dockerfile.hardened` distroless metadata
  (machine-bound).** `Dockerfile.hardened` is used by neither the quickstart
  nor the host binaries, so its distroless revision limitation (no revision
  label; LICENSE bound to `GoogleContainerTools/distroless` master at fetch
  time) is surfaced as an `OUT-OF-SCOPE (unassessed)` note rather than a
  Preview2 blocker. The note is not taken from the JSON claim: it is
  reserved for exactly `gcr.io/distroless/static-debian12` and is emitted
  only when the machine basis passes -- every Compose `dockerfile:`
  reference is a standard one (`Dockerfile`, `web/dashboard/Dockerfile`,
  and the `deploy/classifier`/`deploy/mock-provider` files; the quickstart
  builds via `Dockerfile` and `web/dashboard/Dockerfile` today), no Compose
  file references `Dockerfile.hardened`, and the recorded host-binary
  subject set is exactly the five release binaries. Any other repo or an
  unproven basis leaves the pending gap in force and adds an evidence
  integrity failure. The file is kept, its digest pin and notice binding
  remain enforced gates, and no hardened readiness is claimed. The note is
  confined to this quickstart + five-host-binaries acceptance scope, and
  the verifier re-derives its machine basis on every run.
- **Open classification: node builder `LICENSE` (final-image inspection
  pending).** The node stage of `web/dashboard/Dockerfile` is a build
  stage; the nginx runtime stage is a different base and copies only the
  built `dist` tree from it (nginx configs come from the build context).
  The verifier re-derives this source proof on every run
  (`_retention_failures`: node stage not final; every `COPY --from` the
  builder sources only the WORKDIR `dist` tree) plus the emitted-content
  scan (no shipped file may contain a forbidden marker). The proof is
  bound to the explaining context entry's `retained_check`: a
  record-level `retained_check` is not an honored binding (its presence
  is itself a failure), and an unsupported `retained_check` value is a
  hard failure -- never proof of non-retention. **Closure from Dockerfile
  inspection alone is rejected**: a passing source proof keeps the gap
  PENDING until the exact final nginx image is inspected. Closure requires a hash-bound `final_image_check`
  record: the resolved Node builder image and aggregate LICENSE
  path/hash, each exact GPL marker with section boundaries and the
  auxiliary files it covers, marker AND covered-content scans of the
  final image and every layer (including bundled/minified assets, source
  maps, and compressed files where present), the inspected image
  ID/platform, and zero hits. Any retained occurrence is a hard failure;
  an unresolved match keeps the classification open; the validation door
  is never a waiver.

## Review-correction bindings (R2)

The independent review round added these machine bindings; each has an
original false result, a fixed gate, and an isolated negative control in
`test_release_evidence.py`:

- **Compose pulled-service rows.** Each pulled service binds exactly ONE
  effective image and ONE expected operator subject row
  (`_COMPOSE_SERVICE_SUBJECTS`): repository, digest, notice and
  subject-specific checks all bind to that SAME record. A service pointing
  at another subject's pin (pg pulling the exact redis pin) is a
  cross-subject binding and fails; a duplicated or zero-image pulled
  service is ambiguity, not a silent no-op.
- **Candidate-bound final-image scans.** Every `final_image_check` must be
  bound to the candidate's dashboard quickstart subject (self-consistent
  wrapper + manifest agreement alone is not a candidate binding);
  `layers_scanned` entries must be immutable layer digests, and a scan
  covering zero assets for listed layers scanned nothing.
- **Retained build artifacts (sourcemaps).** The canonical retained tree
  `web/dashboard/dist-sourcemaps/` (raw marker-carrying chunk twins plus
  the `.js.map` files) is the binding surface: the receipt's `map_sha256`
  must equal the retained map bytes, recorded `sources` must equal the
  map's own `sources`, the raw twin's hash and strip-to-dist relationship
  are checked in isolation, and nginx still ships `dist/` only.
- **Git-fact parsing.** DCO signoffs come from actual Git trailers (a
  prose "Signed-off-by:" line in a commit body never counts), `dco_present`
  must be a real boolean (string coercion is refused), `git status` XY
  codes are consumed on EITHER column (`RM` fixes the rename parse, copy
  sources are labeled as remaining), and the untracked-source binding
  compares path-to-hash maps so an in-place untracked edit is drift.
- **Delivery and inventory coverage.** npm delivery coverage is per
  package (one package's row cannot stand in for another), notice-payload
  coverage is per linked module (every `inventory.modules` entry needs a
  listed legal file), and the mock-image blocker binds to the record role
  rather than an artifact filename substring.

## Review-correction bindings (R3)

The R3 REQUEST_CHANGES verdict (`astra-r4-release-evidence-r3-verdict`,
SHA256 `8b46db80cb0a23cd5c7832865d8cf061229b496b7d8b5d8d4beb45baffbe53f9`)
required concrete-artifact bindings for ten findings. All are enforced as
verifier gates with isolated negative controls (63 tests; worker-run, Kimi
rerun pending):

1. **Compose pulled-service set and repository**: the effective pulled set
   must be exactly the expected services (a deleted or `build:`-hidden
   service is a failure, not a silently narrowed check) and the Compose
   image's repository (`name[:tag]` before `@sha256:`) must be the expected
   subject -- a foreign repository at a known digest inherits nothing.
2. **pgvector index->manifest->config chain**: the collected
   `manifest.digest` must equal the pinned image digest AND the row's
   `index_digest`, and the manifest's config descriptor must resolve to the
   collected `image_id` -- changing both digests together no longer
   satisfies. The image-filesystem extraction claim stays honestly
   pending (docker run required; no real image evidence was manufactured).
3. **Quickstart candidate binding**: the build record re-derives from the
   tree -- HEAD (`freshness.head`), the tree object
   (`git rev-parse head^{tree}` vs `tree_sha256`), the build inputs
   (`compose_build_services`, `pinned_builders`), and the platform
   (`linux/amd64`) all bind; previous-build image ids copied beside a
   current HEAD fail.
4. **Core notice bytes**: the manifest's own `image_id` must be the Core
   quickstart subject (an agreeing wrapper is not the manifest's
   identity), and every manifest entry sha must be one of the recorded
   core payload inventory hashes with a matching basename.
5. **Final-image inspection**: platform equality vs the dashboard subject
   (an arm64 wrapper+manifest pair is not this amd64 candidate), the
   scanned `layers_scanned` set must equal the build record's dashboard
   layer set, scan inputs must name this tree's dashboard builder pin
   (re-derived from `web/dashboard/Dockerfile`), the aggregate builder
   LICENSE hash and covered files; counts must be actual JSON integers
   (`true` is not a count); CONFIRMED retained hits are HARD failures,
   never pending.
6. **npm delivery**: delivered paths are PurePosixPath-normalized inside
   `web/dashboard/dist/` (`dist/../` escapes are refused even when
   listed), the required package set is DERIVED from the verified map
   `sources` (chunk label lists must agree), and every package legal file
   must be inside the package's own `node_modules/<name>/` directory (a
   lucide-react row naming the clsx license is a wrong-subject binding).
7. **Map/raw twin identity**: the retained raw twin's own
   `sourceMappingURL` comment must name the recorded `map_name`
   (cross-wired identities fail), and a `*.map` inside the public `dist`
   tree is a hard failure even when listed in `dist_files`.
8. **DCO trailer lists**: the evidence's `signed_off_by` list is compared
   to the commit's actual trailer list (full tuple comparison) -- a row
   keeping `dco_present=true` with a lying or blanked list drifts.
9. **git status parsing**: the porcelain stream is read as BYTES
   (surrogateescape decode; no newline translation corrupting CR
   filenames), must end with the final NUL, entries are strict
   `XY<space>path` rows from the porcelain alphabet, and rename/copy rows
   require their original-path field; a refused parse surfaces as a
   failure line, never empty maps accepted as clean.
10. **Modules and mock alpine**: the linked module set is re-derived from
    the binary's build info (`go version -m`; exercised in tests via a
    PATH shim) -- a module deleted from the inventory and payload while
    still linked fails, and without a go toolchain the derivation degrades
    to an honest PENDING line; module legal files are restricted to
    LICENSE/NOTICE/LICENCE/COPYING/COPYRIGHT names; the mock alpine
    record must match the Dockerfile's `FROM alpine:` pin and keep the
    mock role (a laundered role at that pin is a hard failure).

Complexity after R3: worst functions at 15 (`_pinned_service_failures`,
`_pg_collection_identity_failures`, stdlib AST gocyclo-style approximation;
no pinned Python tool exists -- documented policy gap), remaining changed
functions `<= 14`.

## What is NOT claimed

The seven review areas (`python, containers, models, assets, ownership,
enterprise, distribution`) stay `approved=false` with pending placeholders
until a scoped human review records them; the verifier checks review
structure only and never judges approval authenticity.
`license_check.py --release --release-evidence` is therefore expected to
FAIL naming those pending attestations; that failure is separate from
technical verification and must not be bypassed.

## Usage

```bash
# 1. dashboard map build (same inputs -> same chunk hashes as dist/)
cd web/dashboard
npx vite build --outDir <map-root> --sourcemap --manifest

# 2. release artifacts + notice payloads
make licenses-report
RELEASE_DIR=dist/release bash scripts/release/release-artifacts.sh

# 3. evidence
python3 scripts/release/dashboard_evidence.py --map-root <map-root>
python3 scripts/release/release_evidence.py generate
python3 scripts/release/release_evidence.py verify [--expected-head <commit>]

# 4. negative controls (fixture tree; real-repo provenance included)
python3 scripts/release/test_release_evidence.py
```

`--map-root` is required: public product tooling must not depend on
machine-specific paths, and the command above is the reproducible way to
produce it. `generate` must run after all tracked edits (the evidence
records the source fingerprint of the final tree). `verify` re-derives
every fact from the current tree and exits nonzero on any mismatch; only a
clean tree with zero hard failures and zero pending gaps passes.

## Negative controls

`test_release_evidence.py` builds a fixture tree using the real binding
syntax (digest-pinned compose images and Dockerfile bases, inventory.json
notice payloads, twin-bound chunk, design-token CSS including the recorded
`140ms -> .14s` equivalence) and asserts the intact fixture verifies clean
while each defect fails: dropped or restricted notice, redis version or
digest drift, builder pin drift, missing/unbound emitted chunk, appended
bytes after the sourceMappingURL comment, removed astra token, deleted
module notice, stale dist NOTICE copy, inventory sha drift, alpine corpus
MANIFEST drift, quickstart/mock-base gaps, provenance phantom rows, task
base drift, and malformed review structure - plus the R2 families:
cross-subject compose pins, duplicate/zero-image pulled services,
unbound collection image ids, wrong-head or subject-mismatched
quickstart build records, sibling/nested Core notice paths, unknown scan
layers and zero-coverage scans, non-dashboard scan targets, stashed or
partial npm deliveries, wrong-vs-legal delivered bytes, uncovered linked
modules, role-renamed mock inventories, prose DCO lines, string-boolean
DCO rows, RM/copy status rows, and untracked in-place drift - while a
well-formed
`approved=true` record is accepted (authenticity is human scope).

## Retaining quickstart build receipts

Use named local images built from the clean candidate with BuildKit provenance.
For each role (`core`, `dashboard`, `mock-provider`), record the immutable
engine image ID and platform in the existing quickstart evidence. Export that
exact image with `docker image save`. Keep the following five original JSON
blobs from the archive's `blobs/sha256/` directory under
`artifacts/release-evidence/build-receipts/<role>/`. Use the original SHA256
hex filenames, without the digest prefix. Keep these raw receipts local along
with the build evidence; builder metadata can contain local checkout paths.

1. Start at the recorded OCI index. Select the linux/amd64 descriptor and
   keep its platform image manifest.
2. Follow the platform manifest's `config` descriptor and keep the
   image configuration.
3. In the same index, find the attestation manifest whose
   `vnd.docker.reference.digest` is that platform manifest's digest.
   Keep the attestation manifest. BuildKit normally embeds the OCI empty
   configuration in this manifest. If it references an image configuration
   instead, retain that configuration blob as well.
4. Keep its layer with predicate type `https://slsa.dev/provenance/v1`.
   The in-toto statement must name the same platform image as its subject.

For example, `tar -xOf "$archive" "blobs/sha256/$hex" > "$store/$hex"`
copies the original bytes for one selected digest. Run the ordinary
release-evidence verification after recording all three subjects. The
content checks validate the builder records within the captured image.
Approval of the distribution and final source signing remain separate steps.

## Retaining the mock-provider proof

Use the image and BuildKit receipt for the `mock-provider` quickstart role at
the candidate commit. From its original OCI layout, copy the root filesystem
blobs referenced by the linux/amd64 platform image manifest to
`artifacts/release-evidence/mock-provider-proof/layers/`. Keep the original
compressed or uncompressed blob bytes and their SHA-256 hex filenames. Place the
matching Alpine source companion, including its `SHA256SUMS`, under
`artifacts/release-evidence/mock-provider-proof/source-companion/`.

Run the ordinary `release_evidence.py verify --expected-head COMMIT` command.
The verifier resolves the mock-provider image through its retained receipt.
It checks the layer descriptors and uncompressed layer digests, applies
whiteouts, and passes the effective APK database and notice payload to the
same verifier used for local mock-provider images. That verifier checks source
files and notices against the committed manifest. The manual rights review
remains part of the release process.

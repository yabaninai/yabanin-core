# Offline bundle: build, verify and install

This guide documents the current format-2 bundle tooling for an operator
preparing an offline Docker deployment. For Kubernetes, continue with the
[on-prem install guide](install-guide.md). For a first local evaluation, use
the [quickstart](../quickstart.md).

The archive is authenticated through a signature over its inventory manifest.
A successful checksum check alone does not establish who produced it. Obtain
the expected public signing key through a trusted channel independent of the
archive before installing anything.

## What the producer includes

`scripts/airgap/build_bundle.sh` packages the following material:

| Path in the archive | Contents |
|---|---|
| `bundle-info.txt` | Format version, supplied tag, source description and image-entry count |
| `images/*.tar` | Docker images named by the input inventory |
| `images/sbom-*.spdx.json` | Per-image SBOMs when Syft is available |
| `images/image-digests.txt` and signature | Recorded registry digests and their signature |
| `THIRD-PARTY-NOTICES.md`, optional `NOTICE` | Notice materials copied from the release-artifact directory |
| `install/compose/` | Offline Compose profile and app-role bootstrap SQL |
| `install/charts/` | Helm charts and their configuration schemas |
| `models/` | Verified declared model packs, or a marker explaining that none were included |
| `manifest.sha256` and signature | Inventory covering the archive payload and its detached signature or Sigstore bundle |

The bundler does **not** automatically copy the release binaries,
`SHA256SUMS`, or the entire `dist/release` directory. Deliver these separately
when needed, with their own verification materials. It copies the configured
Compose profile verbatim; it does not replace image placeholders for you.

Keep secrets out of the staging directory and custom install materials.
Private signing keys, provider credentials, `.env` files and deployment
passwords must not enter the archive. Review unpacked inputs before signing;
grepping a compressed archive is not a reliable secret check.

## Producer prerequisites

Use a connected build host with Go, Make, Docker, Cosign, Syft and the
repository's release tooling. Supply a signing key you control and complete
the dependency-license review before distribution. Generated notice material
is a draft; it does not replace required license texts or human review.

The bundle builder **pulls every declared image**, saves it and can write
Cosign signatures to the source registry. The producer needs registry read
access and signing/push permissions appropriate to that workflow. Locally
building an image without making it pullable does not satisfy the bundler.

Strict mode (`RELEASE_STRICT=1`) rejects missing signing/SBOM/notice materials.
Although authoring tools have unsigned modes, an unsigned format-2 bundle
cannot satisfy the installer's signature contract. Use the signed path below.

## 1. Prepare the artifacts and image inventory

From the source checkout, choose a version and a build registry you control.
The following values are examples; replace the registry before running:

```sh
export VERSION=v0.1.0-preview.1
export BUILD_REGISTRY=registry.example.com/yabanin-builds
export COSIGN_KEY=/secure/release-signing.key
export SOURCE_DATE_EPOCH="$(git log -1 --pretty=format:%ct)"
make licenses-report
RELEASE_STRICT=1 make release-artifacts

docker build -f Dockerfile.hardened \
  --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
  -t "$BUILD_REGISTRY/yabanin:$VERSION" .
docker push "$BUILD_REGISTRY/yabanin:$VERSION"
```

This builds the unified image used by the Compose `gateway` and `migrate`
commands and by the Helm services. `SOURCE_DATE_EPOCH` is required by the
hardened Dockerfile; reproducibility still requires an independent rebuild
comparison, not just setting that variable.

Use an explicit image inventory to avoid the default inventory's separate
`yabanin-gateway`, `yabanin-loggerd` and `yabanin-admin` names:

```sh
mkdir -p dist/offline-inputs
printf '%s\n' \
  "$BUILD_REGISTRY/yabanin:$VERSION" \
  'pgvector/pgvector:pg16' \
  'redis:7-alpine' > dist/offline-inputs/images.txt
```

Entries with tags are used as written. Untagged entries receive the bundle
version supplied to the script; they do not implicitly become `:latest`.
`REGISTRY_PREFIX`, if set, prefixes every entry, including third-party images.
Leave it empty for this mixed inventory. Review the actual image versions and
scanner results for your delivery; mutable upstream tags are not a permanent
security or reproducibility guarantee.

## 2. Assemble and transfer a signed bundle

```sh
RELEASE_STRICT=1 REGISTRY_PREFIX= \
  IMAGES_FILE="$PWD/dist/offline-inputs/images.txt" \
  scripts/airgap/build_bundle.sh "$VERSION" "dist/airgap-$VERSION"
```

The output is `dist/airgap-$VERSION/yabanin-airgap-$VERSION.tar.gz`.
Without the second argument the staging directory defaults to `dist/airgap`.
Use a fresh staging directory for each delivery.

Optional inputs:

- `MLPACK_PACKS_DIR`: a directory of model-pack subdirectories, each with a
  valid `pack.json`. Every declared pack is verified before copying.
- `AIRGAP_COMPOSE_SRC`, `AIRGAP_BOOTSTRAP_SQL_SRC`, `AIRGAP_CHARTS_SRC`:
  reviewed custom install materials. Missing inputs fail the build.
- `RELEASE_DIR`: directory supplying notice material; default `dist/release`.

Transfer the archive, the matching repository install scripts, and any
separately delivered release binaries through your approved channel. Retain
the source revision used for the tooling. Transfer the trusted public key
independently; a public key found inside the archive is reference material,
not an independently established trust root.

## 3. Verify, load and retain install materials

The install host needs Docker, Docker Compose, Cosign and a reachable offline
registry. Even the Compose path currently requires a registry: the loader
loads **and pushes** every verified image. It has no load-only option.

From the matching source checkout on the offline host:

```sh
export VERSION=v0.1.0-preview.1
export BUILD_REGISTRY=registry.example.com/yabanin-builds
export OFFLINE_REGISTRY=registry.internal.example:5000
export INSTALL_ROOT=/opt/yabanin-offline
scripts/airgap/load_bundle.sh \
  --pubkey /secure/yabanin-release.pub \
  --retain "$INSTALL_ROOT" \
  "/media/yabanin-airgap-$VERSION.tar.gz" "$OFFLINE_REGISTRY"
```

Replace all example locations with your actual paths and registry. The loader
verifies the signed manifest, complete inventory and file hashes before
loading images. It refuses missing signatures, signature mismatches, unlisted
payloads and unsuitable archive paths. `--retain` preserves the verified
`install/` directory at `$INSTALL_ROOT/install`; it does not preserve the
whole extracted archive. Without it the temporary install materials disappear
at exit. Choose an unused destination: existing retained material is not
overwritten.

The loader retains the original image name in the local Docker store. For
registry pushes, it prefixes the offline registry unless the image already
has that exact prefix. Thus this example's unified image is pushed as
`$OFFLINE_REGISTRY/$BUILD_REGISTRY/yabanin:$VERSION`. It does not strip the
build registry from that name. Use that complete repository in Kubernetes.

## 4. Configure and start the offline Compose profile

Keep the retained profile and bootstrap SQL together. Create secrets locally
with restrictive permissions, then provide an override for the two unified
image references. This avoids modifying signed source materials:

```sh
cd "$INSTALL_ROOT/install/compose"
umask 077
cat > .env <<ENV
POSTGRES_PASSWORD=$(openssl rand -hex 16)
YABANIN_CACHE_HMAC_SECRET=$(openssl rand -hex 32)
ENV
cat > images.local.yml <<YAML
services:
  migrate:
    image: $BUILD_REGISTRY/yabanin:$VERSION
  gateway:
    image: $BUILD_REGISTRY/yabanin:$VERSION
YAML

docker compose --env-file .env -f airgap-compose.yml -f images.local.yml config --images
```

Confirm every displayed image exists in the local Docker image store:

```sh
docker compose --env-file .env -f airgap-compose.yml -f images.local.yml config --images |
  while IFS= read -r image; do docker image inspect "$image" >/dev/null || exit 1; done

docker compose --env-file .env -f airgap-compose.yml -f images.local.yml \
  up -d --pull never --no-build

docker compose --env-file .env -f airgap-compose.yml -f images.local.yml ps -a
curl --fail-with-body -sS http://127.0.0.1:8082/healthz
```

The one-shot migration and app-role jobs must exit successfully before the
gateway starts. The profile exposes the gateway on host loopback port 8082;
it does not include the admin console, loggerd, model registration, API-key
issuance or a model server. A healthy gateway is infrastructure verification,
not proof that an authenticated inference works. Complete those deployment
steps before expecting a first model response; see the
[air-gap first-request runbook](../ops/runbooks/airgap-first-request.md).

Persist and back up database data using your deployment's reviewed storage
configuration. This minimal profile is not a complete production backup or
high-availability design. Do not run `down -v` against data you need to keep.

## Model packs

The core verifies model-pack files; it does not download model weights.
Declared packs can be included using `MLPACK_PACKS_DIR` or delivered
separately. A bundle without packs carries `MODELS-UNAVAILABLE.txt`.
`--retain` preserves install materials only: arrange a separately verified
transfer/extraction of `models/` when deploying those packs. Model-serving
containers such as vLLM are operator-supplied and must be included in your
own offline image inventory and deployment configuration.

## Updates, rollback and verification limits

Build each update from an identified source revision, scan it, sign a new
bundle and repeat verification into a fresh install directory. Back up the
database and record the current image/configuration before upgrading. Keep
the previous verified bundle and the corresponding data backup.

Image rollback is safe only when the older application is compatible with
the current schema and persistent data. Forward migrations can require
restoring the pre-upgrade database backup as well as the old image; assess
that compatibility before changing running services.

The manifest binds archive bytes to the trusted signing key. The signed
registry-digest list records the producer's observations; Docker save/load
does not independently reconstruct registry manifests and prove that
correspondence. Container CVE scans, license review, independent rebuilds and
an actual offline inference test remain separate acceptance work.

For deeper artifact checks, `scripts/release/airgap-verify.sh --help` describes
its explicit artifact, image and Compose inputs. Supply the separately
prepared release-artifact directory when checking binaries; it is not
implicitly present in the bundle. A `SKIP` result is not a passed check.
Legacy unsigned archives require the explicit `--allow-legacy-unsigned`
loader option and do not provide signature-based authenticity; that option
never makes an unsigned format-2 archive installable.

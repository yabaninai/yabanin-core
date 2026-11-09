# Kubernetes on-prem installation

Use this guide to install the on-prem Helm chart from a verified offline
bundle. It assumes an existing Kubernetes cluster, a reachable offline image
registry, and operator-managed storage and network policy. The
[offline bundle guide](offline-bundle.md) covers image preparation, signing
and the simpler Docker Compose path.

## Prerequisites

- A healthy cluster, Helm 3, `kubectl`, and sufficient capacity for the chart's
  configured replicas and resource requests.
- A suitable StorageClass for the bundled PostgreSQL volume, or an external
  PostgreSQL deployment with backups.
- An offline registry reachable and trusted by **every node's container
  runtime**. A registry on the jump host's `localhost` is not node-local on
  the cluster; checking it only from the jump host is insufficient.
- The matching source checkout or install scripts, the signed archive, and a
  release public key obtained through an independent trusted channel.
- Any model-serving images and weights required for your inference workload.

The core is Apache-2.0. A vendor-issued license token is not a prerequisite
for the core's Apache rights. Configure a separate license only if your
chosen distribution explicitly requires one; do not infer that requirement
from the chart's optional license fields.

## 1. Verify the bundle and load the registry

Use the same version and build-registry values used to create the bundle:

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

Replace the examples with real addresses and paths. The loader verifies the
signature and complete inventory before loading. `--retain` keeps verified
charts under `$INSTALL_ROOT/install/charts/`; without it the temporary tree
is deleted. The loader prefixes the offline registry to the full original
image name. For the inventory in the offline guide, the unified repository
is `$OFFLINE_REGISTRY/$BUILD_REGISTRY/yabanin`.

Ensure node runtimes can pull the exact unified, PostgreSQL and Redis images.
Configure registry certificates, credentials and image-pull secrets according
to your cluster. Local Docker credentials on the jump host do not configure
Kubernetes nodes.

## 2. Prepare values and secrets

The chart can create Secrets from inline values, or reference existing
operator-managed Secrets. It supports three independent references:

| Value | Existing Secret keys |
|---|---|
| `secrets.existingSecret` | `pg_uri`, `pg_password`, `cache_hmac_secret`, `encryption_key`, `session_key` |
| `kms.existingSecret` | `kek` |
| `license.existingSecret` | `license` |

When an existing Secret is selected, leave the corresponding inline fields
empty; the chart rejects ambiguous sources. Creating a Secret with the
chart's generated name without selecting the existing-Secret mode can cause
a Helm ownership conflict.

For a new evaluation deployment with bundled PostgreSQL and Redis, create a
protected values file. Preserve this file securely for future upgrades:

```sh
umask 077
cat > onprem.local.yaml <<YAML
image:
  repository: $OFFLINE_REGISTRY/$BUILD_REGISTRY/yabanin
  tag: $VERSION
postgres:
  image: $OFFLINE_REGISTRY/pgvector/pgvector:pg16
redis:
  image: $OFFLINE_REGISTRY/redis:7-alpine
secrets:
  pg_password: "$(openssl rand -hex 16)"
  cache_hmac_secret: "$(openssl rand -hex 32)"
  encryption_key: "$(openssl rand -hex 32)"
  session_key: "$(openssl rand -hex 32)"
  kek: "$(openssl rand -hex 32)"
YAML
```

Do not regenerate the database password on upgrade: it must remain consistent
with the initialized volume. Inline secrets also become part of Helm release
state; use existing Secrets when your secret-management process requires it.
`cache_hmac_secret` must be hexadecimal. For external PostgreSQL, set
`bundled.postgres=false` and provide the appropriate `secrets.pg_uri` instead
of relying on the bundled database's generated connection string.

Review the chart values for storage, replica counts, ingress/TLS and egress
policy. Rendering a chart does not prove its NetworkPolicies are enforced by
your cluster's networking implementation.

## 3. Install in the correct namespace

```sh
export CHART="$INSTALL_ROOT/install/charts/yabanin-onprem"
umask 077
helm template yabanin "$CHART" --namespace yabanin \
  -f "$CHART/values-airgap.yaml" -f onprem.local.yaml > rendered.local.yaml
chmod 600 rendered.local.yaml

helm install yabanin "$CHART" --namespace yabanin --create-namespace \
  -f "$CHART/values-airgap.yaml" -f onprem.local.yaml
```

The rendered file contains Secret data; handle it as confidential. Use
`image.repository`, not `image.registry`. Override all three image sources
as shown so cluster nodes do not try to fetch PostgreSQL or Redis from a
public registry.

A post-install migration Job bootstraps the application role and applies
migrations. Check failed Jobs before investigating application pods. The
chart also has upgrade hooks; review backup and migration compatibility
before running `helm upgrade`.

## 4. Verify infrastructure and first inference

```sh
kubectl -n yabanin get pods,jobs,pvc
kubectl -n yabanin rollout status deployment/yabanin-gateway --timeout=180s
kubectl -n yabanin port-forward service/yabanin-gateway 18082:8082
```

Keep port-forward running. In another terminal:

```sh
curl --fail-with-body -sS http://127.0.0.1:18082/healthz
```

Expect a successful health response. This is not an authenticated inference
test. Register the actual model-serving endpoint, configure its reachable
upstream address/allow-list, and issue a gateway key for the intended
organization. Then follow the
[air-gap first-request runbook](../ops/runbooks/airgap-first-request.md).
Local-model weights and serving containers must already be available;
changing an `enabled` database flag does not install them.

## Troubleshooting

| Symptom | Check |
|---|---|
| `ImagePullBackOff` | Verify the complete image name, node registry trust/authentication, and that the image was pushed. |
| Secret ownership conflict | Use the `existingSecret` references or let Helm create the Secret; do not mix ownership modes. |
| `invalid cache_hmac_secret` | Supply the same valid hexadecimal cache-signing secret to the services that share Redis. |
| `role "yabanin_app" does not exist` | Inspect the migration/bootstrap Job logs and database connectivity. |
| PVC remains pending | Check StorageClass, access mode, capacity and node constraints. |
| PostgreSQL authentication failure after upgrade | Compare the preserved Secret with the password in the existing database; do not replace credentials blindly. |
| Health passes but inference fails | Check model registration, gateway authentication, upstream reachability/allow-list and provider credentials separately. |

Complete the [air-gap checklist](airgap-checklist.md) and record actual
inference, restart, backup and restore results for your deployment. These
instructions are not a claim that your cluster has passed those checks.

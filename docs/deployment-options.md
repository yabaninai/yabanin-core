# Deployment options

Yabanin runs where you put it. The gateway controls configured traffic;
where inference runs depends on the model endpoints you configure.

## Choose a path

| If you want | Read | First run looks like |
|---|---|---|
| A localhost stack on one machine | [quickstart](quickstart.md) | explicit timestamped build, startup, seed, and smoke check; ports on `127.0.0.1` |
| Docker/compose on a machine with no network | [offline bundle](onprem/offline-bundle.md) | verify checksums, signature, SBOM and image digests, `docker load`, minimal compose |
| Kubernetes/Helm in an air-gapped cluster | [install guide](onprem/install-guide.md) + [air-gap checklist](onprem/airgap-checklist.md) | `load_bundle.sh --pubkey …` (trust root pinned before the bundle), then `helm install` |
| To try before installing | [public stand](ops/public-stand.md) | an operator-managed stand at `https://yabanin.ai/gw/v1` |
| Day-2 operations | runbooks: [upgrade/rollback](runbooks/onprem-upgrade.md), [backup/restore rehearsal](runbooks/backup-restore-rehearsal.md), [production](runbooks/production.md) | `helm upgrade` pre-flight, quarterly restore drill, ops procedures |

## Local-only configuration

Use local inference (e.g. llama.cpp behind the gateway) when the workload
must stay inside your chosen environment. Verify network rules and the
full dependency chain — including tools, telemetry, logs and backups.

See: [air-gap checklist](onprem/airgap-checklist.md).

## Approved-cloud configuration

Run Yabanin in your VPC or on premises and configure approved external
inference routes (OpenAI-compatible providers). Review provider terms and
data settings for each enabled service and feature.

See: [install guide](onprem/install-guide.md).

## Verify before you run

Verify the inputs for your chosen installation path:

- the quickstart builds from your checkout, so you verify the checked-out
  release commit first ([quickstart](quickstart.md), "Obtain and verify the source");
- the offline paths verify checksums (`manifest.sha256`), the cosign
  signature of the inventory manifest against a trust root obtained
  **independently of the bundle**, the SBOM and per-image digests — before
  `docker load`, `helm install` or the first container start
  ([offline bundle](onprem/offline-bundle.md), [install guide](onprem/install-guide.md));
- a published image or bundle whose configuration you cannot verify (signature
  skipped without a recorded disclosure) must not be installed.

## The boundary

Self-hosting the gateway does not turn external inference into local inference. Both
configurations require secure installation and ongoing operation. For the
data-handling questions to answer before expanding, see the
[agent readiness checklist](agent-readiness.md).

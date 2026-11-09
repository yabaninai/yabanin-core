# Deployment checklist for an operator-managed instance

The public core includes a localhost development stack, container build sources,
Helm charts and on-premises packaging tools. It does **not** include a turnkey
public-VPS production Compose stack. This checklist describes the work needed to
operate an internet-accessible instance; it is not a claim that the local
quickstart is production hardened.

For a reproducible first request, follow [Quickstart](../quickstart.md). For a
Kubernetes installation, follow the [on-premises installation guide](../onprem/install-guide.md).
For day-two operations, use [Production operations](production.md).

## 1. Establish the deployment inputs

Record the source commit, image digest, target architecture, configuration revision,
PostgreSQL and Redis versions, enabled features and external dependencies. Verify
release signatures/provenance according to the release artifacts available to you.
An image label or matching commit hash alone is not proof of publisher identity.

Size the machine from a representative workload. The local mock stack does not
measure provider latency, large histories, concurrent streams, embedding models,
or background processing under production load. Keep data services on persistent
storage with capacity and disk-pressure monitoring.

Choose explicitly:

- A private database and Redis network; only the edge should accept public traffic.
- Separate migration/backup credentials and the least-privileged application role.
- A TLS edge, stable public API origin, and same-origin dashboard/admin routing.
- An immutable application image and a separately built dashboard artifact.
- A secret store or protected mounted secret files, with a backup/rotation owner.
- Provider routes, allowed egress destinations, organization limits and retention.

## 2. Prepare secrets and state

Generate independent session-signing, cache-HMAC and data-encryption secrets.
Consult [Security](../security.md) and [Secret rotation](../ops/secrets-rotation.md)
for their distinct purposes. Retain the encryption material required to decrypt
persisted credentials; replacing a key without a migration can make data unusable.

The quickstart's database passwords and mock provider are development settings.
Do not expose that configuration as a production service. Keep secrets out of
shell history, committed values files, logs and build contexts. Configure TLS and
certificate verification for remote database connections.

Apply migrations with the application's migration runner under a controlled
migration role. Use the version's supported bootstrap to establish the application
role and grants. Do not execute a glob of SQL files: the migration tree contains
both forward and rollback scripts. Confirm migration completion before starting
application replicas.

## 3. Deploy the application and dashboard

Use your reviewed deployment manifests or the documented Helm route. Build the
unified image with the required reproducibility argument when building from source:

```bash
docker build \
  --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
  -t yabanin:local .
```

The unified image accepts runtime service commands such as `gateway`, `admin`,
`loggerd`, and `migrate`; see [Developer guide](../DEVELOPMENT.md). The local `dev`
command runs multiple services together and is the quickstart topology.

Build dashboard assets separately with the Node version required by its package:

```bash
npm ci --prefix web/dashboard
npm run build --prefix web/dashboard
```

Serve `web/dashboard/dist` through your static server. Route `/api` and `/auth` to
the admin service on the same public origin. Port 8086 alone is not the dashboard.
Configure SPA fallback and check a deep-link refresh. Follow [DNS and TLS](../ops/dns-setup.md)
for an edge reference. Supply the actual public admin origin and, where enabled,
SSO callback URLs.

## 4. Bootstrap access and configure an upstream

Use the seed flow appropriate to the chosen deployment and keep its one-time
secrets in a password manager. An organization gateway API key is distinct from
an admin password, session cookie, and the optional internal-service key.

Start with a controlled test organization. Configure a registered model route and
an eligible credential; a credential alone does not create a model. Follow [BYOK](../byok.md)
for endpoint validation and key selection. Set organization budgets, team limits
and permitted models before giving users access. Rotate or revoke bootstrap keys
that are no longer needed.

## 5. Accept the running deployment

Record actual results, not only that containers started:

| Boundary | Required observation |
| --- | --- |
| TLS and edge | Valid certificates, expected hostnames, private ports inaccessible externally |
| Gateway | Health succeeds, unauthorized inference rejected, authorized model listing works |
| Inference | A permitted model returns a valid response; streaming terminates correctly |
| Provider credentials | Controlled authenticated upstream confirms intended credential selection |
| Admin/dashboard | Login, protected API, organization selection and logout work |
| Tenant boundary | A test key cannot read or change another organization's resources |
| Persistence | Request history appears; restart preserves expected state and keys |
| Failure | Invalid/revoked key, unavailable upstream and exhausted budget produce expected errors |
| Monitoring | Targets scrape successfully and a synthetic alert reaches its intended receiver |
| Recovery | Disposable restore succeeds and application checks pass against restored state |

A health response alone is not inference acceptance. A mock reply is not a live
provider test. Do not run disruptive rate-limit or failover drills against shared
users without a scheduled test window and isolated fixtures.

## 6. Establish operations before opening access

Use [Alert delivery](alerts.md) to configure and test notifications. The shipped
Alertmanager file contains placeholders; the public export supplies no automatic
production rendering/deployment for it. Set backup frequency from your recovery
objectives and execute the [restore rehearsal](backup-restore-rehearsal.md).

Keep a deployment record containing image/configuration versions, migrations,
acceptance evidence, rollback compatibility, on-call contact and outstanding
limitations. Updates need the same checks on the new state. A one-container
restart interrupts requests; zero-downtime updates require replicas, traffic
draining and a tested rollout strategy.

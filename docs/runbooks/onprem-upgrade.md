# On-prem upgrade runbook

## Prepare

Choose a specific release, verify its artifacts and review its migration and
configuration changes. Keep the previous image, configuration and a tested
PostgreSQL backup. Confirm backup storage capacity and arrange a maintenance
window when the change cannot tolerate mixed application versions.

A successful `/healthz` response is a process-health check; it does not validate
license files, migration compatibility or recoverability.

## Upgrade with Helm

Use the on-prem chart with values for your actual database, registry, secrets and
backup volume. Inspect the rendered hooks before applying an upgrade. The chart
includes pre-upgrade backup, post-upgrade migration and rollback restoration jobs;
their success depends on the configured credentials, storage and images.

```bash
# Set RELEASE_TAG to the release you have verified and loaded into your registry.
: "${RELEASE_TAG:?Set the verified release tag}"
helm upgrade yabanin deploy/helm/yabanin-onprem \
  -f deploy/helm/yabanin-onprem/values-airgap.yaml \
  --set-string image.tag="$RELEASE_TAG"
```

Check hook completion, migration status, readiness, an authenticated gateway
request and request-history persistence. Multiple replicas alone do not guarantee
zero downtime: database changes, session storage and readiness behavior also matter.

## Roll back

Inspect `helm history yabanin` and select the intended revision. Before using
`helm rollback`, review the chart's post-rollback restore job and the backup it
will select. Restoring an older database can discard writes made after that
backup. Stop writers and coordinate recovery when database restoration is needed.

Keep the image and database schema compatible. Reverting only an image does not
reverse a migration. Rehearse the complete backup and restore procedure on a
separate database before relying on it in production.

## Migration discipline

Use the migration runner from the same source version as the application. Do not
apply migration SQL manually or rewrite the migration tracking table to bypass an
error. Investigate the applied schema and recover from a verified backup when
necessary. Prefer additive changes for rolling upgrades; destructive changes need
an explicit compatibility and recovery plan.

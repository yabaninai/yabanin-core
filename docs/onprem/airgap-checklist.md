# Air-gap installation checklist

Record the source revision, bundle version, operator, date and evidence for
each check. A skipped check is not a passed check. Start with the
[offline bundle guide](offline-bundle.md) or
[Kubernetes install guide](install-guide.md).

## Infrastructure

- [ ] Cluster or Docker host is healthy and has the required CPU, memory and storage.
- [ ] Every node runtime can pull the exact images from the offline registry using its configured trust and credentials.
- [ ] Persistent storage and backup/restore procedures are configured for PostgreSQL.
- [ ] Required GPU drivers, serving images and model weights are already present, if applicable.

## Trust and artifacts

- [ ] Public signing key was pinned through a channel independent of the archive.
- [ ] Format-2 inventory signature verifies against that pinned key.
- [ ] Every archive payload is listed in the manifest and its checksum matches; `load_bundle.sh` verification passes before image loading.
- [ ] Container and dependency scan results correspond to these exact artifacts; unresolved findings are documented and assessed.
- [ ] Required SBOMs, notices and third-party license texts accompany the delivery.
- [ ] The reviewed image inventory matches the rendered Compose/Helm configuration, including PostgreSQL and Redis.
- [ ] Verified install materials are retained in a durable directory; any model packs are separately retained and verified.

## Secrets and configuration

- [ ] Database password, session secret, encryption key and hexadecimal cache HMAC secret are generated on the install side and stored securely.
- [ ] Existing Secret references and inline values are not mixed for the same chart secret group.
- [ ] Secrets are absent from the transferred archive and ordinary logs.
- [ ] Namespace, image repositories/tags, storage and upstream allow-list are correct.
- [ ] License requirements are checked for any separately licensed distribution; no vendor token is assumed necessary for Apache-2.0 core rights.

## Network and workload

- [ ] Egress restrictions are enforced by the actual host/cluster networking implementation.
- [ ] Internal DNS, database, Redis and approved model endpoints remain reachable under those restrictions.
- [ ] External DNS/HTTPS and unapproved destinations are denied in an observed test.
- [ ] Migration/bootstrap jobs succeed and application workloads become healthy.
- [ ] An authenticated request to a registered offline model returns the expected result.
- [ ] Expected request history, policy and lineage behavior are checked for the enabled configuration.
- [ ] Restart recovery and backup restoration have been exercised; upgrade and rollback compatibility are recorded.

# Multi-region deployment boundaries

Yabanin includes regional database context, organization region assignments,
peer-health/failover policy components and an optional analytics rollup shipper.
These components do not provision an active-active deployment. The public export
does not include a Cloudflare edge worker or regional Terraform infrastructure.
This page explains the implemented boundaries and the integration work required
before relying on regional routing.

## Region identifiers and database isolation

`gateway.region` is a short deployment identifier, such as `sg`; `home_region` is
a country label used in lineage, such as `SG`. Neither proves a machine's physical
location. A `gateway.regions` map describes peer country labels, gateway URLs and
priorities. With an empty map, the gateway runs without the regional failover
evaluator.

Production database pools use `pkg/regionrouter.ConfigurePool`: each connection
assumes the non-owner `yabanin_app` role and sets PostgreSQL `app.region`. Regional
RLS policies use that context on the tables to which they are attached. The
organization mapping is stored in `org_home_region` and cached in Redis.

RLS is a database access control, not a promise that all data remains inside a
country. Verify the applied policies and role grants, physical database/storage
placement, backups, provider routes, logs, analytics exports and operator access.
A privileged backup/migration role has a different boundary from the application.
Do not use a table owner or superuser to test the application's isolation.

## Routing behavior and limits

The region router caches successful assignments for 60 seconds. Its current
runtime lookup falls back to `sg`, unpinned, when a mapping is missing **or the
lookup fails**; do not treat this default as an authoritative residency answer.
The admin region-read API separately returns 503 on a store failure and returns
the default only when there is no assignment row.

The failover evaluator considers pinning, peer health, priority and, when wired,
per-organization egress policy. Pinned assignments do not gain an alternate-region
fallback. Policy-denied peers remain excluded even when the home region is down.

**The current gateway does not implement an automatic HTTP 307 redirect or proxy
to the selected regional peer.** Its region middleware turns evaluator errors,
including redirect-shaped decisions, into `503 region_unavailable`. An external
edge or client routing integration must be designed and tested separately; the
presence of a peer map is not evidence of working cross-region failover. Routing
a request elsewhere also does not copy the organization's database state.

The administration surface includes `GET/PUT /api/organizations/{id}/region` with
`home_region` and `residency_pinned` fields. Use authorized admin sessions and CSRF
protection for mutations. Verify propagation across running gateways; a successful
update alone does not prove all cached readers have adopted it.

## Configuration reference

This example describes peer metadata, not a complete installation or secret set:

```yaml
gateway:
  region: sg
  home_region: SG
  kms_provider: local
  regions:
    sg:
      name: sg
      country: SG
      gateway_url: https://sg-api.example.com
      priority: 1
    eu:
      name: eu
      country: DE
      gateway_url: https://eu-api.example.com
      priority: 2
```

Use actual reachable endpoints and validate network/TLS policy. Configure each
service's database, Redis, secrets and region consistently. The gateway factory
supports `local`; `FileKMS` exists as a library implementation but is not a
selectable `file` provider in that factory. `aws` is a fail-closed placeholder.
See [Security](security.md) for key handling.

The `deploy/helm/yabanin` chart renders configuration from its `gateway` values.
Review rendered manifests and the values schema before installation. Historical
`values-sg.yaml`, `values-in.yaml` and `values-eu.yaml` files are sketches; their
`env` map is not a substitute for the chart's `gateway.region` and
`gateway.home_region` settings. The [on-premises guide](onprem/install-guide.md)
provides the separate on-premises installation workflow. Neither chart provisions
a cross-region control plane, data replication, or an external edge router.

## Optional analytics export

When `loggerd.replication_endpoint` is set and PostgreSQL is available, loggerd
attempts to aggregate and ship the previous day's request counts and token totals.
The implementation starts a 24-hour ticker with the process; it is not aligned
to midnight and is not a durable catch-up scheduler. The shipper posts JSON to
`<endpoint>/internal/rollup-ingest`, with up to three attempts per batch.

Rows include region, day, model and an eight-hex-character SHA-256 prefix of the
organization ID. This is pseudonymization, **not k-anonymity or proof of anonymous
data**. Small buckets and known identifiers may still reveal organization
activity. The current aggregation does not populate `total_cost_usd`; a zero in
that field is not measured zero spend.

The shipper does not attach an application authentication credential. A compatible,
access-controlled receiver, transport protections, retention policy and replay/
deduplication behavior are operator responsibilities. Leave replication disabled
until those boundaries and the intended cross-region data transfer are verified.
The export does not replicate request bodies or make a second region ready to
serve an organization's traffic.

## Acceptance before regional use

Test in disposable regional environments with synthetic organizations:

1. Verify each service's region context and least-privileged RLS reads/writes.
2. Establish a mapping and confirm the actual routing behavior from every entry
   point, including cold caches, expired entries and database/Redis failure.
3. Make one peer unavailable; record behavior for pinned and unpinned assignments,
   policy-denied peers and no-healthy-peer cases. Confirm forbidden egress is absent.
4. Test recovery and assignment changes, including cache propagation and stale
   readers. Keep request IDs and region decisions in the evidence.
5. If analytics shipping is enabled, verify receiver authentication boundaries,
   payload scope, retries, duplicate handling and restart/missed-day behavior.
6. Restore a regional backup with the necessary encryption keys and verify that
   application access stays scoped to that region.

The historical `scripts/chaos_drill.sh` is not a validated executable acceptance
suite: it contains placeholder simulation steps and must not be cited as proof
of an actual region outage or successful failover. Use deployment-specific fault
injection and assert both successful recovery and prohibited cross-region paths.
See [Region-down response](runbooks/region-down.md) for adjacent operational context.

---
title: Jurisdictional Lineage Attestation
description: Per-request Signed request records with model, region evidence and log jurisdiction.
sidebar_position: 5
---

# Jurisdictional Lineage Attestation

Per-request signed claims about the model, region evidence and log jurisdiction.
Verification establishes integrity of the recorded claim; it does not independently establish the physical location of inference.
Ed25519-signed. Append-only, tamper-evident ledger.

## Architecture

```
Gateway:
  ┌─ RegionResolver ─→ header evidence / pinned endpoint → ISO-3166 region + evidence tier
  ├─ KeyStore ───────→ EnsureKeyPair(orgID) → Ed25519 keypair (AES-GCM encrypted)
  ├─ AsyncLedger ───→ Insert signed attestation into lineage_outbox
  ├─ Outbox relay ──→ Append chained row to request_lineage
  └─ EventPublisher ─→ InferenceRegion, ModelOriginCountry, LogStorageRegion,
                        ProviderEntityJurisdiction, AttestationHash, Signature, KeyID

Loggerd:
  └─ Consumer ───────→ Persists request-log events; separate from the lineage outbox

Admin API:
  GET  /api/lineage/{request_id}        → attestation JSON
  POST /api/lineage/{request_id}/verify → {valid: bool}
  GET  /api/organizations/{id}/lineage  → recent attestations
```

## Cryptography

- **Algorithm:** Ed25519 (stdlib `crypto/ed25519`)
- **Hash target:** hex SHA-256 of canonical attestation JSON (`json.Marshal` of struct)
- **Key storage:** new production private keys require configured AES-GCM
  encryption (`enc:` prefix). Legacy plaintext rows remain readable and are
  migrated when an encryptor is configured. Development/test configurations
  can explicitly allow plaintext writes.
- **Determinism:** canonical JSON uses the attestation struct field order;
  identical field values under the same schema produce identical signing bytes.

## Evidence tiers (what the region field actually proves)

`inference_region` in the attestation is graded. The attestation carries the
tier it was resolved at (`region_evidence`), so a reviewer never has to guess
how strong the claim is:

| Tier | Meaning | Example |
|---|---|---|
| `endpoint_pinned` | The destination endpoint itself encodes the region — the gateway *sent* the request to a region-specific resource and records that fact | self-hosted vLLM/llama.cpp; Azure OpenAI Japan East; Bedrock `ap-northeast-1`; any model registered with a non-GLOBAL region |
| `header_observed` | Response headers provide a location signal, which may identify a CDN edge rather than inference compute | `cf-ray` colo suffix, `x-served-by` |
| `provider_attested` | The provider explicitly attests the region via the trusted `x-yabanin-region` opt-in header | provider opt-in integrations |
| `provider_declared` | The vendor does not disclose serving regions; the value is the provider's registered default | global endpoints like `api.openai.com` |

Scope: for global vendor endpoints, no provider discloses the physical
processing location — the attestation records `provider_declared` rather than
implying knowledge it does not have. Residency packs (fail-closed) let an org
forbid `provider_declared`-tier models entirely, which is the appropriate configuration
for region-pinned buyers.

## Database schema

| Table | Purpose |
|---|---|
| `request_lineage` (baseline `0001_init`) | Append-only ledger, tamper-evident (UPDATE/DELETE blocked by trigger) |
| `provider_jurisdictions` (baseline `0001_init`) | Provider→country mapping with seed data |
| `org_lineage_keys` (baseline `0001_init`) | Per-org Ed25519 keypairs, versioned, revocable |

## Configuration

```yaml
gateway:
  lineage_enabled: true   # enable gateway lineage resolution and signing
```

When disabled (`false` or unset), the gateway skips region resolution and signing
entirely — zero latency overhead.

## Relationship to other features

Lineage and residency are complementary, not redundant:

- **Lineage records** region evidence after the request, with a verifiable signature.
- **Residency prevents** data from going to the wrong jurisdiction (before the fact, via policy
  enforcement). See [Residency policy-packs](./residency-packs.md).

Lineage integrates with the following deployment components; their presence alone does not establish legal compliance:

- [Multi-region active-active](./multi-region.md) — data pinned to a home region via Postgres
  Row-Level Security; lineage attests the region per request.
- [Air-gap / on-prem](./onprem/install-guide.md) — single-tenant deployments with bundled KMS and
  license/PKI; lineage keys never leave the customer environment.
- [Sovereign-model registry](./sovereign-models.md) — `model_origin_country` is part of the signed
  attestation, as a recorded model-registry claim.
- **Admin audit log** — mutations are written to `admin_audit_logs` as
  tamper-evident hash-chained rows (the admin
  write path appends through the shared protocol `auditlog.AppendInTx` —
  `pkg/adminstore.InsertAuditLogEntry` — with persisted before/after/reason
  snapshots and an explicit `hash_version`, migration `0019`; the chain is
  verified end-to-end against a real Postgres by integration tests, including
  concurrency and tamper detection). The JIT-access package (`pkg/jitaccess`)
  exists in-tree but is **not wired** into the admin write path; do not
  present it as shipped. Formal SOC 2 / ISO 27001 control worksheets are
  internal drafts, not certifications.

## Durability and failure behavior

`pkg/lineage.AsyncLedger.Append` inserts the signed attestation into
`lineage_outbox`. This is a synchronous database write on the request path,
not an in-memory queue. After a successful insert, a process restart does
not discard the pending row. A relay runs approximately every 500 ms and
moves up to 500 pending rows per pass into `request_lineage`.

The outbox insert is **independent of request-log persistence**: it does not
share a transaction with the request log. Lineage is best effort from the
inference client's perspective. A signing or database error is logged and
can leave a successful model response without an attestation. Monitor these
errors and the pending outbox backlog if your workflow requires evidence
for every request.

| Failure | Current behavior |
|---|---|
| Process stops after a successful enqueue | The pending row remains in Postgres and a relay can process it after restart. |
| Database unavailable during enqueue | Append fails and the gateway logs the failure; inference can still succeed without lineage evidence. |
| Relay database error | The row remains pending for a later relay attempt. |
| Malformed outbox payload | The row is logged and marked relayed so it cannot block the queue; it does not become a valid lineage record. |
| Relay delay or backlog | Successfully enqueued rows remain pending; the final lineage API may not expose them yet. |

The relay is the writer of chained ledger rows. It deduplicates on
`request_id`; replaying delivery does not intentionally create a second
ledger row. `lineage_outbox` is mutable staging storage, not the signed,
append-only evidence chain. Database backup and recovery still determine
whether committed rows survive loss of the database itself.

## Tamper-evidence: hash chain + WORM export

There are **two independent** hash chains in this system. Do not mix them up:

| Chain | Table | Scope | Origin | Status |
|---|---|---|---|---|
| **Request lineage** | `request_lineage` | per-org, successfully recorded attestations | baseline `0001_init` | shipped (chain + verify + export) |
| **Admin audit log** | `admin_audit_logs` | per-operator, admin mutations | baseline `0001_init`; chain protocol (`0019_audit_snapshots_chain`) | shipped (chain written by the admin write path; verify — integration tests) |

They are separate append-only ledgers with separate schemas, separate writers,
and separate verification. This section documents the **request-lineage** chain
only. The `admin_audit_logs` table is a different concern (admin action
evidence) with its own chain protocol — see the note above.

### How the request-lineage chain works

Each `request_lineage` row carries two extra columns (baseline `0001_init`):

- `record_hash` — `sha256(prev_hash || canonical_record)`, the row's own link
  hash. A fixed-order, `|`-delimited `canonical_record` string (over the INSERT
  columns) is the authoritative source shared by the writer and the verifier.
- `prev_hash` — the previous row's `record_hash` (`NULL` for the chain head).

Because every row embeds the previous row's hash, any edit, insertion, or
deletion in the middle of an org's history breaks every link after it. The
writer (`pkg/lineage/ledger.go`) computes the chain head per org on append; the
outbox relay appends chained rows; verification checks the resulting links.

Legacy rows written before the chain shipped have `record_hash = ''`; the verifier counts and
skips them (they are not part of the chain) rather than treating them as
breakage.

### Verification

`yb lineage verify --pg-uri <url> --org <org-id>` walks an org's rows in
timestamp order, recomputes each chained row's hash, and checks that
`prev_hash` matches the previous `record_hash` (`NULL` head). It reports the row
count, the chained/legacy split, and whether the chain is intact (and, if broken,
the offending row). It exits non-zero on a broken chain so it can be used as a
periodic compliance check.

### WORM export

`yb lineage export --pg-uri <url> --org <org-id> --out <file.jsonl> [--s3 <bucket> --region <r> --lock-compliance --lock-days <n>]`

- Writes the org's rows as JSONL, one object per row, plus a `sha256` checksum
  of the file.
- With `--s3` it uploads the archive and (with `--lock-compliance --lock-days N`)
  sets an S3 Object Lock in **COMPLIANCE** mode for `N` days — nobody, including
  a root account, can alter or delete the export during the retention window.
  This is the "write once, read many" (WORM) evidence copy: you can keep the
  live DB mutable for operations while retaining an immutable, independently
  verifiable snapshot.

### Verifying an export

An exported JSONL file is self-describing: recompute each row's `record_hash`
from its `canonical_record` + the previous row's `record_hash` and confirm the
`sha256` file checksum matches. A compliant WORM export therefore doubles as an
offline audit artifact that does not require read access to the live database.

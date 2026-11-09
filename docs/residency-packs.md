---
title: Residency Policy-Packs
description: Per-request region-pin enforcement for Singapore (PDPA + MAS), India (DPDP + RBI), and Indonesia (UU PDP).
sidebar_position: 1
---

# Residency policy-packs

> **Scope:** policy-packs are typed residency-rule presets plus lineage
> hooks. They are NOT certified compliance products — Yabanin is not "HIPAA
> compliant" or "ITAR certified" because a pack exists, and marketing must never
> claim so. Certification, where needed, is a separate audit process.

Yabanin enforces **region-pin per request** for regulated jurisdictions:
Singapore (PDPA + MAS), India (DPDP + RBI), Indonesia (UU PDP), and Japan
(APPI). This document describes what is enforced, the default rules per
region, how to override per org via the admin API, and how residency relates
to the rest of the sovereignty stack.

## What is enforced

For every `/v1/chat/completions` request, after the final model is selected
(classifier + tier router + routing rules), the gateway runs the residency
**Enforcer** (`pkg/policy/enforcer.go`):

1. Resolve the org's `residency_region` (column on `organizations`, NULL = global).
2. If global → **free-pass** (no latency overhead, no pack evaluation).
3. If regulated but no pack is registered for that region → **fail-closed** (403).
4. The pack evaluates the model's `region` + `family` against its rules:
   - jurisdiction not allowed → **403 `residency_policy_violation`**
   - family not whitelisted → **403**
   - (IN only) blacklist hit → **hard-deny 403**
5. On allow, the response carries `X-Residency-Region` and `X-Residency-Pack`.

Fail-closed is intentional: for a regulated region, **blocking is safer than
serving through the wrong jurisdiction**.

## Default rules

| Region | Pack ID | Allowed jurisdictions | Allowed families | Data residency | Blacklist |
|--------|---------|-----------------------|------------------|----------------|-----------|
| SG | `sg_pdpa_mas` | SG, EU | openai, anthropic, sovereign_sg, open_weights | SG | — |
| IN | `in_dpdp_rbi` | IN, SG | openai, anthropic, sovereign_in, open_weights | IN | CN |
| ID | `id_pdp` | ID, SG | openai, anthropic, sovereign_id, open_weights | ID | — |
| JP | `jp_appi` | JP | openai, anthropic, sovereign_jp, open_weights | JP | — |

The JP preset permits models registered with region `JP` by default. The
gateway evaluates registered metadata; it does not independently verify a
provider's datacenter, storage, subprocessors, or transfer arrangements.
Review those independently before assigning a model's region or changing an
allowlist. The pack name is not a legal determination.

## Per-org overrides (admin API)

Overrides are stored in `policy_packs` as a JSON override of
the `ResidencyRule`. Root-only endpoints:

```bash
# Set org residency region
curl -X PUT http://admin/api/organizations/$ORG_ID/residency \
  -H 'Content-Type: application/json' \
  -d '{"residency_region":"SG"}'

# Override the SG pack to also allow US
curl -X PUT http://admin/api/organizations/$ORG_ID/policy-packs/SG \
  -H 'Content-Type: application/json' \
  -d '{"pack_id":"sg_pdpa_mas","config":{"allowed_jurisdictions":["SG","EU","US"]}}'

# List overrides
curl http://admin/api/organizations/$ORG_ID/policy-packs
```

To clear enforcement for an org, set `residency_region` to `""`.

## Metrics

- `gateway_residency_enforcement_total{region,decision}` — allowed / denied
- `gateway_residency_remap_total{region}` — denied → in-region remap
- `gateway_residency_evaluation_seconds{pack_id}` — pack eval latency

## Relationship to the rest of the sovereignty stack

Residency rules constrain routing using model registry metadata. They do not
prove the physical location of inference, storage, logs, or backups.

- [Lineage](lineage.md) signs recorded routing evidence. Its evidence tiers
  distinguish declarations from stronger attestations.
- [Multi-region deployment](multi-region.md) requires an operator-designed
  topology. Database row-level security controls access, not storage geography.
- [Air-gap / on-prem](onprem/install-guide.md) provides deployment components;
  verify actual egress and dependencies to establish isolation.
- [Model registry](sovereign-models.md) records model metadata used by policy.
  A family allowlist does not establish legal approval of a provider.

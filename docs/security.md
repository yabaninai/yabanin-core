# Yabanin Security

This page is the entry point to Yabanin's security model: who can
authenticate through which surface, how secrets are stored, where the policy
pipeline fits as a control layer, and how the supply chain is guarded.
Security checks and the threat model are described in
[security-audit.md](security-audit.md); the OWASP Top-10 for LLM Applications
mapping lives in [security-owasp-llm.md](security-owasp-llm.md).

## Authentication surfaces

| Surface | Credential | Mechanism | Code |
|---|---|---|---|
| Admin console (local) | email + password | bcrypt (cost 12) hashes; a login attempt always burns bcrypt work (timing-equalized); HMAC-signed session cookie with expiry + issued-at | `pkg/adminauth/auth.go`, `pkg/adminauth/hash.go` |
| Admin SSO — OIDC | upstream IdP | Authorization Code + PKCE (S256), `state` CSRF token, `nonce`, fail-closed user mapping | `pkg/adminauth/oidc.go`, [sso-oidc.md](sso-oidc.md) |
| Admin SSO — SAML 2.0 | upstream IdP | ACS endpoint, signed AuthnRequests, process-local assertion replay cache (see SAML limitations) | `pkg/adminauth/saml.go`, [sso-saml.md](sso-saml.md) |
| SCIM 2.0 provisioning | org-scoped bearer token | mounted on the public router under its own bearer guard (never the admin session); token lookup by SHA-256 (unique index, no secret comparison in SQL) + constant-time compare | `services/admin/handlers/scim.go`, `pkg/adminstore/scim.go` |
| Gateway JWT auth | external JWT | keys selected by `kid` from the deployment-configured JWKS only; `iss`/`aud`/`exp`/`nbf` enforced; the org claim becomes the request's org context and the key-label claim becomes locked key labels; symmetric keys planted in the JWKS are rejected; with an unreachable JWKS the gateway fails closed (503, bounded staleness) | `pkg/gateway/auth_jwt.go` |
| Gateway API keys (`yb_…`, `ybs_…`) | bearer key | stored SHA-256-hashed; resolved through a Redis cache keyed by `sha256(plaintext)` with HMAC-signed entries (`CacheSigner`) — a Redis attacker cannot forge a resolve result | `pkg/auth/resolver.go`, `pkg/auth/sessionkeys.go` |
| Agent keys (`yag_*`) | bearer key | same hashing; agent-principal semantics (tool calls, budgets, task tags) | `pkg/auth/agentkey.go`, [agent-governance.md](agent-governance.md) |

Revocation propagation is bounded and pinned by tests: every revocation path
purges the shared resolve cache, so a revoked key is denied immediately with
Redis, or within `YABANIN_ORG_RESOLVER_TTL` (default 300 s) without it —
[security-audit.md](security-audit.md), "Key Revocation Propagation".

Brute force and abuse: admin login is limited to 5 attempts / 15 min, the
admin API to 1000 req/min, with a Redis-backed limiter
(`pkg/adminauth/ratelimit_redis.go`); the gateway applies per-IP token-bucket
limits. Admin mutations land in the hash-chained audit journal
(`pkg/auditlog`: `row_hash = sha256(prev_hash || payload)`), and privileged
routes require root-only middleware.

## Secrets at rest

- **`enc:` envelopes.** Provider keys (BYOK) and MCP upstream credentials are
  stored as AES-256-GCM ciphertext with an `enc:` version prefix. Writes are
  fail-closed: without a configured encryptor the write is refused — a
  missing key can never silently downgrade to plaintext. Weak keys (short,
  low-entropy hex) are rejected at construction
  (`pkg/encryption/encryption.go`).
- **KMS master key.** `local` accepts its configured master key or versioned keyset.
  `FileKMS` exists as a library implementation, but `file` is not a selectable
  provider in the gateway factory in this version. The `aws` provider is an unimplemented,
  fail-closed placeholder; supplying configuration cannot enable it
  (`pkg/kms/factory.go`).
- **Hashed, never recoverable.** API/agent keys are SHA-256 hashes; SCIM
  bearer tokens resolve by hash lookup with a constant-time confirm; admin
  passwords are bcrypt. These stored hashes cannot be used to recover the
  original credentials; newly issued keys are returned once to their creator.
- **Masked credential reads.** Stored upstream credential APIs return masked
  metadata (`secret_last4`, `has_secret`), not the stored plaintext. Upstream
  authentication resolves the secret in memory. Newly issued gateway and
  agent keys are a separate case: their plaintext is returned once at issuance
  ([mcp-gateway.md §6](mcp-gateway.md)).
- **Org isolation.** Secret-bearing tables sit under the org-isolation RLS
  contract (`ENABLE` + `FORCE`, `app.current_org` GUC pinned per
  transaction); a foreign org's rows are invisible and unwritable.
- **Deployment secrets** (`session_key`, `cache_hmac`, `pg_uri`, KMS keys)
  depend on the deployment profile. Development profiles use environment
  variables; hardened installations can mount secret files under
  `/run/secrets/` and use supported file-based settings. See the rotation runbook
  ([ops/secrets-rotation.md](ops/secrets-rotation.md)).

## The policy pipeline as a control layer

[Policy Pipeline](pipeline.md) (YPP) is the enforcement point for
content-level controls: PII/secret/injection detectors, redaction and
pseudonymization mutators, external scanners, LLM judges, output-schema and
streaming checks. Properties that make it a *control* rather than a feature:

- **Off by default, admin-owned.** With `YABANIN_POLICY_MODE` unset the
  runtime is never built; there are no per-request (SDK-supplied) policy
  configs, so a client cannot bypass an admin's policy.
- **Fail-closed default.** A step error denies by default (`on_error:
  fail_closed`); `fail_open` is an explicit per-step choice. Unknown actions
  rank as deny.
- **Shadow → enforce.** Policies roll out in shadow mode (record-only, never
  mutates), with the decision log (90-day retention, content hashed) and
  per-policy metrics as the review surface. A process-wide kill switch
  downgrades everything to shadow in one move.
- **Bounded egress.** Callout steps require an operator allow-list
  (`YABANIN_POLICY_CALLOUT_ALLOW_HOSTS`); every dial is SSRF-guarded with
  pinned DNS (no rebinding window), no redirects, no retries, per-URL circuit
  breaker.

The OWASP LLM Top-10 mapping
([security-owasp-llm.md](security-owasp-llm.md)) spells out per-risk what
this layer covers and what it does not.

## Supply chain

- **Dependency CVE scanning in the gates.** `make analyze-security` runs
  `go mod verify` + symbol-level `govulncheck`; the same check is a quality
  gate (`scripts/quality/dep_audit.py`), so a reachable CVE fails the build,
  not just a report. Analyzer versions are pinned (`make
  install-analysis-tools`); findings triage uses
  `scripts/security/govulncheck-classify.sh`. Current scan results:
  [security-audit.md](security-audit.md).
- **Dependency policy.** New Go dependencies ride the same review + quality
  gates as code changes; the scanner classifies findings by reachability, and
  "not called" findings are recorded with that justification rather than
  silenced.
- **Runtime supply chain.** Container restrictions and listener exposure depend
  on the chosen Compose or Helm profile. Review the rendered configuration
  for read-only filesystems, privilege restrictions, network isolation and
  published ports. The shared SSRF package guards configured upstream and
  callout paths; it is not a replacement for deployment-level egress controls.
- **Policy/prompt/model provenance.** Policies reconcile from git and record
  the git SHA of the declaring revision; judge prompts and prompt-studio
  resources are versioned; model eligibility can be constrained per org with
  the model-whitelist step. The npm tree of the dashboard/site and Docker
  base images are outside Go scanning — a known, documented boundary
  ([security-owasp-llm.md](security-owasp-llm.md), LLM03).

## Incident response

Runbooks: [incident response](runbooks/incident-response.md), [severity
classification](runbooks/sev-classification.md), [secret
rotation](ops/secrets-rotation.md), [budget-reservation alerts](runbooks/budget-reservations-alerts.md),
and the [production runbook](runbooks/production.md).

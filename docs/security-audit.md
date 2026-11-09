# Security checks and threat model

For the current preview's disclosed vulnerabilities and reporting process, read
[security policy](https://github.com/yabaninai/yabanin-core/blob/main/SECURITY.md). A historical scan is not a current security result.
Source scans, binary scans and container scans have different coverage; retain the
source version, tool version, database date and raw findings with each result.

## Dependency checks

With the project's Go toolchain and `govulncheck` installed:

```bash
govulncheck ./...
```

A source finding can identify a call path; a binary finding may have only module
precision. Neither alone demonstrates exploitability or establishes that a
vulnerability is absent. Container checks must cover both operating-system and
linked Go packages, using the actual image and a current vulnerability database.

## Deployment boundaries

| Surface | Deployment consideration |
| --- | --- |
| Gateway | Authenticate API traffic and configure provider egress; protect exposed listeners with TLS and rate limits |
| Admin API and dashboard | Restrict network access, protect sessions and configure allowed origins for the deployed dashboard |
| PostgreSQL and Redis | Keep on trusted networks with appropriate authentication, backups and access controls |
| Classifier and optional detectors | Restrict access and apply resource limits; inspect data sent to remote detectors |

The local quickstart binds the gateway to localhost port 8082 and the admin API
to localhost port 8086. Its optional dashboard development server uses port 5173.
These local settings are not an internet deployment configuration.

[Security controls](security.md) describes authentication, encryption, key storage
and auditing. Review the actual rendered container or Kubernetes configuration:
read-only filesystems, capabilities and network isolation depend on that
configuration, not merely on using a Yabanin binary.

### Key Revocation Propagation

With a shared Redis resolver cache, successful cache invalidation makes the next
key resolution consult the database. Without Redis, cached key information can
remain until `YABANIN_ORG_RESOLVER_TTL` (default 300 seconds). Check revocation on
each active gateway replica; a control-plane mutation alone is not proof that all
replicas have observed it.

## Policy and tool boundaries

Prompt injection remains a risk in model input and tool output. Optional guards
and pipeline policies can detect or reject configured patterns; they do not
provide universal detection. See the [OWASP mapping](security-owasp-llm.md) for
controls and limitations, and [secret rotation](ops/secrets-rotation.md) for
credential handling.

### Pipeline threat model (pkg/pipeline, pkg/policystore)

The pipeline is a programmable inspection/mutation conveyor over gateway
traffic ([pipeline.md](pipeline.md)). Its own attack surface, and the
controls:

| Surface | Threat | Control |
|---|---|---|
| Condition engines (`pkg/pipeline/script`: `expr` default, `lua`, `starlark`) | a policy condition becomes a DoS/escape vector | conditions are compiled once at policy load (invalid source = load error, never a silent skip); `expr` is loop-free by design; `lua` runs sandboxed with an instruction budget; per-step `timeout` bounds every engine; condition errors follow `on_error` (default fail-closed). Policies are admin-authored and git-reconciled — not client input |
| Callout steps (`pkg/pipeline/callout`) | SSRF via scanner URLs; data exfiltration through projections | steps compile only with `YABANIN_POLICY_CALLOUT_ALLOW_HOSTS` set (empty = fail-closed); SSRF guard pins DNS answers and rejects reserved addresses at dial time (rebinding window closed); no redirects, no retries, per-URL circuit breaker, per-step timeout; `expose` projections bound what leaves (metadata never leaves); `max_response_bytes` caps replies |
| LLM judge (`pkg/pipeline/llmjudge`) | pipeline recursion (judge calls the gateway, re-entering the pipeline, amplifying cost) | hard exclusion: gateway-made judge calls carry `judge=true` meta and `X-Yabanin-Judge: true`; internal calls are exempt, while any inbound request presenting that header (any value, empty or duplicated included) is rejected with `400 judge_reentry_unsupported` after auth ([pipeline.md §6.2](pipeline.md)); judge prompts are versioned resources; temperature pinned to 0; omitted confidence counts as 1.0 (fail-closed) |
| Verdict composition | a buggy step smuggles an `allow` past a deny | fixed strictness scale deny > mask > flag > allow; union across attached policies with most-restrictive verdict; unknown actions rank as deny; first deny short-circuits |
| Streaming mutation | torn writes leak pre-substitution values across chunk boundaries | prefix gate (64 tokens / 500 ms) denies before release; chunk-carry holds partial matches; transform runs before the cache writer ([pipeline.md §7](pipeline.md)) |
| Decision log | sensitive content persisting via findings | evidence stored hashed; quoted user content persists only in shadow/debug retention; 90-day retention (`PolicyDecisionsRetentionDays`, enforced by the loggerd purge loop) |

### MCP credentials threat model (pkg/mcpagg, migration 0007)

See [MCP gateway credentials](mcp-gateway.md). Secrets exist only as `enc:`-encrypted envelopes
(fail-closed writes), under org-isolation RLS; reads return masked rows only
(`secret_last4`/`has_secret`); every CRUD/status step lands in the
hash-chained audit journal; plaintext bounded (8 KiB) and never logged. A
credential can never widen egress: the SSRF allow-list check on the server
URL precedes credential resolution on every invoke. Per-user credential flows
(submit/rotate, OAuth begin/callback) require an enabled grant — the grant is
the ceiling for every flow step.

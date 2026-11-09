---
title: "Bring Your Own Keys (BYOK)"
description: "Configure organization-scoped provider credentials, understand selection and quarantine, and verify upstream authentication."
sidebar_position: 13
---

# Bring Your Own Keys (BYOK)

BYOK associates upstream provider credentials with an organization. Clients
continue to authenticate with their gateway key; the gateway resolves the
provider credential for that organization's request. Adding a key does not
register a model or change a model's upstream URL.

## Before you start

- Start a gateway and admin deployment using the [quickstart](quickstart.md)
  or your deployment configuration.
- Sign in to the correct organization with permission to manage keys.
- Configure encryption for stored credentials on admin and gateway.
- Register a model with the provider and upstream URL you intend to use.
- Ensure both services can reach that endpoint and the gateway's upstream
  allow-list admits it. An admin connection test and a gateway request use
  different network paths.

## Add a provider key

Open **Settings → Provider keys → Add key**. Enter a descriptive name,
provider identifier, base URL and the actual provider API key. Keys must be
between 20 and 5000 characters. Save the record; subsequent reads show a
last-four-character mask, never the stored plaintext.

| Provider | Registry identifier | Base URL |
|---|---|---|
| OpenAI | `openai` | `https://api.openai.com/v1` |
| Anthropic | `anthropic` | `https://api.anthropic.com` |
| Z.AI Coding Plan | `zai-coding` | `https://api.z.ai/api/coding/paas/v4` |
| vLLM, Ollama or another compatible server | `openai-compat` | Your HTTPS OpenAI-compatible endpoint, usually ending in `/v1` |

The Coding Plan adapter pins its endpoint and requires
`YABANIN_ZAI_CODING_ENABLED=true`; see [providers](providers.md).
**Test connection** runs a guarded server-side probe and is rate-limited per
organization. It is a connectivity check, not proof that a subsequent model
request chose the same credential.

### Private model servers

HTTPS is the default requirement, including for local hosts. The BYOK API
rejects `http://localhost`, `http://127.0.0.1`, and
`http://host.docker.internal`; these are not working registration examples.

An operator can enable `YABANIN_ORG_CRED_ALLOW_HTTP_PRIVATE=1` on the admin
server for literal private-network IP addresses. For example,
`http://192.168.50.20:11434/v1` is eligible for this exception only if that is
the actual address of your model server. Accepted networks include RFC 1918,
IPv6 ULA and CGNAT. Loopback, link-local and metadata addresses remain
excluded from the admin probe. DNS hostnames do not qualify for the HTTP
exception.

The gateway separately requires a matching explicit upstream allow-list
entry, configured through `gateway.allowed_upstreams`. Use the actual
literal address and apply configuration to the running services. A hostname
that resolves to a private address does not bypass the DNS SSRF checks.
Check routing and firewall reachability from both containers before testing.

A server with authentication disabled does not need a fabricated BYOK key.
Configure that model's endpoint directly instead. Put TLS and authentication
in front of a server when credentials or prompts cross an untrusted network.

## Credential selection

| Priority | Credential source | Condition |
|---|---|---|
| 1 | Organization provider keys | An enabled key matches the provider and the exact upstream base URL or its `/v1`-stripped form. |
| 2 | Per-model credential | No organization credential matches. |
| 3 | Global gateway credential | Neither earlier source supplies a credential. |

With the built-in database store, multiple matching organization keys form
a round-robin pool. A selected key is pinned to that provider attempt.
Upstream authentication/rate-limit failures can quarantine it until the end
of the current UTC day. If the organization has keys but all are quarantined,
the attempt fails; it does not silently spend a global credential. Store
failures also fail closed. The legacy single-key resolver uses newest-first
selection; it is not the built-in pool's balancing contract.

BYOK changes upstream authentication and credential attribution. It does not
remove gateway budgets, policies, client authentication or audit controls.

## Verify the credential used

Use a controlled endpoint that actually validates the upstream key, or check
the gateway's masked credential attribution. Do not log authorization headers.
For a controlled test, ensure the registered endpoint requires the org key
and that no matching fallback credential can make the same request succeed.

Send a request with your gateway key and the registered model ID:

```sh
export YABANIN_GATEWAY_URL=http://127.0.0.1:8082
# Set YABANIN_API_KEY to your gateway key and YABANIN_MODEL to a registry ID.
: "${YABANIN_API_KEY:?set your gateway API key}"
: "${YABANIN_MODEL:?set the registered model ID}"
jq -n --arg model "$YABANIN_MODEL" \
  '{model:$model,messages:[{role:"user",content:"Reply with OK."}]}' |
  curl --fail-with-body -sS \
    -H "Authorization: Bearer $YABANIN_API_KEY" \
    -H 'Content-Type: application/json' \
    --data-binary @- "$YABANIN_GATEWAY_URL/v1/chat/completions"
```

This command requires `jq` and `curl`. A successful response alone proves
request completion, not credential selection. In a disposable test org,
disabling its only matching key should remove that authentication path.
Record the observed masked credential reference and upstream acceptance;
restore the test configuration afterward. Do not rotate production keys
merely to run this check.

## Storage and isolation

Stored records contain encrypted key ciphertext, the last-four mask and
metadata such as name, provider, URL, organization and enabled status. The
plaintext is resolved in memory for upstream authentication; it cannot be
exported or retrieved through the credential API. Key rows are scoped by
organization under row-level security. A last-four mask is a display aid,
not proof that a provider still accepts the key.

## Troubleshooting

| Symptom | Check |
|---|---|
| HTTP URL rejected | Use HTTPS or the explicit literal-private-IP exception described above. |
| Key rejected at creation | Check the 20–5000 character length and required fields. |
| Probe succeeds, inference fails | Check the model's provider/URL, gateway allow-list and connectivity, and upstream model permissions. |
| Organization key not selected | Check the requesting organization, enabled status, matching provider/base URL and quarantine state. A lower-priority per-model credential does not shadow a matching eligible org key. |
| All organization keys quarantined | Inspect upstream 401/429 failures and fix or rotate the affected credentials; no global-key fallback occurs. |
| Another organization cannot see the key | Expected: credentials do not cross organization boundaries. |

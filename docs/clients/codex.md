# Codex

Point Codex at the gateway Responses API. This page is a configuration sketch.
Verification scope: a mock Codex CLI end-to-end run
(`TestResponses_CodexCLI_MockE2E`) plus a real codex-cli binary e2e —
verified 0.162.1 (2026-10-18), re-verified 0.163.0 (2026-10-28),
and re-verified 0.166.0 (2026-11-03, tools loop / capability errors /
mid-stream cancel — `TestResponses_CodexCLI_RealE2E_*`) against a local mock
upstream; see the [compatibility matrix](../compatibility.md). A
paid-upstream live run is not covered by that evidence.

## Config

`~/.codex/config.toml`:

```toml
model_provider = "yabanin"
model = "YOUR_REGISTERED_MODEL"

[model_providers.yabanin]
name = "Yabanin"
base_url = "https://gateway.example.internal/v1"
env_key = "YABANIN_API_KEY"
wire_api = "responses"
```

Replace `YOUR_REGISTERED_MODEL` with a model enabled for your organization
and replace the example hostname with your gateway. The quickstart gateway URL
is `http://127.0.0.1:8082/v1`; its `mock-model` can exercise request plumbing but
is not a capable coding model. Put the top-level `model_provider` and `model`
settings before any TOML table. Defining a provider table alone does not select
it. Preserve unrelated existing configuration.

Read the gateway key into the environment without storing it in this file or
as a literal command in shell history:

```bash
read -r -s -p "Gateway API key: " YABANIN_API_KEY
printf '\n'
export YABANIN_API_KEY
```

## Endpoint

`POST /v1/responses`. When the resolved provider is `openai` and the org has
no deny tool policy, the gateway forwards the body unchanged. Otherwise it
translates the call into chat completions.

## Bring your own provider key (BYOK)

Your org admin adds the upstream provider key once in the admin console
(**Settings → Provider keys** — see [BYOK](../byok.md)). When the model routes
through the org credential, the client needs no changes: keep the `yb_…`
gateway key above and the gateway authenticates upstream with the org key.

## Limits

- Stateless session model: the gateway keeps no response state on
  any path. `previous_response_id` is rejected with 400 everywhere — Codex's
  full-history resend (`store=false`) is the supported flow.
- Fields the translation cannot represent (`reasoning.effort`, verbosity,
  unsupported tools, …) are dropped and announced in the
  `X-Yabanin-Unsupported` response header — never silently.
- Stream breaks: if the upstream stream dies mid-response, the
  gateway appends a `response.failed` SSE event, records `request.failed`
  and charges nothing for the interrupted stream. A client hangup is
  recorded per route canon: the native passthrough settles the consumed
  prefix billed (`request.completed`), the adapted chat route records
  `request.failed` without a charge — verified on 0.166.0 (SIGINT mid-stream:
  the CLI exits 1 fast, writes no last-message file, and the gateway settles
  exactly one terminal event while tearing the upstream relay down).
- Wire behavior (0.166.0, verified): every turn sends `store=false` and
  `previous_response_id=null` with a full-history resend; there is no config
  lever to force `previous_response_id` on a custom provider. The session
  UUID arrives as `prompt_cache_key` (the gateway maps it to session
  affinity). An unsupported tool call the CLI cannot register is fed back
  verbatim as `unsupported call: <name>` and the run completes with the limitations reported.
- Auth surface: API-key bearer (`yb_…`) only. The Codex ChatGPT-OAuth login
  (`codex login`) is not supported; configure `env_key` as shown above.
- Client confirmation: real `codex exec` (codex-cli 0.162.1 verified
  2026-10-18; re-verified 0.166.0 2026-11-03 with tools/cancel
  scenarios) against the gateway with a mock upstream; live paid-upstream
  runs are not covered by this evidence.

## Check

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer $YABANIN_API_KEY" \
  https://gateway.example.internal/v1/models
```

`200` means the gateway accepted the key. It does not start Codex.

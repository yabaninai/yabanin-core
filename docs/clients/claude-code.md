# Claude Code

Point Claude Code at the gateway Messages API. A live Claude Code binary has
not been run against the gateway (`not verified` in the
[compatibility matrix](../compatibility.md)).

Anthropic does not officially support Claude Code with non-Claude models.

## Config

```bash
export ANTHROPIC_BASE_URL='https://gateway.example.internal'
export ANTHROPIC_AUTH_TOKEN='yb_…'
```

For a translation route to a model that is not Claude, also set:

```bash
export CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1
export CLAUDE_CODE_ATTRIBUTION_HEADER=0
```

Choose the model with an alias from the gateway registry, or with:

```bash
export ANTHROPIC_MODEL='claude-sonnet-4-6'
export ANTHROPIC_DEFAULT_SONNET_MODEL='claude-sonnet-4-6'
export ANTHROPIC_DEFAULT_HAIKU_MODEL='claude-haiku-4-5'
export ANTHROPIC_DEFAULT_OPUS_MODEL='claude-opus-4'
```

Model discovery:

```bash
export CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY=1
```

Discovered ids must contain `claude`. Register aliases such as
`claude-sonnet-4-6` that point at the registry model you actually run.

## Endpoint

`POST /v1/messages`. `provider=anthropic` is forwarded as-is, including
`cache_control` and request fields the gateway does not model (such as
`thinking`). A successful non-stream reply that organization policy leaves
unmodified is forwarded byte-identically; post-upstream policy may instead
mask the reply or refuse it with 400. Any other provider is translated
into chat completions. `POST /v1/messages/count_tokens` forwards to the
provider for `anthropic` models; other models get a bytes/4 estimate
announced by the `X-Yabanin-Estimated: true` response header.

Native Anthropic forwarding sends `anthropic-version` upstream (`2023-06-01`
when your request omits it), forwards `anthropic-beta` and
`anthropic-workspace-id` when set, and sends no beta header otherwise. On a
successful reply it relays the provider `request-id`, `retry-after`,
`x-should-retry` and `anthropic-ratelimit-unified-*` headers; on an
upstream error it additionally relays the provider `Content-Type`. Other
provider response headers are not relayed.

## Bring your own provider key (BYOK)

Your org admin adds the upstream provider key once in the admin console
(**Settings → Provider keys** — see [BYOK](../byok.md)). When the model routes
through the org credential, the client needs no changes: keep the `yb_…`
gateway key above and the gateway authenticates upstream with the org key.

## Limits

- Translation drops `thinking`, hosted tools, and `cache_control`.
- Org tool policies gate the model's tool calls on both routes: deny
  policies strip denied calls on the translated route, and native Anthropic
  mode strips denied `tool_use` blocks from the reply (buffered and
  streaming) while keeping the surviving call indices contiguous and
  rewriting a stranded `tool_use` finish to `end_turn`.
- Fixture coverage is not a live Claude Code run.

## Check

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H "x-api-key: $ANTHROPIC_AUTH_TOKEN" \
  -H "anthropic-version: 2023-06-01" \
  https://gateway.example.internal/v1/models
```

`200` means the gateway accepted the key. It does not start Claude Code.

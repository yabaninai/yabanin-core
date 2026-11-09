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
`cache_control`. Any other provider is translated into chat completions.
Token estimates are `POST /v1/messages/count_tokens`.

## Bring your own provider key (BYOK)

Your org admin adds the upstream provider key once in the admin console
(**Settings → Provider keys** — see [BYOK](../byok.md)). When the model routes
through the org credential, the client needs no changes: keep the `yb_…`
gateway key above and the gateway authenticates upstream with the org key.

## Limits

- Translation drops `thinking`, hosted tools, and `cache_control`.
- Native Anthropic mode does not apply tool gating.
- Fixture coverage is not a live Claude Code run.

## Check

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H "x-api-key: $ANTHROPIC_AUTH_TOKEN" \
  -H "anthropic-version: 2023-06-01" \
  https://gateway.example.internal/v1/models
```

`200` means the gateway accepted the key. It does not start Claude Code.

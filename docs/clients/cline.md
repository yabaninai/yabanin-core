# Cline

Point Cline at the gateway as an OpenAI-compatible provider. A live Cline
session has not been run against the gateway (`not verified` in the
[compatibility matrix](../compatibility.md)).

## Config

```text
baseURL: https://gateway.example.internal/v1
apiKey: yb_…
```

## Endpoint

`POST /v1/chat/completions`. The checked fixture is a non-stream request
that expects `tool_calls` in the assistant message.

## Bring your own provider key (BYOK)

Your org admin adds the upstream provider key once in the admin console
(**Settings → Provider keys** — see [BYOK](../byok.md)). When the model routes
through the org credential, the client needs no changes: keep the `yb_…`
gateway key above and the gateway authenticates upstream with the org key.

## Limits

- Fixture coverage is not a live Cline session.

## Check

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer yb_…" \
  https://gateway.example.internal/v1/models
```

Replace `yb_…` with the real key. `200` checks the gateway, not Cline.

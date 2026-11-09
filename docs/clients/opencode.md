# OpenCode

Point OpenCode at the gateway as an OpenAI-compatible provider. A live
OpenCode binary has not been run against the gateway (`not verified` in the
[compatibility matrix](../compatibility.md)).

## Config

```text
baseURL: https://gateway.example.internal/v1
apiKey: yb_…
```

## Endpoint

`POST /v1/chat/completions`. Function tool calls are passed through. Content
arrays are forwarded as chat content parts.

## Bring your own provider key (BYOK)

Your org admin adds the upstream provider key once in the admin console
(**Settings → Provider keys** — see [BYOK](../byok.md)). When the model routes
through the org credential, the client needs no changes: keep the `yb_…`
gateway key above and the gateway authenticates upstream with the org key.

## Limits

- Fixture coverage is not a live OpenCode run.

## Check

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer yb_…" \
  https://gateway.example.internal/v1/models
```

Replace `yb_…` with the real key. `200` checks the gateway, not OpenCode.

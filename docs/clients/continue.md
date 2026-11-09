# Continue

Point Continue at the gateway as an OpenAI-compatible provider. A live
Continue process has not been run against the gateway (`not verified` in the
[compatibility matrix](../compatibility.md)).

## Config

Chat uses the chat completions endpoint. Autocomplete is a separate model
on the completions endpoint:

```json
{
  "models": [
    {
      "title": "Yabanin chat",
      "provider": "openai",
      "model": "gpt-4o",
      "apiBase": "https://gateway.example.internal/v1",
      "apiKey": "yb_…"
    }
  ],
  "tabAutocompleteModel": {
    "title": "Yabanin complete",
    "provider": "openai",
    "model": "gpt-4o",
    "apiBase": "https://gateway.example.internal/v1",
    "apiKey": "yb_…"
  }
}
```

Set the autocomplete model so Continue calls `POST /v1/completions` (prompt
and suffix). Chat calls `POST /v1/chat/completions`.

## Bring your own provider key (BYOK)

Your org admin adds the upstream provider key once in the admin console
(**Settings → Provider keys** — see [BYOK](../byok.md)). When the model routes
through the org credential, the client needs no changes: keep the `yb_…`
gateway key above and the gateway authenticates upstream with the org key.

## Limits

- The completions row in the matrix is fill-in-the-middle only, not chat.
- Fixture coverage is not a live Continue run.

## Check

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H "Authorization: Bearer yb_…" \
  https://gateway.example.internal/v1/models
```

Replace `yb_…` with the real key. `200` checks the gateway, not Continue.

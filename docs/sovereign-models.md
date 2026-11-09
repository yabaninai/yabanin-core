# Sovereign-model registry

> **What the adapters are (and are not):** each "sovereign provider" adapter is
> an OpenAI-compatible HTTP client to that vendor's public API. An adapter is
> NOT a partnership, endorsement, or commercial agreement with the vendor.
> Access requires the customer's own API credentials for that provider.

## Tier taxonomy
- `full` — vendor HQ + inference + data inside buyer's trusted jurisdiction.
- `partial` — vendor HQ trusted, inference/data partially external.
- `open_weights` — buyer self-hosts weights (Llama/Mistral/Falcon via vLLM).
- `foreign` — vendor HQ outside trusted jurisdictions (CN-off default).

## Adding a new sovereign provider (5 steps, under 30 min)
1. Create `pkg/provider/<name>.go` implementing `provider.Provider`.
2. Add `case "<name>": return <Name>{}, nil` to `pkg/provider/factory.go`.
3. Add the provider name to `chk_provider` constraint (migration).
4. Seed a row in `models_registry` with `country`/`jurisdiction`/`sovereignty_tier`.
5. Add a compile-time assertion + a unit test in `sovereign_adapters_test.go`.

## Policy examples
- **Defense tenant**: `required_tier=full, excluded_countries={US,CN}, cn_allowed=false`.
- **Commercial (CN-opt-in)**: `required_tier=foreign, cn_allowed=true`.
- **EU BFSI**: `required_tier=full, buyer_jurisdiction=EU`.

## Lineage
Each attestation carries `model_origin_country`, covered by the HMAC signature.

## Limitations
- RU adapters require the Astana-Hub (KZ) entity for commercial use.
- GigaChat requires an mTLS client cert (`SBER_CLIENT_CERT`/`SBER_CLIENT_KEY`).
- Yandex IAM tokens expire ~12h; rotate `upstream_api_key` on a schedule.

# Getting Started — Yabanin Operator (Prepaid Credits)

Yabanin is self-hosted: **you** operate the gateway, the admin panel and the
billing relationship with your users. There is no hosted sign-up and no
price list in this repository — provider prices and any resale markup are
configured in your own database. This guide walks an operator through a
working prepaid setup.

## 1. Deploy the stack

```bash
make docker-up        # postgres + redis + migrations + gateway + admin
# or a single process:
yabanin dev --migrate
```

The admin panel listens on `:8086` (compose host `:9091`). Create your
administrator account with `yabanin admin create-user` (see `--help`; the CLI
refuses inline passwords — use `--password-stdin` or `YABANIN_ADMIN_PASSWORD_FILE`).

## 2. Configure prices

Model prices live in the `models_pricing` table and are what the gateway
bills against. Load them from your providers' price sheets:

```bash
yb pricing sync --apply     # sync provider prices into models_pricing
```

After a sync the gateway picks up database prices within 5 minutes
(`DBPricer` cache). Whether you resell at a markup is **your** commercial
decision; Yabanin can compute resale amounts from a configured markup, but the
rate is set in your deployment, not published here.

## 3. Create an org and an API key

In the admin panel: create the customer organization, then mint an API key
for it (`api_keys`). Keys are org-scoped; spend is attributed through
[labels](labels.md) and [session keys](agent-governance.md).

## 4. Top up prepaid credits

Yabanin bills prepaid: requests are only served while the org holds credits.

```bash
# Admin API (admin session auth; cross-org views are root-only):
POST /api/orgs/{org_id}/credits/topup          # add credits
GET  /api/orgs/{org_id}/credits/balance        # current balance
GET  /api/orgs/{org_id}/credits/transactions   # ledger
```

When the balance is exhausted the gateway rejects inference requests with
`402 Payment Required` (`insufficient_credits`) until the next top-up.
`GET /api/credits/low-balance` lists orgs approaching zero. How you collect
payment (invoice, Stripe, bank transfer) is outside Yabanin's scope.

## 5. First request

```bash
export YABANIN_API_KEY="<key you minted>"
export BASE_URL="http://localhost:8082/v1"

curl "$BASE_URL/chat/completions" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $YABANIN_API_KEY" \
  -d '{
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "Hello, World!"}],
    "max_tokens": 50
  }'
```

The response is standard OpenAI chat format (plus SSE with `"stream": true`).
Spend is recorded server-side — the gateway does not add cost fields to the
chat response. To read spend:

- per session: `GET /v1/yabanin/session-keys/{id}/usage` (returns `cost_usd`);
- per org / per label: the admin analytics and the request log
  (`request_logs`, see [analytics.md](analytics.md)).

## Where to look next

- [docs/quickstart.md](quickstart.md) — local stack
- [docs/labels.md](labels.md) — spend attribution
- [docs/agent-governance.md](agent-governance.md) — agent keys and budgets
- [docs/cli.md](cli.md) — `yb` command reference

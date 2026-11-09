# Yabanin CLI (`yb`)

`yb` contains operator commands and offline tools. This page covers health
checks, the read-only `keys list` and `spend` service commands, and offline
audit. Other command families can create credentials, change policies, or run
workloads; the CLI as a whole is not read-only.

Use `bin/yb --help` and `bin/yb COMMAND --help` to inspect your built version.
See [evaluation](evaluation.md), [CI](ci.md), [harness integration](harness.md),
and [policies](pipeline.md) for those workflows.

```bash
# install (from the repository root)
go build -o bin/yb ./cmd/yb
bin/yb --help
export PATH="$PWD/bin:$PATH"
```

Use the Go version declared in `go.mod`. The PATH change applies only to this
shell and lets the following examples invoke `yb`. The server executable
`yabanin` is a different command and does not contain `audit`.

## Global flags

| Flag | Default | Description |
|------|---------|-------------|
| `--admin-url` | command-specific | `keys list`/`spend`: flag, then `YABANIN_ADMIN_URL`, then `http://localhost:8086`; doctor requires an explicit target |
| `--api-key` | — | `keys list`/`spend`: admin **service key** in `X-Admin-Key`; gateway commands use their own authentication contract |
| `--org` | — | Organization ID; required for `keys list` and `spend` |
| `--base-url` | command-specific | Gateway target; doctor uses the flag or `YABANIN_GATEWAY_URL` and does not auto-select a server |

The service key must match `YABANIN_ADMIN_API_KEY` configured on the
yabanin-admin server; without it the `/internal` service API is not mounted at
all. See [production runbook — Internal service API](runbooks/production.md).

For `keys list` and `spend`, setting `YABANIN_ADMIN_API_KEY` in the client shell
does not populate `--api-key`. Read the operator-issued service key without
putting its literal value into shell history:

```bash
read -r -s -p "Admin service key: " YABANIN_ADMIN_API_KEY
printf '\n'
# Replace the organization ID with one you are authorized to inspect.
yb keys list --org YOUR_ORG_ID --api-key "$YABANIN_ADMIN_API_KEY"
unset YABANIN_ADMIN_API_KEY
```

The shell-expanded flag can still be visible in process arguments. Use a
trusted machine; do not commit literal secrets or reuse a gateway key as an
admin service key. The local quickstart does not enable this service API by
default; its browser admin login is a separate authentication flow.

## Commands

### `yb version`

Prints the CLI version.

```bash
yb version
# Example source build:
# 0.1.0 (commit dev)
# Your Agnostic Bridge Across Numerous Inference Networks
```

### `yb doctor`

Checks the gateway (`/healthz`) and admin panel (`/health`) only when an
operator configures their targets with `--base-url`/`--admin-url` or
`YABANIN_GATEWAY_URL`/`YABANIN_ADMIN_URL`. Flags take precedence over the
corresponding environment variable. Existing base path prefixes are preserved.
Deployment mode and region do not select a target automatically.

```bash
yb doctor --base-url http://localhost:8082 --admin-url http://localhost:8086
yb doctor --offline
```

Use service roots, without `/v1`. Port 8085 is the standalone log consumer,
not the gateway. The offline example intentionally exits nonzero.

`--offline` skips every request, including configured targets. Without targets,
checks are also skipped. Both cases report health as unknown and exit nonzero;
they do not confirm service health. A selected unhealthy or unreachable target
also exits nonzero. A successful check of every selected target exits zero.

Each request has a five-second timeout, respects command cancellation and
refuses redirects. Targets must be HTTP(S) URLs without credentials, query
parameters or fragments. Invalid targets are rejected without a request; target
URLs and transport details are omitted from diagnostics. Correct the configured
URL or restore service connectivity, then rerun the command. These diagnostics
cover the selected health endpoints; they do not audit backend or browser egress.

### `yb keys list`

Lists the API keys of one organization (name, active status, creation date).
The key list contains no plaintext key material by design — the admin store
keeps hashes only.

```bash
yb keys list --org YOUR_ORG_ID --api-key "$YABANIN_ADMIN_API_KEY"
# NAME      STATUS    CREATED
# deploy    active    2026-08-01
# ci        inactive  2026-07-01
```

Pagination: `yb keys list --org YOUR_ORG_ID --api-key "$YABANIN_ADMIN_API_KEY" --page 2 --page-size 10`.
Without `--page`/`--page-size` the server defaults (page 1, size 50) apply; when the
organization has more keys than fit on one page, a "Showing N of M keys" hint is printed.

### `yb spend`

Shows the organization's savings analytics for a look-back window: request
total, actual vs counterfactual cost, combined savings, and a per-model
breakdown.

```bash
yb spend --org YOUR_ORG_ID --api-key "$YABANIN_ADMIN_API_KEY"
yb spend --org YOUR_ORG_ID --api-key "$YABANIN_ADMIN_API_KEY" --days 30   # -d 30
```

### `yb audit`

Offline spend analyzer. Point it at a local LLM request log (JSONL, CSV, or
this gateway's format). It reports actual spend and simulated cache/routing
savings. It needs **no** gateway, admin URL, API key, or organization, and in
`--cache-mode exact` (the default) it makes **no network calls**.

```bash
yb audit path/to/traffic.jsonl
yb audit path/to/traffic.jsonl --format html --output report.html --no-prompts
```

| Flag | Default | Meaning |
|------|---------|---------|
| `--format`, `-f` | `md` | `md`, `json`, or `html` |
| `--cache-mode` | `exact` | `exact` or `off`; `semantic` is recognized but unavailable in this CLI |
| `--output`, `-o` | *(stdout)* | write the report to this file |
| `--no-prompts` | `false` | drop raw prompt text after hashing |

`--cache-mode semantic` is rejected because this CLI has no embedder wiring.
Starting an embedding service does not enable it. Supported modes make no
network requests. A complete runnable synthetic example, pricing limits, and
privacy guidance are in [Offline spend audit](./audit.md).

## Error semantics

| CLI error | Meaning |
|-----------|---------|
| `--api-key required` | `--api-key` flag not provided |
| `org required` | `--org` flag not provided |
| `admin service rejected the key: check --api-key and that yabanin-admin has YABANIN_ADMIN_API_KEY set` | HTTP 401 — wrong key, or the admin server has no `YABANIN_ADMIN_API_KEY` configured |
| `admin service: org_id query parameter is required` | HTTP 400 — server-side org validation |
| `admin service unreachable at <url>` | connection refused / timeout (10s client timeout) |

## Security notes

- The `/internal` service API is **read-only** and **org-scoped**: the key-list and
  savings endpoints require `org_id` and expose no mutation operations.
- The key comparison is constant-time on the server; the key value is never
  logged by the CLI or the server.
- The service API uses `X-Admin-Key`, not the browser session cookie. Keep it
  on a trusted network and use TLS when crossing a network boundary.

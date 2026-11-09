# SDK source installation and verification

Exact versions the shipped SDKs and client pages are pinned to, with the date
and command each `tested` claim rests on. Gateway-side client-protocol rows
(Codex/Claude Code/OpenCode/Cline/Continue *shaped traffic*) live in
[../compatibility.md](../compatibility.md); this page owns the SDK packages
themselves.

## Make a first local SDK request

Complete the [quickstart](../quickstart.md) through its successful curl/smoke
check. Keep its gateway API key in `YABANIN_API_KEY` and use the seeded
`mock-model`. These instructions install or import the SDKs from this checkout;
they do not claim that a matching package is published in a registry.

**URL convention:** these Yabanin SDKs append `/v1` themselves. Pass
`http://127.0.0.1:8082` with no trailing slash or `/v1`. An official OpenAI
client generally expects `http://127.0.0.1:8082/v1` instead. Set the URL
explicitly; the SDKs' historical hosted defaults are not a promise that a
hosted account or endpoint is available.

### Python

Use Python 3.9 or newer with venv support. On Debian/Ubuntu, a missing
`ensurepip` error means the matching `python3-venv` package is required.
Install it through your system package manager, then recreate the environment.
From the repository root:

```bash
python3 -m venv .venv-sdk
. .venv-sdk/bin/activate
python -m pip install ./sdks/python
python - <<'PYTHON'
import os
from tokenrouter import Client

client = Client(
    base_url="http://127.0.0.1:8082",
    admin_url="http://127.0.0.1:8086",
    api_key=os.environ["YABANIN_API_KEY"],
)
response = client.chat.completions.create(
    model="mock-model",
    stream=False,
    messages=[{"role": "user", "content": "Hello from the Python SDK"}],
)
assert response["choices"][0]["message"]["content"]
print(response["choices"][0]["message"]["content"])
PYTHON
deactivate
```

Installation downloads declared dependencies. The SDK returns dictionaries;
use dictionary access rather than an official OpenAI client's object syntax.
This synchronous example makes one mock request and exits. It does not call
admin endpoints.

### Node.js

Use a Node.js installation with global `fetch` support. From the repository
root, install the locked development dependencies and compile the SDK before
importing it:

```bash
npm ci --prefix sdks/node
npm --prefix sdks/node run build
node --input-type=module <<'JAVASCRIPT'
import { Client } from './sdks/node/dist/index.js';
const client = new Client({
  baseUrl: 'http://127.0.0.1:8082',
  adminUrl: 'http://127.0.0.1:8086',
  apiKey: process.env.YABANIN_API_KEY,
});
const response = await client.chat(
  [{ role: 'user', content: 'Hello from the Node SDK' }],
  'mock-model',
);
if (!response.choices?.[0]?.message?.content) throw new Error('Missing reply');
console.log(response.choices[0].message.content);
JAVASCRIPT
```

The package's `main` and `types` point to generated `dist/` files. A source
checkout alone is not a built package; do not omit the build step.

### Go

The SDK is a nested module. In your own Go application, use a local `replace`
directive pointing to this checkout's `sdks/go` directory while evaluating
unpublished source. For example, from the repository root:

```bash
SDK_SOURCE="$PWD/sdks/go"
SDK_EXAMPLE="$(mktemp -d)"
(
  cd "$SDK_EXAMPLE"
  go mod init example.com/yabanin-sdk-demo
  go mod edit -require=github.com/reireirei/yabanin/sdks/go@v0.0.0
  go mod edit -replace="github.com/reireirei/yabanin/sdks/go=$SDK_SOURCE"
  cat > main.go <<'GO'
package main

import (
    "context"
    "fmt"
    "log"
    "os"
    "time"
    yabanin "github.com/reireirei/yabanin/sdks/go"
)

func main() {
    client, err := yabanin.New(yabanin.Config{
        BaseURL: "http://127.0.0.1:8082",
        APIKey: os.Getenv("YABANIN_API_KEY"),
    })
    if err != nil { log.Fatal(err) }
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    response, err := client.Chat(ctx, yabanin.ChatRequest{
        Model: "mock-model",
        Messages: []yabanin.Message{{Role: "user", Content: "Hello from the Go SDK"}},
    })
    if err != nil { log.Fatal(err) }
    if len(response.Choices) == 0 { log.Fatal("Missing reply choices") }
    fmt.Println(response.Choices[0])
}
GO
  go mod tidy
  go run .
)
```

Expected result for each example is a non-empty mock reply. A `401` usually
means the gateway key is missing or wrong; a `404` can indicate a URL/model
mismatch. Check the quickstart curl request before debugging an SDK. No example
here establishes real-provider or streaming support.

The Node/Python packages also contain analytics and lineage methods. Their
presence and mock tests do not establish a working browser-admin session or
organization authorization flow. A gateway bearer key is not automatically an
admin credential. This first-call guide covers the inference method only.

## Historical verification records

The rows below preserve checks recorded by earlier development work. They are
not fresh verification of this documentation change, the latest checkout, or
your deployment. Installation examples above still require the local acceptance
check described there. Compare each recorded dependency version with your
checkout before treating its result as applicable.

### Status rules (read before citing any green row)

- A `tested` row is bound to the exact triple **(version, date, command)** in
  its Evidence column. Evidence level here is **offline unit test against an
  in-process mock** (`httptest`, `vi.stubGlobal(fetch)`, `respx`) unless a row
  says otherwise — it is not a live-gateway or live-upstream run.
- **Updating any version invalidates the row.** A dependency, toolchain or SDK
  version change resets that row to `not verified` until the listed command is
  re-run and this page is re-dated. An old green badge is never a guarantee for
  a new version: if the date does not match the shipped version, the row is
  stale by definition.
- Missing evidence is `not verified` (or `source-reviewed` where only code was
  inspected). Absence of a failing test is not a pass.
- Re-verification is cheap: every `tested` command below runs offline in
  seconds with no network or credentials.

Historical matrix verification date: **2026-10-28** (environment: darwin/arm64,
go1.27.3, node v26.10.0, npm 11.19.1).

## Go SDK — `github.com/reireirei/yabanin/sdks/go`

| Component | Version | Pin source | Endpoint | Evidence (date) | Status | Limitations |
|---|---|---|---|---|---|---|
| Go SDK module | module `sdks/go`, `go 1.25`, toolchain `go1.27.3` | `sdks/go/go.mod` | `POST /v1/chat/completions` only | `go test ./... -count=1` — 6 PASS, 1 design-skip, exit 0 (2026-10-28, go1.27.3 darwin/arm64) | tested | Mock upstream only (`httptest`); no live gateway/upstream run. Single endpoint: no `spend`, no lineage helpers in this SDK. |
| `github.com/sashabaranov/go-openai` | v1.41.2 | `sdks/go/go.mod` `require` | — (never imported by `yabanin.go`) | `rg sashabaranov sdks/go` → go.mod only; `go vet ./...` exit 0; `gofmt -l` empty (2026-10-28) | source-reviewed | **Declared but unused**: the SDK is stdlib-only. No `go.sum` committed. Do not infer coverage of this dependency from SDK tests. |

Symbols pinned by the tests: `Config`, `ConfigFromEnv`, `Client`, `New`,
`Client.BaseURL`, `Client.APIKey`, `Message`, `ChatRequest`, `ChatResponse`,
`Client.Chat`, `truncate`. Behavior pinned: bearer auth header, 401/non-2xx
surfaces as a Go `error` carrying status + verbatim error envelope (never
decoded into a completion), `YABANIN_*` env with `TOKENROUTER_*` legacy
fallback, saas/on-prem base-URL defaults.

## Node SDK — `@yabanin/tr-node` 0.1.0

| Component | Version | Pin source | Endpoint | Evidence (date) | Status | Limitations |
|---|---|---|---|---|---|---|
| Node SDK package | 0.1.0 | `sdks/node/package.json` | `POST /v1/chat/completions`; `GET /api/analytics/savings`; `GET /api/lineage/{id}`; `POST /api/lineage/{id}/verify` | `vitest run` — 7/7 PASS, exit 0 (2026-10-28, node v26.10.0, vitest 1.6.1) | tested | `fetch` is stubbed in tests (`vi.stubGlobal`) — no real socket exercised. `dist/` is gitignored while `main`/`types` point at `dist/index.js`: a consumer must build first; install from source as shown above. No `engines` field declared. |
| `openai` (peer) | declared `^4.50.0`; lockfile-resolved **4.104.0** | `package.json` peerDependencies; `package-lock.json` (lockfileVersion 3) | — (never imported by `src/`) | lockfile inspected; `node_modules/openai/package.json` = 4.104.0 (2026-10-28) | source-reviewed | **Declared but unexercised**: `src/` uses global `fetch`, not the peer SDK. Widest-tested combination is 4.104.0; the `^4.50.0` floor is not separately verified. The declared range is broader than the tested version. |
| `typescript` / `vitest` / `msw` (dev) | 5.9.3 / 1.6.1 / 2.15.0 | `package-lock.json` | — | vitest executed 2026-10-28; tsc/msw not exercised this cycle | source-reviewed | `npm run build` (tsc) not run this cycle — `dist/` output unverified here. `msw` installed but unused by tests. |

Symbols pinned by the tests: `Client` (`chat`, `spend`), `LineageHelper`
(`get`, `verify`), config consts `BASE_URL`/`ADMIN_URL`/`API_KEY` (`YABANIN_*`
canonical, `TOKENROUTER_*` legacy fallback). Behavior pinned: non-2xx throws
with status + body text, exact URL shapes incl. `?days=N` query.

## Python SDK — `tokenrouter` 0.1.0

| Component | Version | Pin source | Endpoint | Evidence (date) | Status | Limitations |
|---|---|---|---|---|---|---|
| Python package | 0.1.0 (`__version__`) | `sdks/python/pyproject.toml` | `POST /v1/chat/completions`; `GET /api/analytics/savings`; `GET/POST /api/lineage/{id}(/verify)` | 29 test cases executed via `PYTHONPATH=sdks/python python3 -m pytest tests -q` → **29/29 PASS, 2.74s** (2026-10-28, post-review; pytest 9.1.1, httpx 0.28.1, respx present; `openai` not required — never imported) | pass (mock transport) | `requires-python >=3.9` floor unexercised on other interpreters; no lockfile (see `httpx` row). Re-run: `PYTHONPATH=sdks/python python3 -m pytest sdks/python/tests -q`. |
| `httpx` | floor `>=0.27` — **no lockfile** | `pyproject.toml` dependencies | transport for all endpoints | manifest inspected (2026-10-28) | source-reviewed | No `requirements.txt`/lock file committed: the resolved runtime version is environment-dependent and cannot be cited as tested. Lockfile/pin decision is a follow-up. |
| `openai` | floor `>=1.40` | `pyproject.toml` dependencies | — (never imported by the package) | `rg openai sdks/python/tokenrouter/` → docstring only (2026-10-28) | source-reviewed | **Declared but unused**; the SDK is httpx-based. Follow-up: drop or actually build on it. |

Symbols covered by the recorded Python tests: `Config`, `config_from_env`,
`Client` (`spend`, `chat.completions.create`), `LineageHelper` (`get`,
`verify`), TP-23 precedence matrix (explicit arg → `YABANIN_*` → legacy
`TOKENROUTER_*` → deployment defaults; empty env = absent; whitespace never
trimmed).

## Client pages (docs/clients/)

Each page documents one client against the gateway and states its own
verification level; the gateway-side rows and evidence dates live in
[../compatibility.md](../compatibility.md).

| Page | Client-facing endpoint | Pinned version / config | Evidence date (per matrix) | Status | Limitations |
|---|---|---|---|---|---|
| [codex.md](codex.md) | `POST /v1/responses` | codex-cli **0.166.0**, `wire_api="responses"` | real-binary e2e 2026-11-03 (see client page) | tested | Mock upstream behind the gateway; paid-upstream run is not covered. `previous_response_id` → 400 everywhere (stateless). Dropped fields announced via `X-Yabanin-Unsupported`. |
| [claude-code.md](claude-code.md) | `POST /v1/messages`, `POST /v1/messages/count_tokens` | `anthropic-version: 2023-06-01` header | fixture 2026-09-30 | tested (shaped traffic) | No live Claude Code binary run. Translation drops `thinking`, hosted tools, `cache_control`. |
| [opencode.md](opencode.md) | `POST /v1/chat/completions` | config sketch | fixture 2026-09-30 | tested (shaped traffic) | No live OpenCode binary run. |
| [cline.md](cline.md) | `POST /v1/chat/completions` | config sketch | fixture 2026-09-30; streaming fixture 2026-10-12 | tested (shaped traffic) | No live Cline session. |
| [continue.md](continue.md) | `POST /v1/completions` (FIM), `POST /v1/chat/completions` | config sketch | fixture 2026-09-30 | tested (shaped traffic) | Completions row is fill-in-the-middle only, not chat. |

Native Gemini ingress (`generateContent`/`streamGenerateContent`) is deferred
in this preview and therefore has **no row here or in the
compatibility matrix**; the client-facing protocol scope is OpenAI Chat
Completions, OpenAI Responses and Anthropic Messages. Conversation
continuation via `previous_response_id` is unsupported with a clear 400 ;
clients resend full history.

## Cross-SDK endpoint coverage

| Endpoint | Go | Node | Python |
|---|---|---|---|
| `POST /v1/chat/completions` | ✓ `Client.Chat` | ✓ `Client.chat` | ✓ `chat.completions.create` |
| `GET /api/analytics/savings` | — | ✓ `Client.spend` | ✓ `Client.spend` |
| `GET /api/lineage/{id}` | — | ✓ `LineageHelper.get` | ✓ `LineageHelper.get` |
| `POST /api/lineage/{id}/verify` | — | ✓ `LineageHelper.verify` | ✓ `LineageHelper.verify` |
| `POST /v1/responses`, `POST /v1/messages`, `POST /v1/completions` | — | — | — (client-page territory; no SDK method) |

Limitations: the Go SDK is chat-only (no admin control-plane methods); no SDK
exposes Files/Batches, media or streaming helpers; SDK surface is a
convenience slice, not the full documented API (consult the API contract and OpenAPI for the broader surface). Unsupported-field behavior is documented per route in the
[compatibility matrix](../compatibility.md). Provider-side integrations are
separate from this client SDK matrix.

## Follow-ups recorded (not done here)

1. Remove or exercise the three declared-but-unused dependencies
   (go-openai, node `openai` peer, python `openai`) — dependency changes need
   license review and fresh verification; not a documentation-only edit.
2. Add a Node `engines`/CI pin and verified release packaging. The source
   build step is documented above; it does not establish registry publication.
3. Python: add a lockfile or exact-pin dev requirements. (Suite executed
   post-review 2026-10-28: 29/29 PASS; see the Python row above.)
4. Go: mirror `spend`/lineage helpers for parity, or document chat-only scope
   in README (no README exists today).
5. Mirror SDK rows into `docs/compatibility.md` by the matrix owner once any
   row above graduates from mock-level evidence.

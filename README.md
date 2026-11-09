# Yabanin Core

Yabanin Core is a self-hosted AI gateway. Connect applications through
OpenAI-compatible or Anthropic-compatible APIs, route requests to model
providers, manage access and budgets, and inspect request logs and usage.

This is a **Developer Preview**. Read the release notes before deploying it
with production traffic.

## Quickstart with Docker Compose

Start the whole local stand — gateway, PostgreSQL, Redis, a mock model
provider, and the dashboard UI — with one Compose stack. No provider account
or paid inference is needed. The mock returns sample responses so you can try
the API, request logging, and the dashboard. Nothing listens on `0.0.0.0`.

You need Docker with Compose v2, Git, Bash, OpenSSL, curl, and Python 3.
On Windows, use WSL2 with Docker integration. Keep localhost ports **3000**
(dashboard), **8082** (gateway), and **8086** (admin API) and Docker subnet
**10.207.0.0/24** available. The first build downloads Go modules and
container images; you do not need Go or Node.js installed on your computer
(see [First-start timing](#first-start-timing)).

### 1. Download, configure, and start

```bash
git clone https://github.com/yabaninai/yabanin-core.git
cd yabanin-core

bash scripts/quickstart/init-env.sh

docker compose -f deploy/quickstart/docker-compose.yml \
  --profile mock --profile ui build \
  --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"

docker compose -f deploy/quickstart/docker-compose.yml \
  --profile mock --profile ui up -d --no-build --wait
```

The `mock` profile adds the mock provider; the `ui` profile adds the
containerized dashboard on **http://127.0.0.1:3000**. Omit `--profile ui` for
a leaner stack without the dashboard. Configuration is saved in
`deploy/quickstart/.env`; keep this file with your database between restarts.

### 2. Create your organization and credentials

```bash
bash scripts/quickstart/seed.sh
```

Save the **gateway API key** and **admin password** printed by the command.
They are shown once. The default admin email is `admin@localhost`.

### 3. Send a request

Paste the gateway API key when prompted:

```bash
read -r -s -p "Gateway API key: " YABANIN_API_KEY
printf '\n'

curl --fail-with-body --silent --show-error \
  http://127.0.0.1:8082/v1/chat/completions \
  -H "Authorization: Bearer $YABANIN_API_KEY" \
  -H 'Content-Type: application/json' \
  --data '{"model":"mock-model","stream":false,"messages":[{"role":"user","content":"Hello from Yabanin"}]}'
```

You should receive a chat response with `choices[0].message.content`.
Check model discovery, chat responses, and request logging together:

```bash
bash scripts/quickstart/smoke.sh "$YABANIN_API_KEY"
```

### 4. Open the dashboard

Open **http://127.0.0.1:3000** and sign in with the admin credentials from
step 2 (default email `admin@localhost`). The dashboard container serves the
built UI and proxies `/api` and `/auth` to the admin API on the same origin,
so no local Node.js and no CORS configuration are needed. Port 8086 serves
the admin API itself; it does not serve the dashboard.

The [full quickstart](docs/quickstart.md) covers organization membership,
request history, real providers, and troubleshooting. To iterate on the
dashboard source with hot reload, install Node.js 22 and npm and run in
another terminal:

```bash
npm ci --prefix web/dashboard
npm --prefix web/dashboard run dev -- --host 127.0.0.1
```

Then open **http://127.0.0.1:5173**.

To stop the stack while keeping its database:

```bash
docker compose -f deploy/quickstart/docker-compose.yml \
  --profile mock --profile ui down
```

### First-start timing

With images built once, `up -d --wait` finishes in about ten seconds, and the
`mock-openai` container itself starts in under a second (its health check
polls every two seconds). If the stand appears to hang on the mock, it is
waiting on image transfer or build, not on the service. The first start is
dominated by three things:

- **Image pulls — the largest cost, network-bound.** The builds download the
  pinned `golang` builder image and Alpine, Node, and nginx base images, and
  `up` pulls the pinned PostgreSQL and Redis images; together roughly a
  gigabyte unpacked. On a slow or throttled link to Docker Hub this takes
  minutes and the progress lines sit on `mock-openai` for most of it, which
  is why the mock *looks* like the slow part. Configuring a registry mirror
  is the effective fix.
- **Compilation.** The gateway image downloads all Go modules and compiles
  the whole monorepo (about a minute on a fast machine); the mock image
  compiles its binary. BuildKit layer cache plus the mock's persistent Go
  build cache make later rebuilds take seconds.
- **The dashboard build** runs `npm ci` and the Vite production build (tens
  of seconds).

Restarting later reuses the layer cache and the named database volume, so
`up` returns in seconds.

## What is included

- Gateway APIs for connecting model clients and applications.
- Provider routing, request policies, rate limits, and caching.
- Organizations, API keys, budgets, and usage reporting.
- An admin API, React dashboard, and the `yb` operator CLI.
- PostgreSQL request storage and a Redis-backed log consumer.

Protocol support varies by endpoint and client. See the
[compatibility guide](docs/compatibility.md) for supported operations.
Costs depend on configured prices and recorded usage. The bundled reference
prices have limited coverage and may be outdated; LiteLLM pricing data is not
included. Configure current prices before relying on cost reports. The mock quickstart makes no paid provider calls.

## Documentation

| Task | Guide |
| --- | --- |
| Understand the request path | [Introduction](docs/intro.md) · [Architecture](docs/architecture.md) |
| Connect an application | [Compatibility](docs/compatibility.md) · [SDKs](docs/clients/sdk-versions.md) |
| Set up access and provider keys | [Organizations](docs/organization-setup.md) · [BYOK](docs/byok.md) |
| Configure routing and policies | [Providers](docs/providers.md) · [Pipeline](docs/pipeline.md) |
| Inspect a local request log | [Spend audit](docs/audit.md) · [CLI](docs/cli.md) |
| Deploy and operate | [Deployment](docs/deployment-options.md) · [Production runbook](docs/runbooks/production.md) |
| Build and contribute | [Development](docs/DEVELOPMENT.md) · [Contributing](CONTRIBUTING.md) |

## Build from source

Use the Go version declared in `go.mod`, Git, and make:

```bash
make unified yb
./yb --help
```

`yabanin` runs the server components, migrations, and bootstrap commands.
`yb` provides operator commands. For service configuration and tests, see
[Development](docs/DEVELOPMENT.md).

## Security

Keep provider credentials and the generated `.env` file out of Git.
The quickstart is a local demonstration; use deployment-specific secrets and
network settings for production. See [SECURITY.md](SECURITY.md) to report a
vulnerability and the release notes for known issues.

## License

Yabanin Core is licensed under [Apache-2.0](LICENSE), copyright 2026
Dmitry Lakhvich. Commercial use, modification, and redistribution are permitted
under that license. Third-party materials retain their own terms; see
[NOTICE](NOTICE) and [LICENSING.md](LICENSING.md).
The license does not grant rights to the Yabanin trademarks beyond its terms.

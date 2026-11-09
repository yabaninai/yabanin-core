# Yabanin Core

Yabanin Core is a self-hosted AI gateway. Connect applications through
OpenAI-compatible or Anthropic-compatible APIs, route requests to model
providers, manage access and budgets, and inspect request logs and usage.

This is a **Developer Preview**. Read the release notes before deploying it
with production traffic.

## Quickstart with Docker Compose

Start a local gateway with PostgreSQL, Redis, and a mock model provider.
No provider account or paid inference is needed. The mock returns sample
responses so you can try the API and request logging.

You need Docker with Compose v2, Git, Bash, OpenSSL, curl, and Python 3.
On Windows, use WSL2 with Docker integration. Keep ports **8082** and **8086**
and Docker subnet **10.207.0.0/24** available. The first build downloads Go
modules and container images; you do not need Go installed on your computer.

### 1. Download, configure, and start

```bash
git clone https://github.com/yabaninai/yabanin-core.git
cd yabanin-core

bash scripts/quickstart/init-env.sh

docker compose -f deploy/quickstart/docker-compose.yml --profile mock build \
  --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"

docker compose -f deploy/quickstart/docker-compose.yml --profile mock \
  up -d --no-build --wait
```

The stack binds to localhost. Configuration is saved in
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

### 4. Open the dashboard (optional)

With Node.js 22 and npm installed, run in another terminal:

```bash
npm ci --prefix web/dashboard
npm --prefix web/dashboard run dev -- --host 127.0.0.1
```

Open **http://127.0.0.1:5173** and sign in with the admin credentials from
step 2. Port 8086 serves the admin API; it does not serve the dashboard.
The [full quickstart](docs/quickstart.md) covers organization membership,
request history, real providers, and troubleshooting.

To stop the stack while keeping its database:

```bash
docker compose -f deploy/quickstart/docker-compose.yml --profile mock down
```

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

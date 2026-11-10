---
title: Quickstart
description: Build a local Yabanin gateway, make a first request without a provider key, and open the optional dashboard.
---

# Quickstart

Run Yabanin locally, create an organization and credentials, and send your
first request. The default upstream is a **mock**: no provider account,
model download, or paid inference is needed. Its replies demonstrate the
request path, not model quality.

Demo requests do not incur provider charges, and demo cost figures are not
live provider quotes. For a real provider, configure and verify your own
applicable prices; a missing price means unknown cost, not free inference. See
[pricing data and optional imports](compat/litellm-migration.md#pricing-data).

This guide is for the **Developer Preview**. It starts PostgreSQL, Redis,
a mock provider, one Yabanin process containing the gateway, admin API, and
log consumer, and (with the `ui` profile) the containerized React dashboard.
Published ports bind to `127.0.0.1`.

## Before you start

Use a Bash shell on Linux, macOS with Docker Desktop, or Windows through
WSL2 with Docker integration. The commands below run from the repository
root. You need:

- Git, Docker Engine or Docker Desktop, and Docker Compose v2 with `--wait`.
- Bash, `make`, OpenSSL, `curl`, and Python 3 (used by the smoke check).
- Internet access for container base images and Go modules during the first
  build. Go itself is installed inside the build image; host Go is optional.
- Enough Docker memory and disk space to compile the gateway and run
  PostgreSQL and Redis. Start with at least 4 GB of Docker memory; this is
  a development sizing guideline, not a measured production requirement.
- Free localhost ports **3000** (dashboard), **8082** (gateway), and
  **8086** (admin API), and an available Docker subnet **10.207.0.0/24**.

Check the tools and daemon before downloading dependencies:

```bash
git --version
docker version
docker compose version
bash --version
make --version
openssl version
curl --version
python3 --version
```

A Docker client without a reachable daemon is insufficient. Docker group
membership grants substantial host access; use your normal approved Docker
installation rather than changing host permissions for this guide.

## 1. Obtain and verify the source

Download or clone the public **yabanin-core** repository linked from the
release announcement, then enter its root directory. Choose the release tag
or commit named by that announcement; do not substitute an unrelated latest
branch or an unverified image.

```bash
# Run inside your yabanin-core checkout.
git status --short
git rev-parse HEAD
git show -s --format='%h %s'
```

The working tree should be clean. Compare the full commit with the release
record obtained from a source you trust. A matching commit or checksum alone
does not authenticate a publisher. When signed release artifacts are
available, obtain the expected signing identity or public key independently
and follow [artifact verification](onprem/offline-bundle.md).

The steps below build Yabanin from this checkout. They do not download a
prebuilt Yabanin release. Third-party Compose images are pinned by digest.

## 2. Generate local configuration

```bash
bash scripts/quickstart/init-env.sh
```

Expected output on a new checkout:

```text
wrote deploy/quickstart/.env (mode 600)
```

The file contains randomly generated session, cache-HMAC, and encryption
keys plus the mock model settings. Keep it private. Running the command
again leaves the existing file unchanged. Retain this file together with
the database when restarting; replacing its encryption key can make stored
credentials unreadable.

## 3. Build and start

The Dockerfile requires a source timestamp for reproducible builds. Pass the
checked-out commit time explicitly:

```bash
docker compose -f deploy/quickstart/docker-compose.yml \
  --profile mock --profile ui build \
  --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"

docker compose -f deploy/quickstart/docker-compose.yml \
  --profile mock --profile ui up -d --no-build --wait

docker compose -f deploy/quickstart/docker-compose.yml \
  --profile mock --profile ui ps -a
```

The `ui` profile adds the `dashboard` service; omit it for a leaner stack
without the web interface. The first build can take several minutes — see
the timing notes in the repository README. `postgres`, `redis`,
`mock-openai`, `yabanin`, and `dashboard` should become healthy. The one-shot
`migrate` and `db-app-role` services should finish with exit code **0**; an
exited migration container is expected. The seed service has not run yet.

Do not replace these two steps with `make quickstart-up` in this preview:
that target performs a build without forwarding the required timestamp.
The explicit build followed by `--no-build` is the supported sequence here.

Check the gateway independently:

```bash
curl --fail-with-body --silent --show-error http://127.0.0.1:8082/healthz
```

Expect JSON containing `"status":"ok"`, plus build and dependency information.
This checks service health; it does not
yet prove that a model request can succeed.

## 4. Create your organization and credentials

```bash
bash scripts/quickstart/seed.sh
```

The command creates the bootstrap organization, team, model, budget, credits,
a gateway API key, and a root admin. It prints:

- **API key (shown once, store it now):** use this for gateway requests.
- **Admin password (shown once, store it now):** use this for browser login.

Save both in your password manager. They are different credentials; the admin
password is not a gateway bearer token. The default admin email is
`admin@localhost` (`QS_ADMIN_EMAIL` in the generated configuration).

A second seed run reuses existing records and does **not** reveal the API key
or reset the admin password. Demo credits are local accounting data, not
credit with an external provider.

## 5. Make your first request

Read the gateway key without saving it in shell history:

```bash
read -r -s -p "Gateway API key: " YABANIN_API_KEY
printf '\n'
export YABANIN_API_KEY

curl --fail-with-body --silent --show-error \
  http://127.0.0.1:8082/v1/models \
  -H "Authorization: Bearer $YABANIN_API_KEY"
```

The model list should contain **`mock-model`**. Send a chat request:

```bash
curl --fail-with-body --silent --show-error \
  http://127.0.0.1:8082/v1/chat/completions \
  -H "Authorization: Bearer $YABANIN_API_KEY" \
  -H 'Content-Type: application/json' \
  --data '{"model":"mock-model","stream":false,"messages":[{"role":"user","content":"Hello from Yabanin"}]}'
```

Expect HTTP 200 and a non-empty `choices[0].message.content`. The exact mock
text is not a stable contract. To check the gateway, model list, chat reply,
and asynchronous PostgreSQL request logging together, run:

```bash
bash scripts/quickstart/smoke.sh "$YABANIN_API_KEY"
```

Expected final line: `smoke ok (N request log rows)`, where `N` is at least 1.
The check waits for the log consumer, so it takes several seconds. On a fresh
database it verifies local plumbing against the mock. It counts cumulative
log rows: on later runs, old rows can satisfy the logging check, so inspect
the new request separately when diagnosing delivery. It does not establish live provider or
coding-client compatibility. See the [compatibility matrix](compatibility.md).

## 6. Open the dashboard

Open **http://127.0.0.1:3000** (the `dashboard` service from the `ui`
profile). Port **8086 is the admin API**, not the dashboard; a JSON response
at its root after login is expected. On the initial “Session expired” screen,
click **Sign in**; that message also appears when you have not signed in
before. Sign in with `admin@localhost` and the admin password from step 4.
The dashboard container serves the built UI and proxies `/auth` and `/api`
to the admin API on the same origin, so no local Node.js is needed. Keep the
same hostname (`127.0.0.1`) throughout the login flow.

To iterate on the dashboard source with hot reload instead, install Node.js
22 and npm, open a second terminal at the repository root, and run:

```bash
npm ci --prefix web/dashboard
npm --prefix web/dashboard run dev -- --host 127.0.0.1
```

Open **http://127.0.0.1:5173**. The development server proxies `/auth` and
`/api` to port 8086. If Vite selects another port because 5173 is busy, use
the exact URL printed in its terminal.

Select the seeded **Seed** organization. Click **Skip for now** on the welcome
screen: the mock does not require an organization provider credential.

### View the requests you just made

The seed creates a platform administrator but does not add organization
membership. Request-history access is separately scoped; an empty Request
explorer at this point does not mean the log consumer failed.

For this disposable local organization:

1. In another tab in the same browser, open
   **http://127.0.0.1:3000/api/me**. Copy the top-level `id` value from the JSON
   response. It identifies your admin user; it is not an API key.
2. Return to the dashboard and open **Teams & members** with **Seed** selected.
3. In **Members**, paste that ID into **User ID**, choose **reader**, and click
   **Add member**. This grants organization metadata visibility without needing
   an organization-admin role.
4. Open **Request explorer**. The mock requests should now appear with status
   `200`. If a very recent request is outside the displayed time range, refresh
   the view and check its period/filter settings.

The **Developers** subsection can report an unavailable API in this preview;
it is not needed for adding the existing administrator as a member. Organization
membership and request-content access have separate permissions; seeing metadata
does not grant unrestricted original-payload access. See
[organization setup](organization-setup.md).

This Vite setup is for local development. Serve a built dashboard behind a
properly configured HTTPS reverse proxy for an external deployment; do not expose
the development server as a production console.

## Use a real model next

Keep the working mock setup while learning the control plane. A provider
credential alone does not register a model or change its upstream URL.
For a real request you need **all three**:

1. A model registry entry with the correct provider, model identifier, and
   upstream URL.
2. Credentials for that provider, where required; [BYOK](byok.md) explains
   organization credentials and precedence.
3. Gateway egress policy allowing that upstream and the selected
   organization's access and budget policies allowing the request.

OpenAI-compatible local inference servers can avoid external provider
charges, but still need network access from the container. Container
`localhost` is the container itself, not your host. Private-address upstreams
require an explicitly allowed **IP literal**; a hostname resolving to a
private address is rejected by the rebinding guard. Do not disable that
protection to make an example work.

Use the [provider guide](providers.md) and [BYOK setup](byok.md) for the
configuration boundary. Real-provider requests can incur charges. The
mock test above makes no such calls.

## Stop, restart, and reset

Stop the Compose services (the dashboard container stops with them):

```bash
docker compose -f deploy/quickstart/docker-compose.yml \
  --profile mock --profile ui down
```

This retains the named PostgreSQL volume and your configuration file. To
restart the same checkout without rebuilding:

```bash
docker compose -f deploy/quickstart/docker-compose.yml \
  --profile mock --profile ui up -d --no-build --wait
bash scripts/quickstart/smoke.sh "$YABANIN_API_KEY"
```

Your existing gateway key and admin password should still work. Redis is
not persisted in this stack; cached responses are disposable.

**Reset deletes this quickstart's database, users, keys, credits, and logs.**
Only run this on the disposable local stack created by this guide:

```bash
docker compose -f deploy/quickstart/docker-compose.yml \
  --profile mock --profile ui down -v
```

Start again with step 3's `up` command and repeat step 4. The old key will no
longer work; store the new credentials. Do not delete shared Docker volumes
or use `docker system prune` as a troubleshooting step.

When finished with requests in your shell:

```bash
unset YABANIN_API_KEY
```

## Troubleshooting

| Symptom | Check and recovery |
| --- | --- |
| `SOURCE_DATE_EPOCH must be an integer` during build | Use the explicit build command in step 3 from a Git checkout. Setting an environment variable without passing the build argument is insufficient. |
| Docker cannot connect | Start Docker Engine/Desktop and confirm `docker version` shows both client and server. |
| Port already allocated | Stop only your own conflicting service, or select different quickstart ports as described below. |
| Network pool overlaps | The stack reserves `10.207.0.0/24`. Inspect `docker network ls` / `docker network inspect`; do not remove another stack's network. Use a separate Docker host for this default setup if the subnet is already in use. |
| Container unhealthy or migration exited nonzero | Read the service logs using the command below. Fix the first failed dependency before rerunning `up`; do not manually replay all SQL migration files. |
| `401` from `/v1/models` or chat | Use the gateway key printed by seed, not the admin password. After a reset, use the newly issued key. |
| `402` from chat | Inspect the organization's credits and budget. Local credits do not fund upstream accounts. |
| `502` / `503` from chat | Check mock health, upstream configuration, logs, and egress policy. Keep the generated URL and model unchanged for the first run. |
| Seed says the key/user already exists | Seeding is idempotent. Use the credentials saved earlier; it is not a password-reset command. For disposable data, use the explicit reset above. |
| Request explorer is empty after successful smoke | Add the seeded admin as a `reader` of Seed using step 6; then check time filters and logging. |
| Browser shows JSON at 8086 | Open **http://127.0.0.1:3000** instead; port 8086 is the admin API, not the dashboard. |
| Smoke reports no request log rows | Inspect the `yabanin` logs and PostgreSQL/Redis health. A health response alone does not verify log persistence. |

```bash
docker compose -f deploy/quickstart/docker-compose.yml \
  --profile mock --profile ui \
  logs --tail=100 yabanin migrate db-app-role postgres redis mock-openai dashboard
```

Review and redact logs before sharing them. Never attach the generated `.env`,
API keys, admin passwords, session cookies, or private request content.

For alternative host ports, add `QS_GATEWAY_PORT=18082`,
`QS_ADMIN_PORT=18086`, and `QS_DASHBOARD_PORT=13000` to
`deploy/quickstart/.env` **before starting**. Use the matching URLs; run
smoke with `QS_BASE=http://127.0.0.1:18082`. For the Vite development
server, start npm with `YABANIN_ADMIN_URL=http://127.0.0.1:18086`. These
settings do not change the reserved subnet or create isolated copies of the
stack.

## Before deploying to production

- Production security: database credentials are fixed local-development
  values; TLS, backups, external exposure, and operational access need a
  separate deployment review.
- Real model quality, live provider compatibility, or guaranteed savings.
- Semantic cache quality: this stack does not include an embedding service.
- A supported upgrade or downgrade between arbitrary preview schemas.
- A vulnerability-free release. Read `SECURITY.md` and the selected release's
  security notes before enabling optional integrations.

Continue with [organization setup](organization-setup.md),
[client configuration](compatibility.md), or
[deployment options](deployment-options.md).

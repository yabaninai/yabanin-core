# Local demonstration

Use the **[quickstart](quickstart.md)** for a reproducible local demonstration.
It builds Yabanin from your checkout, starts PostgreSQL, Redis and a mock
provider, creates credentials, and verifies a chat request and persisted
request logs. The dashboard is an optional separate step.

## A useful demonstration sequence

1. Complete the quickstart through its smoke check. Keep the gateway API key
   and admin password private; they serve different purposes.
2. Start the dashboard as described there and sign in. Select the seeded
   organization before viewing keys, requests, or credits.
3. Send another mock request using the quickstart's curl command. Allow time
   for the log consumer before refreshing analytics.
4. Inspect the model, status, and usage associated with that request. Explain
   which figures are recorded usage and which are estimates.
5. Stop the dashboard and Compose stack with the quickstart's shutdown
   commands. Retain the volume and configuration to resume later.

Mock replies show that the local request path works. They do not measure model
quality, semantic cache quality, real-provider compatibility, or savings on a
customer workload. Local demo credits are accounting data; they do not fund
an external provider account. A healthy service does not by itself establish
a successful model request.

To demonstrate offline analysis instead, use the self-contained synthetic
fixture in [Offline spend audit](audit.md). Its small sample deliberately
produces an insufficient-sample warning.

## Legacy demo harness

The repository also contains `scripts/demo/run_demo.sh`, used by `make demo`.
It targets the broader `deploy/docker-compose.yml` development stack. It is
not a clean-checkout installer: it assumes separately provisioned secret files
and configuration, and the Docker image still requires its reproducible-build
timestamp. The script does not create every secret required by that stack.

The harness counts failed inference calls but can still print its completion
message. Treat that message as script completion, not proof of successful
requests or populated dashboard screens. It also uses synthetic upstream and
embedding behavior; resulting cache and dollar figures are demonstration
values. This guide makes no fixed startup-time promise.

For a new installation, follow the quickstart rather than adapting that legacy
harness. For an existing installation, use deployment-specific operating
procedures; do not run a demo reset or teardown against shared data.

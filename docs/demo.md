# Local demonstration

From the root of your Core checkout run `bash scripts/quickstart/demo.sh`.
It builds the gateway and dashboard from that checkout. On completion open
the printed Requests link and sign in using the private `admin-password`
file. In the Seed organization compare the review, support, documentation and
tool-planning rows. The mock returns a grep/read plan for the tools example.
Each row has its own request ID, job label and recorded token usage.

### Optional provider endpoints at installation

Keep a JSON manifest and its private key files in a directory outside the Core
checkout. Protect each key file with mode 600. Use the model IDs accepted by
the upstreams. The manifest may contain several distinct models:

```json
[
  {"model":"model-a","base_url":"https://provider-a.example/v1","key_file":"a.key"},
  {"model":"model-b","base_url":"https://provider-b.example/v1","key_file":"b.key"}
]
```

```bash
bash scripts/quickstart/demo.sh --providers /path/to/providers.json
```

The quickstart registers each model through the authenticated admin API and
verifies its URL, credential presence and catalog entry. The demo organization
uses explicit model selection. Automatic sample traffic always targets the mock.
Add `--probe-providers` to send one potentially billable chat to each model
and check its recorded route. Use `--ca-bundle /path/to/ca.pem` for private
HTTPS endpoints. Repeat the original setup options when resuming the stand.
The default state is under `~/.local/share/yabanin/quickstart/<compose-project>`
or the equivalent `XDG_DATA_HOME` path. Retain this directory with the
database volume and the quickstart environment file.

### Inspect a stored request

In Requests Explorer, open a request as a root operator. With Privacy mode off,
choose **Show request body and response (audited)**. This uses a single-use,
one-minute grant to display the stored request sent to the model *after*
routing and policies, not the original client HTTP body. If no upstream body
was captured (for example, on an exact cache hit), the inspector says so.
Close the drawer to dismiss the disclosed content.

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

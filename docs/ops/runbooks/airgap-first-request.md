# First request in an offline deployment

An offline installation needs all application and database images, configuration,
model files and dependencies before network isolation. Follow the
[offline bundle guide](../../onprem/offline-bundle.md) and
[installation guide](../../onprem/install-guide.md) for artifact verification and
installation. A bundle checksum detects changed bytes; publisher authentication
also requires an independently trusted signing key or identity.

## Prepare the deployment

1. Verify the selected release and record its image digests. Load the images into
   the registry available to the offline cluster.
2. Configure PostgreSQL, Redis, application secrets and persistent storage. Use
   the migration binary matching the application release.
3. Install the local model server and its model files. Model weights are separate
   inputs with their own license and hardware requirements; Yabanin does not
   include them.
4. Configure the model registry, provider endpoint and credentials for that local
   server. Restrict egress to the intended internal services.
5. Create an organization, team and API key with permission to use that model.
   Set budgets and prices deliberately; an unavailable price is unknown, not zero.

Use the deployment's actual Helm values or Compose configuration. The local
[quickstart](../../quickstart.md) demonstrates the API flow with a mock provider;
its deterministic reply is not a real model inference result.

## Verify isolation and a request

From the same network context as the gateway, verify that required internal
services are reachable and unintended external DNS and TCP destinations are not.
Do not infer isolation from an idle host or an empty application log.

Send an authenticated request using the configured gateway URL and a model ID
returned by `/v1/models`. Confirm that the response came from the local provider,
that usage is recorded, and that request history persists after a service restart.
Inspect errors and accounting for unknown-price cases as well as successful calls.

Keep the request, gateway and model-server timestamps together when diagnosing
failures. Retain status codes, configuration identifiers and image digests without
publishing API keys or prompt content.

## Rehearsal limits

`scripts/airgap/e2e_drill.sh` is a local development rehearsal using a mock model
and one Docker daemon for both connected preparation and isolated execution.
Its internal Docker network can demonstrate blocked egress for that stack; it
does not reproduce separate physical hosts, cluster network policy, GPU inference
or every behavior of your offline infrastructure. Review the script and its
resource names before running it on a shared host.

A license-format verification, if explicitly configured for your deployment, is
separate from artifact authenticity and network isolation. See
[license verification](../../license/customer-setup.md) for its inputs and limits.

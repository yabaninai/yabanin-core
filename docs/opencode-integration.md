# OpenCode integration

OpenCode can use Yabanin through its OpenAI-compatible gateway. Follow the
[OpenCode client guide](clients/opencode.md) to configure your gateway URL, API
key and available model IDs. The gateway does not install or select OpenCode
agent profiles for you.

## Routing and accounting

Requests use `POST /v1/chat/completions`. The selected model and routing policy
depend on your gateway configuration. Choose an ID returned by `GET /v1/models`;
do not assume that a model from another deployment exists locally.

The `X-Yabanin-Decision` response header exposes routing information. See
[agent governance](agent-governance.md#decision-header) for the header contract
and task accounting. Provider calls still require configured credentials and
applicable pricing; unknown prices must not be interpreted as free inference.

## Session controls {#governing-an-opencode-session}

- Send `X-Yabanin-Task` when the client supports custom headers to associate
  requests with a logical task, such as `feature-42`.
- Configure task and session token budgets for your workload. The gateway can
  return a budget warning and reject requests that exceed the configured limit;
  a client retry does not increase that limit.
- Configure guard hooks for sensitive traffic. Start with representative inputs
  and review matches before enabling blocking behavior. See
  [false-positive limitations](agent-governance.md#false-positive-limitations).
- Inspect request logs and [lineage](lineage.md) to investigate model selection,
  tool use and cost. Task tags are labels, not authentication credentials.

Yabanin handles the gateway traffic. Local editor tools, filesystem permissions,
agent approval settings and client-side subprocesses remain the responsibility
of the OpenCode installation.

## Test routing changes

Use the [evaluation guide](evaluation.md) to compare routing and guard behavior
on your own fixtures before changing production configuration. The local
[quickstart](quickstart.md) uses a mock provider and demonstrates connectivity;
it does not measure a real model's coding quality.

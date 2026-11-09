# Load-test scripts

These scripts measure a separately prepared test deployment. They do not create
provider credentials, register models or establish production capacity. Use a
disposable environment and record its configuration, hardware, versions,
concurrency, errors and raw results. Latency thresholds below are assertions in
the scripts, not published performance guarantees.

## Basic k6 scenarios

Install k6 using its supported platform instructions. From the repository root,
set the base URL and a valid key for your test organization. The three
`k6_*.js` scripts retain the historical `TOKENROUTER_*` variable names; setting
`YABANIN_*` does not configure them.

```sh
export TOKENROUTER_BASE_URL=http://127.0.0.1:18082
# Set TOKENROUTER_API_KEY in your environment to the test organization's key.
: "${TOKENROUTER_API_KEY:?Set a valid test-organization key}"
k6 run tests/load/k6_chat.js
```

The scripts default to `http://localhost:8082` and `yabanin-dev-key` when those
variables are absent; that default key is not created by the public quickstart.
Their hard-coded model IDs must exist and be authorized in the target deployment.
The quickstart's mock model alone does not satisfy these scenario inputs.

| Script | Requests/models | Configured assertions |
|---|---|---|
| `k6_chat.js` | Mixed prompts using `gpt-4o`; ramps as high as 1,000 virtual users. | p95 < 500 ms, p99 < 1,000 ms, failed requests < 1%, checks > 95%. |
| `k6_cache_hit.js` | Repeated prompts using `gpt-4o`; ramps to 200 virtual users. | p95 < 200 ms, checks > 90%; includes a separate fast-response check. |
| `k6_mixed_models.js` | Round-robin `gpt-4o`, `claude-3.5-sonnet`, `gpt-4o-mini`; ramps to 500 virtual users. | p95 < 800 ms, p99 < 1,500 ms, failed requests < 5%, checks > 90%. |

Choose the script explicitly:

```sh
k6 run tests/load/k6_cache_hit.js
k6 run tests/load/k6_mixed_models.js
```

Virtual-user counts are not request-per-second guarantees. End-to-end duration
includes provider latency. Repeated prompts and low latency alone do not prove
a cache hit: inspect cache counters and response metadata as well.

## Configurable benchmark scenarios

The `bench_*.js` scripts use `BASE_URL`, `API_KEY` and `BENCH_MODEL`, with
`BENCH_RPS`, `BENCH_DUR` and optional `BENCH_OUT` for rate, duration and summary
output. `API_KEY` is required. Prepare a registered model and the intended
policy state before running them; the scripts do not install policies.

| Script | Default load | Required deployment state |
|---|---|---|
| `bench_latency.js` | 50 arrivals/s for 120 seconds | Baseline with policy disabled. |
| `bench_pipeline_shadow.js` | 50 arrivals/s for 120 seconds | Matching policy in shadow mode. |
| `bench_pipeline_enforce.js` | 50 arrivals/s for 120 seconds | Matching policy in enforce mode; requests expected to pass. |
| `bench_breakers.js` | 30 arrivals/s for 90 seconds | Prepared healthy/failing upstream routes and the flap-control endpoint expected by the script. |

A small baseline example against an already prepared mock deployment:

```sh
export BASE_URL=http://127.0.0.1:18082
export BENCH_MODEL=mock
# Set API_KEY to the prepared organization's key.
: "${API_KEY:?Set a valid test-organization key}"
BENCH_RPS=2 BENCH_DUR=30s k6 run tests/load/bench_latency.js
```

Use the actual registered mock model ID if it differs. Reducing arrival rate
for a check does not validate the scripts' default load or release capacity.

## Sustained and long-response profiles

`soak_steady.js` uses constant-arrival-rate scheduling and unique prompts. Its
default is 20 new requests/s; `SOAK_DURATION`, `SOAK_RPS`, `SOAK_MODEL`,
`SOAK_PRE_VUS`, `SOAK_MAX_VUS` and `SOAK_COMPLETION_FLOOR` control the scenario.
It uses `BASE_URL` and requires `API_KEY`. Its assertions include zero dropped
iterations, a completion-rate floor (default 98% of the configured rate),
failed requests below 0.1%, p95 below 1,000 ms and checks above 99%.

[PROFILES.md](PROFILES.md) describes the burst and delayed-response inputs.
Report actual elapsed time, completed iterations and generator shortfalls;
a short or undersupplied run is not evidence of sustained capacity. The
scenario's end-to-end latency is not an isolated gateway-overhead measurement.

The orchestration helpers `run-soak.sh` and `run-profiles.sh` depend on
`deploy/docker-compose.prod.yml` and `deploy/docker-compose.e2e.yml`, which are
not included in the public Core export. The separate benchmark stand helper
`scripts/bench/run-bench.sh` is also not a public entry point. Consequently these orchestration
commands are not supported as self-contained public quickstarts. The k6 scripts
can target a separately provisioned environment, but reproducing the runners'
policy setup, Prometheus collection and backlog-recovery checks requires that
additional deployment setup. Do not claim those checks from a standalone k6 run.

In a checkout that provides those dependencies, the runners write summaries
under `artifacts/soak/` or `artifacts/profiles/`, use dedicated Compose projects,
and can retain their stacks for inspection. Review their cleanup behavior and
reserved ports before use; never direct them at a shared production stack.

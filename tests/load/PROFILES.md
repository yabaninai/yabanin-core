# Burst and long-response load profiles

These k6 scenarios send requests at a configured arrival rate to a real gateway
backed by a deliberately slow mock. Their numeric defaults are workload inputs,
not measured deployment capacity or a sustained-throughput guarantee. See
[README.md](README.md) for the basic scripts and steady soak scenario.

## Default scenarios

| Script and mode | Arrival window | Mock response delay | Approximate in-flight demand |
|---|---|---|---|
| `soak_burst.js` | Three 60-second bursts at 100 arrivals/s, separated by 300-second gaps. | 30 seconds | Up to about 3,000 requests per burst. |
| `soak_longres.js`, `LONG_MODE=30s` | 20 arrivals/s for 5 minutes. | 30 seconds | About 600 once the workload settles. |
| `soak_longres.js`, `LONG_MODE=120s` | 20 arrivals/s for 2 minutes. | 120 seconds | Ramps toward about 2,400. |

The in-flight figures are rate-times-duration estimates, not observations. The
long-response script also accepts `long30` and `long120` as mode aliases. Arrival
windows do not include all response-drain time, setup or recovery observation.

Each scenario uses constant-arrival-rate scheduling. Assertions include zero
dropped iterations and a completion count at least as large as the configured
rate multiplied by the arrival window. The summaries separately account for the
allowed boundary arrival at the end of a window. Failed HTTP requests must stay
below 1% for bursts and below 0.1% for long-response scenarios. The p95 duration
limit is the selected response delay plus five seconds. These are test
thresholds, not independent evidence of gateway overhead or availability.

## Required target environment

Register an authorized model that routes to `tests/load/slowmock`, and configure
the gateway to allow that upstream. The mock reads a `[delay=Ns]` marker from the
prompt (`ms`, `s` and `m` units; bounded to ten minutes). Its streaming response
spreads chunks over that interval, with the stop frame at the end. The
`MOCK_DELAY_MS` environment variable sets a process-wide default. The ordinary
instant mock does not provide this delayed-response scenario.

Before load, verify that both an instant request and a delayed request return
the intended response through the gateway. An error returned quickly is not a
successful low-latency sample. Ensure policy, caching and routing do not remove
or bypass the intended delay. The slow mock is a test service, not an upstream
provider configuration for production traffic.

## Standalone k6 inputs

Both scripts read `BASE_URL`, require `API_KEY` and use `PROFILE_MODEL` (default
`profile-model`). Configure these for the separately prepared environment. For
example, after registering the delayed mock model and setting a test key:

```sh
export BASE_URL=http://127.0.0.1:18082
export PROFILE_MODEL=profile-model
: "${API_KEY:?Set a valid test-organization key}"
LONG_MODE=30s LONG_RATE=2 LONG_WINDOW=60s k6 run tests/load/soak_longres.js
```

This reduced-rate check does not validate the default workload. For the full
burst script, plan enough generator and gateway resources before running it:

```sh
k6 run tests/load/soak_burst.js
```

| Scenario | Environment variables |
|---|---|
| Burst | `BURST_RPS`, `BURST_LEN`, `BURST_GAP`, `BURST_COUNT`, `BURST_RESP`, `BURST_PRE_VUS`, `BURST_MAX_VUS`, `BURST_OUT` |
| Long response | `LONG_MODE`, `LONG_RATE`, `LONG_WINDOW`, `LONG_PRE_VUS`, `LONG_MAX_VUS`, `LONG_OUT` |
| Both | `BASE_URL`, `API_KEY`, `PROFILE_MODEL`, `REQ_TIMEOUT` |

Duration strings require explicit units such as `60s` or `2m`. The burst request
timeout defaults to 150 seconds; long-response timeouts default to the selected
response delay plus 60 seconds. A client timeout shorter than the response delay
changes the scenario into a timeout test.

## Orchestration boundary

`run-profiles.sh` also manages a Compose deployment, policy setup, warmup,
Prometheus snapshots, backlog recovery and report generation. It requires
`deploy/docker-compose.prod.yml` and `deploy/docker-compose.e2e.yml`; these are
not included in the public Core export. The runner is therefore not a
self-contained public setup command. A standalone k6 run exercises only its
script's assertions and does not reproduce those additional operational checks.

In a checkout with the required deployment files, the runner uses Compose
project `profiles`, subnet `10.208.0.0/24`, dedicated host ports and outputs in
`artifacts/profiles/<run-id>/`. Its paired soak runner uses a different project
and subnet, but simultaneous heavy runs can still interfere through shared CPU,
memory, disk and Docker resources. Do not interpret concurrent measurements as
isolated results.

When reporting a run, preserve exact source/configuration identities, hardware,
actual elapsed time, launch/completion counts, dropped iterations, latency and
errors. Include backlog-recovery observations only when the metrics and collector
were actually present. Short validation runs do not establish sustained-hours
behavior at high concurrency.

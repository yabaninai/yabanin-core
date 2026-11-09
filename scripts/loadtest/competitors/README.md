# Local competitor benchmark configurations

This directory contains optional, frozen benchmark configurations for Bifrost
and LiteLLM. They connect to the repository's deterministic mock provider over
loopback. They are test-harness inputs, not production deployment examples or
current product recommendations. Neither image is included in the Yabanin
runtime image.

| Directory | Recorded version label | Files |
|---|---|---|
| `bifrost/` | Bifrost v2.4.0 | `config.json`, `docker-compose.yml` |
| `litellm/` | LiteLLM Proxy 1.108.0 | `config.yaml`, `docker-compose.yml` |

[VERSIONS.md](VERSIONS.md) records the exact image references. The validator also
contains the expected digests: update it, both relevant Compose/config files and
the version record together when changing a pin. The labels describe these
frozen inputs; they do not assert which versions are currently available.

## Static validation

Run from the repository root:

```sh
bash scripts/loadtest/competitors/validate-configs.sh --static-only
```

This checks digest agreement, selected configuration fields, loopback bind
settings, absence of the reserved benchmark ports and absence of floating
`latest`/`main` image tags. It parses the Bifrost JSON and checks selected LiteLLM
YAML text; it is not a complete upstream configuration-schema validator. The
script currently requires `python3`, the Docker CLI and `curl` on `PATH` even
in static mode, but that mode does not contact Docker or start containers.

## Live validation

On a host supporting Docker Compose host networking, with the repository's Go
toolchain available, run:

```sh
bash scripts/loadtest/competitors/validate-configs.sh
```

The script builds the local mock/benchmark client, starts both pinned gateways,
waits for an actual mock reply, probes JSON and SSE, then runs six small cells:
direct mock, Bifrost and LiteLLM, each in JSON and SSE mode. Each cell must report
`errs=0`. Defaults are `BENCH_N=20`, `BENCH_C=2`, `BENCH_WARMUP=2` and
`BENCH_READY_TRIES=120`; these environment variables can override the defaults.
It also attempts a `docker stats` snapshot. A successful validation is not a
comparative performance result.

Reserve these loopback ports before running:

| Port | Process |
|---|---|
| `14650` | Shared deterministic mock |
| `14660` | Bifrost |
| `14661` | LiteLLM |

The separate `gatewayoverhead/run-benchmark.sh` harness uses ports 14651–14655.
The validator refuses to start if an HTTP probe detects a listener on its own
ports. Use a disposable test environment and do not run another invocation of
these same Compose projects concurrently. Temporary build/log files are placed
under a `yb-competitor-val.*` directory; its exit handler attempts to remove the
container IDs it recorded and stop its mock process.

## Configuration boundaries

Both configurations expose model name `bench-model` and point to the same mock:

- Bifrost maps `bench-model` to `openai/bench-model`, sets its base URL to
  `http://127.0.0.1:14650`, enables private-network access for that loopback
  target and disables its configuration store. It binds through
  `APP_HOST=127.0.0.1` and `APP_PORT=14660`.
- LiteLLM uses `http://127.0.0.1:14650/v1`, starts with one worker and binds
  through `--host 127.0.0.1 --port 14661`. Its configuration reads upstream
  credentials from an environment variable.

The live validator sets obviously synthetic credentials itself; no real API
key is needed. If starting the Compose files directly, they require
`BIFROST_BENCH_UPSTREAM_KEY`, or `LITELLM_MASTER_KEY` and
`LITELLM_BENCH_UPSTREAM_KEY`, respectively. Use dummy values only. Bifrost's
file-only configuration does not configure gateway authentication, whereas the
LiteLLM request path supplies a master key. Keep these services on loopback.

A fair comparison must disclose authentication, logging, caching, workers,
concurrency, warmup, payloads, streaming semantics, hardware and error counts.
The current configurations are not proof of equivalent enabled features.
Upstream gateways may transform JSON and SSE responses; inspect actual output
before treating byte equality or first-frame timing as equivalent behavior.
Keep raw results and exact input digests with any reported measurement. This
directory contains no measured competitor ranking or current-version claim.

---
title: Gateway performance
description: Measure gateway latency and cache behavior on your deployment.
---

# Gateway performance

Measure the gateway and provider separately under the same workload. Record the
source version, hardware, concurrency, request rate, cache state, response sizes,
error counts and database placement alongside latency percentiles.

## Compare direct and gateway requests

`scripts/loadtest/matched` sends the same workload directly to a provider and
through Yabanin. It uses unique prompts to avoid measuring repeated exact-cache
hits. Configure a disposable gateway with a mock or other controlled provider;
the provider's direct endpoint must also be reachable from the benchmark host.
The quickstart mock is on the Compose network and is not published to the host
by default.

Build the benchmark with the repository's Go toolchain:

```bash
go build -o /tmp/yabanin-matched ./scripts/loadtest/matched
```

Set the target URLs, a temporary gateway key and a model available on both paths:

```bash
: "${DIRECT_URL:?Set the controlled provider URL}"
: "${GATEWAY_URL:?Set the gateway URL}"
: "${YABANIN_API_KEY:?Set a temporary gateway key}"
: "${MODEL_ID:?Set a configured model ID}"
/tmp/yabanin-matched \
  -direct "$DIRECT_URL" -gateway "$GATEWAY_URL" \
  -key "$YABANIN_API_KEY" -model "$MODEL_ID" \
  -n 200 -c 1 -rps 40
```

The tool refuses to attach credentials to a non-loopback gateway unless
`-allow-remote-target` is explicitly supplied. Use a test key: the CLI key argument
can be visible to other users through process inspection. Set provider spend
limits before benchmarking a paid endpoint.

The JSON output includes per-cell latency percentiles and error codes. Compare
successful requests at matched concurrency and rate; HTTP 429 responses measure
rate limiting, not normal request latency. Repeat on a quiet host and report the
variation instead of presenting a single best run as a capacity guarantee.

## Streaming and cache measurements

Time to first token requires a provider that emits SSE frames. A mock that returns
one JSON response to `stream:true` cannot establish streaming latency. Verify the
response format before interpreting a streaming benchmark cell.

For cache behavior, `scripts/loadtest/http` repeats prompts and reports latency
and `X-Cache` outcomes. Cache hit rate depends on prompt distribution, enabled
cache layers and warm-up. It is a separate measurement from the unique-prompt
matched benchmark. Inspect the tool's flags and configured model before using it
against a deployment.

A local mock isolates gateway processing but omits provider latency, TLS paths,
remote databases, real token generation and production concurrency. Use the
actual deployment topology for sizing decisions.

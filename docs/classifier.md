# Task Classifier

## Overview

The task classifier analyzes user prompts to determine complexity level, then routes the request to an appropriate model tier — cheap models for simple tasks, premium models for complex ones. Classification is a routing heuristic; validate answer quality and cost on your own workload.

## Architecture

```
                    ┌─────────────┐
  Request ───────► │ Classifier  │
                    │   Pipeline  │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              ▼            ▼            ▼
         ┌─────────┐ ┌─────────┐ ┌─────────┐
         │  Easy   │ │ Medium  │ │  Hard   │
         │  ↓      │ │   ↓     │ │   ↓     │
         │ Cheap   │ │  Mid    │ │ Premium │
         │ Pool    │ │  Pool   │ │  Pool   │
         └─────────┘ └─────────┘ └─────────┘
```

## Components

| Component | Package | Description |
|---|---|---|
| Classifier interface | `pkg/classifier/classifier.go` | `Classifier` interface with `Classify()` and `Name()` methods |
| Rule tier V0 | `pkg/classifier/rule_tier.go` | Deterministic classification based on prompt features (keywords, length, code fences) |
| ML classifier V1 | `pkg/classifier/ml_v1.go` | HTTP client for an operator-supplied classification service |
| Classifier cache | `pkg/classifier/registry_cached*.go` | 4-tier lookup: Redis exact → DB exact → DB semantic (pgvector) → inner classifier |
| Tier router | `pkg/router/tier_pool.go` | Weighted round-robin pool selection per complexity class |
| Circuit breaker | `pkg/classifier/circuit_breaker.go` | Closed/Open/HalfOpen state machine for ML service health |
| Evalgate judge | `pkg/evalgate/judge.go` | LLM-as-judge quality evaluation comparing cheap vs premium responses |
| Calibration | `pkg/classifier/calibration.go` | Platt scaling to align classifier confidence with actual accuracy |
| A/B assigner | `pkg/classifier/ab_assigner.go` | Deterministic SHA-256 bucketing for classifier experiments |
| Feedback collector | `pkg/feedback/collector.go` | Records thumbs_up/down/regenerate signals for online learning |

## Classification Classes

| Class | Description | Example keywords | Mapped tier |
|---|---|---|---|
| **Easy** | Simple, short prompts with clear intent | summarize, translate, list, extract, name, what is | Cheap pool (gpt-4o-mini) |
| **Medium** | General questions, moderate complexity | No strong markers, 200–2000 tokens | Mid pool |
| **Hard** | Complex reasoning, debugging, architecture | debug, architect, step by step, code review, troubleshoot | Premium pool (gpt-4o) |

## Per-Org Routing Modes

Each organization can override routing behavior via the admin API:

| Mode | Behavior | Threshold |
|---|---|---|
| `auto` (default) | Route by classifier confidence | 0.6 |
| `aggressive_cost` | Aggressive cheap routing | 0.4 |
| `always_premium` | All requests → premium pool | N/A |
| `always_cheap` | All requests → cheap pool | N/A |
| `classifier_only` | Only route when very confident | 0.9 |
| `disabled` | Skip classifier entirely | N/A |

## Admin API

```
GET    /api/organizations/{id}/routing          # Get org routing settings
PATCH  /api/organizations/{id}/routing          # Update routing_mode + threshold (root only)
POST   /v1/feedback                             # Submit thumbs_up/down/regenerate feedback (Authorization: Bearer <org or agent API key>; the org is derived from the key)
```

## Configuration

| Env var | Default | Description |
|---|---|---|
| `YABANIN_CLASSIFIER_SERVICE_URL` | `""` | ML classifier service URL (empty = rule-tier only) |
| `YABANIN_EVALGATE_URL` | `""` | Judge endpoint for quality evaluation |
| `YABANIN_EVALGATE_API_KEY` | `""` | API key for judge endpoint |
| `YABANIN_EVALGATE_MODEL` | `gpt-4o-mini` | Model to use as judge |
| `YABANIN_EVALGATE_SAMPLE_RATE` | `0.05` | Fraction of Medium/low-conf requests to sample |
| `YABANIN_CLASSIFIER_CIRCUIT_ENABLED` | `true` | Select configurable circuit timeout (see limitation below) |
| `YABANIN_CLASSIFIER_CIRCUIT_THRESHOLD` | `3` | Consecutive failures before open state |
| `YABANIN_CLASSIFIER_CIRCUIT_TIMEOUT` | `30s` | Duration to stay in open state |

The current gateway still wraps the ML service when
`YABANIN_CLASSIFIER_CIRCUIT_ENABLED=false`, using a fixed 30-second open
timeout. See [external classifier limitations](classifier-ml.md).

## Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `classifier_class_total` | Counter | class, source | Classification counts by class and source |
| `classifier_confidence` | Histogram | — | Classification confidence distribution |
| `classifier_latency_seconds` | Histogram | source | Classification latency |
| `tier_routing_total` | Counter | class, from_model, to_model | Model routing decisions |
| `tier_routing_skipped_total` | Counter | reason | Skipped routings (low_confidence, etc.) |
| `classifier_cache_hit_total` | Counter | type | Cache hits by type (exact/semantic) |
| `classifier_circuit_breaker_state` | Gauge | classifier | Circuit breaker state (0=closed, 1=open, 2=half-open) |
| `evalgate_verdict_total` | Counter | should_upgrade | Judge verdict counts |
| `evalgate_latency_seconds` | Histogram | — | Judge evaluation latency |

## Adding a New Rule

Rules are defined in `pkg/classifier/rule_tier.go` in the `Classify` method. The rule order is:

1. **Hard rules** checked first (prompt >2000 tokens, hard keywords, code fences >50 lines, tool-call JSON with >800 prompt tokens)
2. **Easy rules** checked second (short prompt + easy keywords, no code fences)
3. **Default** → Medium

To add a new rule:
1. Add the keyword or pattern to `features.go` keyword lists
2. Add a check in `rule_tier.go` before the default Medium return
3. Set appropriate confidence value (0.60–0.90)
4. Add a test case in `rule_tier_test.go`

## External ML service

See [External ML classifier](classifier-ml.md) for its HTTP contract,
timeout, fallback, and data-handling requirements. Training scripts,
weights, and training data are not included in the public core.

## Limitations

- Keyword heuristics are language-dependent. Evaluate each supported language;
  the rule tier does not detect language and automatically select a trained model.
- Short or ambiguous prompts can be misclassified.
- Classification is not an assessment of the eventual response's correctness.
- Text-derived features do not establish understanding of attached images or files.
- Configuring a response-cache embedder does not configure the ML classifier.

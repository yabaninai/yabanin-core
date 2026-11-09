# Cache Architecture

## Overview

Yabanin's semantic cache system reduces LLM costs and latency by caching responses at multiple layers. It supports per-org privacy controls, A/B testing, and comprehensive observability.

```mermaid
graph TB
    Client[Client / App] -->|POST /v1/chat/completions| GW[Gateway]

    subgraph "Cache Decision"
        GW --> CC["Cache-Control: no-store?"]
        CC -->|yes| UPSTREAM[Upstream Provider]
        CC -->|no| CK{"Check Cache"}
    end

    subgraph "Cache Layers"
        CK --> Redis[(Redis Exact<br/>cache:{org}:{tier}:{hash})]
        Redis -->|miss| PG[(pgvector)<br/>cache_entries table]
        PG -->|miss| Embed["Embedder (bge-small-en)"]
        Embed --> SemanticSearch[ANN Search<br/>cosine >= 0.95]
    end

    subgraph "Cache Write"
        GW -->|"upstream success"| ASync[Async Writer Pool<br/>4 workers]
        ASync --> RedisWrite[(Redis)]
        ASync --> PGWrite[(pgvector + embedding)]
    end

    UPSTREAM --> GW
    SemanticSearch -->|hit| GW
    Redis -->|hit| GW

    subgraph "Observability"
        GW --> Prometheus[Prometheus Metrics]
        GW --> Loggerd[loggerd → request_logs]
        Prometheus --> Grafana[Grafana Dashboard]
        Loggerd --> Analytics["/api/analytics/{org}/cache"]
    end

    subgraph "Admin API"
        Admin[Admin Panel] --> CacheSettings["PATCH /api/organizations/{id}/cache-settings"]
        Admin --> Flush["POST /api/cache/flush"]
        Admin --> Warm["POST /api/cache/warm (410, removed)"]
        Admin --> Experiments["POST /api/cache/experiments"]
    end

    style GW fill:#e1f5fe
    style Redis fill:#fff3e0
    style PG fill:#e8f5e9
    style Embed fill:#fce4ec
```

## Components

| Component | Description |
|-----------|-------------|
| **CacheService** | Top-level orchestrator — manages Redis exact cache, pgvector semantic cache, and the async write pipeline |
| **RedisStore** | In-memory key-value store backed by Redis. Keys: `cache:{org_id}:{model_tier}:{hash}` |
| **SemanticCache** | ANN search over pgvector using HNSW index with cosine similarity threshold (0.95) |
| **Writer** | Async write pipeline with 4 workers, non-blocking Submit(), drop-on-full queue management |
| **Cleaner** | Periodic TTL janitor (5min intervals) that purges expired entries from both backends |
| **Invalidator** | Org-scoped, model-version-scoped, and prompt-hash-scoped invalidation via Redis SCAN + pgvector DELETE |
| **PolicyCache** | Per-org policy cache with 60s TTL — controls enabled/disabled/read-only modes |
| **Analytics** | In-memory hit/miss tracking with per-org and per-tier breakdowns |
| **ABTest** | Deterministic hash-based bucketing for A/B experiments (control vs treatment) |
| **Warmer** | Removed (W-CACHE): wrote unsigned entries the RT-05 lookup always rejected; `/api/cache/warm` answers 410 |

## Cache Flow

### Read Path (Lookup)
1. **Cache-Control: no-store** check — skip if present
2. **Per-org policy check** — skip if disabled; read-only permits lookup
3. **Redis exact lookup** by `sha256(normalized_prompt)` — fastest path
4. **pgvector exact lookup** by prompt_hash + model_version — for entries
   written to pgvector only. **Disabled by default**
   (`YABANIN_CACHE_PG_EXACT_LOOKUP=true` to re-enable): Redis is the exact
   layer; the pg exact lookup only helps after Redis data loss and costs a
   Postgres round-trip on every miss.
5. **Semantic ANN search** — embed prompt → cosine similarity ≥ 0.95 → return if found
6. If all miss: forward to upstream provider

### Write Path (after successful upstream response)
1. Check `shouldCache()` — skip error responses, empty bodies, no-store orgs
2. **Redis exact write** — synchronous; latency depends on Redis availability and network
3. **Async pgvector write** — 4-worker pool, computes embedding, upserts into cache_entries

## Privacy Model

| Mode | Lookup | Write | Description |
|------|--------|-------|-------------|
| `off` | ❌ | ❌ | No caching at all |
| `exact` | ✅ (Redis only) | ✅ (Redis + pgvector) | Only exact-key matching |
| `semantic` | ✅ (Redis + pgvector) | ✅ (Redis + pgvector) | Full semantic cache |

Toggle is admin-only with audit logging. Changes trigger automatic cache invalidation for the affected org.

## Threshold Tuning

- **Cosine similarity**: 0.95 (default). Lower = more hits, higher risk of false positives.
- **HNSW ef_search**: 100 (default). Higher = better recall, slower queries.
- **TTL**: 24 hours (Redis), configurable per org via policy.
- **Embedding model**: operator-configured; the schema expects 384 dimensions

## Cost and latency overhead

Measure the entire cache path on your deployment. Exact lookup includes Redis
I/O; semantic lookup adds an embedding request and a pgvector query. Redis
writes are synchronous, while pgvector writes use a bounded asynchronous
queue and can be dropped when that queue is full. Cache writes are not a
durable request-history mechanism.

The 384-dimensional vector alone takes 1,536 bytes as float32 values, before
row/index overhead and the response payload. Include storage, indexing,
embedding compute, and operations when evaluating cost. Neither classifier
throughput nor a vector-distance microbenchmark establishes cache throughput.

### Measured (make bench-cache)

Reference: Apple M5 Max, Redis 7 in Docker on localhost, 2026-09-02.
Reproduce on your hardware with `make bench-cache`.

| Benchmark | Result | What it is |
|---|---|---|
| `ExactCache_Get_Hit` | ~0.22 ms/op, 11 allocs | full exact hit: SHA-256 + Redis GET round-trip |
| `ExactCache_Get_Miss` | ~0.24 ms/op, 14 allocs | exact miss path |
| `SemanticNormalize_Normalized` | ~1.7 µs/op | canonical-JSON normalization before embedding |
| `CosineDistance` (384-dim) | ~93 ns/op, 0 allocs | the similarity judgment itself |

These are historical measurements, not results from this documentation
revision. Unit benchmarks do not cover the end-to-end embedder HTTP call or
production pgvector query latency. Reproduce on your own hardware with the
required services and inspect `cache_lookup_duration_seconds` alongside
request latency and failure metrics.

## Monitoring

### Prometheus Metrics
| Metric | Type | Description |
|--------|------|-------------|
| `cache_hits_total{type,org_id}` | Counter | Cache hits by source (exact/semantic/miss) |
| `cache_writes_total{status}` | Counter | Write attempts (written/dropped) |
| `cache_lookup_duration_seconds{type}` | Histogram | Lookup latency p50/p90/p99 |
| `cache_similarity_score` | Histogram | Cosine similarity on semantic hits |
| `cache_size{backend}` | Gauge | Entry count per backend |
| `cache_write_queue_size` | Gauge | Pending write jobs |
| `cache_janitor_runs_total` | Counter | TTL janitor runs |
| `cache_ab_arm_total{variant}` | Counter | A/B experiment arm assignment |

### Grafana Dashboard
8-panel dashboard covering hit-rate, latency percentiles, similarity distribution, queue depth, per-org breakdown, savings_usd, janitor stats, and error rates. Import via `docs/observability/cache-dashboard.json`.

## A/B Experiment Flow

1. Admin creates experiment with control (cache=off) and treatment (cache=enabled) variants
2. Gateway assigns each org deterministically: `hash(org_id + experiment_id) % 100 < traffic_pct`
3. Control arm: skip all cache lookups, always forward upstream
4. Treatment arm: full cache lookup pipeline
5. Results aggregated via `/api/cache/experiments/{id}/results` comparing savings_usd per variant

## Cache Warming (removed)

Cache warming was removed (W-CACHE): warmed entries lacked the RT-05 HMAC signature, so every lookup rejected them. `/api/cache/warm` now answers `410 Gone`; the semantic cache learns exclusively from live traffic.

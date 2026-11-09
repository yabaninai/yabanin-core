# Semantic Cache

The semantic cache system provides multi-layer caching for LLM responses, combining exact-match Redis caching with pgvector-based semantic search.

## Architecture

```
Request
  │
  ├─→ [Redis Exact Cache] ─── hit → Return cached response
  │     key: cache:{org_id}:{model_tier}:{sha256(prompt)}
  │
  ├─→ [pgvector Exact Cache] ─── hit → Return + warm Redis
  │     unique index on (org_id, model_tier, prompt_hash, model_version)
  │     (disabled by default — see Read Path below)
  │
  ├─→ [Embedding Service] → vector(384)
  │     operator-configured embedding service
  │
  ├─→ [pgvector Semantic Search] ─── hit → Return + warm Redis
  │     HNSW index with cosine similarity threshold (≥0.95)
  │
  └─→ [Upstream LLM API]
        ↓ synchronous Redis write + queued pgvector write
```

## Components

| Component | Package | Description |
|---|---|---|
| Redis exact cache | `pkg/cache/redis.go` | SHA-256 keyed Redis store, 24h TTL |
| pgvector storage | `pkg/cache/store.go` | CRUD operations, vector I/O helpers |
| Semantic search | `pkg/cache/semantic.go` | ANN lookup via HNSW cosine distance |
| Write pipeline | `pkg/cache/writer.go` | Async worker pool for cache writes |
| SSE replay | `pkg/cache/replay.go` | RecordingWriter + 3 replay modes |
| Key normalization | `pkg/cache/normalize.go` | Canonical JSON for consistent hashing |
| Embedding service | `pkg/embeddings/client.go` | HTTP client for embedding API |
| Unified service | `pkg/cache/service.go` | Orchestrates all layers with privacy controls |
| Privacy policies | `pkg/cache/service.go` | Per-org enabled/disabled/read-only modes |
| TTL cleaner | `pkg/cache/cleaner.go` | Periodic expired entry purge |
| Prometheus metrics | `pkg/cache/metrics.go` | 8 cache-specific metric vectors |
| Analytics + A/B | `pkg/cache/analytics.go` | Hit rate tracking, traffic splitting, warming |

## Multilingual traffic (Japanese and others)

Choose and evaluate an embedding model for your workload's languages. The
classifier and response-cache embedder are independent services; changing one
does not retrain or replace the other.

The gateway settings identify an already running, reachable embedding service:

```bash
export YABANIN_EMBEDDER_BASE_URL=http://embedder-multilingual:6006
export YABANIN_EMBEDDER_MODEL=intfloat/multilingual-e5-small
export YABANIN_EMBEDDER_QUERY_PREFIX="query: "
```

These settings alone do not download weights or launch a service. In a container,
use a hostname reachable on that container's network. The main development
Compose file contains optional `embedder-multilingual` and `embedder-bge`
services. Its default `bge-embedder` service is a **mock**, despite its name;
it does not measure semantic quality. The quickstart does not start a real
embedding model.

The schema expects **384 dimensions**. Verify the output dimension and model
revision before enabling writes. The query prefix is added to both lookups
and writes. Changing the model, weights, or preprocessing makes old vectors
incompatible even when dimensions match: invalidate affected cache entries
and rebuild them from new traffic. Evaluate precision using your own labeled
requests; see [Cache precision](cache-precision.md).

## Privacy Controls

Each organization has a cache policy:

- **enabled** — full read/write cache access
- **disabled** — no caching at all (privacy-first)
- **read-only** — can look up cached responses but never write new ones

Policies are cached in-memory with 60s TTL to avoid DB overhead on every request.

## SSE Streaming

For streaming responses, the cache captures individual SSE frames with timing:

```go
rw := cache.NewRecordingWriter(w)
// ... upstream response is written through rw ...
chunks := rw.Chunks() // []SSEChunk{Data, DelayMS}
```

Replay modes:
- **faithful** — preserve original timing (default)
- **burst** — send all chunks immediately
- **paced** — equal 10ms intervals

## Deployment

Start with the [mock quickstart](quickstart.md) for the gateway request path.
For semantic reuse, provision an embedding service separately, configure the
gateway's base URL/model/prefix, and validate health, dimensions, timeouts,
quality, and cache invalidation. Pin container and model revisions and review
their licensing. A successful mock response is not an embedding benchmark.

## Prometheus Metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `cache_hits_total` | Counter | type, org_id | Cache hits by lookup type |
| `cache_writes_total` | Counter | status | Write attempts (written/dropped) |
| `cache_purged_total` | Counter | backend | Expired entries removed |
| `cache_size` | Gauge | backend | Current entry count |
| `cache_lookup_duration_seconds` | Histogram | type | Lookup latency |
| `cache_write_queue_size` | Gauge | — | Pending write jobs |
| `cache_write_queue_drops_total` | Counter | — | Dropped writes (queue full) |
| `cache_embedding_errors_total` | Counter | — | Embedding failures |

## Migration

The cache tables and the pgvector extension are created by the initial migration `0001_init` (there is no separate pgvector migration):

```sql
-- migrations/0001_init.up.sql (excerpt)
CREATE EXTENSION IF NOT EXISTS vector;
CREATE TABLE cache_entries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL, model_tier TEXT NOT NULL,
    prompt_hash TEXT NOT NULL, embedding vector(384) NOT NULL,
    response JSONB NOT NULL, sse_chunks JSONB,
    tokens_in INT DEFAULT 0, tokens_out INT DEFAULT 0,
    hit_count INT DEFAULT 0, model_version TEXT DEFAULT '1',
    created_at TIMESTAMPTZ DEFAULT now(),
    expires_at TIMESTAMPTZ DEFAULT (now() + interval '24 hours')
);
```

## Tests

- Unit tests: `go test ./pkg/cache/...`
- Benchmarks: `go test -bench=. ./pkg/cache/...`
- Integration (requires Docker): `go test -race ./services/gateway/integration/...`

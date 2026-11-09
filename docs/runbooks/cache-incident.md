# Runbook: Cache Hit Rate Dropped Below 25%

## Diagnosis Steps

### 1. Check Metrics Immediately
```bash
# From Grafana dashboard or Prometheus:
# - cache_hits_total{type="miss"} spike?
# - cache_lookup_duration_seconds p99 > 15ms?
# - cache_embedding_errors_total increasing?
# - cache_write_queue_drops_total increasing?

curl http://localhost:2112/metrics | grep "cache_"
```

### 2. Check Embedder Health
```bash
# bge-embedder health check (port 6006)
curl http://localhost:6006/health

# Check embedder logs
docker logs deploy-bge-embedder-1 --tail=50
```

### 3. Check Cache Configuration
```bash
# Verify org cache settings haven't been accidentally changed
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:2112/api/organizations/$ORG_ID/cache-settings

# Check if any orgs were switched to "exact" or "off" mode
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:2112/api/organizations?cache_mode=off
```

### 4. Check for Schema Changes
```bash
# Verify pgvector extension is still valid
docker exec deploy-postgres-1 psql -U yabanin -d yabanin \
  -c "SELECT extversion FROM pg_extension WHERE extname='vector';"

# Check cache_entries table size
docker exec deploy-postgres-1 psql -U yabanin -d yabanin \
  -c "SELECT count(*), min(expires_at), max(expires_at) FROM cache_entries;"
```

### 5. Check for Traffic Pattern Changes
```bash
# Look at request volume vs cache hits in the last hour
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
  http://localhost:2112/api/analytics/$ORG_ID/cache?from=$(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%SZ)

# Check if new request patterns don't match existing cache entries
docker exec deploy-postgres-1 psql -U yabanin -d yabanin \
  -c "SELECT count(*) FROM request_logs WHERE created_at > now() - interval '1 hour' AND cache_hit_type IS NULL;"
```

## Remediation Actions

### Quick Fix: Flush
If the cache has stale entries or the embedding model changed:

```bash
# Flush entire cache (root admin only)
curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://localhost:2112/api/cache/flush?org_id=$ORG_ID&reason=low_hit_rate"

# NOTE: cache warming was removed (W-CACHE); POST /api/cache/warm answers 410.
# The semantic cache re-populates from live traffic only.
```

### Medium Fix: Adjust Threshold
If semantic cache is returning too few hits (threshold too high):
- Edit `pkg/cache/semantic.go`: change `DefaultSimilarityThreshold` from `0.95` to `0.92`
- Restart gateway: `docker compose restart gateway`

If too many false positives (threshold too low):
- Increase threshold to `0.97`

### Long Fix: Add New Cache Entries
Cache warming is removed (W-CACHE); entries are written from live traffic only.
1. Identify top missing prompts from request_logs
2. Exercise those prompts through the gateway (real or replayed traffic)
3. Monitor hit-rate improvement over next 30 minutes

## Escalation

| Symptom | Action |
|---------|--------|
| Embedder down >5min | P1 incident — restart embedder, fallback to Redis-only mode |
| Cache write queue drops >10/min | Check disk I/O on Redis; consider increasing `cache_write_queue_size` |
| pgvector extension missing | **CRITICAL** — migrations not applied (the pgvector extension and cache tables ship in migration `0001_init`); inspect migration status and follow the controlled migration procedure in the [development guide](../DEVELOPMENT.md) or your deployment runbook; back up persistent data first, and never loop over all SQL files |
| Hit-rate below 10% for >1h after flush | Review normalization policies; check if request patterns changed significantly |

## Prevention

- Set Grafana alert: `cache_hits_total{type="miss"} / (cache_hits_total{type="exact"} + cache_hits_total{type="semantic"} + cache_hits_total{type="miss"}) > 0.75 for 15m`
- Weekly review of `savings_usd` trend in dashboard
- Monthly normalization policy audit: check for false collision reports

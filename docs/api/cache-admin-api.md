# Cache Admin API Reference

All endpoints require admin authentication (Bearer token with admin role). Base path: `/api`.

## Cache Settings

### `GET /organizations/{id}/cache-settings`
Get per-org cache configuration.

**Response:** `200 OK`
```json
{
  "org_id": "abc-123",
  "cache_enabled": true,
  "cache_mode": "semantic"
}
```

### `PATCH /organizations/{id}/cache-settings`
Update per-org cache configuration. Root admin only.

**Request:**
```json
{
  "cache_enabled": true,
  "cache_mode": "exact"
}
```

**Modes:** `off`, `exact`, `semantic`
**Validation:** Invalid mode → `400 Bad Request`. Missing org → `404 Not Found`. Non-root → `403 Forbidden`.

---

## Cache Operations

### POST /cache/flush?org_id=&model_tier=
Flush cache entries. Requires `org_id` or `model_tier`. Root admin only.

**Response:** `200 OK` — `{"status": "flushed", "org_id": "...", "reason": "manual"}`

### GET /cache/analytics
Get global cache analytics (hit rates, org count).

**Response:** `200 OK` — `{"total_hits": {"exact": 1500, "semantic": 300}, "total_misses": 800, "org_count": 42}`

### POST /cache/warm (deprecated)
Removed. The warmer wrote unsigned entries the RT-05 lookup always rejected; the semantic cache learns from live traffic only.

**Response:** `410 Gone`

### `POST /models/{name}/bump-version`
Bump model version to invalidate cache. Root admin only.

---

## Cache Analytics

### `GET /analytics/{org_id}/cache?from=&to=`
Get per-org cache hit-rate and savings analytics.

**Query params:**
- `from`: Start time (RFC3339, default: 24h ago)
- `to`: End time (RFC3339, default: now)

**Response:** `200 OK`
```json
{
  "total_requests": 1000,
  "hits_exact": 350,
  "hits_semantic": 150,
  "misses": 500,
  "cache_hit_rate": 0.5,
  "savings_usd": 2.45,
  "counterfactual_cost_usd": 4.90,
  "avg_similarity": 0.973
}
```

---

## A/B Experiments

### POST /cache/experiments
Create a new cache experiment. Root admin only.

**Request:**
```json
{
  "name": "cache-ab-test-1",
  "org_id": "abc-123",
  "traffic_pct": 50
}
```

**Response:** `201 Created` — Experiment object with deterministic assignment.

### GET /cache/experiments?org_id=&enabled=
List experiments. Optional query params: `org_id`, `enabled=true`.

**Response:** `200 OK` — Array of experiment objects.

### `GET /cache/experiments/{exp_id}/results`
Get savings per variant for an experiment.

**Response:** `200 OK`
```json
{
  "control_savings_usd": 0.50,
  "treatment_savings_usd": 1.20
}
```

---

## Error Responses

| Status | Code | Description |
|--------|------|-------------|
| `400` | invalid_request | Malformed JSON or invalid mode |
| `403` | permission_denied | Non-root admin on root-only endpoints |
| `404` | not_found | Org/model/experiment not found |
| `500` | internal_error | Database error or cache service failure |

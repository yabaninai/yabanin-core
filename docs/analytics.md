# Analytics

The explorer, the boards, and `GET /api/analytics/query` read the same
request log. Shadow rows are excluded from the totals. Dollar totals sum
only rows whose cost status is `priced`, `cache_hit`, or `legacy`.
`unknown_price` and `no_usage` count as `unpriced_requests` and add nothing
to `cost_usd`. The JSON body includes `unpriced_requests` and
`unpriced_share` so a gap in the price table is visible.

## Explorer

The dashboard route is `#analytics`. The hash is the query: organization,
`from`, `to`, metrics, group-by, granularity, top, chart, filter, and
compare. Opening a saved view writes that hash back.

`GET` and `POST /api/analytics/views?org_id=` need `analytics.read`.
A view stores the normalized query. `label:Issue` is stored as
`label:issue`. Each owner can keep 100 views in an org; the next create
is 409 `view_limit`. A private view owned by someone else is 404. A shared
view can be changed by its owner or by a caller with `org.update`.
Creating or deleting a shared view is audited. Mutations use the admin
CSRF cookie.

## Query API

`GET /api/analytics/query` needs `analytics.read`.

| Parameter | Meaning |
| --- | --- |
| `org_id` | Organization. Required |
| `from`, `to` | RFC3339, `from` before `to` |
| `metrics` | One to six names, comma-separated |
| `group_by` | At most two dimensions. `label:<key>` is lowercased |
| `granularity` | `none` (default), `hour`, `day`, `week`, `month`. `hour` allows at most 14 days |
| `top` | Default 20 |
| `tz` | IANA zone. Omitted means the org zone, then UTC |
| `filter` | YQL, for example `label.ci.pipeline = "9001"` |
| `compare` | `previous` adds the preceding window |
| `format` | `csv` returns a spreadsheet. Anything else is JSON |

Metric names: `requests`, `tokens_in`, `tokens_out`, `cache_read_tokens`,
`cost_usd`, `unpriced_requests`, `errors`, `retried_requests`,
`fallback_requests`, `error_rate`, `cache_hit_rate`, `prompt_cache_ratio`,
`cost_per_request`, `latency_p50`, `latency_p95`, `ttft_p50`, `ttft_p95`,
`sessions`.

Dimensions: `model`, `model_requested`, `endpoint`, `team`, `agent`,
`task`, `status_class`, `cache`, and `label:<key>`.

```bash
curl -fsS -b "$ADMIN_COOKIE" \
  "$ADMIN/api/analytics/query?org_id=$ORG&from=2026-09-01T00:00:00Z&to=2026-09-08T00:00:00Z&metrics=cost_usd,requests,unpriced_requests&group_by=label:ci.pipeline&granularity=day&top=20&filter=label.ci.pipeline%20%3D%20%229001%22"
```

CSV is the same URL with `&format=csv`.

A filter, a non-additive metric, or a range the rollup cannot answer reads
`request_logs` directly. That path covers at most 93 days. A query with an
empty filter, additive metrics, and granularity `hour`, `day`, `week`, or
`month` can use the rollup and then covers up to 400 days. The JSON field
`source` is `rollup` in that case.

## Rollups and price coverage

`loggerd` rewrites `analytics_rollup_hourly` and `label_rollup_hourly`
every 5 minutes for `[now−3h, now+1h)`, and at 03:17 UTC recomputes 7 days
in daily chunks. A grouped query that hits the rollup can lag by one
refresh. `YABANIN_ROLLUPS=0` stops the loop. Label rollups keep only keys
listed in the org policy's `rollup_keys`.

`cost_usd` ignores unpriced rows. `unpriced_requests` counts them. After
`yb pricing sync --apply`, database prices reach the gateway within 5
minutes. Until then those requests stay in the unpriced count.

## Boards

The CI board groups cost by pipeline, job name, and trigger, and plots
daily cost for requests that have `ci.system`. A pipeline with no
`ci.pipeline` label does not appear on the pipeline panel. Other boards
cover models, tools, and hygiene. A panel whose required dimension was
never seen is hidden rather than filled with a zero.

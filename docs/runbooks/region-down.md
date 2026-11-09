# Runbook: Region Down

## Symptoms

- Admin dashboard shows region health check failures
- Pinned org requests return 503
- Non-pinned org requests may experience increased latency (failover routing)

## Diagnosis

### Step 1: Check region health

```bash
curl http://localhost:8082/health   # Local region
curl http://gateway-in.internal:8082/health  # Peer regions
```

### Step 2: Check Postgres replication lag

```sql
-- On each region's Postgres:
SELECT pg_last_wal_receive_lsn(), pg_last_wal_replay_lsn();
```

### Step 3: Check RLS enforcement

Verify that cross-region queries are correctly filtered:

```sql
-- Set region context and verify isolation:
SELECT set_config('app.region', 'sg', false);
SELECT count(*) FROM request_logs; -- should only show sg rows
```

## Remediation

### For non-pinned orgs

Failover is automatic. Non-pinned orgs are routed to the next best healthy peer based on priority order (SG < IN < EU). No manual intervention needed.

### For pinned orgs

Pinned orgs **cannot** failover — their data must stay in their home region. Options:

1. **Restore the down region**: Restart containers, restore network connectivity
2. **Unpin the org** (if business-critical): Admin API call to set `residency_pinned=false`, then re-pin after recovery

```bash
# Unpin via admin API (root access required)
curl -X PUT http://localhost:9090/api/organizations/{org_id}/region \
  -H "Content-Type: application/json" \
  -d '{"home_region":"sg","residency_pinned":false}'

# After recovery, re-pin:
curl -X PUT http://localhost:9090/api/organizations/{org_id}/region \
  -H "Content-Type: application/json" \
  -d '{"home_region":"sg","residency_pinned":true}'
```

## Prevention

- Run chaos drills weekly: `./scripts/chaos_drill.sh sg`
- Monitor region health dashboards (Grafana)
- Set up alerts for RLS policy violations

# Severity Classification Decision Matrix

## SEV-1 — Critical
**Definition**: Production is down or there is imminent risk of data loss.

**Examples**:
- All gateway regions returning 5xx errors
- Postgres database corruption detected
- Audit-log hash-chain broken (tamper detected)
- License expiry affecting all orgs simultaneously
- mTLS certificate failure across all provider connections

**Response**:
- Acknowledge within 15 minutes
- All-hands war room via Slack #incidents
- Status page update within 30 minutes
- Determine external breach-notification recipients and deadlines from applicable obligations and contracts; no universal SOC 2 72-hour customer deadline is assumed
- Post-mortem within 5 business days

## SEV-2 — Major Degradation
**Definition**: Significant portion of service degraded but not fully down.

**Examples**:
- One region out of three unavailable (SG/IN/EU failover active)
- Latency > 5x normal for all model providers
- Single model provider unreachable with no fallback configured
- Cache layer (Redis) failure causing increased DB load

**Response**:
- Acknowledge within 1 hour
- On-call + backup engineer engaged
- Status page update if customer-visible impact
- Post-mortem within 5 business days

## SEV-3 — Minor Degradation
**Definition**: Non-critical issue affecting limited users or features.

**Examples**:
- Single model provider failing (others operational)
- Admin dashboard unavailable (API still functional)
- Slow query performance on non-critical endpoints
- Telemetry/monitoring data gap

**Response**:
- Acknowledge within 4 hours during business hours
- On-call engineer assigned
- Ticket created in Jira with severity label
- Root cause documented for SEV-3

## SEV-4 — Cosmetic / Non-Urgent
**Definition**: Non-functional issues, typos, or minor bugs.

**Examples**:
- Dashboard UI spacing issue
- Documentation typo
- Minor UX inconsistency
- Log message formatting

**Response**:
- Next business day acknowledgment
- Standard Jira workflow (no on-call required)
- Root cause optional

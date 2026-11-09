# Incident Response Playbook

## Severity Classification

| Sev | Definition | Response Time | Examples |
|-----|------------|---------------|----------|
| SEV-1 | Production down, data loss risk | 15 min ack, all-hands | All regions 5xx, DB corruption, audit-log chain break |
| SEV-2 | Major degradation | 1 hour ack, on-call + backup | Single region down, latency 5x, model provider unreachable |
| SEV-3 | Minor degradation | 4 hours ack, on-call | Single model failing, dashboard down, slow queries |
| SEV-4 | Cosmetic / non-urgent | Next business day | Typo, minor UI bug, documentation error |

## Response Steps

### SEV-1 / SEV-2
1. **Declare**: On-call engineer declares severity and creates war-room (`#incident-YYYYMMDD-HH`).
2. **Page**: PagerDuty auto-pages primary + secondary. Escalate to manager after 30 min no-ack.
3. **Communicate**: Post initial update on status page within 30 minutes. Determine notification recipients and deadlines from applicable obligations and customer contracts with the incident lead; SOC 2 does not define a universal 72-hour customer deadline.
4. **Mitigate**: Apply known fix or rollback (`helm rollback yabanin`). If DB corruption, trigger DR drill.
5. **Resolve**: Restore service to normal. Document resolution steps in war-room.
6. **Post-mortem**: Within 5 business days (blameless). Publish findings to all-staff.

### SEV-3 / SEV-4
1. Triage in on-call queue during business hours.
2. Assign owner, set target resolution time.
3. Resolve and close ticket. Document root cause for SEV-3.

## Communication Templates

### Initial Incident Update
```
[INCIDENT] Yabanin Platform — Sev <X> — <brief description>
Time: <HH:MM UTC>
Impact: <what's affected>
Status: Investigation ongoing
Next update: <30 min from now>
```

### Resolution Notice
```
[RESOLVED] Yabanin Platform — Sev <X> — <brief description>
Duration: <start> to <end> (<total time>)
Root cause: <summary>
Preventive action: <what's being done>
Post-mortem: <link or ETA>
```

## Related Documents
- `docs/runbooks/sev-classification.md` — severity decision matrix
- `docs/runbooks/post-mortem-template.md` — blameless post-mortem format
- Internal SOC 2 incident-response policy (local private worksheets, not in this tree)

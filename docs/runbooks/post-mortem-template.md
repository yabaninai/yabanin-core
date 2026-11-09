---
title: Post-Mortem Template (Blameless)
description: Blameless post-mortem template for production incidents.
---

# Post-Mortem Template (Blameless)

## Incident Summary
- **Date**: YYYY-MM-DD
- **Severity**: SEV-X
- **Duration**: HH:MM — HH:MM (`[total]`)
- **Impact**: `[description of affected users/services]`
- **Author**: `[name of person writing post-mortem]`

## Timeline
| Time (UTC) | Event |
|------------|-------|
| HH:MM | Incident detected / first alert fired |
| HH:MM | On-call engineer acknowledges |
| HH:MM | War room created |
| HH:MM | Mitigation applied (rollback, failover, etc.) |
| HH:MM | Service restored to normal |
| HH:MM | Incident closed |

## Root Cause
**What happened**: `[technical description of the underlying cause]`

**Why it wasn't prevented**: `[gap in controls that allowed this to happen]`

## Contributing Factors
- [ ] `[factor 1 — e.g., missing alert on metric X]`
- [ ] `[factor 2 — e.g., insufficient redundancy]`
- [ ] `[factor 3 — e.g., documentation gap]`

## Impact Assessment
- **Users affected**: `[count or percentage]`
- **Data loss**: `[yes/no, amount if yes]`
- **SLA impact**: `[any SLA breach]`
- **Customer notifications sent**: `[yes/no, count]`

## Action Items
| ID | Action | Owner | Due Date | Status |
|----|--------|-------|----------|--------|
| AI-001 | `[specific, actionable task]` | `[name]` | YYYY-MM-DD | Open |
| AI-002 | `[specific, actionable task]` | `[name]` | YYYY-MM-DD | Open |

## What Went Well
- [ ] `[positive observation 1]`
- [ ] `[positive observation 2]`

## Lessons Learned
- [ ] `[key takeaway 1]`
- [ ] `[key takeaway 2]`

## Sign-off
| Name | Title | Date |
|------|-------|------|
| | Engineering Manager | |
| | CTO | |

# Budget Reservations — Alerts Runbook

Operator reference for reservation metrics, reconciliation and settlement lag.
The alert rules are installed in `deploy/prometheus/alert-rules.yml`, group
`yabanin-budget`. Each alert links to its recovery section below. Thresholds are
operational defaults; calibrate them against your workload and recovery targets.

Sources:

- **loggerd reconcile worker** (`pkg/budget/reconcile.go`, component
  `budget-reconcile`) — releases lapsed escrow, exports the
  invariant gauges and the settlement lag on every pass (default every 5
  min). It runs wherever the settlement worker runs; when loggerd is down
  nothing is released — that blind spot is exactly
  what the settlement-lag alert watches.
- **gateway admission layer** (`pkg/budget/admission.go`, component
  `budget-admission`) — grant/admit outcomes, added latency and bound
  violations.

## 1. Metric reference

| Series | Type | Producer | Meaning |
| --- | --- | --- | --- |
| `budget_reserved_micro_usd{scope_kind}` | gauge | reconcile | Capacity frozen by reservations per hard scope (`wallet`/`team_month`/`agent_day`/`session`). |
| `budget_allowance_released_total{reason}` | counter | reconcile | Releases by reason: `expired_safety_window` (replica died, lease lapsed past 2 h) / `zero_remainder` (draining/expired, nothing to return) / `crash_orphan` (orphan escrow closed on a permanently-lost-replica verdict). |
| `budget_reserved_divergence_micro_usd{scope_kind}` | gauge | reconcile | Divergence: Σ\|reserved(row) − Σ remainders of the row's non-released allowances\|. Money-conserving paths keep this at 0. |
| `budget_wallet_headroom_micro_usd` | gauge | reconcile | Worst-case LHS across orgs: min(balance − remainder − floor − reserved). |
| `budget_wallet_invariant_violations` | gauge | reconcile | Org count with negative headroom (orgs named in loggerd logs, never in labels). |
| `budget_stranded_micro_usd` | gauge | reconcile | Capacity frozen by lapsed non-released allowances: dead replicas block money up to 2 h + TTL. |
| `settlement_lag_seconds` | gauge | reconcile | Age of the oldest unsettled settlement job (pending/retry/processing). |
| `budget_grants_total{scope_kind,result}` | counter | gateway | `granted` / `insufficient` / `no_source` / `error` (store outage). |
| `budget_grant_duration_seconds` | histogram | gateway | PG grant latency. |
| `budget_local_admit_total{result}` | counter | gateway | How Reserve funded a request: `local` / `grant` / `refused`. |
| `budget_admission_overhead_seconds` | histogram | gateway | Synchronous admission latency added by the layer (Plan + Reserve). Configured threshold: p95 ≤ 5 ms. |
| `budget_bound_violation_total{scope_kind}` | counter | gateway | Finalized requests with actual > bound — the only legitimate overspend source. |
| `budget_bound_overshoot_micro_usd_total{scope_kind}` | counter | gateway | Accumulated (actual − bound)+ in µUSD. |
| `gateway_reservations_would_deny_total{scope_kind}` | counter | gateway | Refusals observed in shadow (shadow review input). |
| `gateway_reservations_denied_total{scope_kind}` | counter | gateway | Refusals applied in enforce (402/429/403). |
| `gateway_would_bill_partial_micro_usd_total{scope_kind}` | counter | settlement | Partial-usage cost enforce would bill, observed in shadow. |
| `gateway_uncharged_unknown_total{scope_kind}` | counter | settlement | Reserved bound of unknown-usage events — never billed, visible here. |
| `gateway_settlement_batch_size` | histogram | settlement | Jobs per org-batch settlement TX. |
| `gateway_settlement_jobs_backlog{state}` | gauge | settlement | Backlog by state; `requires_attention` is durable debt. |

No org/key/session identifiers ever appear in labels (cardinality and
privacy protection); per-org values are the admin API's job.

## 2. Alert rules

### BudgetSettlementLagHigh — warning → critical {#BudgetSettlementLagHigh}

```yaml
- alert: BudgetSettlementLagHigh
  expr: settlement_lag_seconds > 1800
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Settlement lag above 30 minutes"
    description: "Oldest unsettled settlement job is {{ $value | humanizeDuration }} old."
```

Lag > 30 min means the settlement worker is stalled. While it
stalls, reconcile conservatively releases nothing (the reserve stays
frozen — safe direction); a stalled worker also delays billing. Escalate
to `critical` after 30 min (`for: 30m` clone) — a double outage (dead
replica + stalled loggerd beyond the 2 h safety window) can temporarily
overstate available capacity by the unaccounted spend of the dead replica.

**Action**: check `gateway_settlement_jobs_backlog{state=~"pending|retry|processing"}`
and settlement worker logs; restart loggerd if the worker is down. Reconcile
resumes automatically; no manual release is ever needed.

#### BudgetSettlementLagHighCritical {#BudgetSettlementLagHighCritical}

The installed escalation clone of the rule above: same expression
(`settlement_lag_seconds > 1800`) with `for: 30m` and `severity: critical`,
so a stall that outlives the warning window pages the critical receiver
(webhook + Telegram) — a double outage (dead replica + stalled loggerd
beyond the 2 h safety window) can temporarily overstate available capacity
by the unaccounted spend of the dead replica. Owner action is the same as
the warning above; treat a firing critical as the signal to also invoke the
RPO/reserve-overshoot review, not just a worker restart.

### BudgetScopeReserveDivergence — critical {#BudgetScopeReserveDivergence}

```yaml
- alert: BudgetScopeReserveDivergence
  expr: max by (scope_kind) (budget_reserved_divergence_micro_usd) > 0
  for: 10m
  labels:
    severity: critical
  annotations:
    summary: "Reserved-money invariant divergence ({{ $labels.scope_kind }})"
    description: "reserved_µ(S) ≠ Σ remainders of non-released allowances; {{ $value }} µUSD unexplained."
```

The money invariant `reserved_µ(S) = Σ remainders of non-released
allowances` holds on every code path (grant/return/settle/release commit
under the per-org advisory lock). Any non-zero value sustained for 10 min
is drift: a bug or manual tampering. Release paths re-check under the lock,
so reconcile never widens a divergence; releasing "over" a drift freezes
capacity in the safe direction and logs
`reconcile reserve decrement failed; releasing anyway`.

**Action**: grep loggerd logs for `scope reserve invariant divergence` and
`reconcile reserve decrement failed` (rows carry scope/key), then compare
`budget_allowances` with the scope row's `reserved_micro_usd` for the named
key. Escalate to the billing-owner; do not hand-edit reserves — fix the
diverging writer and re-run reconcile.

### BudgetWalletInvariantBreach — critical {#BudgetWalletInvariantBreach}

```yaml
- alert: BudgetWalletInvariantBreach
  expr: budget_wallet_invariant_violations > 0
  for: 15m
  labels:
    severity: critical
  annotations:
    summary: "Wallet invariant breached on {{ $value }} org(s)"
    description: "balance − floor − reserved < 0 sustained beyond the bound-overshoot window."
```

Transient dips are legal: a bound overshoot (estimation error) can
pull `balance − floor − reserved` below zero until the overshoot settles
and reconciliation clears the escrow. A persistent violation requires checking
for overspend beyond the recorded overshoot or reserve accounting drift.

The 15-minute alert window spans three default reconciliation intervals.
Detection also depends on when reconciliation computes the gauge. Compare this
window with measured settlement latency in your deployment before treating a
transient dip as persistent accounting drift.

**Action**: cross-check `increase(budget_bound_overshoot_micro_usd_total[30m])`
against `budget_wallet_headroom_micro_usd`; find the org in the loggerd log
(`wallet invariant violation (§7.1.4)`, carries org id). If covered by
overshoot: bound estimation for that model needs review (see shadow review inputs).
If not: treat as reserve drift (see the divergence alert).

### BudgetWalletHeadroomNegative — warning (precursor) {#BudgetWalletHeadroomNegative}

```yaml
- alert: BudgetWalletHeadroomNegative
  expr: budget_wallet_headroom_micro_usd < 0
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Worst-case wallet headroom is negative"
```

Early signal of the breach above (one or more orgs inside the transient
window). Watch, do not page.

### BudgetStrandedCapacityHigh — warning {#BudgetStrandedCapacityHigh}

```yaml
- alert: BudgetStrandedCapacityHigh
  expr: budget_stranded_micro_usd > 10000000
  for: 30m
  labels:
    severity: warning
  annotations:
    summary: "Stranded reservation capacity {{ $value | humanize }}µUSD"
    description: "Dead/lost replicas keep freezing capacity (released after TTL 10m + safety 2h)."
```

**Action**: identify dead replicas (`budget_allowances` non-released rows
with `lease_until < now()`; `replica_id` names host:boot), restart or drain
them; reconcile releases automatically after the safety window. Sustained
stranded capacity with no dead replicas → renewal loop broken (check
gateway logs `reservation renewal failed`).

### BudgetExpiredReleaseSpike — warning (replicas dying) {#BudgetExpiredReleaseSpike}

```yaml
- alert: BudgetExpiredReleaseSpike
  expr: increase(budget_allowance_released_total{reason="expired_safety_window"}[1h]) > 10
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Multiple allowances released past the safety window"
    description: "Replicas are dying (or losing renewal) without graceful drain."
```

**Action**: correlate with deploys/OOM kills of gateway replicas. A gentle
background rate is normal for autoscaling; a spike is a stability signal.

### BoundViolationRateHigh — configured threshold monitor {#BoundViolationRateHigh}

```yaml
- alert: BoundViolationRateHigh
  expr: >
    sum(increase(budget_bound_violation_total[7d]))
      / clamp_min(sum(increase(budget_local_admit_total{result=~"local|grant"}[7d])), 1) > 0.001
  for: 1h
  labels:
    severity: warning
  annotations:
    summary: "Bound-violation rate above 0.1% of reserved requests (configured threshold)"
```

The shadow review target is ≤ 0.1% for 7 consecutive days. This alert does
not page for money (overshoot is absorbed by grace, and
`budget_bound_overshoot_micro_usd_total` sizes it) — it blocks the shadow
exit report while firing.

**Action**: pull the bound-estimate fields from request events
(`in_est`, `out_cap`, model) for the violating models; review
`InputMargin`/`default_output_cap_tokens` before re-attempting exit.

### AdmissionOverheadP95High — configured threshold monitor {#AdmissionOverheadP95High}

```yaml
- alert: AdmissionOverheadP95High
  expr: histogram_quantile(0.95, sum by (le) (rate(budget_admission_overhead_seconds_bucket[1h]))) > 0.005
  for: 30m
  labels:
    severity: warning
  annotations:
    summary: "Reservation admission p95 overhead above 5ms (configured threshold)"
```

**Action**: check `budget_grant_duration_seconds` p95 first (grants are the
PG round trip inside the overhead) and PG health; admission only adds
latency on the reserve path (cache miss), so a rise with stable grants
points at the org-settings/probe caches (5 s TTL) being cold.

The 5 ms threshold is an alert setting, not a universal performance guarantee.
Compare admission and grant latency under the actual workload, including cold
caches and database delays. A microbenchmark does not establish fleet latency.

### ReservationGrantErrors — warning {#ReservationGrantErrors}

```yaml
- alert: ReservationGrantErrors
  expr: sum(rate(budget_grants_total{result="error"}[10m])) > 0
  for: 10m
  labels:
    severity: warning
  annotations:
    summary: "Reservation store errors during grant"
    description: "PG unreachable for grants — enforce orgs get 503 budget_store_unavailable once local escrow drains."
```

**Action**: restore PG connectivity. `result="insufficient"` and
`result="no_source"` are normal refusals (exhaustion / missing budget row),
not outages.

## 3. Shadow review inputs

Before enabling enforcement, review a representative shadow period. The following
seven-day targets provide a starting point; they do not automatically change the
organization's mode:

1. `sum(increase(budget_bound_violation_total[7d])) / sum(increase(budget_local_admit_total{result=~"local|grant"}[7d]))` ≤ 0.001;
2. cumulative overshoot `increase(budget_bound_overshoot_micro_usd_total[7d])` ≤ org's `|grace_floor|` (per-org value via admin API);
3. p95 `budget_admission_overhead_seconds` ≤ 0.005;
4. `gateway_reservations_would_deny_total` and `gateway_would_bill_partial_micro_usd_total` broken down and every reason dispositioned (unpriced models priced or consciously denied).

## 4. Notes

- The reconcile pass interval (5 min default) quantizes all reconcile-side
  gauges; `for:` durations in the rules above already account for it.
- `BudgetStrandedCapacityHigh` (10M µUSD) and `BudgetExpiredReleaseSpike`
  (>10 per hour) depend on reserve size and replica churn. Review these defaults
  against observed distributions and document any changes.
- Retention of `released` allowances defaults to 90 days (same horizon as
  the settled settlement-jobs retention). It deletes only terminal
  `released` rows in bounded batches; live states are never touched.
- Global kill switch `YABANIN_RESERVATIONS=off` stops new reservations
  (mode clamp, ); existing allocations drain via reconcile.

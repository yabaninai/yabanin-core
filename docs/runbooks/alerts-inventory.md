# Alerting inventory and operating boundaries

This inventory reflects the shipped `deploy/prometheus/alert-rules.yml` and
`deploy/alertmanager/alertmanager.yml`, reviewed on 2026-11-09. It describes source
configuration, not a live deployment or verified notification delivery. Reconcile
it with your installed versions whenever rules or routing change.

## Four distinct surfaces

| Surface | What it does | What it does not establish |
| --- | --- | --- |
| Prometheus rules | Evaluate infrastructure/application metrics | An installed scraper, delivered notification or service-level commitment |
| Alertmanager | Groups/routes alerts to configured receivers | Receiver credentials, reachability or receipt without a live test |
| Organization spend webhook | Application-level threshold notification | The Prometheus pipeline or real-time provider invoice reconciliation |
| Health/readiness | Exposes application/dependency state at a point in time | Successful authenticated inference, data persistence or continuous availability |

The local quickstart does not include a monitoring stack. The public export ships
Prometheus/Alertmanager configuration inputs but excludes the maintainer's
production Compose deployment and placeholder renderer. Operators must mount the
rule file, configure target addresses, supply scrape credentials, render receiver
secrets and validate the running configuration.

## Shipped rule inventory

There are 29 alerts in the reviewed rule file. The table's `for` duration is
how long the expression must remain true; expression lookback windows and scrape
intervals add to detection latency. Exact expressions remain authoritative in the
YAML source.

| Alert | Rule group | Severity | `for` | Response |
| --- | --- | --- | --- | --- |
| `HighGatewayLatencyP99` | yabanin-gateway | warning | 2m | [Runbook](../runbooks/alerts.md#HighGatewayLatencyP99) |
| `HighGatewayErrorRate` | yabanin-gateway | critical | 2m | [Runbook](../runbooks/alerts.md#HighGatewayErrorRate) |
| `UpstreamDown` | yabanin-gateway | critical | 1m | [Runbook](../runbooks/alerts.md#UpstreamDown) |
| `CircuitBreakerOpen` | yabanin-gateway | warning | 30s | [Runbook](../runbooks/alerts.md#CircuitBreakerOpen) |
| `HighFallbackRate` | yabanin-gateway | warning | 2m | [Runbook](../runbooks/alerts.md#HighFallbackRate) |
| `LowClassifierAccuracy` | yabanin-classifier | warning | 5m | [Runbook](../runbooks/alerts.md#LowClassifierAccuracy) |
| `DiskSpaceLow` | infrastructure | warning | 5m | [Runbook](../runbooks/alerts.md#DiskSpaceLow) |
| `HighDeductionFailureRate` | infrastructure | warning | 2m | [Runbook](../runbooks/alerts.md#HighDeductionFailureRate) |
| `HighGatewayErrorRateV2` | infrastructure | warning | 2m | [Runbook](../runbooks/alerts.md#HighGatewayErrorRateV2) |
| `ServiceDown` | infrastructure | critical | 1m | [Runbook](../runbooks/alerts.md#ServiceDown) |
| `ShadowHighErrorRate` | yabanin-shadow | warning | 10m | [Runbook](../runbooks/alerts.md#ShadowHighErrorRate) |
| `ShadowBudgetBurn` | yabanin-shadow | info | 5m | [Runbook](../runbooks/alerts.md#ShadowBudgetBurn) |
| `CreditAuditDropped` | yabanin-drops | critical | 1m | [Runbook](../runbooks/alerts.md#CreditAuditDropped) |
| `CacheWriteDrops` | yabanin-drops | warning | 5m | [Runbook](../runbooks/alerts.md#CacheWriteDrops) |
| `SilentFailureObserved` | yabanin-drops | warning | 5m | [Runbook](../runbooks/alerts.md#SilentFailureObserved) |
| `LeaderFnFailed` | yabanin-drops | warning | 5m | [Runbook](../runbooks/alerts.md#LeaderFnFailed) |
| `RegionCacheInvalidateFailed` | yabanin-drops | warning | 5m | [Runbook](../runbooks/alerts.md#RegionCacheInvalidateFailed) |
| `OTelLogsDropped` | yabanin-drops | warning | 2m | [Runbook](../observability/otel-export.md#OTelLogsDropped) |
| `LoggerdConsumerStalled` | yabanin-loggerd | warning | 5m | [Runbook](../runbooks/alerts.md#LoggerdConsumerStalled) |
| `BudgetSettlementLagHigh` | yabanin-budget | warning | 5m | [Runbook](../runbooks/budget-reservations-alerts.md#BudgetSettlementLagHigh) |
| `BudgetSettlementLagHighCritical` | yabanin-budget | critical | 30m | [Runbook](../runbooks/budget-reservations-alerts.md#BudgetSettlementLagHighCritical) |
| `BudgetScopeReserveDivergence` | yabanin-budget | critical | 10m | [Runbook](../runbooks/budget-reservations-alerts.md#BudgetScopeReserveDivergence) |
| `BudgetWalletInvariantBreach` | yabanin-budget | critical | 15m | [Runbook](../runbooks/budget-reservations-alerts.md#BudgetWalletInvariantBreach) |
| `BudgetWalletHeadroomNegative` | yabanin-budget | warning | 5m | [Runbook](../runbooks/budget-reservations-alerts.md#BudgetWalletHeadroomNegative) |
| `BudgetStrandedCapacityHigh` | yabanin-budget | warning | 30m | [Runbook](../runbooks/budget-reservations-alerts.md#BudgetStrandedCapacityHigh) |
| `BudgetExpiredReleaseSpike` | yabanin-budget | warning | 5m | [Runbook](../runbooks/budget-reservations-alerts.md#BudgetExpiredReleaseSpike) |
| `BoundViolationRateHigh` | yabanin-budget | warning | 1h | [Runbook](../runbooks/budget-reservations-alerts.md#BoundViolationRateHigh) |
| `AdmissionOverheadP95High` | yabanin-budget | warning | 30m | [Runbook](../runbooks/budget-reservations-alerts.md#AdmissionOverheadP95High) |
| `ReservationGrantErrors` | yabanin-budget | warning | 10m | [Runbook](../runbooks/budget-reservations-alerts.md#ReservationGrantErrors) |

The drop, loggerd and budget rule groups are already installed **in the source
rule file**. Earlier statements that these metrics have no rules are obsolete.
This does not mean a running Prometheus instance has loaded the file.

## Scrape and delivery wiring

The example Prometheus configuration loads `alert-rules.yml`, sends alerts to
`alertmanager:9093`, and names gateway, admin, loggerd and node-exporter targets.
Those service names must resolve in your deployment. The gateway scrape uses
`/etc/prometheus/metrics-bearer.key`; supply the file with the configured bearer
key, or explicitly review the scrape/application auth configuration together.
Do not rely on a missing credential file silently disabling authentication.

The Alertmanager template has a default `webhook` receiver and a critical child
route with both webhook and Telegram configurations. Its placeholders must be
rendered or replaced before loading. A compatible webhook endpoint and valid
Telegram bot/chat configuration are external prerequisites. SMTP is not configured
by the template. See [test-firing instructions](alerts.md#test-firing-notification-channels).

Critical inhibits warning only when `alertname` and `job` match.
`HighGatewayErrorRate` and `HighGatewayErrorRateV2` therefore both notify above
10% error rate. `LowClassifierAccuracy` watches hard-class routing share, not
accuracy measured against labels. `ServiceDown` watches scrape success, not
inference success. These differences matter when diagnosing alerts.

## Organization spend notifications

The admin API exposes `GET/PATCH /api/organizations/{id}/spend-alert` to authorized
root administration. A positive `threshold_usd` enables the threshold; null
turns it off. Use the administrative session/CSRF flow, not a gateway API key.
The application checks accumulated spend periodically and sends a separate
webhook; it does not go through Alertmanager.

The payload includes event, organization ID/name, observed spend, threshold,
currency, timestamp and a message. It excludes API keys and request content, but
organization identity and spending are still sensitive operational data. The
configured receiver must be authorized to receive it. This feature is distinct
from hard budget enforcement and provider billing reconciliation.

## Validation and evidence

For each installed rule set, retain:

1. Source revision and rendered configuration identity, without secret values.
2. Prometheus/Alertmanager configuration validation results and loaded-rule state.
3. Target scrape success, including authenticated metrics access where enabled.
4. A synthetic warning and critical alert, actual receiver receipts and resolution.
5. A controlled application failure, the expected alert, the recovery action and
   observed return to health. Use synthetic traffic and an isolated environment.
6. Review of annotation labels/receiver payloads for sensitive data exposure.

Static source checks can verify anchors, declarations and routing structure. They
cannot prove receiver reachability or that a real application failure produces the
intended notification. The maintainer `scripts/quality/alert_check.py` also expects
its private Compose renderer; a clean public export lacks that prerequisite.
Use the checks supported by your deployment and record their actual scope.

## Known operating limits

- Thresholds need workload-specific validation. Historical microbenchmarks do not
  provide a production traffic baseline or guarantee a detection/recovery time.
- A zero or flat counter can mean no traffic, a restart, a failed scrape or actual
  recovery. Correlate it with successful operations and process uptime.
- Asynchronous audit/export drops may be irreversible. Resolving the alert does
  not reconstruct lost records; document and reconcile the affected interval.
- No automatic external alert delivery exists until you configure and test receivers.
- Backups, restoration, provider health and regional routing need separate
  acceptance; see [production operations](production.md).

# Gateway alerts runbook

The shipped rules live in `deploy/prometheus/alert-rules.yml`. Their `runbook_url`
annotations resolve to this page, [budget alerts](budget-reservations-alerts.md),
or [OTel export](../observability/otel-export.md). The [inventory](alerts-inventory.md)
lists all current rules and distinguishes them from organization spend webhooks.

Rules and receiver templates are configuration inputs, not an installed monitoring
service. The local quickstart does not start Prometheus or Alertmanager. The public
export does not include the maintainer's production Compose renderer. Install and
validate these components in your own deployment before relying on notifications.

## Test-firing notification channels

Prepare a protected copy of `deploy/alertmanager/alertmanager.yml`. Replace
`__ALERT_WEBHOOK_URL__`, `__ALERT_TG_BOT_TOKEN__` and `__ALERT_TG_CHAT_ID__` with valid
values, or remove unused receiver configurations and update their routes. The chat
ID must be a YAML integer. Alertmanager does not expand those placeholders or
ordinary shell environment variables automatically. Use a secret-aware deployment
mechanism; do not commit the rendered file or print it into a diagnostic log.

The template sends warning/info alerts to the `webhook` receiver; critical alerts
select `critical`, which contains both webhook and Telegram configurations. The
generic webhook needs an Alertmanager-compatible receiver or adapter. Do not assume
a Slack/PagerDuty incoming URL accepts the generic payload unchanged.

Validate the rendered config with the matching Alertmanager `amtool check-config`
command, install it, and check that the process loaded it without errors. If the
receiver tokens are absent, there is no meaningful delivery test. Confirm the
receiver owner expects a synthetic notification before sending one.

For an Alertmanager exposed only on host loopback port 9093:

```bash
curl --fail-with-body --silent --show-error \
  -X POST http://127.0.0.1:9093/api/v2/alerts \
  -H 'Content-Type: application/json' -d '[{
    "labels": {
      "alertname": "TestFireCritical",
      "severity": "critical",
      "job": "manual-test"
    },
    "annotations": {
      "summary": "Synthetic notification delivery test",
      "description": "No customer data; verify delivery and resolution."
    }
  }]'
```

Verify the webhook receipt, Telegram message, and resolved notification at the
configured destinations. Record timestamps, receiver identity and sanitized error
messages. A successful API POST means Alertmanager accepted the alert; it does
not prove a receiver got it. Inspect Alertmanager logs and notification-failure
metrics if delivery is missing. A separate `"severity": "warning"` test checks
the webhook-only route. A stopped synthetic alert expires according to
`resolve_timeout`; confirm the resolved message instead of assuming it arrived.

Keep the notification payload free of keys, credentials, prompts, responses and
customer identifiers. After a configuration change, use your deployment's
supported reload/restart path and repeat delivery acceptance.

## Routing, timers and evidence limits

| Setting in the template | Value | Meaning |
| --- | --- | --- |
| `group_wait` | 10s | Initial group batching delay |
| `group_interval` | 10s | Delay between updates to an existing group |
| `repeat_interval` | 1h | Repeat interval for an unchanged firing alert |
| `resolve_timeout` | 5m | Expiry for alerts without an explicit end time |
| Inhibition | critical suppresses warning for equal `alertname` and `job` | Does not suppress differently named alerts |

Rule `for` durations range from 30 seconds to one hour. Detection time also
includes the expression's lookback window and scrape/evaluation interval. A flat
counter after recovery does not immediately resolve an `increase(...[10m])`
alert; the old increase must leave the window.

`HighGatewayErrorRate` and `HighGatewayErrorRateV2` have different names, so both
can notify above 10% errors. The latter's lower severity does not mean its
threshold represents a milder condition. Inspect expressions rather than inferring
behavior from names. Some names/annotations are historical: `LowClassifierAccuracy`
measures routing class share, not measured classification accuracy.

The source checker `scripts/quality/alert_check.py` verifies metric declarations,
anchors and static routing/noise requirements in the maintainer environment. It
also expects the maintainer production Compose renderer, which is absent from the
public export. It is not a substitute for validating your rendered deployment or
receiving a real test notification. Historical local measurements do not establish
latency or reliability SLOs for a new installation.

## HighGatewayLatencyP99 {#HighGatewayLatencyP99}

The configured histogram expression exceeds 100 ms for two minutes, using a
five-minute rate window. Investigate affected paths/models, upstream latency,
stream duration, gateway processing, queues and database pools. Determine what the
instrumented duration includes before attributing all delay to the gateway.

**Action:** fix the slow dependency or capacity bottleneck; change routing only
with its quality/cost consequences understood. **Recovery:** under comparable
traffic, inspect the same histogram and verify the rule returns below threshold.
The default threshold is an operating starting point, not a published performance
promise or an independently measured baseline for your deployment.

## HighGatewayErrorRate {#HighGatewayErrorRate}

More than 5% gateway 5xx over five minutes, sustained for two minutes. Inspect
status/path, request IDs, provider errors, credentials, budgets, egress refusals
and [history admission](history-admission.md). Separate provider failures from
gateway persistence/dependency failures.

**Action:** recover the failed boundary without bypassing authorization or durable
history protection. **Recovery:** an authorized request completes and its history
persists; the observed 5xx ratio decreases under representative traffic.

## UpstreamDown {#UpstreamDown}

An upstream health state remains unhealthy for one minute. Inspect the endpoint,
DNS/TLS, configured model and credential, and any provider quota/error response.

**Action:** repair the route or deliberately remove the failed upstream from
selection. Check fallback policy before changing priority. **Recovery:** the health
probe and an authenticated model request both succeed. Never include the provider
key in a ticket or command transcript.

## CircuitBreakerOpen {#CircuitBreakerOpen}

An upstream circuit remains open for 30 seconds. **Action:** investigate the
underlying failures; resetting state without fixing the dependency can repeat the
outage. **Recovery:** the breaker admits a successful probe, returns to normal
operation and successful requests resume without excessive fallback.

## HighFallbackRate {#HighFallbackRate}

More than 20% of requests use fallback over five minutes, sustained for two
minutes. **Action:** identify the failing primary route and check fallback budget,
quality and residency constraints. **Recovery:** primary success returns and the
fallback ratio normalizes; a successful fallback alone does not repair the primary.

## LowClassifierAccuracy {#LowClassifierAccuracy}

The expression measures a **hard-class share above 30%**, sustained for five
minutes. It does not compare classifications against ground truth. The shipped
annotation's accuracy wording must not be interpreted as measured accuracy.

**Action:** inspect traffic mix and classifier source before recalibrating.
**Recovery:** confirm intended classifications against a labeled representative
sample. A changed class share alone is not proof of improved quality.

## DiskSpaceLow {#DiskSpaceLow}

Available filesystem space is below 10% for five minutes. **Action:** identify the
mount and growth source, restore capacity and review retention/backups. Do not
delete database WAL, live database files, or unprocessed event streams to silence
the alert. **Recovery:** sufficient space remains after normal write load resumes
and required data is intact.

## HighDeductionFailureRate {#HighDeductionFailureRate}

The rate of skipped deductions for insufficient funds exceeds 0.5/second for two
minutes. **Action:** inspect affected organizations, balances, limits, reservations
and settlement status. Correct funding/configuration through authorized workflows.
**Recovery:** appropriately funded requests succeed while intentionally exhausted
accounts still reject; do not disable budget enforcement to improve the metric.

## HighGatewayErrorRateV2 {#HighGatewayErrorRateV2}

More than 10% 5xx over five minutes for two minutes. Follow
[HighGatewayErrorRate](#HighGatewayErrorRate). Both rules can fire simultaneously.

## ServiceDown {#ServiceDown}

Prometheus `up == 0` for one minute means a scrape failed. **Action:** check the
process, scrape endpoint, network, TLS and metrics bearer credential. A missing
or wrong scrape credential can cause this even when inference is healthy.
**Recovery:** the target scrapes successfully and application health/inference
checks separately pass. Scrape success is not readiness or tenant authorization.

## SLO signals

- Latency: `gateway_http_request_duration_seconds` histogram.
- Errors: `gateway_http_requests_total` by status.
- Loggerd progress: `gateway_loggerd_events_consumed_total` and
  `gateway_loggerd_events_in_flight` together with stream lag/pending entries.

Define service objectives for your workload, including successful requests,
streaming behavior and durable history. These metric names alone do not establish
an SLO or an external service commitment.

## ShadowHighErrorRate {#ShadowHighErrorRate}

More than 50% shadow errors over fifteen minutes while shadow traffic exists,
sustained for ten minutes. **Action:** inspect the shadow model, endpoint,
credential, quota and budget; pause the experiment if its results are unreliable
or its extra cost is unwanted. **Recovery:** controlled shadow requests succeed
and comparison evidence is again usable. Check the primary path independently.

## ShadowBudgetBurn {#ShadowBudgetBurn}

Shadow calls were skipped because the configured daily cap was reached.
**Action:** reduce the sample, pause the experiment or deliberately adjust its
budget. **Recovery:** observed shadow volume matches the intended policy. Raising
the cap spends additional money; a cap-triggered skip can be expected behavior.

## CreditAuditDropped {#CreditAuditDropped}

The credit-audit drop counter increased within ten minutes and remained in that
condition for one minute. Audit records have been lost at a bounded asynchronous
queue. **Action:** inspect admin database health, audit insert latency and bursts
of credit operations. Restore drain capacity and document the affected interval.

**Recovery:** the drop counter stops increasing and normal audit events persist.
Already dropped records are not recreated by a restart. Reconcile affected credit
operations against authoritative state and record any remaining audit gap.

## CacheWriteDrops {#CacheWriteDrops}

The cache-write drop counter increased within ten minutes, sustained for five
minutes. **Action:** inspect writer occupancy, embedder/database latency and input
rate. Restore capacity or adjust intended caching load. **Recovery:** new cache
writes succeed and drops stop increasing. These are cache warm-up losses, distinct
from request-history or accounting loss; measure the resulting upstream load.

## SilentFailureObserved {#SilentFailureObserved}

`gateway_silent_failures_total{place,reason}` increased. The labels identify a
registered best-effort/fallback failure site. **Action:** find the pair in
`pkg/metrics/silent_failures.go` and correlate logs by timestamp/request ID.
`event_publish` failures can indicate missing history; optional-field parsing
failures have a different impact. Prioritize by affected data rather than treating
all increments as equivalent.

**Recovery:** the affected operation works, the relevant counter stops increasing,
and any missing-data interval is accounted for. Counter reset on restart is not
recovery evidence.

## LeaderFnFailed {#LeaderFnFailed}

Loggerd's leader workload returned errors in the last fifteen minutes. **Action:**
inspect leader election, database connectivity, schema compatibility and the
workload's first error. Budget settlement lag may show a downstream consequence.
**Recovery:** the workload completes healthy passes and settlement/backlog metrics
recover. Restart only after addressing the underlying failure.

## RegionCacheInvalidateFailed {#RegionCacheInvalidateFailed}

A region-cache mutation failed. `op="del"` can leave stale mappings until expiry;
`op="set"` forces further database reads. **Action:** repair cache connectivity and
verify the actual organization mapping from each gateway. **Recovery:** changes
propagate and new mutation failures stop. Review [multi-region limits](../multi-region.md)
before interpreting a region label as successful routing or residency evidence.

## LoggerdConsumerStalled {#LoggerdConsumerStalled}

Successful deliveries have stopped for a five-minute rate window while in-flight
activity is observed, then the condition persists another five minutes. Detection
is roughly ten minutes from the last completion, plus scrape/evaluation timing.
This is a progress signal, not merely queue occupancy.

**Action:** inspect consumer logs, PostgreSQL availability, stream pending entries
and group lag. Restore the blocked dependency. Do not trim the stream to make lag
appear smaller. **Recovery:** the completion counter advances and pending work
drains without loss. A dead process is primarily a `ServiceDown` concern; brief
in-flight pulses can also be missed between scrapes, so inspect lag independently.

## Budget and export alerts

Budget settlement, invariants, reservation errors and admission overhead have
[dedicated runbooks](budget-reservations-alerts.md). OTel export drops are covered
by [OTel export](../observability/otel-export.md#OTelLogsDropped). Their rules are
already present in the shipped rule file; do not install duplicate copies based
on historical planning text.

## Changing thresholds

Record the workload, metric semantics, baseline distribution, intended detection
time and tolerated notification noise before changing a threshold. Validate the
new rule with Prometheus tooling and replay representative healthy/failing cases.
Use your deployment's supported reload path, then inspect loaded rules and actual
notifications. A rule file committed to source does not prove the running
Prometheus instance loaded it.

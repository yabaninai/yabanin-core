# Usage and impact accounting

Open **Budgets → Units & spend** to view one organization's recorded cost,
counterfactual cost, wallet credits, token usage and modeled CO₂e for a selected
time window. The cards summarize the same values as the detailed table; they
are not amounts to add together. The returned window and request count identify
the data being displayed. Changes to the time inputs take effect after **Apply
window**.

The underlying endpoint is `GET /api/units/spend?org_id=...`, with optional
RFC3339 `from` and `to` bounds. Organization members need `analytics.read`;
root administrators can also view it. Viewing usage does not grant permission
to change budgets, credit balances or organization settings.

## What each quantity means

| Quantity | Source and interpretation |
| --- | --- |
| Recorded cost | Request-log cost in USD, using the configured pricing data. Coverage and legacy cost rows affect its quality label. |
| What-if cost | A counterfactual cost projection for the window. It is not an additional charge or a promise of invoice savings. |
| Credits spent | Usage settlements recorded in the wallet ledger during the window. One credit equals one USD cent. Ledger and request-log timing may differ. |
| Tokens used | Input plus output tokens from requests with recorded usage. Estimated usage is distinguished from provider-reported usage; missing usage is reported separately. |
| Estimated CO₂e | A model-factor calculation expressed in grams of CO₂ equivalent. It is not measured electricity use or a provider's verified emissions report. |

Monetary prices remain USD-based. Organization presentation settings do not
perform currency conversion. Credits, tokens and CO₂e are separate accounting
units, not exchangeable currencies or a universal resource meter.

## Carbon calculation and coverage

For a request with token usage and a matching configured model factor:

```text
estimated gCO2e = factor_g_per_million_tokens × (input_tokens + output_tokens) / 1,000,000
```

Factors come from the `carbon_factors` database table. No populated factor
catalog ships with the quickstart, and the dashboard does not currently provide
a factor editor. Operators must source and maintain suitable factors separately;
do not insert sample factors and present the resulting values as real emissions.

The current calculation matches factors by model name, preferring a verified
factor when several exist. It does not establish which physical provider or
data center performed inference. Provider, hardware, regional power mix and
measurement uncertainty are not independently verified by this report.

Missing factors are not treated as evidence of zero emissions. If all requests
with usable token counts lack factors, the carbon amount is unknown. With partial
factor coverage, the view reports a subtotal and missing-factor notices. Missing
token usage is reported separately: a window with no usable token rows can have
a zero carbon total even when requests exist. Always read the coverage notices
and request count before interpreting a value, including zero.

The API's `exact` quality label describes its accounting calculation and factor
coverage. It does not turn a factor estimate into physical measurement, and its
input tokens may themselves have been estimated. The dashboard therefore labels
the carbon summary **Estimated CO₂e** even when the API reports `exact`.

The read-only cap-status view can compare this estimate with a configured
`YABANIN_CARBON_BUDGET_GRAMS` threshold. That comparison does not enforce a
gateway emissions quota. Water consumption and electricity in kWh are not
tracked by this report.

## Prices and data quality

The detailed view retains each amount's unit, data-quality label, source and
available notes. Null amounts remain unknown; tiny nonzero amounts must not
appear as zero merely because of display rounding. Recorded and what-if USD
rows remain separate even when both are zero or unknown.

The report includes the pricing timestamp and, when available, catalog version
and digest. Root administrators can inspect the reference catalog, preview a
pricing-pack diff and promote an accepted pack through the Rates interface.
Catalog identity and provenance help trace pricing; they do not guarantee that
the prices are current or match a provider's final invoice.

The bundled reference prices cover a limited set of models and may be outdated.
Configure current prices before relying on cost totals. Coverage notices identify
unknown usage, missing model factors and legacy cost rows; a successful API
response alone does not mean the data is complete.

For local workload scenarios without a running gateway, use the
[offline spend audit](audit.md). Its routing and cache projections remain
simulations, separate from recorded usage and invoice charges.

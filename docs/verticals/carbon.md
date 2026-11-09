# Carbon estimation preset

The `carbon_brsr` library preset contains estimation and model-selection
helpers. It does not establish BRSR/CSRD compliance or produce an independently
verified emissions inventory. Its administrative handler name is `carbon`.

## Current implementation

`pkg/verticals/carbon/pack.go` stores model factors and organization budgets
in memory. It estimates prompt tokens from byte length divided by four and
uses a configured factor to estimate grams. These are estimates, not measured
energy or provider-reported request emissions.

When estimated usage would exceed a budget, the transform can choose a
configured model whose factor is below 70% of the current model's factor.
It does not validate equivalent model quality or capabilities. It does not
hard-deny a request when no alternative exists, and the transform does not
increment a durable monthly usage ledger or reset monthly windows.

The report reads in-memory budget data rather than an audited, date-filtered
request history. Its date arguments do not establish a reporting-period
calculation. Do not use its `compliance` field or hard-coded report budget as
evidence of regulatory readiness. An operational carbon program requires
validated factors, usage measurement, persistent accounting, model eligibility,
and independent review of the reporting methodology.

## Integration status

These are library capabilities, not a complete activated administrative
workflow. `services/admin/handlers/vertical_handlers.go` currently acknowledges
enable/disable requests without persisting organization assignments and returns
an empty enabled-vertical list. An HTTP acknowledgement does not prove that
traffic is passing through this pack. The short handler name differs from
the pack identifier. No copy-and-paste activation recipe is offered here
because it would imply functionality the handler does not provide.

Before using the library in an integration, verify organization isolation,
configuration persistence, gateway invocation, denial behavior, restart
behavior, and report provenance. See [residency packs](../residency-packs.md),
[policy pipelines](../pipeline.md), and [lineage](../lineage.md) for their
separate implemented contracts and limitations.

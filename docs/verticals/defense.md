# Defense screening preset

The `defense_itar` library preset contains model-list and keyword-screening
helpers. Its name does not establish ITAR authorization, export-control
classification, approved suppliers, or verified sovereign infrastructure.
Its administrative handler name is `defense`.

## Current implementation

`pkg/verticals/defense/pack.go` evaluates configured model region/family
metadata. Separately, its transform checks an in-memory model pool when that
pool is nonempty. **An empty pool permits all models at this membership
check**; it is not a deny-all default. Populate and verify the intended pool
before relying on this integration, and evaluate residency independently.

Keyword matches add `itar_screened` and `flagged_terms` metadata. The
transform does not automatically deny a keyword match or wait for a human
review. A caller must implement and verify any required review or denial
workflow. Keyword absence is not a determination that data is uncontrolled.

The report contains the in-memory pool size, not an independently verified
history of screened requests. Model metadata and a signed routing record do
not independently prove where a provider processed data.

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

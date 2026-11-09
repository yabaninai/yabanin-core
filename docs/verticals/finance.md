# Finance review preset

The `finance_rbi` library preset contains model-list checks and sensitive-task
flags. It does not establish RBI compliance or provide a completed regulatory
approval system. Its administrative handler name is `finance`.

## Current implementation

`pkg/verticals/finance/pack.go` checks an in-memory approved-model list.
**An empty list allows every model** at this check. With a nonempty list,
the transform denies models absent from that list.

For matching sensitive-task keywords, the transform adds
`regulatory_decision=true` and `requires_approval=true`, and records an
in-memory pending marker. It still returns the request without waiting for
approval. A caller must implement and test any blocking review workflow.
The marker key is derived from the model name rather than a unique request
identifier, so its count is not a count of distinct pending requests.

The report summarizes in-memory pending markers; it does not query a
persistent, date-filtered audit log. Restart persistence, approval identities,
request uniqueness, review decisions, and tamper-evident records require
additional integration. Do not describe the placeholder report as an RBI
inspection-ready audit trail.

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

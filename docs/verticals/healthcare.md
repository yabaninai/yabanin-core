# Healthcare pattern-redaction preset

The `healthcare_phi` library preset provides a limited pattern detector and
redactor. It does not establish HIPAA, DPDP, or PDPA compliance, de-identify
all health information, or guarantee that protected information cannot leave
the deployment. Its administrative handler name is `healthcare`.

## Current implementation

`pkg/verticals/health/pack.go` scans the prompt string using built-in regular
expressions and replaces matches with redaction markers. The transform adds
`phi_detected`, `phi_types`, and `prompt_redacted` metadata when it finds
matches, then returns the transformed prompt. It does not hard-deny on a
match; the previously documented `strict_mode` switch is not implemented by
this transform.

Pattern matching can miss sensitive information or redact harmless text.
This transform does not establish complete coverage of system messages,
attachments, tool payloads, streamed output, logs, or every language. Test
those surfaces separately before sending any sensitive workload.

The report method returns fixed zero redaction and violation counts rather
than querying an audit store. Those zeros are placeholders, not evidence of
clean traffic. Use measured detection outcomes and verified request history
for operational review.

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

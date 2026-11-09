# Halal policy preset

`halal_bpjph` is the identifier of a software policy preset. Its name does
not establish BPJPH approval, halal certification, supplier certification,
or regulatory compliance. The current implementation checks configured model
metadata; it does not inspect a supplier's certificates or validate a model's
religious or legal suitability.

## Implemented behavior

`pkg/verticals/halal/pack.go` evaluates the selected model's registered region
and family against allowed lists and an optional country blacklist. Its
request transform returns the request unchanged.

The built-in rule values are:

```json
{
  "allowed_jurisdictions": ["SG", "IN", "ID", "GLOBAL"],
  "allowed_model_families": ["openai", "anthropic", "google", "sovereign_sg", "open_weights"],
  "data_residency": "ID",
  "cross_border_allowed": false,
  "blacklisted_countries": []
}
```

The evaluator checks the jurisdiction list, family list, and blacklist.
It does **not** independently enforce `data_residency` or
`cross_border_allowed`. In particular, the defaults above permit registered
regions outside Indonesia; they must not be described as Indonesia-only
processing. A registered region is operator-supplied metadata, not physical
location verification.

## Integration status

The administrative vertical handlers are scaffolding: enable/disable handlers
return an acknowledgement without persisting an organization assignment, and
the list handler returns an empty list. The enable handler accepts the short
name `halal`, whereas the pack identifier is `halal_bpjph`. A successful HTTP
response from that handler does not prove activation or request enforcement.

The pack's report method returns a static summary containing an `attested`
status. It does not query request history or verify suppliers. Treat it as
an implementation placeholder, not a compliance report.

For implemented residency controls, start with [residency policy packs](../residency-packs.md).
For signed request records and their limits, see [lineage](../lineage.md).
Any use of this preset requires integration tests proving the intended
organization assignment and gateway enforcement, plus independent review
of the requirements for that deployment.

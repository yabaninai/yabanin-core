# Guard detector packs

A detector pack adds versioned regular-expression rules to the guard runtime.
It consists of a manifest and one `detector.json` file. Loading verifies the
pack and compiles its rules; it does not activate a policy or block a request.
The public implementation is in [lifecycle.go](lifecycle.go), with manifest
validation in [pack.go](pack.go) and evaluation in [runtime.go](runtime.go).

## Pack format and limits

The manifest uses `schema_version: "guardpacks.v1"` and
`runtime_api: "guardrails.v1"`. It requires nonempty `pack_id` and
`pack_version`, plus a `files` array containing relative paths and their
hexadecimal SHA-256 digests. The detector loader accepts exactly one entry,
whose path is `detector.json`.

`detector.json` contains a `detectors` array. Each rule requires nonempty
`rule_id`, `rule_version`, `category`, and `pattern` fields. Patterns must
compile with Go's `regexp` package (RE2 syntax). Detector identities include
both pack and rule versions; duplicate complete identities are rejected.

| Boundary | Limit or behavior |
| --- | --- |
| Manifest bytes | At most 1 MiB |
| General manifest file list | At most 64 entries; the detector loader further restricts this to one `detector.json` |
| `detector.json` bytes | At most 4 MiB |
| Rules per detector pack | Between 1 and 256 |
| Retained findings per evaluation | At most 10,000 across all detectors |
| Input content bytes at the evaluator | No size limit at this layer |

Manifest decoding rejects unknown fields and trailing JSON values. The
`detector.json` decoder uses `json.Unmarshal`; it does not provide the same
unknown-field rejection. File verification rejects duplicate or unsafe paths,
paths resolving outside the pack root, and digest mismatches. The loader
checks the bytes it compiles against the declared digest as well as performing
the initial file verification.

The findings cap limits retained output, not input size or total evaluation
work. Callers must apply suitable request limits before evaluating untrusted
content. Transport limits are separate from these pack and evaluator limits.

## Signatures and trust

Use `LoadDetectorPackWithVerifier(root, manifestBytes, verifier)` to load a
pack with an explicit signature verifier. The built-in
`NewEd25519Verifier` accepts a configured map of key IDs to Ed25519 public
keys. [packsign.go](packsign.go) also provides configuration helpers for
`<key-id>.pub` files and inline keys; public keys are raw 32-byte values
encoded as hexadecimal or standard base64.

The supported signature envelope uses version `guardpack-sig.v1`, algorithm
`ed25519`, a trusted `key_id`, and a standard-base64 signature. A declared
signature is rejected if no verifier is configured, its scheme is unsupported,
or verification fails. `LoadDetectorPack` supplies no verifier, so it rejects
signed manifests.

**Unsigned manifests remain accepted, including when a verifier is configured.**
Configuring trusted keys is not a requirement that every pack be signed.
A caller requiring signed packs must enforce that requirement separately.
`VerifyPack` verifies file integrity; it is not a substitute for manifest
signature verification.

Signatures cover the canonical manifest payload, including file hashes and
any `coverage` or `not_covered` declarations, but excluding the signature
envelope itself. Canonicalization uses the typed manifest representation in
[pack.go](pack.go), not the original JSON file's whitespace. The returned pack
digest identifies that canonical payload, not an archive. Verification binds
the payload to a configured public key; the operator must establish the key's
trust independently. It does not certify rule quality or prove coverage.

## Inputs and evaluation

An `Invocation` requires a context, `Version: RuntimeVersion`, a `before` or
`after` phase, and a content kind. `text` selects `Text`, `arguments` selects
`Arguments`, and `result` selects `Result`. Arguments and results are evaluated
as strings; the regular-expression loader does not parse them as JSON or
execute their contents. Finding spans are byte offsets into the selected
content.

`NewExtendedEvaluator` combines built-in detectors and additional pack
rules. The resulting evaluator sorts detectors by pack ID, rule ID, and rule
version; built-in detectors do not have guaranteed priority over pack rules.
Detection returns findings without applying a blocking or redaction action.
Policy application is a separate step. Detector errors are returned rather
than converted into a successful allow result.

The built-in text behavior is pinned by
[inputs_matrix_test.go](inputs_matrix_test.go). Its cases cover Russian
identifiers, email and phone patterns, payment-card checks, secret-shaped
strings, and selected prompt-injection patterns. These are specific tested
patterns, not comprehensive detection of every identifier or attack.

- Empty input produces no built-in findings. Custom rules can have different
  behavior, including patterns that match empty strings.
- Invalid UTF-8 and binary bytes are not rejected at this boundary. A finding
  still depends on a matching pattern; there is no binary-format decoder.
- No Unicode normalization is applied. Canonically equivalent strings can
  produce different findings; the tests include composed and decomposed text.
- The tests pin repeatable built-in results and behavior on oversized input.
  They do not establish determinism for arbitrary custom Go detector
  implementations or a universal resource bound.

## Coverage declarations

Coverage metadata is optional and implemented today. A `coverage` entry
contains `rule_id`, `ev_ids`, and `evidence_test`. Scenario identifiers come
from the package's closed `EV-A01` through `EV-A08` registry. Loading checks
that each declared coverage rule exists in the pack. Manifest decoding checks
field shape, supported scenario IDs, and duplicate declarations. Each coverage
block is limited to 64 entries; rule IDs are limited to 128 bytes and evidence
references to 256 bytes.

An optional `not_covered` entry contains `ev_id`, a `state` of `partial` or
`not_covered`, and a nonempty `reason` of at most 256 bytes. This block is also
limited to 64 entries. A manifest cannot both claim coverage and declare
partial or absent coverage for the same scenario.

`CoverageStateFor` and `CoverageStates` report what the manifest declares:
`covered`, `partial`, `not_covered`, or `unknown`. An omitted scenario is
`unknown`. These methods also work on unsigned manifests and do not themselves
verify signatures. An `evidence_test` value is a reference supplied by the pack
author; loading does not locate or run that test. A declaration is therefore
not a measured protection guarantee or an OWASP certification.

See [coverage.go](coverage.go), [notcovered.go](notcovered.go),
[coverage_verify_test.go](coverage_verify_test.go), and
[coverage_states_test.go](coverage_states_test.go) for validation and state
semantics. Signature and loading regressions are in
[packsign_test.go](packsign_test.go) and [lifecycle_test.go](lifecycle_test.go).

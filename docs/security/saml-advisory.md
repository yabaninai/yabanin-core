# SAML advisory GO-2026-6909

The Go vulnerability database reports `ServiceProvider.ParseResponse` as
reachable in the SAML login flow. Its [GO-2026-6909 record](https://pkg.go.dev/vuln/GO-2026-6909)
currently lists every version of `github.com/crewjam/saml` as affected.

The selected `v0.5.2` has different behavior from the affected code described
in that record. At [upstream commit `400b0e48`](https://github.com/crewjam/saml/tree/400b0e48aad125f09de4627eae3245985c8275fc):

- `Assertion.Issuer` is a value. An omitted issuer becomes empty and fails the
  expected-issuer comparison; there is no issuer pointer to dereference.
- `validateAssertion` checks for missing `Subject`, `Conditions`, and
  `SubjectConfirmationData` before using them.
- `Subject.NameID` requires the SAML assertion namespace. A foreign or
  unqualified `NameID` does not become the login identity.

`pkg/adminauth/saml_advisory_test.go` checks these properties using
signed assertions and responses through the ACS parser and email mapping.
It also checks valid login identities, request correlation, recipient,
audience, expiry, certificate trust, and signature tampering. Historical
`v0.5.1` negative controls reproduce the foreign-namespace identity substitution
and missing-field panics. No SAML feature is disabled to obtain these results.

The source scan wrapper retains the original scanner output and reachable
finding. It classifies only this exact advisory/module combination as
`NOT_AFFECTED`, with these required pins:

- Module: `github.com/crewjam/saml v0.5.2`.
- Module checksum: `h1:C6Md0Q8bI5AtkYeSbnvmJAm77GnoO4HlTuOO9w9V4Sw=`.
- Reviewed advisory content, complete cached module contents, and security
  source files must match the recorded hashes.
- No SAML replacement, workspace, vendor directory, or `GOFLAGS` override.
- Review window: November 10 through December 9, 2026, inclusive.

Any drift, expired review, malformed or incomplete scanner output, unsuccessful
scan, or other reachable advisory blocks the check. A new advisory is never
covered by this disposition. The callable library functions remain reachable;
this is a version-specific source assessment, not an assertion of unreachability
or acceptance of a known vulnerability. The original database record is not
edited. Updating dependencies or advisory content requires a fresh review.

The wrapper is invoked by the source security gate. It writes the raw JSON,
stderr, their hashes, and a summary to a new directory under
`artifacts/security/go-disposition-*`. This assessment does not cover container
packages, frontend dependencies, deployment settings, or release approval.

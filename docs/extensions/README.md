# Extend Yabanin

These guides describe extension points in the public core. Choose the smallest
surface that fits your change; editing configuration is different from adding
code that runs inside the gateway or operator process.

| Guide | Extension | Source entry points |
| --- | --- | --- |
| [Client adapters](adapters.md) | Render client configuration or plan managed configuration edits | `pkg/clientconfig`, `pkg/harness/adapters` |
| [Pipeline steps and conditions](pipeline-steps.md) | Add an in-process policy step or condition compiler | `pkg/pipeline`, `pkg/gateway/gateway_policy.go` |
| [Guard detector packs](guard-packs.md) | Load declarative regular-expression detectors | `pkg/guardhooks` |

## Trust and execution boundaries

Go extensions are compiled into trusted application code. They are **not an
operating-system sandbox**: arbitrary Go code can access whatever files,
network, and process privileges the application has. Interfaces and review
rules constrain intended behavior, but do not prevent a malicious or buggy
implementation from bypassing them. Review extensions and run services with
appropriate OS, container, and network permissions.

The existing callout family uses an operator-configured host allow-list and
SSRF protection. This protection applies to that implementation; it is not a
universal restriction on every newly compiled step or adapter. LLM judge steps
also depend on a configured model client. Trace each outbound dependency and
its credentials separately.

Policy compilation rejects unknown names and invalid parameters it validates.
Runtime work can still fail, time out, or panic. Test the configured error,
shadow, and enforcement behavior; loading successfully is not an assurance
that requests cannot fail.

Declarative guard packs have a narrower format: the current loader compiles
regular-expression definitions, not arbitrary Go or shell code. They can still
change decisions and consume resources. Checksums verify file integrity;
signatures require a trusted verification key and do not establish detection
quality.

## Compatibility and validation

Preserve names and formats used in existing configurations. Pipeline factory
names and client IDs are user-facing contracts. Guard manifests declare
`guardpacks.v1` and runtime API `guardrails.v1`; incompatible versions must be
handled explicitly rather than silently reinterpreted.

Start with the [development guide](../DEVELOPMENT.md). Include focused tests
for valid input, invalid input, cancellation, conflicts, and the relevant
rollback path. Runtime and network changes also need deployment-specific
verification. The examples here explain extension mechanics; they do not
establish support for a new client, provider, or production workload.

The `yb client-config` renderer and `yb harness` editor have different client
lists. Rendering a snippet does not verify the client itself. The current
Gemini CLI harness entry refuses automatic setup, and `yb delegate` uses a
fake executor in this preview; neither should be advertised as a working
live delegation or Gemini integration based on these extension points.

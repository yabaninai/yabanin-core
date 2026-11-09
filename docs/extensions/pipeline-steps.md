# Add a pipeline step or condition engine

The [policy pipeline](../pipeline.md) inspects and can mutate gateway traffic.
Its implementation lives in `pkg/pipeline`; production registration happens in
`newPolicyEngineWithJudgeDeps` in `pkg/gateway/gateway_policy.go`.

A new Go implementation requires rebuilding and deploying the gateway. The
registries are ordinary in-process Go objects, not a dynamically downloaded
plugin system or a security sandbox.

## Step contract

A step implements:

```go
type Step interface {
    Name() string
    Run(ctx context.Context, p *Pipeline, in *Payload, out *Result) error
}

type StepFactory func(params map[string]any) (Step, error)
```

`Registry.Register` maps a name to a factory and rejects empty names, nil
factories, and duplicate names. `MustRegister` panics on registration error;
use it only where initialization failure is intentional. The API does not
prevent a program from calling registration methods at runtime, but production
wiring should finish registration before compiling policies that use them.

Factories validate policy parameters and build reusable steps. Do not retain
or mutate the supplied parameter map. A compiled step may serve concurrent
requests, so do not store request-specific mutable state on the step itself.

Follow the contracts in `pkg/pipeline/step.go`:

- Honor cancellation and return promptly. A context deadline is cooperative;
  it cannot safely terminate arbitrary Go code that ignores it.
- Detectors treat input as read-only and append findings to the result. Embed
  `DetectorBase` for the marker required by parallel detector groups.
- Mutators edit the request payload and embed `MutatorBase`. They run in
  declaration order and cannot join a read-only parallel group.
- Only decision steps raise the verdict; the engine keeps the strongest
  verdict. `Mutated` and `Trace` are engine-owned result fields.
- Do not retain `Pipeline`, payloads, or per-request context after the call.
  Keep private request content and credentials out of findings and logs.

## Add and wire a step

1. Choose a stable name and define its parameters, findings, mutation scope,
   time budget, and error behavior. Existing names are configuration contracts;
   renaming or removing them can break stored policies.
2. Implement the step and factory in the relevant `pkg/pipeline` package.
   `pkg/pipeline/builtins/registry.go` maps built-in names to factories; inspect
   an existing detector or mutator with similar behavior before extending it.
3. Register the factory in the production engine wiring. Do not assume adding
   a factory to a package makes it available in the gateway automatically.
4. Compile a policy referencing the name. Check unknown-name and invalid-param
   failures, detector/mutator classification, and parallel-group restrictions.
5. Run the compiled policy with representative input, errors, cancellation,
   concurrent requests, and shadow/enforce modes. Verify the actual gateway
   hook where it will execute, not just a standalone factory test.

For example, registration within the existing engine assembly follows this
pattern; `exampleFactory` stands for the implementation you supply:

```go
if err := eng.Steps().Register("builtin/example", exampleFactory); err != nil {
    return nil, fmt.Errorf("register example step: %w", err)
}
```

This fragment is not a complete standalone extension. The factory and policy
must agree on how the step name resolves; inspect `StepSpec` in
`pkg/pipeline/policy.go` and compilation in `pkg/pipeline/compile.go`.

## Conditions

`ScriptRegistry` maps an engine name to a compiler with this contract:

```go
type ConditionCompiler func(source string) (ConditionProgram, error)

type ConditionProgram interface {
    Evaluate(ctx context.Context, env ConditionEnv) (bool, error)
}
```

Programs must be deterministic, side-effect free, safe for concurrent use,
and bounded in time and memory. The condition implementation is responsible
for those bounds; the interface alone does not provide them. Treat the
findings, traces, metadata, and decision data in `ConditionEnv` as read-only.

Production wiring registers `expr`, `lua`, and `starlark`. With multiple
registered engines, policies must explicitly name `when_engine`; the first
registration is not an implicit default. The core supports omitting the name
when exactly one engine is registered. Add a compiler through
`eng.Scripts().Register`, and test syntax errors as well as runtime errors,
resource limits, and cancellation.

## Network and runtime failures

`services/run/gateway.go` reads these deployment settings:

| Setting | Behavior |
| --- | --- |
| `YABANIN_POLICY_MODE` | `off` by default; `shadow` and `enforce` enable policy processing |
| `YABANIN_POLICY_COLD_FAILURE_MODE` | `fail-closed` by default when no usable organization policy snapshot exists; `fail-open` is an explicit alternative |
| `YABANIN_POLICY_CALLOUT_ALLOW_HOSTS` | Host patterns for the existing outbound HTTP callout implementation |

With an empty callout allow-list, production wiring does not register callout
factories, and policies referencing them cannot compile. This does not mean
all pipeline work is network-free: LLM judges use a configured client, and
arbitrary newly compiled Go code can dial out unless the operating environment
prevents it. Reuse reviewed transport and credential boundaries; do not bypass
them with an ad hoc HTTP client.

Compilation catches reference and parameter errors; it cannot eliminate
runtime failures. Steps can return errors, time out, or panic, and condition
evaluation can fail. The engine recovers step panics and applies its configured
error behavior. Validate `on_error`, shadow/enforce behavior, and gateway
cold-policy handling for your use case. Policy loading may occur while serving
requests, so a load error is not necessarily only a deployment-time event.

## Rollout and rollback

Use shadow mode and representative traffic before enforcing a new behavior.
Check findings, latency, privacy, and error handling. Turning the pipeline off
skips its request processing, but it does not make unrelated code changes in
a custom gateway build harmless.

For rollback, coordinate policy and binary versions. Deploying a binary that
lacks a still-referenced step causes policy compilation failures. Remove or
migrate references while the old implementation is still available, then
revert the code. Keep the prior policy and executable available and test the
transition against the actual policy store and cache behavior.

# Add a client adapter

Yabanin has two independent client configuration surfaces:

- `yb client-config` renders a snippet to stdout for a user to review and apply.
- `yb harness connect` plans and applies configuration changes through a
  transaction journal; `disconnect` attempts to undo them.

Both are Go implementations compiled into the operator CLI. They are not
sandboxed plugins. A contribution must preserve the intended file and secret
boundaries, and reviewers must inspect the actual implementation.

## Render-only configuration

`renderClientConfig` in `pkg/trcli/client_config.go` selects a renderer from
`pkg/clientconfig`. `clientconfig.Params` carries the base URL, key environment
variable name, model IDs, labels, key mode, and provider ID. It does not contain
the raw API key.

From the repository root, build the CLI and render a sample:

```bash
go build -o bin/yb ./cmd/yb
bin/yb client-config --client opencode   --base-url http://127.0.0.1:8082 --key-env YABANIN_API_KEY   --model mock-model --models mock-model --repo example --label team=demo
```

Expected output is an OpenCode JSON configuration referencing the environment
variable rather than a literal credential. It does not modify client files or
verify a running gateway. The quickstart's mock model is suitable for checking
configuration plumbing, not useful coding work.

To add another renderer:

1. Read `pkg/clientconfig/clientconfig.go` and a renderer for the same target
   file format. Renderers expose format-specific methods or return strings;
   there is no shared `Renderer` interface to implement.
2. Add a renderer that produces valid target syntax and references a supported
   environment variable or credential helper. Keep it free of file writes and
   network calls. Escape supplied URLs, model IDs, labels, and variable names
   for the target format.
3. Add the client case in `renderClientConfig` and update the `--client` help.
4. Add tests in `pkg/clientconfig` for normal and adversarial inputs, including
   quotes, newlines, empty optional fields, and secret-free output. Existing
   golden files are examples of expected formatting, not proof the target
   application accepts every version.
5. Exercise the actual client version in an isolated configuration and record
   the result in its client guide and [compatibility matrix](../compatibility.md).

## Managed configuration edits

The interface in `pkg/harness/adapters/registry.go` is:

```go
type Adapter interface {
    ID() string
    Supported() (bool, string)
    Detect(home string, run cictx.Runner) Detection
    Plan(home string, p ConnectParams) (harness.Plan, error)
    Unapply(path string, current []byte, m harness.Managed) ([]byte, error)
}
```

`Detection` records installed status, version, configuration path, and whether
the tool is connected. `ConnectParams` includes gateway URL, labels, model
selection, and options such as `SetDefault`, `Force`, and `Experimental`.
Read the actual struct before extending it; it does not carry a raw API key.
`All()` registers the supported implementations and explicit refusal entries.

Implement `Plan` to return proposed changes instead of writing files directly.
The CLI shows diffs and normally asks before applying them. The shared
`harness.Engine` handles locking, backups, atomic writes, and journal state.
Detection may invoke a client executable through the supplied runner; it is
not a promise that adapters have no host-process access.

With a configured gateway and an installed Codex client, inspect a plan:

```bash
bin/yb harness connect codex --gateway-url http://127.0.0.1:8082   --model mock-model --set-default --dry-run
```

This example is a preview of a configuration change, not a useful coding
session. `--dry-run` prevents applying the plan but the command still probes
the gateway before planning. It can fail because the endpoint is unavailable
or lacks a required route. Do not assume it is offline or add `--force` just
to hide an unexplained failure. See the [harness guide](../harness.md) for
credential setup, applying a reviewed plan, and disconnecting.

## Preserve user changes and report conflicts

Use each tool's existing managed-block convention. Some adapters also disable
conflicting top-level settings or manage helper files, so a universal promise
that all changes occur inside one text block would be incorrect. Record every
intended file change in the plan and test unrelated content preservation.

`Engine.Rollback` in `pkg/harness/engine.go` restores the saved bytes when the
current file hash matches the journal's post-edit hash. If the user changed the
file afterwards, the engine calls `Unapply` to remove the managed changes while
preserving unrelated edits. That path can report conflicts or a partial
rollback. Missing backups and filesystem errors can also prevent restoration.

An adapter's `Unapply` must refuse ambiguous edits rather than delete user
content. Test both unchanged-file restoration and changed-file unapply, plus
malformed markers, concurrent edits, interrupted writes, and reconnect after a
successful disconnect. Inspect the returned report; command completion alone
does not establish that every file was restored.

## Current client surfaces

The lists are maintained separately in `pkg/trcli/client_config.go` and
`pkg/harness/adapters/registry.go`.

| Client | Render snippet | Harness edit |
| --- | --- | --- |
| Codex, Claude Code, OpenCode | Yes | Implemented |
| Continue, Aider | Yes | Requires `--experimental` |
| Shell | No | Implemented shell profile adapter |
| Cline | Instructions/snippet | Refused: extension-state configuration |
| Cursor, Roo Code, Kilo Code, Zed, JetBrains, Copilot | No | Explicit refusal entries |
| Gemini CLI | No | Refused; gateway protocol support is unavailable |

These are configuration capabilities, not live-client verification claims.
When adding a client, update both lists deliberately; rendering support need
not imply safe automatic editing. Keep raw credentials out of generated
configuration, diffs, diagnostics, and journal metadata. Do not add new outbound
endpoints or host writes without explicit design and review of their scope.

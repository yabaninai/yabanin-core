# `yb harness`

`yb harness` connects a local client tool to the gateway without writing the
API key into the tool's config.

| Command | Effect |
| --- | --- |
| `yb harness list` | Tool, support, install, config path, connected or drift |
| `yb harness connect <tool>` | Plan, diff, then apply. `--yes` skips the prompt. A non-TTY without `--yes` changes nothing |
| `yb harness disconnect <tool>` | Roll the last applied edit back |
| `yb harness status` | Applied transactions and drift |
| `yb harness doctor <tool>` | Check the config and the gateway. The key is not printed |
| `yb harness key --tool <tool>` | Print the key for `apiKeyHelper` or `auth.command` |

Codex, Claude Code, OpenCode, Continue, Aider, and the shell are edited
inside managed blocks:

```
# >>> yabanin:<tool>:<block> (managed by `yb harness`; undo: `yb harness disconnect <tool>`) >>>
# <<< yabanin:<tool>:<block> <<<
```

A conflicting top-level Codex line is commented as `# yabanin-disabled:` and
restored on disconnect. Continue and Aider require `--experimental`. Cursor,
Cline, Roo, Kilo, Zed, JetBrains, Copilot, and Gemini CLI are listed with a
reason and are not edited.

The key is a helper command or an env reference such as `{env:YABANIN_API_KEY}`.
Backups under `~/.yabanin/harness` are mode `0600`.

## Session keys

`yb harness connect <tool> --session [--session-ttl 8h]` stores
`harness.<tool>.session` in `~/.yabanin/config.json`. After that,
`yb harness key --tool <tool>` mints a `ybs_` key whose labels are the
profile's static labels, the git checkout of the helper's working directory,
and `.yabanin.yml`. The key is cached under `~/.yabanin/sessions` (`0700`,
files `0600`) until ten minutes before it expires. A mint failure prints the
parent key and a warning on stderr so the tool keeps working. `yb logout`
deletes the session cache. If `yb ci finish` does not run, the key dies at
its TTL.

Claude Code caches the helper for five minutes
(`CLAUDE_CODE_API_KEY_HELPER_TTL_MS`). Codex refreshes on
`refresh_interval_ms` (five minutes). A branch change is therefore visible
only after that delay. The labels are computed in the helper process's
working directory. A check against the installed Claude Code and Codex
helpers was not run in this change; the cache key includes the encoded
label set, so a different branch produces a different file.

## Adding support for another tool

To contribute a new client adapter (render-only `yb client-config` output,
auto-edit harness support, or a documented refusal entry with a reason), or
to understand why the render and auto-edit tool lists differ, follow
[extensions/adapters.md](extensions/adapters.md) — the walkthrough pins the
`adapters.Adapter` contract, the managed-block rules and the compatibility
table to code.

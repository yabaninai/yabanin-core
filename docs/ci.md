# CI labels

On GitHub Actions, `GITHUB_JOB` is the job key from the workflow file. Every
instance of a matrix job shares that key. To tell them apart, pass
`--label ci.job=${{ github.job }}-${{ strategy.job-index }}`. The flag
overrides automatic detection.

## `yb ci`

`yb ci env` prints `YABANIN_GATEWAY_URL`, `YABANIN_LABELS`,
`ANTHROPIC_BASE_URL`, and `ANTHROPIC_CUSTOM_HEADERS` for the current job.
`--openai-env` adds `OPENAI_BASE_URL`. `--with-key` also prints the CI key
as `YABANIN_API_KEY`, `OPENAI_API_KEY`, and `ANTHROPIC_AUTH_TOKEN`.

`yb ci exec -- <command>` puts that environment on the child process only.
The parent shell is unchanged, and the command's stdout is the child's
stdout. When `codex` or `opencode` is on `PATH`, the child also receives a
temporary Codex config or `OPENCODE_CONFIG_CONTENT`. `--isolate` points
`CLAUDE_CONFIG_DIR` at an empty directory so a runner settings file cannot
override the headers. The process exit code is the child's exit code.
`yabanin-ci.json` records labels, timestamps, the exit code, and usage.
In session mode the file waits up to 30 seconds for `complete: true`.
In header mode it polls until two reads match, or 30 seconds pass. A key
without `can_read_usage` still writes the report, with `usage` null and a
warning on stderr.

`yb ci report --pipeline` totals the pipeline. On GitLab the default window
starts at `CI_PIPELINE_CREATED_AT`. `--fail-over-cost` exits 4 after the
report is written when the cost is higher. `--gitlab-metrics` writes
OpenMetrics (`yabanin_cost_usd`, `yabanin_tokens_in`, `yabanin_tokens_out`,
`yabanin_requests`) for `artifacts:reports:metrics`. GitLab shows that
widget on Premium and Ultimate. On Free the file is only an artifact.

`yb ci finish` writes the report without running a command. If the finish
step does not run, a session key expires at its TTL.

Install snippets and the binary checksum variables are in `integrations/README.md`.

## What a pipeline or a ticket cost

`yb ci exec --session=on` mints a `ybs_` key when the CI key has
`can_mint_sessions`. The child receives that key, not the long-lived one.
The report then polls `GET /v1/yabanin/session-keys/{id}/usage` until
`complete` is true or 30 seconds pass. Header mode polls
`GET /v1/yabanin/usage` until two bodies match. Either way
`yabanin-ci.json` has `version` 1, `mode`, `session_key_id` (null when
there is no session), and `usage`.

`yb ci report --pipeline` sums the pipeline. The explorer filter for the
same run is `label.ci.pipeline = "<id>"`. A ticket uses the label the
policy derived, usually `label.issue = "PAY-123"`:

```text
label.issue = "PAY-123"
```

The CI board's pipeline panel groups `cost_usd` by `label:ci.pipeline`,
so the same id shows the same requests once the log has them. Session
mode attributes those requests to the parent key and to the session id.

## Security

The CI key is masked and protected. A workflow from a fork must not receive
it. `pull_request` from a fork does not get secrets. Do not use
`pull_request_target` to run code from the pull request: that event exposes
secrets to untrusted code.

Give the CI key the minimum rights: mint session keys and read its own
usage. Do not grant org administration.

On GitLab, do not write the key into a dotenv artifact. `yb ci env
--format gitlab-dotenv --with-key` refuses unless
`--allow-secret-dotenv` is set. Prefer `yb ci exec`, which passes the key
only to the child.

`yb` does not print API keys. `yb ci env --format github` emits
`::add-mask::` before each secret. `yb harness key` and `yb key print` write
the key with no trailing newline and no other text, for a helper process,
not for a log.


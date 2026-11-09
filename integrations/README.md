# CI integrations

Jobs call the gateway through `yb ci`. The API key stays in the CI secret
store. `yb` does not print it.

## Variables

| Variable | Where | Notes |
| --- | --- | --- |
| `YABANIN_GATEWAY_URL` | GitHub variable or GitLab variable | Gateway base URL |
| `YABANIN_CI_KEY` | GitHub secret, GitLab masked and protected | Parent CI key. Minimum rights: mint session keys and read its own usage |
| `YABANIN_YB_URL` | GitHub variable or GitLab variable | HTTPS URL of one `yb` binary |
| `YABANIN_YB_SHA256` | GitHub variable or GitLab variable | Expected sha256 of that file |

Where those binaries are hosted is an owner decision. `make audit-dist`
builds `dist/yb-<version>-linux-amd64` and the other platforms in
`AUDIT_DIST_PLATFORMS`, then writes `dist/SHA256SUMS`.

## GitLab

Include `integrations/gitlab/yabanin.gitlab-ci.yml` and `extends: .yabanin`.
The hidden job downloads `yb` only when it is missing, checks
`sha256sum -c`, and keeps `yabanin-ci.json` as an artifact. Do not put the
API key in that dotenv artifact. Run the agent with `yb ci exec`.

## GitHub

`integrations/github/setup-yb` is a composite action. Inputs are `url`,
`sha256`, and `gateway-url`. It downloads the binary, checks `sha256sum -c`,
and adds it to `PATH`. See `integrations/github/examples/agent-job.yml`.

Use `pull_request`, not `pull_request_target`. A fork pull request must not
receive the CI key, and `pull_request_target` runs untrusted PR code with
secrets. Pass the key only as `secrets.YABANIN_CI_KEY` into `yb ci exec`, or
as `anthropic_api_key` for Claude Code. The `yb ci env --format github` step
writes headers, not the key.

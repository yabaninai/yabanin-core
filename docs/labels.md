# Labels

`X-Yabanin-Labels` carries attribution labels. Keys that contain `_`, such as
`ci.job_name`, belong in that header.

`X-Yabanin-Label-<key>` is for a single label. Reverse proxies often drop
headers whose names contain `_` (`underscores_in_headers off` in nginx), so
those keys are reliable only through `X-Yabanin-Labels`. The `yb` client
always uses the list header. Per-key headers are for manual calls.

## Wire format

The list header is `key=value` pairs, comma-separated, keys sorted. Values
are percent-encoded. Canonical CI and git keys include `ci.system`,
`ci.pipeline`, `ci.pipeline_url`, `ci.job`, `ci.job_name`, `ci.stage`,
`ci.workflow`, `ci.trigger`, `ci.run_attempt`, `git.repo`, `git.ref`,
`git.base_ref`, `git.sha`, `git.mr`, and `task`.

## Profile and priority

`.yabanin.yml` version 1 holds `labels.static`, `labels.from_env`,
`labels.extract`, and `require`. Unknown fields are an error. Search order
for the file is `--profile`, then `YABANIN_PROFILE`, then
`<git root>/.yabanin.yml`.

On the client, later layers win:

1. CI or local git context.
2. `labels.static` from `.yabanin.yml`. Labels stored in the `yb` profile
   fill a key only when nothing else set it.
3. `labels.from_env`.
4. `labels.extract`.
5. `--label key=value`.

`on_missing: fail` makes `yb` exit 3 before the command runs.

## Gateway merge

The gateway merges sources from weakest to strongest. A later source
replaces an earlier value unless the earlier one is locked.

1. Labels stored on the API key (`key`). `labels_locked` makes them win
   even when the request sends a different value. The dropped key is
   reported as `locked`.
2. Labels stored on a session key (`session`), when the caller is `ybs_`.
   A locked session label behaves the same way against the request.
3. `X-Yabanin-Labels` and `X-Yabanin-Label-<key>` (`request`).

Each source accepts at most 20 labels. After the merge the effective set
is at most `max_labels` (32 in the default policy). Values are at most
128 characters. The prefix `yabanin.` is reserved. A value that looks like
a secret is dropped and is not echoed.

Labels attribute spend. They are not an authorization check. A request is
allowed or denied by the key, the org role, and the route, not by a label.

## Organization policy

`GET /api/label-policy?org_id=` needs `analytics.read`. `PUT` and `DELETE`
need `policies.manage`. An org with no stored policy uses the default:
every key is allowed, nothing is required, invalid labels are dropped,
and missing required keys are allowed. The default also derives a Jira
key from a branch name.

```json
{"from": "git.ref", "regex": "\\b([A-Z][A-Z0-9]{1,9}-\\d{1,7})\\b", "to": "issue", "template": "$1"}
```

A branch `feature/PAY-123-login` therefore stores `issue=PAY-123` and
`issue.project=PAY`.

A GitLab culture that records `#123` can add its own derive rule:

```json
{"from": "git.ref", "regex": "#(\\d+)", "to": "issue", "template": "$1"}
```

Cost centers stay on the team key. Set `cost_center` (and `labels_locked`)
on that key. Every request from the key carries the center, and the client
cannot replace it. `rollup_keys` already includes `cost_center` and `team`.

A strict org that still wants traffic when a ticket is missing:

```json
{"required_keys": ["issue"], "on_missing": "warn"}
```

`warn` forwards the request and sets `X-Yabanin-Labels-Missing`.
`on_missing: reject` answers 400 `missing_required_labels`.
`on_invalid: reject` answers 400 `invalid_labels`. The default `drop`
keeps the request and lists discarded keys in `X-Yabanin-Labels-Dropped`.

`rollup_keys` selects which label keys are written into
`label_rollup_hourly`. The list holds at most 40 keys. The default
includes `task`, `issue`, `issue.project`, `ci.pipeline`, `ci.job_name`,
`ci.trigger`, `git.repo`, `git.mr`, `team`, `cost_center`, `env`, and
`service`. A key that is not in the list is still stored on the request.
It is not a rollup dimension.

A saved policy is cached in memory for 30 seconds and in Redis for 60
seconds. A put or delete drops that cache.

## Key labels and session keys

`PUT /api/api-keys/{id}/labels` (`keys.manage`) stores the key's labels
and the flags `labels_locked`, `can_mint_sessions`, and `can_read_usage`.
A failed body is 400 with `{key, reason}` and does not echo a secret value.

`POST /v1/yabanin/session-keys` is accepted only from a `yb_` key with
`can_mint_sessions`. The body may set `ttl_seconds` from 60 to 43200
(default 7200), `max_tokens`, `max_cost_usd`, `labels`, and `lock_labels`.
Only labels the policy accepts are stored. Minting more than 60 keys in a
minute returns 429. The session spends against its own token and cost
ceiling and still follows the parent key's whitelist and limits. The
parent's id is what audit and limits see. Deactivating, rotating, or
deleting the parent revokes its session keys. A session key cannot mint
another session key.


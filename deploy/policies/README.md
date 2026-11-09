# Policy declarations (config-as-code, OP-10)

Git is the single source of truth for policy pipelines (OUTPLAY-PLAN
§2.3): `deploy/policies/<org-slug>/<policy-name>.yaml` reconciles into the
policystore via `yb policies reconcile` (dry-run by default).

    make policies-reconcile          # plan (dry-run, human-readable)
    make policies-reconcile-apply    # converge the database onto git

Both read `YABANIN_PG_URI` (default `postgres://yabanin:yabanin@localhost/...`).
Raw command:

    yb policies reconcile --pg-uri "$YABANIN_PG_URI" \
        [--org <slug>] [--apply] [--prune] [--include-pack]

## File format

One policy per file; the file name MUST equal the policy `name`. Two YAML
documents separated by `---`:

```yaml
# Document 1 — the policy (stored in the policystore VERBATIM; this is what
# the gateway compiles at load time). Full ypp/v1 schema.
apiVersion: ypp/v1
kind: Policy
name: pii-guard            # == file stem
mode: shadow               # shadow | enforce
hooks: [pre_upstream]
steps:
  - id: scan
    detector: builtin/pii

# Document 2 — the optional reconcile block (never stored as policy
# content). Omitted fields KEEP the current database value; a new policy
# starts detached (enabled=false, no attachments).
---
enabled: true              # omit = keep DB value
attachments:               # omit = keep DB value; [] = clear all
  - key_label: ""          # "" = every key of the org
    model_pattern: "*"     # glob over model names
    endpoint: chat         # gateway surface
    priority: 100          # smaller runs earlier (default 100)
```

Validation: the CLI parses document 1 with the strict `pkg/pipeline` schema
(unknown fields are errors, with file:line), so a broken declaration fails
fast and fails the run before anything is written — this is the CI gate.

## Workflow (PR → CI → apply)

1. Edit/declare policies in a PR under `deploy/policies/<org-slug>/`.
2. CI runs `yb policies validate --dir deploy/policies --include-pack`
   (the `policies` job in `.github/workflows/ci.yml`, G1) — a strict,
   database-free parse of every declaration; any YAML/schema error fails
   the build before the branch can merge.
3. Review the plan (add/update/activate/enable/disable/attachments/delete):
   from an operator environment, `yb policies reconcile` (dry-run) prints
   the effect of the declarations against the live policystore.
4. Apply from the same operator environment:
   `yb policies reconcile --apply`.

Every applied change records the current `git rev-parse --short HEAD` as the
version's `git_sha` and `policies-reconcile` as `created_by`. Reconciliation
is idempotent: a second run reports zero changes.

## Drift semantics — GIT WINS + DRIFT REPORT

A database edit made past git (a version authored outside git whose content
differs from the declaration) is reported as `DRIFT` in the plan and, under
`--apply`, overwritten by a NEW version carrying the git content and sha.

Why git-wins (and no `--force` flag):

- §2.3 makes git the ONLY source of truth. A `--force` requirement would
  create a two-tier flow where a forgotten flag silently no-ops — the exact
  Bifrost failure mode (silent config drift) this lane exists to close.
- Nothing is destroyed: policy versions are immutable, so a diverged UI edit
  survives in version history; its author ports it into a PR (§2.3: "a UI
  policy edit produces a declaration for a PR") or loses it on the next
  apply — visibly, never silently.
- The Portkey failure mode (policy bypass) stays closed by construction:
  enforcement reads the policystore only, and this reconciler is the single
  intended writer of git-managed policies.

Continuous visibility (no repo checkout needed): the admin API exposes
`GET /api/organizations/{id}/policies/drift` (policies.manage) reporting
per-policy status `managed` / `drift` (edited past git after a reconcile) /
`unmanaged` (never reconciled). Run the CLI reconcile to see the content
diff and converge.

## `--prune` (danger)

Without it, database policies not covered by declarations are reported as
prune candidates and left alone. With `--prune --apply` they are DELETED —
git becomes the complete truth for the org. Always review the dry-run plan
first; deletions cascade to versions and attachments.

## Packs (`_pack/`, ships OFF)

`_pack/` holds org-agnostic declaration packs. Reconcile ignores them
unless `--include-pack` is passed; then every pack policy reconciles into
every org in scope (enablement is one flag on the reconcile line).

- `sovereign-default.yaml` — national PII + secrets + prompt injection,
  all built-in detector steps, `mode: shadow`, org-wide attachment.
  Ships OFF by owner decision (2026-10-06).

Directories starting with `_` are namespaces, never orgs; a stray `.yaml`
directly under this directory is an error (a declaration without an org is
meaningless). `_example/` is a worked example, never reconciled.

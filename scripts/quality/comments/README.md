# comments lane checker

Proves a `.ts`/`.tsx` edit is comment-only: the executable token stream and
its ASI-relevant line boundaries are unchanged, and semantic directive
comments are routed to manual review instead of a silent pass.

Not wired into product gates (follow-up); used by the comment-cleanup lane.

## Use

```sh
node scripts/quality/comments/check.mjs <old-file> <new-file>
node scripts/quality/comments/check.mjs --against <git-rev> <path> [<path>...]
node scripts/quality/comments/self-test.mjs
```

Exit codes: `0` all PASS · `1` ≥1 FAIL (token change, line-boundary/ASI
change, syntax error, file added/removed) · `2` only FLAGs (manual review
required). `--json` emits machine-readable detail.

TypeScript is resolved from `web/dashboard`'s pinned devDependencies (falling
back to `web/site`); `web/site` files ride the same install, so the checker
adds no dependency tree of its own.

## Semantics

- Tokens come from a parsed AST leaf walk (parser-accurate for JSX text,
  regexes and template spans). Each token is compared as
  `(kind, exact source text, line-break-before)`.
- Line *numbers* may shift — deleting whole comment lines is fine. The
  *presence of a line terminator between adjacent tokens* may not change,
  because automatic semicolon insertion depends on it. A newline inside a
  removed/reworded block comment counts as a line break, matching ECMAScript.
- Directive comments — `///` triple-slash references, `@ts-*` pragmas,
  `eslint-*` directives, license/attribution blocks — are collected from
  parser trivia ranges and diffed as a multiset. Any add/remove/reword is a
  FLAG, never a silent pass. Formatting-only reflow (whitespace, `*`
  decoration) does not trigger a flag.
- A shebang line gained or lost is a FLAG.

## Fixtures / negative controls

`fixtures/<case>/{old,new}.*` pairs, asserted by `self-test.mjs`:

| case | expected | proves |
| --- | --- | --- |
| `pass-comment-churn` | PASS | pure comment add/remove/reword passes |
| `pass-tsx-comment-churn` | PASS | same for `.tsx` incl. JSX comments |
| `fail-token-edit` | FAIL | an identifier edit is caught |
| `fail-asi-hazard` | FAIL | merging `return` with the next line (identical tokens, different meaning) is caught |
| `flag-ts-ignore-removed` | FLAG | `@ts-ignore` removal never silently passes |
| `flag-eslint-directive-added` | FLAG | added `eslint-disable` needs review |
| `flag-license-changed` | FLAG | license header removal needs review |
| `flag-triple-slash-added` | FLAG | added `///` reference needs review |

Limitations: comments are read from parser trivia, so JSX text containing
`/*`-like prose cannot be misread; a `//` inside JSX text would be
misclassified by a raw scanner but is not trivia here. Directive keywords
inside ordinary prose comments (e.g. the word "license" in unrelated text)
can cause a false FLAG; flags are cheap, silent passes are not.

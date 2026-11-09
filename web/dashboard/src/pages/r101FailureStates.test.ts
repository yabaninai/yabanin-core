import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

// brought under the smoke (guardrails, feedback, policy-decisions, prompts,
// mcp-credentials). The card's negative scenario is "a page falls or shows
// empty data without diagnostics" — these pins hold each screen to the
// honest-error contract at source level (the JSX pages cannot execute under
// the node strip-types harness; the API-layer error branches they consume are
// executed in feedback.test.ts / policyDecisions.test.ts /
// mcpCredentials.test.ts / prompts.test.ts):
//
//   - errors render as an explicit error StateNotice (server text or the
//     documented loadFailed copy), never as a bare empty table;
//   - partial/unknown is never success: stale rows are dropped on failure,
//     a superseded/aborted load is silence (not an error), "empty" requires
//     a completed load;
//   - rights-gated screens fail closed while /api/me is pending.

const here = dirname(fileURLToPath(import.meta.url))
const pageSrc = (name: string): string => readFileSync(join(here, name), 'utf8')

describe('R101 failure wiring of the newly smoked screens', () => {
  it('FeedbackPage: the caught message renders in an error notice; aborts stay silent; empty needs a settled load', () => {
    const src = pageSrc('FeedbackPage.tsx')
    assert.match(src, /if \(!\(e instanceof DOMException && e\.name === 'AbortError'\)\)\s*\{\s*setError\(/,
      'a superseded load must not render as an error')
    // fix: the error notice REPLACES the card area (error → retry
    // action). Before, the error rendered above the card whose empty branch
    // also claimed «No feedback recorded yet» — a failure reading as a
    // successful empty result.
    assert.match(src, /\{error \? \(\s*<StateNotice\s+state="error"\s+message=\{error\}\s+action=\{\{ label: t\('common\.retry'\), onClick: \(\) => void load\(page, orgId, rating\) \}\}\s*\/>\s*\) : \(/,
      'the failure is one error notice (server text + retry), never error + fake empty')
    assert.match(src, /const empty = !loading && entries\.length === 0/,
      'empty is only claimed once the load settled (the card itself is gated on !error)')
  })

  it('PolicyDecisionsPage: a failed load clears the rows, shows loadFailed + retry, and gates it on loaded', () => {
    const src = pageSrc('PolicyDecisionsPage.tsx')
    // failure never set failed, so a 403/500 rendered the EMPTY notice
    // (empty data without diagnostics). Pinned on the corrected === shape.
    assert.match(src, /\.catch\(\(\) => \{ if \(gen\.current === g\) \{ setFailed\(true\); setRows\(\[\]\); setTotal\(0\) \} \}\)/,
      'failure of the current load drops the rows (no stale table, no false empty)')
    assert.match(src, /state="error"\s+message=\{t\('policyDecisions\.loadFailed'\)\}\s+action=\{\{ label: t\('common\.retry'\), onClick: \(\) => reload\(page\) \}\}/,
      'the error notice uses the documented loadFailed copy and offers the retry action')
    assert.match(src, /\.then\(res => \{\s*if \(gen\.current !== g\) return\s*setRows\(res\.rows\)/,
      'stale successes are still discarded (the newest load owns the screen)')
  })

  it('PromptsPage: the list failure renders an error notice; label-chip failures degrade to empty chips', () => {
    const src = pageSrc('prompts/PromptsPage.tsx')
    // error branch, which preempts the empty row — the standalone notice
    // above the card left the table claiming «No prompts … yet» under the
    // error (a failure reading as a successful empty library).
    assert.match(src, /error=\{list\.error\}/,
      'the DataTable error branch owns the failure (priority over the empty row)')
    assert.ok(!src.includes('{list.error && <StateNotice state="error" message={list.error} />}'),
      'no duplicate standalone notice that let the table fake an empty library')
    assert.match(src, /\.catch\(\(\) => \[p\.id, \[\] as PromptLabelName\[\]\] as const\)/,
      'best-effort label chips fail to empty (documented; the detail view is authoritative)')
  })

  it('McpCredentialsPage: fail-closed while /api/me is pending; load errors get a retry; a null user-credential list is an explicit unavailable notice', () => {
    const src = pageSrc('McpCredentialsPage.tsx')
    assert.ok(src.includes('if (perms.loading || !perms.isRoot) return'),
      'the root-only read never fires before the rights answer landed')
    assert.match(src, /catch \(e: unknown\)\s*\{\s*if \(ctrl\.signal\.aborted \|\| orgRef\.current !== seenOrg\) return\s*setServers\(null\)\s*setLoadError\(errorOf\(e\)\)/,
      'a failed load clears the tables and records the server reason')
    assert.ok(src.includes('<StateNotice state="error" message={loadError} action={{ label: t(\'common.retry\'), onClick: () => void load() }} />'),
      'the load failure offers exactly one retry action')
    assert.ok(src.includes('{userCreds === null ? ('),
      'an unavailable per-user endpoint renders the explicit unavailable branch')
    assert.ok(src.includes("t('mcpCreds.userUnavailable')"),
      '…with the documented unavailable copy (never a fake empty table)')
  })

  it('GuardrailsPage: the card gate is delegated to the pinned model (fail-closed while /api/me loads)', () => {
    const src = pageSrc('GuardrailsPage.tsx')
    assert.ok(src.includes('guardrailsCardOpenable'),
      'the gate ordering lives in guardrailsModel.test.ts — the page must not re-derive it')
    assert.ok(src.includes('guardrails-locked-'),
      'locked cards stay visible while the rights answer is pending')
  })
})

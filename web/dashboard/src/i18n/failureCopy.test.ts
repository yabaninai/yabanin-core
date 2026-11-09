import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, it } from 'node:test'

// resolve in EVERY locale — a missing key in e.g. ja.json would silently fall
// back to en (fallbackLng) and, if absent there too, render the honest
// "[missing:key]" marker the smoke gate then trips on. Failure states are
// where trust matters most, so this pins per-locale presence (not just the
// en.json existence the i18n/keys.test.ts gate already enforces) for:
//
//   - the error / empty / not-loaded copy of feedback, policy decisions,
//   - the Guardrails locked-card vocabulary (unavailable + reason
//     + hint) and its "nothing openable" state;
//   - the shared retry action and the StateNotice state titles these screens
//     inherit.
//
// It also pins the interpolation contract: guardrails.requiresPerm carries
// the {{permission}} placeholder in every locale (the model feeds it,
// guardrailsModel.test.ts), and the missing-key marker in i18n/index.ts
// stays loud (never an empty string that would fake success).

const here = dirname(fileURLToPath(import.meta.url))
const i18nDir = join(here, '..', 'i18n')

const LOCALES = ['en', 'ja', 'ko', 'hi', 'id', 'pt-BR', 'es', 'ar'] as const

// (locale → bundle) with the dotted-path lookup the pages use via t().
const bundles = new Map(LOCALES.map(l => [
  l,
  JSON.parse(readFileSync(join(i18nDir, `${l}.json`), 'utf8')) as Record<string, unknown>,
]))

function resolve(locale: (typeof LOCALES)[number], key: string): unknown {
  let v: unknown = bundles.get(locale)
  for (const part of key.split('.')) {
    if (v === null || typeof v !== 'object') return undefined
    v = (v as Record<string, unknown>)[part]
  }
  return v
}

// their failure branches render.
const FAILURE_KEYS = [
  // PolicyDecisionsPage (error notice + filter-form states)
  'policyDecisions.loadFailed',
  'policyDecisions.notLoaded',
  'policyDecisions.empty',
  // FeedbackPage (error / empty / loading copy)
  'feedback.fetching',
  'feedback.empty',
  // PromptsPage (list states)
  'prompts.empty',
  'prompts.createOrgFirst',
  // McpCredentialsPage (rights / load / unavailable copy)
  'mcpCreds.notLoaded',
  'mcpCreds.checkingRights',
  'mcpCreds.noAccess',
  'mcpCreds.userUnavailable',
  'mcpCreds.userUnavailableDetails',
  'mcpCreds.userEmpty',
  'mcpCreds.serversEmpty',
  'mcpCreds.grantsEmpty',
  // GuardrailsPage locked vocabulary + nothing-openable state
  'guardrails.requiresRoot',
  'guardrails.requiresPerm',
  'guardrails.lockedHint',
  'guardrails.noneVisible',
  // Shared failure furniture these screens render
  'common.retry',
  'states.failedToLoad',
  'states.noData',
  'states.notLoaded',
  'states.loading',
] as const

describe('failure copy resolves in every locale (R101-03)', () => {
  it('every failure-state key is a non-empty string in all eight locales (no en fallback, no [missing:)', () => {
    const missing: string[] = []
    for (const key of FAILURE_KEYS) {
      for (const locale of LOCALES) {
        const v = resolve(locale, key)
        if (typeof v !== 'string' || v.length === 0) missing.push(`${locale}:${key}`)
      }
    }
    assert.equal(missing.length, 0,
      `failure copy falls back to en (or renders [missing:]) in:\n  ${missing.join('\n  ')}`)
  })

  it('guardrails.requiresPerm keeps the {{permission}} placeholder in every locale', () => {
    const broken: string[] = []
    for (const locale of LOCALES) {
      const v = resolve(locale, 'guardrails.requiresPerm')
      if (typeof v !== 'string' || !v.includes('{{permission}}')) broken.push(locale)
    }
    assert.equal(broken.length, 0,
      `the interpolated permission name would disappear in: ${broken.join(', ')}`)
  })

  it('the missing-key marker stays loud in i18n/index.ts (a gap can never render as success copy)', () => {
    const cfg = readFileSync(join(i18nDir, 'index.ts'), 'utf8')
    assert.ok(cfg.includes("parseMissingKeyHandler: (k: string) => `[missing:${k}]`"),
      'unknown keys must render the [missing:] marker the smoke gate asserts absent')
    assert.ok(cfg.includes("fallbackLng: 'en'"),
      'en stays the runtime fallback while locale chunks load')
  })
})

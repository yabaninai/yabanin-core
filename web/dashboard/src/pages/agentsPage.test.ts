// strip-types harness cannot render JSX; the GuardrailsPage.test.ts way —
// pin the decisions the page encodes):
//
//   1. the guided flow order is select → generate → copy → test, with the
//      full six-client vocabulary claude-code/codex/opencode/continue/
//      cline/aider (owner decision 2026-11-04 (b): the UI guides every
//      client the API and the CLI render);
//   2. the config block comes from the parity-pinned mirror
//      (api/clientConfig) — the page invents no format of its own;
//   3. the console never invents a gateway URL: no hardcoded https default,
//      the base URL field starts empty (docs placeholders stay in the
//      onboarding lib where they are labeled as placeholders);
//   4. the test-connection action targets the operator-entered gateway with
//      the pasted key only — all four outcomes (ok/auth/not-found/
//      unreachable) carry their negative-scenario guidance keys;
//   5. every agents.* copy key exists in all eight locales (same key set);
//   6. the nav entry carries the audited keys gate (mirrors
//      App.navGates.test.ts).

import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

const here = dirname(fileURLToPath(import.meta.url))
const srcDir = join(here, '..')
const pageSource = readFileSync(join(srcDir, 'pages', 'AgentsPage.tsx'), 'utf8')
const appSource = readFileSync(join(srcDir, 'App.tsx'), 'utf8')

describe('guided flow structure (R069-02)', () => {
  it('renders select → generate → test sections in order, six-client tabs', () => {
    const select = pageSource.indexOf('data-testid="agents-step-select"')
    const generate = pageSource.indexOf('data-testid="agents-step-generate"')
    const test = pageSource.indexOf('data-testid="agents-step-test"')
    assert.ok(select > -1 && generate > select && test > generate, 'the guided order is select → generate → test')
    assert.ok(pageSource.includes('GUIDED_AGENTS.map'), 'tabs render from the pinned vocabulary')
    // Owner decision 2026-11-04 (b): the page labels every guided client —
    // no agent falls through to an unlabeled tab.
    for (const key of ['agents.clientClaudeCode', 'agents.clientCodex', 'agents.clientOpencode',
      'agents.clientContinue', 'agents.clientCline', 'agents.clientAider']) {
      assert.ok(pageSource.includes(`t('${key}'`), `${key} must render`)
    }
  })

  it('generates the block through the server render only (R069 D2)', () => {
    assert.ok(pageSource.includes("from '../api/clientConfig'"))
    assert.ok(pageSource.includes('getClientConfig('), 'the block comes from GET /api/client-config/{agent}')
    assert.ok(pageSource.includes('agentCopyBlock(genResult)'), 'the copy block wraps the server payload')
    assert.ok(pageSource.includes('genResult.path'), 'the config path is the server-returned one')
    for (const banned of ['model_provider =', 'ANTHROPIC_BASE_URL=', '"wire_api"', '@ai-sdk/openai-compatible', 'renderAgentConfig', 'renderCodexTOML', 'renderClaudeCodeEnv', 'renderOpenCodeJSON']) {
      assert.ok(!pageSource.includes(banned), `the page must not restate the renderer format inline ("${banned}")`)
    }
  })

  it('a failed render surfaces honestly with a retry (never a made-up block)', () => {
    assert.ok(pageSource.includes('agents.generateFailed'), 'the failure notice key renders')
    assert.ok(pageSource.includes('retryGenerate'), 'the retry action re-fetches the server render')
    assert.ok(pageSource.includes('agents.droppedLabels'), 'dropped labels are reported, not silently ignored')
    assert.ok(pageSource.includes('data-testid="agents-generating"'), 'the pending state is visible (not a flash of empty)')
  })

  it('never invents a gateway URL (no hardcoded origin as a value)', () => {
    assert.ok(!pageSource.includes('gateway.example'), 'docs placeholders do not belong on this screen')
    assert.ok(!/useState\('https?:/.test(pageSource), 'no state may seed an invented URL')
    assert.ok(!/value="https?:\/\//.test(pageSource), 'no input may default to an invented URL')
  })

  it('the test call goes browser→gateway with the pasted key only', () => {
    assert.ok(pageSource.includes('agentTestURL(baseURL)'), 'the call targets the entered URL, normalized')
    assert.ok(pageSource.includes("from '../api/keys'"), 'the only admin read is the keys hint')
    assert.ok(!/postJSON|sendMutation/.test(pageSource), 'no admin mutation rides the test')
    assert.ok(pageSource.includes("type=\"password\"") && pageSource.includes('autoComplete="off"'),
      'the pasted key is a masked, non-autocompleted field')
  })

  it('all four outcomes carry their negative-scenario guidance', () => {
    for (const key of ['agents.testOk', 'agents.testAuth', 'agents.testNotFound', 'agents.testUnreachable']) {
      assert.ok(pageSource.includes(`t('${key}'`), `${key} must render`)
    }
    for (const key of ['agents.keyNoteClaudeCode', 'agents.keyNoteCodex', 'agents.keyNoteOpencode',
      'agents.keyNoteContinue', 'agents.keyNoteCline', 'agents.keyNoteAider']) {
      assert.ok(pageSource.includes(key), `${key} must render (key-copied-to-the-wrong-place guidance)`)
    }
  })
})

describe('agents copy exists in all eight locales (same key set)', () => {
  const locales = ['en', 'ja', 'ko', 'hi', 'id', 'pt-BR', 'es', 'ar']

  function flatKeys(obj: Record<string, unknown>, prefix = ''): string[] {
    return Object.entries(obj).flatMap(([k, v]) =>
      v !== null && typeof v === 'object'
        ? flatKeys(v as Record<string, unknown>, prefix ? `${prefix}.${k}` : k)
        : [prefix ? `${prefix}.${k}` : k],
    )
  }

  it('every locale carries the en agents key set and the nav label', () => {
    const en = JSON.parse(readFileSync(join(srcDir, 'i18n', 'en.json'), 'utf8'))
    const enKeys = flatKeys(en.agents as Record<string, unknown>, 'agents').sort()
    assert.ok(enKeys.length >= 30, `expected the agents key family, found ${enKeys.length}`)
    for (const locale of locales) {
      const bundle = JSON.parse(readFileSync(join(srcDir, 'i18n', `${locale}.json`), 'utf8'))
      const keys = flatKeys(bundle.agents as Record<string, unknown> ?? {}, 'agents').sort()
      assert.deepEqual(keys, enKeys, `${locale}.agents key set drifted from en.json`)
      assert.equal(typeof bundle.app?.navAgents, 'string', `${locale}.app.navAgents missing`)
      assert.notEqual(bundle.app?.navAgents, '', `${locale}.app.navAgents empty`)
      for (const k of keys) {
        const v = k.split('.').slice(1).reduce<unknown>((acc, part) => (acc as Record<string, unknown>)?.[part], bundle.agents)
        assert.equal(typeof v, 'string', `${locale} ${k} must be a string`)
        assert.notEqual(v, '', `${locale} ${k} must not be empty`)
      }
    }
  })
})

describe('nav registration (mirrors the audited gate map)', () => {
  it('the agents entry sits in NAV_SECTIONS with the keys gate', () => {
    const re = new RegExp(String.raw`\{ id: 'agents', labelKey: 'app\.navAgents', icon: <\w+ size=\{16\} \/>, access: \{ anyOrg: \['keys\.manage', 'agent_keys\.manage'\] \} \},`)
    assert.match(appSource, re,
      'the nav line must match the pinned gate exactly (App.navGates.test.ts holds the same table)')
  })
})

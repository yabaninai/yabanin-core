// AF-12 unit tests: the locale switcher contract over async bundles.
//
// The switcher is dependency-injected (no i18next/vite here), so these run
// under node --test against the production module. Covered invariants:
//   - rapid switch: the LAST requested locale wins; a stale load that resolves
//     late must NOT be applied (an old locale never comes back);
//   - failed download: the runtime stays on the language that renders and the
//     html attributes are reverted to it (they never lie about the content);
//   - the bundle is registered BEFORE changeLanguage (nothing waits on
//     i18next), html follows the applied language on success;
//   - a request never rejects; a retry after a failure works.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createLocaleSwitcher, type LocaleSwitcherDeps } from './switcher.ts'

interface Deferred<T> {
  promise: Promise<T>
  resolve: (value: T) => void
  reject: (e: unknown) => void
}

function deferred<T>(): Deferred<T> {
  let resolve!: (value: T) => void
  let reject!: (e: unknown) => void
  const promise = new Promise<T>((res, rej) => {
    resolve = res as (value: T) => void
    reject = rej
  })
  return { promise, resolve, reject }
}

type Recorder = {
  log: string[]
  bundles: Map<string, Record<string, unknown>>
  language: string
  deps: LocaleSwitcherDeps
}

function makeDeps(loaders: Record<string, Deferred<Record<string, unknown>> | 'fail'>): Recorder {
  const log: string[] = []
  const bundles = new Map<string, Record<string, unknown>>()
  const rec: Recorder = {
    log,
    bundles,
    language: 'en',
    deps: {
      addBundle: (lng, bundle) => {
        log.push(`add:${lng}`)
        bundles.set(lng, bundle)
      },
      changeLanguage: async (lng) => {
        log.push(`lang:${lng}`)
        rec.language = lng
      },
      currentLanguage: () => rec.language,
      applyHtml: (lng) => {
        log.push(`html:${lng}`)
      },
      loadBundle: async (lng) => {
        log.push(`load:${lng}`)
        const entry = loaders[lng]
        if (!entry) throw new Error(`unexpected load ${lng}`)
        if (entry === 'fail') throw new Error('download failed')
        return await entry.promise
      },
    },
  }
  return rec
}

test('successful switch: bundle registered before changeLanguage, html follows the applied locale', async () => {
  const arBundle = deferred<Record<string, unknown>>()
  const rec = makeDeps({ ar: arBundle })
  const sw = createLocaleSwitcher(rec.deps)

  const pending = sw.changeLocale('ar')
  arBundle.resolve({ nav: { overview: 'نظرة عامة' } })
  assert.equal(await pending, true)
  assert.equal(rec.language, 'ar')
  assert.deepEqual(rec.bundles.get('ar'), { nav: { overview: 'نظرة عامة' } })
  // Order proves nothing ever waits on i18next: register → apply → html.
  assert.deepEqual(rec.log, ['load:ar', 'add:ar', 'lang:ar', 'html:ar'])
  assert.equal(sw.generation(), 1)
})

test('rapid switch: the last request wins, the stale load is not applied', async () => {
  const arBundle = deferred<Record<string, unknown>>()
  const jaBundle = deferred<Record<string, unknown>>()
  const rec = makeDeps({ ar: arBundle, ja: jaBundle })
  const sw = createLocaleSwitcher(rec.deps)

  const first = sw.changeLocale('ar')
  const second = sw.changeLocale('ja')
  assert.equal(sw.generation(), 2)
  jaBundle.resolve({ nav: { overview: '概要' } })
  assert.equal(await second, true)
  arBundle.resolve({ nav: { overview: 'نظرة عامة' } })
  assert.equal(await first, false, 'the superseded ar switch must resolve false')

  assert.equal(rec.language, 'ja', 'the last requested locale is the rendered one')
  assert.equal(rec.bundles.has('ar'), false, 'the stale ar bundle is never registered')
  assert.equal(rec.bundles.has('ja'), true)
  assert.ok(!rec.log.includes('lang:ar'), 'the old locale never comes back')
  assert.equal(rec.log[rec.log.length - 1], 'html:ja')
})

test('failed download: runtime stays on the rendered language, html tells the truth', async () => {
  const rec = makeDeps({ ar: 'fail' })
  const sw = createLocaleSwitcher(rec.deps)

  assert.equal(await sw.changeLocale('ar'), false)
  assert.equal(rec.language, 'en', 'a failed download never changes the language')
  assert.equal(rec.bundles.has('ar'), false)
  assert.deepEqual(rec.log, ['load:ar', 'html:en'])
})

test('a failed switch superseded by a newer request does not revert the html', async () => {
  const arBundle = deferred<Record<string, unknown>>()
  const jaBundle = deferred<Record<string, unknown>>()
  const rec = makeDeps({ ar: arBundle, ja: jaBundle })
  const sw = createLocaleSwitcher(rec.deps)

  const first = sw.changeLocale('ar')
  const second = sw.changeLocale('ja')
  jaBundle.resolve({ nav: { overview: '概要' } })
  assert.equal(await second, true)
  arBundle.reject(new Error('download failed'))
  assert.equal(await first, false)
  assert.equal(rec.log.includes('html:en'), false, 'the stale failure must not touch the html')
  assert.equal(rec.log[rec.log.length - 1], 'html:ja')
})

test('retry after a failed download works', async () => {
  const arBundle = deferred<Record<string, unknown>>()
  const loaders: Record<string, Deferred<Record<string, unknown>> | 'fail'> = { ar: 'fail' }
  const rec = makeDeps(loaders)
  const sw = createLocaleSwitcher(rec.deps)

  assert.equal(await sw.changeLocale('ar'), false)
  loaders.ar = arBundle
  const retry = sw.changeLocale('ar')
  arBundle.resolve({ nav: { overview: 'نظرة عامة' } })
  assert.equal(await retry, true)
  assert.equal(rec.language, 'ar')
  assert.equal(rec.log[rec.log.length - 1], 'html:ar')
})

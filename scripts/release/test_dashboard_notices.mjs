// SPDX-License-Identifier: Apache-2.0
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'

const collector = fileURLToPath(new URL('./dashboard-notices.mjs', import.meta.url))
const repo = path.resolve(path.dirname(collector), '../..')
const digest = bytes => createHash('sha256').update(bytes).digest('hex')
const read = file => readFileSync(file, 'utf8')
const save = (file, data) => {
  mkdirSync(path.dirname(file), { recursive: true })
  writeFileSync(file, data)
}
const asset = 'assets/index.js'
const css = 'assets/index.css'
const lucide = 'node_modules/lucide-react'

// Source fixture from the installed lucide-react 0.469.0 LICENSE.
const lucideLicense = `ISC License

Copyright (c) for portions of Lucide are held by Cole Bemis 2013-2022 as part of Feather (MIT). All other copyright (c) for Lucide are held by Lucide Contributors 2022.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
`

function fixture(t) {
  const root = mkdtempSync(path.join(tmpdir(), 'dashboard-notices-'))
  t.after(() => rmSync(root, { recursive: true, force: true }))
  const dashboard = path.join(root, 'web/dashboard')
  const maps = path.join(root, 'maps')
  const dist = path.join(dashboard, 'dist')
  const out = path.join(dist, 'licenses')
  const license = path.join(dashboard, lucide, 'LICENSE')
  for (const name of ['LICENSE', 'NOTICE', 'LICENSING.md']) save(path.join(root, name), read(path.join(repo, name)))
  const tokens = '.example{--astra-test:2px}'
  save(path.join(root, 'design/astra-tokens.css'), tokens)
  save(path.join(dashboard, 'src/index.css'), "@import '../../../design/astra-tokens.css';")
  const src = 'export const icon = 1;\n'
  save(path.join(dashboard, lucide, 'icon.js'), src)
  save(license, lucideLicense)
  save(path.join(dashboard, lucide, 'nOtIcE.txt'), 'Additional attribution\n')
  save(path.join(dashboard, lucide, 'package.json'), JSON.stringify({ name: 'lucide-react', version: '0.469.0' }))
  save(path.join(dashboard, 'package-lock.json'), JSON.stringify({ packages: { [lucide]: { version: '0.469.0' } } }))
  save(path.join(dist, asset), src)
  save(path.join(maps, asset), src + '//# sourceMappingURL=index.js.map\n')
  save(path.join(maps, asset + '.map'), JSON.stringify({
    version: 3, file: 'index.js', mappings: 'AAAA', names: [], sourcesContent: [src],
    sources: [path.relative(path.dirname(path.join(maps, asset)), path.join(dashboard, lucide, 'icon.js'))],
  }))
  save(path.join(dist, css), tokens)
  save(path.join(maps, css), tokens)
  save(path.join(maps, '.vite/manifest.json'), JSON.stringify({ main: { isEntry: true, file: asset, css: [css] } }))
  return { root, dashboard, dist, maps, out, license }
}

function run(f, verify = false) {
  const args = [collector, '--map-root', f.maps, '--out', f.out]
  if (verify) args.push('--verify')
  return spawnSync(process.execPath, args, { cwd: f.dashboard, encoding: 'utf8' })
}

function passes(f, verify) {
  const result = run(f, verify)
  assert.equal(result.status, 0, result.stderr)
}

function fails(f, pattern, verify) {
  const result = run(f, verify)
  assert.equal(result.status, 1, result.stderr)
  assert.match(result.stderr, pattern)
}

test('ordinary dist alone fails delivery verification; fixed output is complete and deterministic', t => {
  const f = fixture(t)
  fails(f, /ENOENT.*licenses/, true)
  passes(f)
  passes(f, true)
  const snapshot = read(path.join(f.out, 'inventory.json'))
  const inventory = JSON.parse(snapshot)
  assert.equal(snapshot.includes(f.root), false)
  assert.deepEqual(inventory.assets.map(a => [a.path, a.sha256]), [css, asset].map(p => [p, digest(read(path.join(f.dist, p)))]))
  assert.deepEqual(inventory.assets.find(a => a.path === asset).packages, [lucide])
  assert.equal(inventory.packages.length, 1)
  const pkg = inventory.packages[0]
  assert.deepEqual([pkg.name, pkg.version, pkg.origin], ['lucide-react', '0.469.0', lucide])
  assert.deepEqual(pkg.notices.map(n => path.basename(n.path)), ['LICENSE', 'nOtIcE.txt'])
  assert.deepEqual(inventory.project.notices.map(n => n.origin), ['LICENSE', 'NOTICE', 'LICENSING.md'])
  for (const notice of pkg.notices) {
    const bytes = read(path.join(f.dashboard, notice.origin))
    assert.equal(read(path.join(f.out, notice.path)), bytes)
    assert.equal(notice.sha256, digest(bytes))
  }
  for (const notice of inventory.project.notices) {
    assert.equal(read(path.join(f.out, notice.path)), read(path.join(f.root, notice.origin)))
  }
  assert.deepEqual(inventory.project.design, {
    origin: 'design/astra-tokens.css', sha256: digest(read(path.join(f.root, 'design/astra-tokens.css'))), stylesheets: [css],
  })
  rmSync(f.out, { recursive: true })
  passes(f)
  assert.equal(read(path.join(f.out, 'inventory.json')), snapshot)
})

test('a Lucide ISC header without Feather attribution fails collection', t => {
  const f = fixture(t)
  save(f.license, lucideLicense.replace(' as part of Feather (MIT)', ''))
  fails(f, /missing Lucide ISC \/ Feather MIT attribution/)
})

test('missing installed version fails despite a lockfile version', t => {
  const f = fixture(t)
  save(path.join(f.dashboard, lucide, 'package.json'), '{"name":"lucide-react"}')
  fails(f, /missing or mismatched installed version/)
})

test('incorrect notice hash in the inventory fails verification', t => {
  const f = fixture(t)
  passes(f)
  const file = path.join(f.out, 'inventory.json')
  const inventory = JSON.parse(read(file))
  inventory.packages[0].notices[0].sha256 = '0'.repeat(64)
  save(file, JSON.stringify(inventory, null, 2) + '\n')
  fails(f, /inventory hash mismatch: inventory.json/, true)
})

test('missing shipped notice fails verification', t => {
  const f = fixture(t)
  passes(f)
  rmSync(path.join(f.out, 'packages', lucide, 'LICENSE'))
  fails(f, /delivered notice file set differs/, true)
})

test('map without its emitted asset fails verification', t => {
  const f = fixture(t)
  passes(f)
  rmSync(path.join(f.dist, asset))
  fails(f, /emitted asset or source map set differs/, true)
})

test('changed emitted bytes cannot use a stale mapped twin', t => {
  const f = fixture(t)
  save(path.join(f.dist, asset), 'export const icon = 2;\n')
  fails(f, /emitted asset differs from mapped build/)
})

test('a second contributing package needs its own legal text', t => {
  const f = fixture(t)
  const origin = 'node_modules/@example/widget'
  const name = '@example/widget'
  const dir = path.join(f.dashboard, origin)
  save(path.join(dir, 'package.json'), JSON.stringify({ name, version: '1.0.0' }))
  save(path.join(dir, 'widget.js'), 'export const widget = 2;')
  const lockFile = path.join(f.dashboard, 'package-lock.json')
  const lock = JSON.parse(read(lockFile))
  lock.packages[origin] = { version: '1.0.0' }
  save(lockFile, JSON.stringify(lock))
  const mapFile = path.join(f.maps, asset + '.map')
  const map = JSON.parse(read(mapFile))
  map.sources.push(path.relative(path.dirname(mapFile), path.join(dir, 'widget.js')))
  map.sourcesContent.push(read(path.join(dir, 'widget.js')))
  save(mapFile, JSON.stringify(map))
  fails(f, /missing legal text: node_modules\/@example\/widget/)
  save(path.join(dir, 'COPYING'), 'Widget test license\n')
  passes(f)
  assert.equal(read(path.join(f.out, 'packages', origin, 'COPYING')), 'Widget test license\n')
})

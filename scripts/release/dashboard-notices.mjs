// SPDX-License-Identifier: Apache-2.0
import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs'
import path from 'node:path'
import { parseArgs } from 'node:util'

function requireThat(condition, message) {
  if (!condition) throw new Error(message)
}

const hash = bytes => createHash('sha256').update(bytes).digest('hex')
const json = file => JSON.parse(readFileSync(file, 'utf8'))
const legalName = /^(?:licen[cs]e|copying|notice|patents)(?:$|[._-])/i

function files(root, skip = () => false) {
  const result = []
  for (const entry of readdirSync(root, { withFileTypes: true })) {
    const file = path.join(root, entry.name)
    if (skip(file)) continue
    if (entry.isDirectory()) result.push(...files(file, skip))
    else if (entry.isFile()) result.push(file)
    else throw new Error(`unsupported file type: ${file}`)
  }
  return result.sort()
}

function packageOrigins(mapFile, dashboard, asset, entry) {
  const map = json(mapFile)
  requireThat(map.version === 3 && [asset, path.basename(asset)].includes(map.file), `invalid source map: ${mapFile}`)
  requireThat(Array.isArray(map.sources) && (map.sources.length > 0 || /^src\/i18n\/[\w-]+\.json$/.test(entry?.src)), `missing sources: ${mapFile}`)
  const origins = new Set()
  for (const source of map.sources) {
    const local = path.relative(dashboard, path.resolve(path.dirname(mapFile), map.sourceRoot || '', source))
    if (local.startsWith('src/')) continue
    const match = /^(node_modules\/(?:.*\/node_modules\/)?(?:@[^/]+\/)?[^/]+)\//.exec(local)
    requireThat(match, `unknown dashboard source: ${source}`)
    origins.add(match[1])
  }
  return [...origins].sort()
}

function requireSameAsset(mapped, emitted, relative) {
  if (relative.endsWith('.js')) {
    const suffix = Buffer.from(`//# sourceMappingURL=${path.basename(relative)}.map\n`)
    requireThat(mapped.subarray(-suffix.length).equals(suffix), `missing source map trailer: ${relative}`)
    mapped = mapped.subarray(0, -suffix.length)
  }
  requireThat(mapped.equals(emitted), `emitted asset differs from mapped build: ${relative}`)
}

function checkedManifest(maps, emitted) {
  const manifest = Object.values(json(path.join(maps, '.vite/manifest.json')))
  requireThat(manifest.some(entry => entry.isEntry), 'missing Vite entry')
  for (const entry of manifest) {
    for (const asset of [entry.file, ...(entry.css || []), ...(entry.assets || [])]) {
      requireThat(emitted.includes(asset), `missing emitted asset: ${asset}`)
    }
  }
  return new Map(manifest.map(entry => [entry.file, entry]))
}

function emittedAssets(dashboard, dist, maps) {
  const emitted = files(dist, f => f === path.join(dist, 'licenses')).map(file => path.relative(dist, file))
  const mapped = files(maps, f => f === path.join(maps, '.vite')).map(file => path.relative(maps, file))
  const expected = emitted.concat(emitted.filter(f => f.endsWith('.js')).map(f => f + '.map')).sort()
  requireThat(JSON.stringify(expected) === JSON.stringify(mapped), 'emitted asset or source map set differs')
  const manifest = checkedManifest(maps, emitted)
  return emitted.map(relative => {
    const bytes = readFileSync(path.join(dist, relative))
    const twin = path.join(maps, relative)
    requireSameAsset(readFileSync(twin), bytes, relative)
    const packages = relative.endsWith('.js') ? packageOrigins(twin + '.map', dashboard, relative, manifest.get(relative)) : []
    return { path: relative, sha256: hash(bytes), packages }
  })
}

function notice(sourceRoot, origin, destination, copies) {
  const bytes = readFileSync(path.join(sourceRoot, origin))
  requireThat(bytes.toString().trim(), `empty legal file: ${origin}`)
  copies.set(destination, bytes)
  return { origin, path: destination, sha256: hash(bytes) }
}

function packageNoticePath(relative) {
  // Escape the literal "deps" as well so real directories cannot alias a nested install.
  const parts = relative.split('/').slice(1).flatMap(part => {
    if (part === 'node_modules') return ['deps', 'nested']
    if (part === 'deps') return ['deps', 'literal']
    return part
  })
  return ['packages', ...parts].join('/')
}

function packageNotices(dashboard, lock, origin, copies) {
  const dir = path.join(dashboard, origin)
  const { name, version } = json(path.join(dir, 'package.json'))
  requireThat(name === origin.split('node_modules/').at(-1), `package name mismatch: ${origin}`)
  requireThat(typeof version === 'string' && version.length && version === lock[origin]?.version,
    `missing or mismatched installed version: ${origin}`)
  const legal = files(dir, f => path.basename(f) === 'node_modules').filter(file => legalName.test(path.basename(file)))
  requireThat(legal.length, `missing legal text: ${origin}`)
  if (name === 'lucide-react') {
    const license = readFileSync(path.join(dir, 'LICENSE'), 'utf8')
    requireThat(license.includes('ISC License') && license.includes('Feather (MIT)') && license.includes('Cole Bemis'),
      'missing Lucide ISC / Feather MIT attribution')
  }
  const notices = legal.map(file => {
    const relative = path.relative(dashboard, file)
    return notice(dashboard, relative, packageNoticePath(relative), copies)
  })
  return { name, version, origin, notices }
}

function designRecord(repo, dashboard, assets, dist) {
  const origin = 'design/astra-tokens.css'
  const bytes = readFileSync(path.join(repo, origin))
  const importer = readFileSync(path.join(dashboard, 'src/index.css'), 'utf8')
  requireThat(/@import\s+['"]\.\.\/\.\.\/\.\.\/design\/astra-tokens\.css['"]/.test(importer), 'missing design token import')
  const declarations = [...bytes.toString().matchAll(/(--astra-[\w-]+)\s*:/g)].map(m => m[1])
  requireThat(declarations.length > 0, 'missing design token declarations')
  const emitted = assets.filter(a => a.path.endsWith('.css')).map(a => a.path)
  const css = emitted.map(file => readFileSync(path.join(dist, file), 'utf8')).join('\n')
  const names = new Set([...css.matchAll(/(--astra-[\w-]+)\s*:/g)].map(m => m[1]))
  requireThat(declarations.every(name => names.has(name)), 'missing emitted design tokens')
  return { origin, sha256: hash(bytes), stylesheets: emitted }
}

function expectedPayload(dashboard, dist, maps) {
  const repo = path.resolve(dashboard, '../..')
  const assets = emittedAssets(dashboard, dist, maps)
  const origins = [...new Set(assets.flatMap(asset => asset.packages))].sort()
  requireThat(origins.includes('node_modules/lucide-react'), 'missing Lucide source contribution')
  const copies = new Map()
  const lock = json(path.join(dashboard, 'package-lock.json')).packages
  const packages = origins.map(origin => packageNotices(dashboard, lock, origin, copies))
  const notices = ['LICENSE', 'NOTICE', 'LICENSING.md'].map(f => notice(repo, f, 'project/' + f, copies))
  const design = designRecord(repo, dashboard, assets, dist)
  const inventory = { schema: 1, assets, packages, project: { notices, design } }
  copies.set('inventory.json', Buffer.from(JSON.stringify(inventory, null, 2) + '\n'))
  return copies
}

function verify(out, payload) {
  const delivered = files(out).map(f => path.relative(out, f))
  requireThat(JSON.stringify(delivered) === JSON.stringify([...payload.keys()].sort()), 'delivered notice file set differs')
  for (const [file, bytes] of payload) {
    requireThat(readFileSync(path.join(out, file)).equals(bytes), `notice or inventory hash mismatch: ${file}`)
  }
}

function main() {
  const { values } = parseArgs({ options: {
    'map-root': { type: 'string' }, out: { type: 'string' }, verify: { type: 'boolean' },
  } })
  requireThat(values['map-root'] && values.out, 'usage: dashboard-notices.mjs --map-root DIR --out DIST/licenses [--verify]')
  const out = path.resolve(values.out)
  requireThat(path.basename(out) === 'licenses', 'output directory must be named licenses')
  const payload = expectedPayload(process.cwd(), path.dirname(out), path.resolve(values['map-root']))
  if (!values.verify) {
    mkdirSync(out)
    for (const [file, bytes] of payload) {
      const target = path.join(out, file)
      mkdirSync(path.dirname(target), { recursive: true })
      writeFileSync(target, bytes)
    }
  }
  verify(out, payload)
}

main()

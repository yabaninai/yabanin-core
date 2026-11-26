import { readFile } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig, transformWithEsbuild, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'

// Vite's default JSON transform emits empty maps for standalone locale chunks.
function localeSourceMaps(): Plugin {
  const entry = fileURLToPath(new URL('./src/i18n/index.ts', import.meta.url))
  const suffix = '.json.mjs'
  return {
    name: 'locale-source-maps',
    enforce: 'pre',
    apply: 'build',
    resolveId(source, importer) {
      if (importer === entry && source !== './en.json' && /^\.\/[a-z]{2}(?:-[A-Z]{2})?\.json$/.test(source)) {
        return resolve(dirname(entry), source + '.mjs')
      }
    },
    async load(id) {
      if (dirname(id) !== dirname(entry) || !id.endsWith(suffix)) return
      const file = id.slice(0, -'.mjs'.length)
      this.addWatchFile(file)
      return transformWithEsbuild(await readFile(file, 'utf8'), file, { loader: 'json', format: 'esm', sourcemap: true })
    },
  }
}

function stripSecureCookies(proxy: { on: (event: string, fn: (...args: never[]) => void) => void }) {
  proxy.on('proxyRes', (proxyRes: { headers: { [key: string]: unknown } }) => {
    delete proxyRes.headers['strict-transport-security']
    const cookies = proxyRes.headers['set-cookie']
    if (Array.isArray(cookies)) {
      proxyRes.headers['set-cookie'] = cookies.map((c: string) =>
        c.replace(/;\s*Secure/gi, ''),
      )
    }
  })
}

const admin = process.env.YABANIN_ADMIN_URL || 'http://127.0.0.1:8086'

// ("node_modules/<pkg>/") so near-named packages (react-i18next, react-smooth)
// land in the intended chunk: i18n and recharts lists are checked first.
function vendorChunk(id: string): string | undefined {
  if (!id.includes('node_modules')) return undefined
  const pkg = id.match(/node_modules\/((?:@[^/]+\/)?[^/]+)\//)?.[1]
  if (!pkg) return undefined
  if (pkg === 'i18next' || pkg === 'react-i18next') return 'vendor-i18n'
  if (
    pkg === 'recharts' ||
    pkg === 'recharts-scale' ||
    pkg === 'react-smooth' ||
    pkg === 'react-transition-group' ||
    pkg === 'react-is' ||
    pkg === 'victory-vendor' ||
    pkg === 'internmap' ||
    pkg === 'decimal.js-light' ||
    pkg === 'eventemitter3' ||
    pkg === 'tiny-invariant' ||
    pkg === 'clsx' ||
    pkg === 'lodash' ||
    pkg === 'lodash.merge' ||
    /^d3-[a-z-]+$/.test(pkg)
  ) {
    return 'vendor-recharts'
  }
  if (pkg === 'react' || pkg === 'react-dom' || pkg === 'scheduler') return 'vendor-react'
  return undefined
}

export default defineConfig({
  plugins: [localeSourceMaps(), react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks: vendorChunk,
      },
    },
  },
  server: {
    host: '127.0.0.1',
    port: Number(process.env.YABANIN_DASHBOARD_PORT || 5173),
    proxy: {
      // Preserve the browser-facing Host so the admin's same-origin check
      // compares Origin against the development server, including its port.
      '/api': { target: admin, changeOrigin: false, configure: stripSecureCookies },
      '/auth': { target: admin, changeOrigin: false, configure: stripSecureCookies },
    },
  },
})

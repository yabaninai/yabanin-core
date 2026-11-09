import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

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
  plugins: [react()],
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

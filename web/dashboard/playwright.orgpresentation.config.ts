// CV-03 org-presentation browser acceptance — configuration.
//
// This suite runs ONLY under the Go stand
// (services/admin/handlers/cv03_org_presentation_browser_int_test.go),
// which serves the REAL built dashboard artifact (web/dashboard/dist) at
// the same origin as the REAL admin API over a disposable, fully migrated
// Postgres. There is deliberately no `webServer` here: the artifact under
// test must be the one the stand serves, never a vite dev server or a
// stub API.
//
// The stand provides:
//   CV03_BASE_URL    same-origin base (dist + /api) on 127.0.0.1
//   CV03_FIXTURE     JSON: seeded orgs/users/cookies + raw-SQL oracle
//                    values + the /_cv03/barrier* control paths
//   CV03_ARTIFACTS   gitignored dir for screenshots/timings/output
//
// Run via (from the repo root):
//   go test -tags integration -run TestCV03OrgPresentationBrowserAcceptance \
//     ./services/admin/handlers/ -count=1 -timeout 20m
import { defineConfig } from '@playwright/test'

const baseURL = process.env.CV03_BASE_URL
const artifacts = process.env.CV03_ARTIFACTS
const fixture = process.env.CV03_FIXTURE
if (!baseURL || !artifacts || !fixture) {
  throw new Error([
    'CV03_BASE_URL/CV03_ARTIFACTS/CV03_FIXTURE are not set — this suite runs through the Go stand:',
    '  cd web/dashboard && npm run build   # real artifact first',
    '  go test -tags integration -run TestCV03OrgPresentationBrowserAcceptance ./services/admin/handlers/ -count=1 -timeout 20m',
  ].join('\n'))
}

export default defineConfig({
  testDir: 'e2e-orgpresentation',
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  reporter: [['list']],
  outputDir: artifacts,
  use: {
    baseURL,
    trace: 'off',
    screenshot: 'off',
    video: 'off',
    locale: 'en-US',
  },
  projects: [
    { name: 'chromium', use: { viewport: { width: 1280, height: 800 } } },
  ],
})

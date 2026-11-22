// CV-02 request-journey browser acceptance — configuration.
//
// This suite runs ONLY under the Go stand
// (services/admin/handlers/cv02_journey_browser_int_test.go), which serves
// the REAL built dashboard artifact (web/dashboard/dist) at the same origin
// as the REAL admin API over a disposable, fully migrated Postgres. There is
// deliberately no `webServer` here: the artifact under test must be the one
// the stand serves, never a vite dev server or a stub API.
//
// The stand provides:
//   CV02_BASE_URL    same-origin base (dist + /api) on 127.0.0.1
//   CV02_FIXTURE     JSON: seeded orgs/users/cookies + raw-SQL oracle values
//   CV02_ARTIFACTS   gitignored dir for screenshots/timings/output
//
// Run via (from the repo root):
//   go test -tags integration -run TestCV02RequestJourneyBrowserAcceptance \
//     ./services/admin/handlers/ -count=1 -timeout 15m
//
// The Preview 2 journey runs on a desktop viewport.
import { defineConfig } from '@playwright/test'

const baseURL = process.env.CV02_BASE_URL
const artifacts = process.env.CV02_ARTIFACTS
if (!baseURL || !artifacts) {
  throw new Error([
    'CV02_BASE_URL/CV02_ARTIFACTS are not set — this suite runs through the Go stand:',
    '  cd web/dashboard && npm run build   # real artifact first',
    '  go test -tags integration -run TestCV02RequestJourneyBrowserAcceptance ./services/admin/handlers/ -count=1 -timeout 15m',
  ].join('\n'))
}

export default defineConfig({
  testDir: 'e2e-journey',
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: 0,
  // Playwright prefixes each top-level spec title with its file name.
  grepInvert: /(?:^|[/\s])journey\.spec\.ts AC-NARROW-(?:SERVED|BLOCKED)(?:\s|$)/,
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

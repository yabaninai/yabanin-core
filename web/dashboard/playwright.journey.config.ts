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
// Preview 2 UI acceptance is DESKTOP-ONLY: the two archived mobile (390px)
// specs in journey.spec.ts are retained archived fixtures, excluded from
// this registered desktop config by anchored match on their two frozen IDs
// (the specs sit at the top level, so the full title starts with the ID).
// The Go verifier independently fails the gate if an archived case ever
// records an executed verdict.
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
  // Archived mobile (390px) fixtures are never collected by this desktop
  // config. The grep subject is the project/file-prefixed full title (not
  // verified to start at the spec title), so match the two frozen IDs as
  // word-delimited tokens anywhere in it. A changed or new ID containing
  // these tokens verbatim stays excluded only if it keeps the exact token;
  // any other AC-* ID is an unknown case for the Go verifier and fails.
  grepInvert: [/\bAC-NARROW-(SERVED|BLOCKED)\b/],
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

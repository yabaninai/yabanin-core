#!/usr/bin/env bash
# browser.sh — NEXT-06 trusted browser gate runner.
#
# The gate does NOT install browser dependencies (npm ci / npx playwright
# install); those are installed separately by the owner. When the browser
# runtime is absent, the gate SKIPs explicitly (exit 77) with a reason — it
# never reports a silent pass, and it never falls back to a weaker check.
#
# Exit codes: 0 = all specs passed; 77 = skipped (browser runtime absent);
# any other non-zero = one or more specs failed (the gate caught a regression).
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

# 1) @playwright/test must be resolvable from the workspace node_modules.
if ! node -e "require.resolve('@playwright/test')" >/dev/null 2>&1; then
  echo "SKIP browser gate: @playwright/test is not installed (owner: npm ci at repo root). No silent pass."
  exit 77
fi

# 2) The chromium binary managed by Playwright must be present.
if ! node -e '
  const { chromium } = require("@playwright/test");
  const fs = require("fs");
  let p;
  try { p = chromium.executablePath(); } catch { process.exit(1); }
  process.exit(fs.existsSync(p) ? 0 : 1);
' >/dev/null 2>&1; then
  echo "SKIP browser gate: chromium browser binary is not installed (owner: npx playwright install chromium). No silent pass."
  exit 77
fi

# Artifacts (traces/screenshots/report) go to the isolated run directory provided
# by the quality runner (QUALITY_BROWSER_OUT), else a gitignored fallback.
out="${QUALITY_BROWSER_OUT:-artifacts/quality-browser}"
mkdir -p "$out"

QUALITY_BROWSER_OUT="$out" npx playwright test --config playwright.config.ts

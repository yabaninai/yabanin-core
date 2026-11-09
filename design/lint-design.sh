#!/bin/sh
# ASTR-01 + AVR-09 lint-design gate (v2).
#
# Three scans, each with its own baseline section in
# design/lint-design-baseline.txt:
#
#   [hex]     — hex / rgba() literals in web/dashboard/src (the original
#               ASTR-01 scan; unchanged).
#   [utils]   — Tailwind palette utilities (bg-white, bg-gray-*, text-gray-*,
#               border-gray-*, and the other color scales) in web/dashboard/src.
#               These are the "implicit hardcoded colors" that [hex] never
#               caught. Pinned for the un-migrated ASTR-12x screens; the goal
#               after those migrations is an empty [utils] section.
#   [site]    — hex / rgba() literals in web/site/src/css/custom.css (the site
#               shell). After AVR-08 this is empty; new literals fail.
#   [render]  — hex / rgba() literals in pkg/costsim/render.go (the self-contained
#               HTML report). Pinned: the report is a standalone artifact and
#               inlines its Astra-neutral palette by design (no external CSS).
#
# A NEW occurrence in any section (not in that section's baseline) fails the
# gate: use the --astra-* semantic tokens (or, for the renderer, the pinned
# inline palette) instead of a fresh literal. Resolved baseline lines are
# reported so they can be deleted in the same change that migrates the screen.
set -eu
root="$(cd "$(dirname "$0")/.." && pwd)"
baseline="$root/design/lint-design-baseline.txt"

# Color scales Tailwind exposes as utilities. We flag the *color* utility, not
# layout/spacing (bg-red-100 is a color; bg-100 is not a real class).
PALETTE='bg-white|bg-black|(bg|text|border|hover:bg|hover:text|hover:border|ring|divide|from|to|via)-(gray|slate|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)-'

hex_scan() { grep -rHEn '#[0-9a-fA-F]{3,8}\b|rgba?\(' "$@" 2>/dev/null || true; }
util_scan() { grep -rHEn "$PALETTE" "$@" 2>/dev/null || true; }

scan() {
  # scan <section-name> <grep args...>
  # Re-runs the matching grep for the section and compares to its baseline
  # block. The baseline file uses "[section]" headers; lines between a header
  # and the next header belong to that section. grep -H always prints the file
  # path (even for a single file), so every section compares in the uniform
  # <relpath>:NN:content form.
  section="$1"; shift
  found="$("$@" | sed "s|^$root/||" | sort -u || true)"

  awk -v sec="$section" '
    /^\[/ { insec = ($0 == "[" sec "]") ; next }
    insec { print }
  ' "$baseline" | sort -u > "$tmp_expected"

  if [ -n "$found" ]; then printf '%s\n' "$found" | sort -u > "$tmp_found"; else : > "$tmp_found"; fi

  comm -13 "$tmp_expected" "$tmp_found" > "$tmp_new"
  comm -23 "$tmp_expected" "$tmp_found" > "$tmp_gone"
}

tmp_expected="$(mktemp)"; tmp_found="$(mktemp)"; tmp_new="$(mktemp)"; tmp_gone="$(mktemp)"
trap 'rm -f "$tmp_expected" "$tmp_found" "$tmp_new" "$tmp_gone"' EXIT INT TERM

fail=0

report() {
  # report <section> — after scan() has filled the tmp files.
  section="$1"
  if [ -s "$tmp_new" ]; then
    echo "lint-design FAIL [$section]: new color literals outside the baseline." >&2
    echo "--- new (must use --astra-* tokens; renderer literals stay pinned) ---" >&2
    sed 's/^/  + /' "$tmp_new" >&2
    fail=1
  fi
  if [ -s "$tmp_gone" ]; then
    echo "lint-design [$section]: resolved — remove these from the baseline:" >&2
    sed 's/^/  - /' "$tmp_gone" >&2
  fi
}

# --- [hex] original ASTR-01 scan: dashboard source hex/rgba -----------------
scan hex hex_scan --include='*.css' --include='*.ts' --include='*.tsx' "$root/web/dashboard/src"
report hex

# --- [utils] Tailwind palette utilities: dashboard source -------------------
scan utils util_scan --include='*.tsx' --include='*.ts' "$root/web/dashboard/src"
report utils

# --- [site] site shell custom.css hex/rgba ----------------------------------
scan site hex_scan --include='*.css' "$root/web/site/src/css/custom.css"
report site

# --- [render] self-contained HTML report palette (pinned by design) ---------
# (grep needs --include to treat the path as a file, not a directory glob.)
scan render hex_scan --include='*.go' "$root/pkg/costsim/render.go"
report render

if [ "$fail" -eq 0 ]; then
  total="$(cat "$baseline" | grep -cE '^[^[:space:]]' || true)"
  echo "lint-design OK: no new hardcoded colors (baseline pinned: $total)"
  exit 0
fi

echo "" >&2
echo "To retire a baseline line, migrate the screen to Astra primitives (ASTR-12x)" >&2
echo "and delete the entry from design/lint-design-baseline.txt in the same change." >&2
exit 1

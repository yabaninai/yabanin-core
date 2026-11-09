#!/usr/bin/env python3
"""Docs language gate: the public English documentation must not contain
Cyrillic. Scans docs/**, README.md, SECURITY.md and CONTRIBUTING.md for the
character class [А-Яа-яЁё] and exits 1 on any finding.

Internal planning/work-record docs (docs/plans/**) follow the same rule as
standards/, skills/ and AGENTS.md: they are internal, not translated, and are
not scanned.

False positives are widened through the allowlist file
(scripts/docs_lang_allowlist.txt), never by disabling the gate. Each line of
the allowlist exempts exactly one line of one file:

    <repo-relative-path>:<sha256-of-line-content, first 16 hex chars>

Blank lines and #-comments are ignored. The checker prints the ready-to-paste
entry for every finding.
"""
import hashlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ALLOWLIST = ROOT / "scripts" / "docs_lang_allowlist.txt"

CYRILLIC = re.compile(r"[А-Яа-яЁё]")

# Public surface under scan. docs/plans/** is internal (see module docstring);
# every other *.md/*.mdx under docs/ plus the repo-root public docs are in.
SCAN_FILES = [ROOT / "README.md", ROOT / "SECURITY.md", ROOT / "CONTRIBUTING.md"]
SCAN_DIRS = [ROOT / "docs"]
SCAN_SUFFIXES = (".md", ".mdx")
EXCLUDED_PARTS = ("docs/plans/",)


def scan_targets():
    out = [f for f in SCAN_FILES if f.is_file()]
    for d in SCAN_DIRS:
        if not d.is_dir():
            continue
        out.extend(p for p in sorted(d.rglob("*"))
                   if p.is_file() and p.suffix in SCAN_SUFFIXES)
    unique = sorted(set(out))
    return [f for f in unique
            if not any(f.relative_to(ROOT).as_posix().startswith(p) for p in EXCLUDED_PARTS)]


def load_allowlist():
    entries = set()
    if not ALLOWLIST.is_file():
        return entries
    for raw in ALLOWLIST.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        entries.add(line)
    return entries


def line_key(rel: str, content: str) -> str:
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]
    return f"{rel}:{digest}"


def main() -> int:
    allow = load_allowlist()
    errs = []
    for f in scan_targets():
        rel = f.relative_to(ROOT).as_posix()
        try:
            text = f.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            errs.append(f"{rel}: unreadable: {exc}")
            continue
        for i, content in enumerate(text.splitlines(), start=1):
            if not CYRILLIC.search(content):
                continue
            key = line_key(rel, content)
            if key in allow:
                continue
            errs.append(f"{rel}:{i}: cyrillic found: {content.strip()!r}\n"
                        f"  allowlist entry (scripts/docs_lang_allowlist.txt): {key}")
    if errs:
        print(f"docs-lang: {len(errs)} finding(s)")
        for e in errs:
            print("FAIL:", e)
        return 1
    print(f"docs-lang: OK ({len(allow)} allowlist entr"
          f"{'y' if len(allow) == 1 else 'ies'})")
    return 0


if __name__ == "__main__":
    sys.exit(main())

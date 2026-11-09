#!/usr/bin/env python3
"""Docs source-of-truth checks: markdown link targets, migration mirror,
and rename-leftover patterns. Exit 1 on any finding."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def md_files():
    patterns = ["*.md", "docs/**/*.md", "skills/**/*.md", "standards/**/*.md"]
    out = []
    for pat in patterns:
        out.extend(ROOT.glob(pat))
    return sorted(set(out))

LINK_RE = re.compile(r'\[[^\]]*\]\(([^)\s]+)(?:\s+"[^"]*")?\)')

HISTORICAL = ("/work-records/", "/strategy/qa/", "/strategy/research/", "/plans/prompts/", "/plans/")

def historical(f: Path) -> bool:
    """Work records, QA snapshots and research docs are historical evidence:
    they are never rewritten to match the present tree."""
    return any(part in f.as_posix() for part in HISTORICAL)

def check_links(errs):
    n = 0
    for f in md_files():
        if historical(f):
            continue
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        for m in LINK_RE.finditer(text):
            target = m.group(1)
            if target.startswith(("http://", "https://", "mailto:", "#", "pathname://")):
                continue
            path = target.split("#")[0]
            if not path:
                continue
            resolved = (f.parent / path).resolve()
            if not resolved.exists():
                errs.append(f"broken link in {f.relative_to(ROOT)}: {target}")
                n += 1
    return n

def check_mirror(errs):
    a = sorted(p.name for p in (ROOT / "migrations").glob("*.sql"))
    b = sorted(p.name for p in (ROOT / "pkg/migrate/migrations").glob("*.sql"))
    if a != b:
        errs.append(f"migration mirror divergence: migrations/ has {len(a)} files, pkg/migrate/migrations/ has {len(b)}")
        return 1
    return 0

def check_leftovers(errs):
    n = 0
    skipped = 0
    patterns = [
        (re.compile(r'bin/tr\b'), "old binary name bin/tr"),
        (re.compile(r'cmd/tr\b'), "old cmd path cmd/tr"),
        (re.compile(r'\b105\+ (SQL )?migrations'), "stale '105+ migrations' claim"),
    ]
    for f in md_files():
        if historical(f):
            skipped += 1
            continue
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        for rx, why in patterns:
            for m in rx.finditer(text):
                errs.append(f"rename leftover in {f.relative_to(ROOT)}: {why}: {m.group(0)!r}")
                n += 1
    return n

def main():
    errs: list[str] = []
    links = check_links(errs)
    mirror = check_mirror(errs)
    leftovers = check_leftovers(errs)
    print(f"docs-verify: {links} broken link(s), mirror {'OK' if mirror == 0 else 'DIVERGED'}, "
          f"{leftovers} leftover(s) (historical records skipped)")
    for e in errs:
        print("FAIL:", e)
    return 1 if errs else 0

if __name__ == "__main__":
    sys.exit(main())

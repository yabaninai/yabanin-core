#!/usr/bin/env python3
"""NEXT-16 container/config policy leaf.

Deterministic in-house checks (no external tool): Dockerfiles and compose
files must not use :latest, must not inline secrets into ENV, runtime images
declare a non-root USER, and published ports are explicit.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent

def relpath(path: Path) -> str:
    """Repo-relative display path; fixture paths outside the repo stay absolute."""
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


SECRET_ENV = re.compile(r"(?i)(api[_-]?key|secret|password|token|private[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9_\-/.]{16,}")
# ${VAR} substitutions are not inline secrets (values come from the env).
SECRET_ENV_SUBST = re.compile(r"\$\{[^}]*\}")
# Third-party images must be pinned. Locally BUILT images (compose services
# with a build: context producing image: <name>:latest) are build outputs,
# not unpinned dependencies — collected per compose file and allowlisted.
# A compose file may also declare locally retagged images (artifacts of
# another stand, applied via `docker tag`) with a directive comment:
#   # policy-local-images: name1 name2
# Declared names are treated the same as build outputs; everything else
# still requires a concrete tag/digest.
LATEST = re.compile(r":\S*latest$|:latest\b")
POLICY_LOCAL = re.compile(r"^#\s*policy-local-images:\s*(.+)$")
PORT_ONLY = re.compile(r"^\s*-?\s*\"?\d{2,5}(?:/tcp)?\"?\s*$")


def check_dockerfile(path: Path):
    issues = []
    text = path.read_text(errors="replace")
    has_user = False
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        # Comments are not image references or ENV lines (the file header may
        # legitimately discuss tagging policy).
        if s.startswith("#"):
            continue
        if LATEST.search(s):
            issues.append(f"{relpath(path)}:{n} uses a :latest tag")
        if SECRET_ENV.search(s):
            issues.append(f"{relpath(path)}:{n} ENV carries an inline secret-shaped value")
        if s.upper().startswith("USER ") and s.split()[1] != "root":
            has_user = True
    if not has_user:
        issues.append(f"{relpath(path)}: no non-root USER declared")
    return issues


def _service_blocks(text: str):
    """Minimal compose parsing: {service: {"build": bool, "image": name}}.

    Order-independent within a service block (image: may precede or follow
    build:) — the previous single-pass scanner only detected build outputs
    when image: came AFTER build:, flagging locally built :latest images as
    unpinned third-party ones (a latent false positive its test never ran
    against, because the fixture uses the natural build-first order).
    """
    blocks: dict = {}
    cur = None
    for raw in text.splitlines():
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        if indent == 2:
            m = re.match(r"^([\w.-]+):\s*$", s)
            if m and not s.startswith("-"):
                cur = m.group(1)
                blocks.setdefault(cur, {"build": False, "image": None})
                continue
            cur = None
            continue
        if cur is None:
            continue
        if s.startswith("build:"):
            blocks[cur]["build"] = True
        im = re.match(r"^image:\s*(\S+)", s)
        if im:
            name = im.group(1)
            blocks[cur]["image"] = name[: -len(":latest")] if name.endswith(":latest") else name
    return blocks


def check_compose(path: Path):
    issues = []
    text = path.read_text(errors="replace")
    # Locally built images: any service with build: + image: name:latest.
    local = set()
    for cfg in _service_blocks(text).values():
        if cfg["build"] and cfg["image"]:
            local.add(cfg["image"])
    for s in text.splitlines():
        s = s.strip()
        m_local = POLICY_LOCAL.match(s)
        if m_local:
            for name in re.split(r"[\s,]+", m_local.group(1)):
                if name:
                    local.add(name)
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        # Comments are not image references (headers document the retag
        # policy); secret scanning keeps its own inline-secret skip.
        if not s.startswith("#") and LATEST.search(s):
            name = s.split("image:")[1].strip() if "image:" in s else s
            base = name.split(":latest")[0]
            if base not in local:
                issues.append(f"{relpath(path)}:{n} third-party image not pinned ({name})")
        if SECRET_ENV.search(s) and "example" not in s and not s.startswith("#") and not SECRET_ENV_SUBST.search(s):
            issues.append(f"{relpath(path)}:{n} inline secret-shaped value")
        if PORT_ONLY.match(s):
            issues.append(f"{relpath(path)}:{n} port published without an explicit host bind")
    return issues


def main() -> int:
    issues = []
    try:
        for df in ROOT.rglob("Dockerfile*"):
            if "node_modules" in str(df) or "/build/" in str(df):
                continue
            issues += check_dockerfile(df)
        for cf in list(ROOT.rglob("docker-compose*.yml")) + list(ROOT.rglob("docker-compose*.yaml")):
            if "node_modules" in str(cf):
                continue
            issues += check_compose(cf)
    except OSError as exc:
        print(f"scanner error: {exc}", file=sys.stderr)
        return 2
    print(f"container/config policy: {len(issues)} issue(s)")
    for i in issues:
        print(f"  {i}")
    return 1 if issues else 0


if __name__ == "__main__":
    sys.exit(main())

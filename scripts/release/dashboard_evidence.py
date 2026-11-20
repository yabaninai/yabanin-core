#!/usr/bin/env python3
"""Dashboard asset evidence: bind every emitted chunk to its sourcemapped twin.

Records rebuild-independent facts for release_evidence.verify:

* every file under web/dashboard/dist with sha256;
* every emitted JS chunk bound to its build-map twin by the map's actual
  relative path (stripping ".map") -- the sourcemap "file" field is NOT
  trusted: dynamic chunks name a bare filename while the file lives under
  assets/. Twin equivalence is the explicit map-comment-only rule: generated
  chunks differ from ordinary
  dist chunks ONLY by the final "//# sourceMappingURL=..." line; replacing
  that one optional line with the original single trailing LF must give an
  exact code-byte match for EVERY chunk. Anything else is a mismatch; any
  unbound or map-less emitted chunk fails this script;
* per-chunk contributing packages derived from sourcemap sources;
* contributing packages' legal files (LICENSE/LICENCE/COPYING/NOTICE/
  PATENTS, case-insensitive) with sha256 from node_modules. These are the
  available texts; DELIVERY is recorded separately and honestly: the nginx
  runtime stage ships dist/ only, so package notices do not accompany the
  built output -- an explicit gap until a product change binds delivery;
* design token binding: web/dashboard/src/index.css @imports
  design/astra-tokens.css and every --astra-* declaration must appear in
  the emitted css. Exactly one explicit recorded minifier equivalence is
  accepted (--astra-duration: 140ms == .14s); no broad value waiver.

The map-comment equivalence is deliberately narrow: the ONLY accepted byte
shape is <one or more code lines ending in LF>//# sourceMappingURL=
<nonempty name> at EOF -- exactly one marker in the file and nothing after
the comment except one optional trailing LF. A marker-only file is not a
chunk and never binds. Appended code or payload after the comment, an empty
map name, a mid-file comment or a missing comment are binding failures;
arbitrary suffix removal is never performed.

Reproducible map build (--map-root is required; public tooling and operator
docs must not depend on machine-specific paths):
    cd web/dashboard
    npx vite build --outDir <map-root> --sourcemap --manifest
The same inputs produce the same chunk hashes as the shipped dist/, which
is the byte-equality reference for the twin binding.

stdlib only. Exit 1 if any chunk is unbound or the token binding fails;
the JSON is still written so the failure is auditable.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DIST = ROOT / "web/dashboard/dist"
# R4-MAP-01 (map-receipt counterexample): build maps are RETAINED here, a
# canonical tree outside dist/ -- the nginx stage copies dist/ only
# (Dockerfile: COPY --from=builder .../dist /usr/share/nginx/html), so the
# retained maps are never exposed in production, and the verifier can bind
# the recorded map_sha256 receipt to actual retained map bytes.
DIST_SOURCEMAPS = ROOT / "web/dashboard/dist-sourcemaps"
NODE_MODULES = ROOT / "web/dashboard/node_modules"
TOKENS_CSS = ROOT / "design/astra-tokens.css"
IMPORT_SITE = ROOT / "web/dashboard/src/index.css"
LEGAL_RE = re.compile(r"^(license|licence|copying|notice|patents)(\.[^/]*)?$", re.I)
PKG_IN_SOURCE = re.compile(r"node_modules/((?:@[^/]+/)?[^/]+)")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


# The single confirmed minifier rewrite: no other
# value equivalence is accepted. Keep in sync with release_evidence.py.
TIME_UNIT_EQUIVALENCES = {("--astra-duration", "140ms"): ".14s"}


def equivalence_match(decl: str, emitted: str) -> bool:
    """Raw containment, or the one explicit recorded time-unit equivalence."""
    if decl in emitted:
        return True
    name, _, value = decl.partition(":")
    canon = TIME_UNIT_EQUIVALENCES.get((name.strip(), value.rstrip(";").strip()))
    return canon is not None and re.search(
        re.escape(name.strip()) + r"\s*:\s*" + re.escape(canon) + r";", emitted) is not None


_MAP_COMMENT_LINE = re.compile(rb"//# sourceMappingURL=(\S+)")

# R4-MAP-01: the single recorded twin equivalence text, shared verbatim by
# the generator's chunk records and the verifier's shape check.
MAP_EQUIVALENCE = ("map-comment-only (exactly one final "
                   "//# sourceMappingURL=<name> line at EOF, replaced by "
                   "the code's own trailing LF)")


def strip_map_comment(data: bytes) -> bytes:
    """Remove the single final sourceMappingURL comment line.

    Accepted shape is exactly:
        <one or more code lines ending in LF>//# sourceMappingURL=
        <nonempty name>[LF at EOF]
    Exactly one marker in the whole file, the comment on the final line, a
    nonempty map name, at least one nonempty code line before the comment,
    and no bytes after the comment except one optional trailing LF. The
    returned bytes keep the code's own final LF. Anything else (code or
    payload appended after the comment, an empty name, a comment mid-file,
    a second marker, no comment at all, or a marker-only file) raises
    ValueError; arbitrary suffix removal is never performed.
    """
    if data.count(b"//# sourceMappingURL=") != 1:
        raise ValueError("expected exactly one //# sourceMappingURL marker")
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    if not lines or not _MAP_COMMENT_LINE.fullmatch(lines[-1]):
        raise ValueError("sourceMappingURL comment must be the final line "
                         "with a nonempty map name")
    if not any(line.strip() for line in lines[:-1]):
        raise ValueError("marker-only file: no code line precedes the "
                         "sourceMappingURL comment")
    return b"\n".join(lines[:-1]) + b"\n"


def collect_dist_files() -> list:
    return [{"path": str(p.relative_to(ROOT)), "sha256": sha256_file(p)}
            for p in sorted(DIST.rglob("*")) if p.is_file()]


def _source_packages(sources: list) -> list:
    """npm packages reachable from one sourcemap's sources entries."""
    return sorted({m.group(1) for s in sources
                   if (m := PKG_IN_SOURCE.search(s or ""))})


def _map_comment_name(data: bytes) -> str:
    """Map file named by the chunk's sourceMappingURL comment, '' if none."""
    m = _MAP_COMMENT_LINE.search(data)
    return m.group(1).decode("utf-8", "replace") if m else ""


def retain_build_artifacts(map_root: Path, dest: Path = None) -> dict:
    """Retain the raw map twins AND maps into the canonical non-served tree.

    R4-MAP-01 (map-receipt and raw-twin counterexamples): verify must be
    able to re-derive every recorded hash relationship from actual bytes,
    so the build's marker-carrying *.js twins and every *.js.map are
    retained verbatim under dist-sourcemaps/ (mirroring the map-root
    layout). dist/ stays the stripped, map-free shipped output."""
    dest = dest if dest is not None else DIST_SOURCEMAPS
    counts = {"raw_twins": 0, "maps": 0}
    for pattern in ("*.js", "*.js.map"):
        for src in sorted(map_root.rglob(pattern)):
            target = dest / src.relative_to(map_root)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(src, target)
            counts["raw_twins" if pattern == "*.js" else "maps"] += 1
    return counts


def _chunk_record(map_root: Path, map_path: Path,
                  retained_root: Path = None) -> dict:
    """One map's twin record: strict strip, dist comparison, packages."""
    map_rel = str(map_path.relative_to(map_root))
    twin_rel = "web/dashboard/dist/" + map_rel[: -len(".map")]
    map_twin = map_root / map_rel[: -len(".map")]
    dist_twin = ROOT / twin_rel
    data = json.loads(map_path.read_text(errors="replace"))
    sources = data.get("sources") or []
    map_bytes = map_twin.read_bytes()
    try:
        stripped = strip_map_comment(map_bytes)
        strip_error = ""
    except ValueError as exc:  # strict shape; never strip arbitrary suffixes
        stripped, strip_error = b"", str(exc)
    map_name = _map_comment_name(map_bytes)
    if not strip_error and map_name != map_path.name:
        strip_error = "sourceMappingURL comment names a different map"
    dist_bytes = dist_twin.read_bytes() if dist_twin.is_file() else b""
    return {
        "twin_rel": twin_rel,
        "equivalence": MAP_EQUIVALENCE,
        "twin_sha256": (None if strip_error
                        else hashlib.sha256(stripped).hexdigest()),
        "map_twin_raw_sha256": hashlib.sha256(map_bytes).hexdigest(),
        "map_name": map_name,
        # R4-MAP-01: the receipt is the sha256 of the RETAINED artifact
        # bytes (dist-sourcemaps/), so verify can recompute it exactly;
        # the --map-root copy is only the fallback before retention.
        "map_sha256": sha256_file(
            (retained_root or DIST_SOURCEMAPS) / map_rel
            if ((retained_root or DIST_SOURCEMAPS) / map_rel).is_file()
            else map_path),
        "sources": sources,
        "strip_error": strip_error,
        "dist_twin_exists": dist_twin.is_file(),
        "dist_twin_matches": (not strip_error and dist_twin.is_file()
                              and stripped == dist_bytes),
        "has_lucide": any("lucide-react" in (s or "") for s in sources),
        "packages": _source_packages(sources),
    }


def _missing_map_record(js: Path) -> dict:
    """Emitted dist chunk with no build map: recorded, never bound."""
    return {
        "twin_rel": str(js.relative_to(ROOT)),
        "equivalence": "unmapped emitted chunk",
        "twin_sha256": None,
        "map_twin_raw_sha256": None,
        "map_name": "",
        "map_sha256": None,
        "sources": [],
        "strip_error": "",
        "dist_twin_exists": True,
        "dist_twin_matches": False,
        "has_lucide": False,
        "packages": [],
        "missing_map": True,
    }


def chunk_origins(map_root: Path, retained_root: Path = None) -> dict:
    """Twin-bind every map to the real dist file; fail on any unbound chunk.

    Every emitted dist *.js must have a build-map twin; a map-less chunk is
    recorded with missing_map and fails the binding like any unbound chunk.
    """
    out = {}
    for map_path in sorted(map_root.rglob("*.js.map")):
        out[str(map_path.relative_to(map_root))] = _chunk_record(
            map_root, map_path, retained_root)
    mapped = {v["twin_rel"] for v in out.values()}
    for js in sorted(DIST.rglob("*.js")):
        if str(js.relative_to(ROOT)) not in mapped:
            out[str(js.relative_to(DIST))] = _missing_map_record(js)
    return out


def package_versions(packages: list) -> dict:
    out = {}
    for pkg in packages:
        pj = NODE_MODULES / pkg / "package.json"
        if pj.is_file():
            try:
                out[pkg] = json.loads(pj.read_text(errors="replace")).get("version")
            except ValueError:
                out[pkg] = None
    return out


def contributing_packages(chunks: dict) -> list:
    names = sorted({p for entry in chunks.values() for p in entry["packages"]})
    versions = package_versions(names)
    out = []
    for pkg in names:
        legal = [{"file": str(f.relative_to(ROOT)), "sha256": sha256_file(f)}
                 for f in sorted((NODE_MODULES / pkg).glob("*"))
                 if f.is_file() and LEGAL_RE.match(f.name)]
        out.append({"name": pkg, "version": versions.get(pkg), "legal_files": legal})
    return out


def token_binding() -> dict:
    decls = re.findall(r"--astra-[A-Za-z0-9-]+\s*:[^;]+;", TOKENS_CSS.read_text())
    emitted = "".join(p.read_text(errors="replace") for p in DIST.rglob("*.css"))
    missing, applied = [], []
    for decl in decls:
        if decl in emitted:
            continue
        name, _, value = decl.partition(":")
        canon = TIME_UNIT_EQUIVALENCES.get((name.strip(), value.rstrip(";").strip()))
        if canon is not None and re.search(
                re.escape(name.strip()) + r"\s*:\s*" + re.escape(canon) + r";", emitted):
            applied.append({"declaration": decl,
                            "equivalent_emitted": f"{name.strip()}: {canon};",
                            "basis": "confirmed minifier time-unit rewrite"})
        else:
            missing.append(decl)
    return {"source": "design/astra-tokens.css",
            "import_site": "web/dashboard/src/index.css (@import '../../../design/astra-tokens.css')",
            "declaration_count": len(decls),
            "missing": missing,
            "time_unit_equivalences_applied": applied,
            "ok": not missing,
            "note": "raw presence required; the single explicit 140ms -> .14s "
                    "equivalence is recorded, no broad value waiver"}


def css_token_reach() -> list:
    out = []
    for f in sorted(DIST.rglob("*.css")):
        text = f.read_text(errors="replace")
        tokens = sorted(set(re.findall(r"--astra-[A-Za-z0-9-]+", text)))
        if tokens:
            out.append({"file": str(f.relative_to(ROOT)), "token_count": len(tokens),
                        "tokens_sample": tokens[:10]})
    return out


def _chunk_unbound(v: dict) -> bool:
    """A chunk record fails the twin binding: strip error, missing map, or
    no byte-identical emitted twin."""
    return bool(v.get("strip_error") or v.get("missing_map")
                or not (v["dist_twin_exists"] and v["dist_twin_matches"]))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--map-root", type=Path, required=True,
                    help="root of a sourcemapped vite build of web/dashboard; "
                         "reproduce with: cd web/dashboard && npx vite build "
                         "--outDir <map-root> --sourcemap --manifest")
    args = ap.parse_args()
    retained = retain_build_artifacts(args.map_root)
    chunks = chunk_origins(args.map_root)
    unbound = [k for k, v in chunks.items() if _chunk_unbound(v)]
    tokens = token_binding()
    delivery = ("dashboard npm package notices do not accompany the built output: "
                "the nginx runtime stage ships dist/ only and the release NOTICE "
                "draft covers the Go module scope; binding delivery requires a "
                "product change (separate bounded assignment) mapping emitted npm "
                "code and assets to full notices delivered with the built output, "
                "including Lucide's ISC and applicable Feather-derived MIT "
                "attribution)")
    evidence = {
        "schema": "yabanin.dashboard-evidence/2",
        "dist_files": collect_dist_files(),
        "chunk_origins": chunks,
        "contributing_packages": contributing_packages(chunks),
        "lucide_react": None,
        "css_token_reach": css_token_reach(),
        "bindings": {"astra_tokens": tokens},
        "notice_delivery": {"status": "not_bound", "detail": delivery},
        "unresolved": [delivery] if tokens["ok"] else [delivery,
            "design/astra-tokens.css declarations not present in emitted css"],
    }
    luc = NODE_MODULES / "lucide-react" / "LICENSE"
    if luc.is_file():
        text = luc.read_text(errors="replace")
        evidence["lucide_react"] = {
            "version": package_versions(["lucide-react"]).get("lucide-react"),
            "legal_file_hashes": {"LICENSE": sha256_file(luc)},
            "feather_attribution": "Feather" in text and "MIT" in text,
        }
    dest = ROOT / "artifacts/release-evidence/dashboard-assets.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    bound = len(chunks) - len(unbound)
    print(f"dashboard evidence: {len(evidence['dist_files'])} dist files, "
          f"{retained['maps']} maps + {retained['raw_twins']} raw twins "
          f"retained under web/dashboard/dist-sourcemaps/, "
          f"{bound}/{len(chunks)} chunks twin-bound, "
          f"{len(evidence['contributing_packages'])} contributing packages, "
          f"astra binding ok={tokens['ok']}")
    for k in unbound:
        print(f"UNBOUND CHUNK: {k}")
    if unbound or not tokens["ok"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

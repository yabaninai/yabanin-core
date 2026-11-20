#!/usr/bin/env python3
"""Release evidence generator/verifier: machine facts only, fail-closed.

generate  assembles artifacts/release-evidence/release-evidence.json from
          collected machine facts (image digests, versions, notice texts and
          hashes, emitted dashboard assets with per-chunk twin binding, git
          provenance, release binaries and their notice payloads) and binds
          them to the current source fingerprint.
verify    re-derives every fact it can from the current tree and recorded
          evidence and fails on any mismatch: removed notices, wrong image
          versions/digests, missing emitted assets, unbound chunks, deleted
          module notice payload files, stale dist NOTICE copies, drifting
          provenance rows, and fabricated review structure.

Fail-closed rules:
* known gaps stay failures: while required facts or notices are missing
  (quickstart image digests, mock alpine text corpus, npm notice delivery,
  recorded revision gaps) verify reports "PENDING gap: ..." lines and does
  NOT pass. A documented gap is not a pass;
* forbidden markers in a recorded notice stay hard failures unless the
  record characterizes the hit with notice_forbidden_contexts: every hit
  marker must be covered and the exact section strings must occur in the
  notice text, and the retention proof is invoked only through the
  explaining context entry's retained_check (a record-level key is not an
  honored binding and fails; an unsupported value is a hard failure, never
  proof of non-retention). node's aggregated LICENSE embeds ICU4C autoconf
  aux-script notices under GPL with the autoconf exception; the Dockerfile
  source proof is necessary but NOT sufficient: a passing proof keeps the
  classification OPEN as a pending gap until the exact final nginx image
  is inspected through a hash-bound final_image_check record -- resolved
  builder image and aggregate LICENSE path/hash, GPL marker section
  boundaries and covered auxiliary files, marker AND covered-content scans
  across image layers including bundled/minified assets, sourcemaps and
  compressed files, with the inspected image ID/platform recorded.
  Unresolved matches stay open; the validation door is never a waiver; any
  retained/runtime occurrence (in the Dockerfile or in emitted content) is
  a hard failure;
* Preview2 scope boundary: the acceptance scope is
  install/provider/request/inspect/recovery and the acceptance artifact is
  the standard Compose quickstart plus the five host binaries.
  Dockerfile.hardened is used by neither, so its distroless revision
  limitation is recorded as an explicit OUT-OF-SCOPE unassessed note (not
  a Preview2 blocker, no hardened readiness claim) while its digest pin
  and notice binding remain enforced. The note is machine-bound, not
  JSON-asserted: it is reserved for exactly
  gcr.io/distroless/static-debian12 and requires a proven basis -- every
  Compose dockerfile reference is a standard one, no Compose file
  references Dockerfile.hardened, the quickstart builds via the core and
  dashboard Dockerfiles, and the host-binary subject set is exactly the
  five release binaries. Any other repo or unproven basis leaves the
  pending gap in force plus an integrity failure. Required blockers are
  never reclassified: quickstart image identities (platform + immutable
  image ID for Core, mock and dashboard), actual notice bytes under
  /usr/share/licenses/yabanin in the built Core image (image-bound
  content manifest), the mock alpine package-to-license mapping, npm
  notice delivery including Lucide ISC / Feather-derived MIT, and the
  node final-image inspection above; these probes are not exhaustive for
  ownership/distribution of the five host binaries, so the human
  inventory review stays pending;
* dashboard contributing packages are bound to the sourcemap chunk
  origins in both directions: every package named by a chunk origin must
  have a record, every record must be named by some origin, and each
  record needs a concrete version and at least one hash-bound legal text
  (an empty or deleted contributing_packages array fails);
* notice payloads are verified exhaustively per binary via inventory.json
  (binary_sha256, every listed legal file present as a regular confined
  file with matching sha, project LICENSE/NOTICE + Go toolchain LICENSE +
  linked-module notices required, unlisted payload files rejected). Empty
  payload directories cannot pass;
* freshness: HEAD must equal the HEAD recorded in the evidence, and an
  explicitly passed --expected-head is an additional assertion on the same
  value, never a substitute for the evidence's own binding (the top-level
  head, when retained, must agree with freshness.head); no hardcoded
  review commit freezes the branch -- a reviewed follow-up commit
  regenerates the evidence instead of failing forever. recipe.json's
  git_commit must equal HEAD and recipe.json's content sha256 must equal
  the recorded distribution.recipe_sha256 (a content mutation that keeps
  the commit id fails),
  the dirty/untracked source sets must match the evidence, and
  dist/release/NOTICE must be byte-identical to the current root NOTICE
  (stale builds are not bound as corrected). Acceptance-grade
  verification requires a clean tree: a dirty working snapshot is
  labeled review-only and fails;
* provenance binds both directions: every actually-added path must be
  listed and every listed row must correspond to a real add. DCO signoff
  presence is recorded as a fact and kept distinct from employer-rights
  approval, which is not assessed here.

Human attestations are NOT produced here: the seven checker-facing review
areas stay truthfully pending (approved=false) until a scoped human review
records them. The verifier checks review STRUCTURE only; judging the
authenticity of a human approval is outside machine scope, so a later
real human-signed packet with approved=true is not rejected as fabricated
by this tool. An expected license_check --release FAIL naming the pending
attestations is the honest state, not something to bypass.

stdlib only; reuses scripts/quality/license_check.py for the FORBIDDEN
marker list and the source fingerprint, and scripts/release/
dashboard_evidence.py for the single recorded time-unit equivalence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/quality"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import license_check  # noqa: E402  (reuse: FORBIDDEN, source_files, source_fingerprint)
import oci_build_receipt
import dashboard_evidence  # noqa: E402  (single recorded token equivalence)

EVIDENCE_REL = "artifacts/release-evidence/release-evidence.json"
ARTS = ROOT / "artifacts/release-evidence"
TASK_BASE = "fb1b1eeef406488ef8c97c12387a7eb8a8ce5b61"  # frozen task base
BINARIES = ("yabanin", "yabanin-gateway", "yabanin-loggerd", "yabanin-admin", "yabanin-mcp")
DISTROLESS_REPO = "gcr.io/distroless/static-debian12"
# The only dockerfiles the standard Compose surface may reference; the
# quickstart acceptance path builds via "Dockerfile" and
# "web/dashboard/Dockerfile" today. Dockerfile.hardened is never in it.
STANDARD_COMPOSE_DOCKERFILES = frozenset({
    "Dockerfile", "deploy/mock-provider/Dockerfile",
    "deploy/classifier/Dockerfile", "web/dashboard/Dockerfile"})
AREAS = license_check.REVIEW_AREAS
BUILDER_FILES = ("Dockerfile", "Dockerfile.hardened", "deploy/mock-provider/Dockerfile",
                 "web/dashboard/Dockerfile")
REQUIRED_ADDED = ("scripts/quality/tests/test_preview2_recovery.py",)
REDIS_FIXED = {"digest": "sha256:2f66de68111e64c3927859f158f8e666066dae2b97d9f82770a6f37a5aa1c335",
               "version": "7.2.17", "copying_sha256":
               "97f0a15b7bbae580d2609dad2e11f1956ae167be296ab60f4691ab9c30ee9828"}
REDIS_NEGATIVE = {"digest": "sha256:7b1753b4c5ad8458906c272a8132b8c15f5557b000379eb115fb239706a384b7",
                  "version": "7.4.12",
                  "license_path": "artifacts/release-evidence/upstream/redis-7.4.12/LICENSE.txt",
                  "license_sha256":
                  "abffee3703161c0a6a0cd7f635b2c1ebb3b81bd199e9d18ea89652d678ae4287"}
PGVECTOR_CONTROL_REL = "artifacts/release-evidence/upstream/pgvector/vector.control"
# the pinned pgvector image is resolved for linux/amd64 (the quickstart
# resolution platform recorded in the resolve artifacts)
_PG_PLATFORM = "linux/amd64"
# R4-PG-PROOF-01: one reviewed tuple for the pgvector operator-pulled subject.
# The control bytes are the committed real upstream vector.control
# (testdata/release-evidence/upstream/pgvector/vector.control) and the
# digest is the reviewed pgvector image pin of the quickstart compose; the
# expected values are PINNED CONSTANTS, never whatever the tree currently
# contains, so a substituted control cannot become its own reference.
PGVECTOR_FIXED = {
    "digest": "sha256:0dd3149a06e4579a0d70d8fef9945636cd514005e7237deb27f9b67886f8dc4f",
    "manifest_digest": "sha256:c0cd736fe8b8b5d408db56b780570bac404fe518e66e39de624aa46f9aabc60a",
    "config_digest": "sha256:31c6867f8fd38f4b75885aeb954d43cd4c2be714659d72b0dc4ae55bdcd9e967",
    "extension_version": "0.8.7",
    "control_sha256": "9f7d0fcada5e68aa41adf9d5b3ab3fd43c83f2edd462c391a0f715d72a9941ec"}
# R4-DUP-01: subjects pulled by the operator into the acceptance quickstart;
# each must have EXACTLY ONE evidence record carrying ALL its checks.
_OPERATOR_SUBJECTS = ("redis", "pgvector/pgvector")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def forbidden_hits(text: str) -> list:
    return [label for label, rx in license_check.FORBIDDEN if rx.search(text)]


def git_out(*args: str) -> str:
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True,
                          capture_output=True, text=True).stdout


def git_bytes(*args: str) -> bytes:
    """Raw git bytes -- no text=True newline translation or decoding.

    R3: universal-newline decoding corrupts CR-containing filenames and
    re-decodes arbitrary path bytes; porcelain streams must be decoded
    once, surrogateescape, by the parser."""
    return subprocess.run(["git", "-C", str(ROOT), *args], check=True,
                          capture_output=True).stdout


def load_json(path: Path):
    return json.loads(path.read_text())


_COMPOSE_IMAGE_PIN = re.compile(r"^([\w./:-]+)@(sha256:[0-9a-f]{64})$")

# R2: each pulled quickstart service is bound to its ONE expected operator
# subject (repo_ref, no tag). A service pointing at another subject's pin
# inherits nothing: repository, digest, notice and subject checks bind to
# the expected subject's single record row.
_COMPOSE_SERVICE_SUBJECTS = {
    "redis": "redis",
    "postgres": "pgvector/pgvector",
    "db-app-role": "pgvector/pgvector",
}


def _compose_model(root: Path) -> tuple[dict, list[str]]:
    """Read the effective service map offline, including every optional profile."""
    path = root / "deploy/quickstart/docker-compose.yml"
    command = ["docker", "compose", "--env-file", os.devnull, "--profile", "*",
               "--project-name", "yabanin-evidence", "--file", str(path.resolve()),
               "config", "--format", "json", "--no-interpolate", "--no-env-resolution",
               "--no-path-resolution", "--no-normalize"]
    try:
        proc = subprocess.run(command, capture_output=True, check=False, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return {}, ["cannot run docker compose config to verify the quickstart services"]
    if proc.returncode:
        # Do not echo config values or dependency diagnostics into the public receipt.
        if b"already defined" in proc.stderr:
            return {}, ["docker compose config rejected a duplicate mapping key"]
        return {}, ["docker compose config rejected the quickstart service model"]
    try:
        services = json.loads(proc.stdout)["services"]
        return {name: {"images": [svc["image"]] if "image" in svc else [],
                       "build": "build" in svc, "build_config": svc.get("build")} for name, svc in services.items()}, []
    except (AttributeError, KeyError, TypeError, ValueError):
        return {}, ["docker compose config returned an invalid service model"]


def _compose_services(root: Path) -> dict:
    return _compose_model(root)[0]


def pinned_services(root: Path) -> dict:
    """Effective digest-pinned service images: name -> sorted digest list.

    Reads effective values only: a commented-out pin is not a pin and a
    quoted pin still is. A service whose effective images carry several
    distinct digests maps to all of them (callers must bind every digest)."""
    out = {}
    for name, svc in _compose_services(root).items():
        digests = {m.group(2) for m in map(_COMPOSE_IMAGE_PIN.match, svc["images"]) if m}
        if digests:
            out[name] = sorted(digests)
    return out


def pinned_builders(root: Path) -> list:
    """Dockerfile FROM pins: (file, ref) for every digest-pinned base."""
    out = []
    for rel in BUILDER_FILES:
        f = root / rel
        if not f.is_file():
            continue
        for line in f.read_text().splitlines():
            m = re.search(r"^FROM\s+(\S+@sha256:[0-9a-f]{64})", line)
            if m:
                out.append((rel, m.group(1)))
    return out


def git_state() -> dict:
    """HEAD plus sha256 of dirty tracked and nonignored untracked source files.

    R4-STATUS-01: porcelain is parsed NUL-separated so paths with spaces,
    quotes or newlines cannot corrupt the record; --untracked-files=all
    enumerates the files INSIDE untracked directories (the abbreviated
    'dir/' row is not a file and used to be dropped silently, hiding its
    contents from the evidence); rename/copy rows consume BOTH NUL fields;
    and tracked files missing from the worktree are recorded as explicit
    tombstones instead of vanishing from the dirty set."""
    head = git_out("rev-parse", "HEAD").strip()
    raw = git_bytes("status", "--porcelain", "-z",
                    "--untracked-files=all").decode("utf-8", "surrogateescape")
    try:
        dirty, untracked = _parse_porcelain(raw, ROOT)
    except ValueError as exc:
        # R3: a refused parse must SURFACE, never silently accept a
        # truncated or malformed stream as a clean tree
        return {"head": head, "dirty": {}, "untracked": {},
                "parse_error": str(exc)}
    return {"head": head, "dirty": dirty, "untracked": untracked}


def _parse_porcelain(raw: str, root: Path) -> tuple:
    """(dirty, untracked) maps from NUL-separated porcelain output.

    R2: the two-character XY code -- a rename staged and then edited in
    the worktree is "RM", so the original-path field must be consumed
    whenever EITHER column is R or C, and a copy's source still exists
    (it is not a tombstone)."""
    dirty, untracked = {}, {}
    # R3: git -z ALWAYS terminates the stream with a NUL; anything else
    # is a truncated read and is refused instead of parsed as clean.
    # R4: an EMPTY stream (zero bytes) is the exact output of a clean
    # `git status --porcelain -z` -- it is valid and clean, not truncated.
    if raw and not raw.endswith("\0"):
        raise ValueError("porcelain stream is truncated (missing final NUL)")
    if not raw:
        return {}, {}
    fields = raw.split("\0")
    assert fields[-1] == ""
    fields.pop()  # drop the empty tail left by the final NUL
    i = 0
    while i < len(fields):
        entry, i = fields[i], i + 1
        code, path = _porcelain_entry(entry)
        if "R" in code or "C" in code:
            # R3: the original-path field is MANDATORY -- a truncated
            # 'RM new.txt\0' row with the origin already cut off used to
            # pass as a plain dirty row
            if i >= len(fields) or not fields[i]:
                raise ValueError(f"truncated rename/copy row: {entry!r}")
            orig, i = fields[i], i + 1
            dirty[orig] = ("copied (source remains)" if "C" in code
                           else "tombstone (renamed away in worktree)")
        f = root / path
        if code.strip() == "??":
            untracked[path] = (sha256_file(f) if f.is_file()
                               else "not a regular file")
        else:
            dirty[path] = (sha256_file(f) if f.is_file()
                           else "tombstone (deleted from worktree)")
    return dirty, untracked


# git status --porcelain=v1 -z without --ignored: ordinary changes,
# the seven unmerged states, and the untracked pair.
_PORCELAIN_XY = re.compile(r"(?: [AMTDCR]|[MTARC][ MTD]|D |DD|AU|UD|UA|DU|AA|UU|\?\?)")


def _porcelain_entry(entry: str) -> tuple:
    """Return a documented two-column status and its unquoted path."""
    if len(entry) < 4 or entry[2] != " " or not _PORCELAIN_XY.fullmatch(entry[:2]):
        raise ValueError(f"malformed porcelain entry: {entry!r}")
    return entry[:2], entry[3:]


def _confined(base: Path, p: Path) -> str:
    if p.is_symlink() or not p.is_file():
        return "not a regular confined file"
    try:
        p.resolve().relative_to(base.resolve())
    except ValueError:
        return "escapes payload directory"
    return ""


_DOCKERFILE_STAGE = re.compile(r"^FROM\s+(\S+)(?:\s+[Aa][Ss]\s+(\S+))?\s*$", re.M)
_DOCKERFILE_COPY = re.compile(r"^COPY\s+(.+)$", re.M)


def _stage_spans(text: str) -> list:
    """(base, alias, start_offset) for every FROM stage, in order."""
    return [(m.group(1), m.group(2), m.start())
            for m in _DOCKERFILE_STAGE.finditer(text)]


def _node_stage_span(text: str):
    """(index, alias, stage text) for the single node builder stage.

    Failure lines cover: no stages at all, no or multiple node stages, or
    the node stage being the final runtime stage (builder notice retained).
    """
    spans = _stage_spans(text)
    if not spans:
        return None, ["containers: node: dashboard Dockerfile parses to no stages; "
                      "build-only characterization unproven"]
    hits = [i for i, (base, _a, _s) in enumerate(spans) if base.startswith("node:")]
    if not hits:
        return None, ["containers: node: no node: stage in the dashboard Dockerfile; "
                      "build-only characterization unproven"]
    if len(hits) > 1:
        return None, ["containers: node: multiple node: stages; build-only "
                      "characterization unproven"]
    idx = hits[0]
    if idx == len(spans) - 1:
        return None, [f"containers: node: node stage is the final/runtime stage "
                      f"({spans[idx][0].split('@')[0]}); builder notice retained in "
                      "the shipped image"]
    end = spans[idx + 1][2] if idx + 1 < len(spans) else len(text)
    return (idx, spans[idx][1], text[spans[idx][2]:end]), []


def _copy_parts(rest: str) -> tuple:
    """(--from value, source paths, destination) for one COPY argument list."""
    ref, paths = None, []
    parts = rest.split()
    i = 0
    while i < len(parts):
        p = parts[i]
        if p == "--from":
            i += 1
            ref = parts[i] if i < len(parts) else ""
        elif p.startswith("--from="):
            ref = p.split("=", 1)[1]
        elif not p.startswith("--"):
            paths.append(p)
        i += 1
    dest = paths.pop() if paths else None
    return ref, paths, dest


def _inheriting_stage_indices(spans: list, idx: int) -> set:
    """Later stages whose FROM chain transitively inherits stage idx."""
    bad, aliases = {idx}, set()
    if spans[idx][1]:
        aliases.add(spans[idx][1])
    changed = True
    while changed:
        changed = False
        for j in range(idx + 1, len(spans)):
            base, alias, _s = spans[j]
            if j in bad or not base or base not in aliases:
                continue
            bad.add(j)
            if alias:
                aliases.add(alias)
            changed = True
    return bad


def _builder_refs(spans: list, idx: int, alias, inheriting: set) -> set:
    """Stage references able to source builder-stage content."""
    refs = {str(j) for j in inheriting}
    if alias:
        refs.add(alias)
    refs |= {spans[j][1] for j in inheriting if spans[j][1]}
    return refs


def _builder_copy_failures(text: str, refs: set, allow: set) -> tuple:
    """(failures, copied?) for every COPY --from the builder stage."""
    fails, copied = [], False
    for m in _DOCKERFILE_COPY.finditer(text):
        ref, srcs, _dest = _copy_parts(m.group(1))
        if ref not in refs:
            continue
        for s in srcs:
            copied = True
            if not any(s == a or s.startswith(a + "/") for a in allow):
                fails.append(f"containers: node: runtime stage copies builder "
                             f"content outside the dist tree ({s}); builder "
                             "notice may be retained in the shipped image")
    return fails, copied


def _retention_failures(root: Path, rec: dict) -> list:
    """Prove a build-stage notice is not retained in the shipped runtime.

    Machine facts only: the proof must be bound to the node dashboard
    builder record, the node builder stage must not be final or inherited
    by the final stage, and every COPY --from the builder (or any stage
    inheriting it) must source only the builder WORKDIR dist tree (the
    emitted-content marker scan in asset_failures completes the proof).
    A proven build-only notice is a recorded characterization, never a
    licensing waiver or approval; any retained or unprovable occurrence
    is a hard failure.
    """
    if rec.get("repo_ref") != "node":
        return ["containers: node: retention proof not bound to the node "
                f"dashboard builder record (repo_ref={rec.get('repo_ref')!r}); "
                "an unbound retention check is never proof of non-retention"]
    kind = rec.get("retained_check")
    if kind != "dashboard-runtime-dist-only":
        return ["containers: node: unsupported retained_check value "
                f"{str(kind)!r} (supported: 'dashboard-runtime-dist-only'); an "
                "unsupported check is never proof of non-retention"]
    df = root / "web/dashboard/Dockerfile"
    if not df.is_file():
        return ["containers: node: dashboard Dockerfile missing; build-only "
                "characterization unproven"]
    text = df.read_text(errors="replace")
    stage, errs = _node_stage_span(text)
    if errs:
        return errs
    idx, alias, seg = stage
    spans = _stage_spans(text)
    inheriting = _inheriting_stage_indices(spans, idx)
    if len(spans) - 1 in inheriting:
        return ["containers: node: final runtime stage inherits the node "
                f"builder stage ({spans[-1][0]}); builder notice retained "
                "in the shipped image"]
    workdirs = re.findall(r"^WORKDIR\s+(\S+)", seg, re.M)
    if not workdirs:
        return ["containers: node: node stage declares no WORKDIR; dist "
                "allowlist underivable, build-only characterization unproven"]
    allow = {w.rstrip("/") + "/dist" for w in workdirs}
    refs = _builder_refs(spans, idx, alias, inheriting)
    fails, copied = _builder_copy_failures(text, refs, allow)
    if not copied:
        fails.append("containers: node: runtime stage copies nothing from the "
                     "node builder; shipped dashboard content unbound")
    return fails


def _read_notice(root: Path, rec: dict):
    """(notice text, failure line) for the record's hash-bound notice file."""
    notice = rec.get("notice") or {}
    p = root / notice.get("path", "-") if notice.get("path") else None
    if p is None or not p.is_file():
        return None, f"notice file missing ({notice.get('path')})"
    if sha256_file(p) != notice.get("sha256"):
        return None, "notice sha mismatch"
    return p.read_text(errors="replace"), ""


_FILE_HEADER = re.compile(r"^\s*File\s*:", re.I | re.M)
_DASH_RULE = re.compile(r"^\s*-{6,}\s*$", re.M)


def _line_starts(text: str) -> list:
    """Character offset of every line start in text."""
    starts = [0]
    starts.extend(m.end() for m in re.finditer(r"\n", text))
    return starts


def _notice_boundaries(text: str) -> list:
    """Character offsets of bundled-notice section boundary lines."""
    offs = [m.start() for m in _FILE_HEADER.finditer(text)]
    offs.extend(m.start() for m in _DASH_RULE.finditer(text))
    return sorted(offs)


def _section_spans(text: str) -> list:
    """(start, end) for every bounded notice section.

    A section runs from its boundary line to the next boundary; a
    trailing section without a closing boundary is unbounded and covers
    nothing.
    """
    bounds = _notice_boundaries(text)
    return list(zip(bounds, bounds[1:]))


def _forbidden_regex(label: str):
    """The compiled forbidden-marker pattern bound to this label."""
    for lab, rx in license_check.FORBIDDEN:
        if lab == label:
            return rx
    return None


def _sections_unique(secs: list, text: str) -> bool:
    """Every section entry matches exactly one full stripped line."""
    stripped = [ln.strip() for ln in text.splitlines()]
    return all(stripped.count(s) == 1 for s in secs)


def _named_spans(secs: list, spans: list, text: str) -> list:
    """The bounded sections containing the named section lines."""
    starts = _line_starts(text)
    stripped = [ln.strip() for ln in text.splitlines()]
    named = []
    for s in secs:
        at = starts[stripped.index(s)]
        named.extend(sp for sp in spans if sp[0] <= at < sp[1])
    return named


def _in_spans(offset: int, spans: list, text: str) -> bool:
    """The line containing offset lies inside one bounded section."""
    at = text.rfind("\n", 0, offset) + 1
    return any(a <= at < b for a, b in spans)


def _context_covers(c: dict, hit: str, text: str) -> bool:
    """The entry binds this hit marker and its exact bounded sections.

    A section entry must match exactly one full stripped line of the
    notice text, and every occurrence of the forbidden pattern must lie
    inside one of those bounded sections. Substring matches, ambiguous
    section names and unbounded trailing sections cover nothing.
    """
    if hit not in (c.get("markers") or []):
        return False
    secs = list(c.get("sections") or [])
    rx = _forbidden_regex(hit)
    if not secs or rx is None or not _sections_unique(secs, text):
        return False
    named = _named_spans(secs, _section_spans(text), text)
    if not named:
        return False
    return all(_in_spans(m.start(), named, text) for m in rx.finditer(text))


def _uniform_retained_check(involved: list):
    """The single retained_check kind shared by every explaining entry."""
    kinds = {str(c.get("retained_check") or "") for c in involved}
    if not involved or "" in kinds or len(kinds) != 1:
        return None
    return kinds.pop()


def _final_image_gate_failures(root: Path, label: str, involved: list,
                               hits: list) -> list:
    """Apply the exact-final-image gate after a passing source-side proof."""
    fics = [c for c in involved if c.get("final_image_check")]
    if len(fics) > 1:
        return [f"containers: {label}: multiple final_image_check records on the "
                "explaining contexts; ambiguous"]
    if not fics:
        return [f"PENDING gap: containers: {label}: notice text hits "
                f"{','.join(hits)} inside recorded bundled third-party "
                "sections; the source-bound build-only proof passes but "
                "the exact final nginx image inspection is pending "
                "(resolved builder image and aggregate LICENSE "
                "path/hash, GPL marker section boundaries and covered "
                "auxiliary files, marker AND covered-content scan of "
                "the image layers including bundled/minified assets, "
                "sourcemaps and compressed files, recorded image "
                "ID/platform; never a waiver)"]
    return _final_image_check_failures(root, label, fics[0])


def _explained_notice_failures(root: Path, label: str, rec: dict,
                               hits: list, text: str) -> list:
    """Decide a characterized forbidden hit; a characterization is not an
    approval and never closes the classification on its own."""
    ctxs = rec.get("notice_forbidden_contexts") or []
    if not all(any(_context_covers(c, h, text) for c in ctxs) for h in hits):
        return [f"containers: {label}: notice text hits forbidden markers "
                f"({','.join(hits)})"]
    involved = [c for c in ctxs if any(_context_covers(c, h, text) for h in hits)]
    kind = _uniform_retained_check(involved)
    if kind is None:
        fails = []
        if any(c.get("final_image_check") for c in involved):
            fails.append(f"containers: {label}: final_image_check requires a "
                         "retained_check on the same explaining context")
        fails.append(f"PENDING gap: containers: {label}: notice text hits "
                     f"{','.join(hits)} inside recorded bundled third-party sections "
                     f"(scoped decision pending; annotation is not an approval)")
        return fails
    ret = _retention_failures(root, {"repo_ref": rec.get("repo_ref"),
                                     "retained_check": kind})
    if ret:
        return ret + [f"containers: {label}: notice text hits "
                      f"forbidden markers ({','.join(hits)})"]
    # Source-side proof passed; closure additionally requires the exact
    # final-image inspection below -- never a waiver.
    return _final_image_gate_failures(root, label, involved, hits)


def _notice_failures(root: Path, label: str, rec: dict) -> list:
    fails = []
    if not str(rec.get("version") or "").strip():
        fails.append(f"containers: {label}: version unbound")
    text, err = _read_notice(root, rec)
    if err:
        return fails + [f"containers: {label}: {err}"]
    # A record-level retained_check is not an honored binding: only the
    # explaining notice_forbidden_contexts entry may carry it (a record-level
    # shortcut would apply the retention proof without the marker+section
    # binding, so its presence is itself an evidence failure).
    if rec.get("retained_check"):
        fails.append(f"containers: {label}: record-level retained_check is not "
                     "an honored binding; it must live in the explaining "
                     "notice_forbidden_contexts entry")
    hits = forbidden_hits(text)
    if hits:
        # A forbidden hit stays a hard failure unless the record
        # characterizes it; even a characterized hit is only ever a pending
        # gap unless the retention proof and the final-image gate pass.
        fails.extend(_explained_notice_failures(root, label, rec, hits, text))
    return fails


def _fic_shape_failures(label: str, fic: dict) -> list:
    """The inspection record names an exact image and platform."""
    errs = []
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(fic.get("image_id") or "")):
        errs.append(f"containers: {label}: final_image_check.image_id is not an "
                    "exact immutable image digest")
    if not str(fic.get("platform") or "").strip():
        errs.append(f"containers: {label}: final_image_check.platform unbound")
    return errs


def _fic_manifest(root: Path, label: str, fic: dict):
    """(manifest json, failures) for the hash-bound scan artifact."""
    rel = str(fic.get("scan_manifest") or "")
    mp = (root / rel) if rel else None
    if mp is None or not mp.is_relative_to(root) or not mp.is_file():
        return None, [f"containers: {label}: final_image_check scan manifest "
                      f"artifact missing ({rel or 'unbound'})"]
    if sha256_file(mp) != fic.get("scan_manifest_sha256"):
        return None, [f"containers: {label}: final_image_check scan manifest "
                      "sha drift"]
    return load_json(mp), []


_FIC_COUNT_KEYS = ("scanned_minified_assets", "scanned_sourcemaps",
                   "scanned_compressed_archives")


def _fic_layer_failures(label: str, man: dict) -> list:
    """Every scanned layer is recorded as an immutable digest."""
    layers = man.get("layers_scanned")
    if (not isinstance(layers, list) or not layers
            or not all(isinstance(x, str) and x.strip() for x in layers)):
        return [f"containers: {label}: scan manifest records no layers scanned"]
    # R2: 'unknown' is not a scanned layer -- every entry must be an
    # immutable layer digest
    if not all(re.fullmatch(r"sha256:[0-9a-f]{64}", x) for x in layers):
        return [f"containers: {label}: scan manifest layers_scanned entries "
                "are not immutable layer digests"]
    return []


def _fic_count_failures(label: str, man: dict) -> list:
    """Coverage counts present, non-negative and nonzero in total."""
    errs = []
    for key in _FIC_COUNT_KEYS:
        # R3: type() is int -- JSON true is not a coverage count even
        # though bool subclasses int in Python
        if type(man.get(key)) is not int or man.get(key) < 0:
            errs.append(f"containers: {label}: scan manifest lacks {key} "
                        "coverage count")
    # R2: layers listed but zero assets covered scanned nothing
    if (all(type(man.get(k)) is int for k in _FIC_COUNT_KEYS)
            and sum(man.get(k, 0) for k in _FIC_COUNT_KEYS) == 0):
        errs.append(f"containers: {label}: scan manifest covers zero assets for "
                    "the listed layers (nothing was actually scanned)")
    return errs


def _fic_coverage_failures(label: str, man: dict) -> list:
    """The manifest records every layer scanned and coverage counts."""
    errs = _fic_layer_failures(label, man)
    errs.extend(_fic_count_failures(label, man))
    # R4-NGINX-01: absent hit lists used to become empty lists -- a scan
    # that does not EXPLICITLY record its marker/covered-content results
    # has not reported them
    for key in ("marker_hits", "covered_content_hits"):
        if not isinstance(man.get(key), list):
            errs.append(f"containers: {label}: scan manifest lacks explicit "
                        f"{key} scan results")
    return errs


def _final_image_check_failures(root: Path, label: str, ctx: dict) -> list:
    """Validate the exact-final-image inspection record.

    Closure requires a hash-bound scan artifact for the inspected image:
    exact immutable image ID, platform, every layer listed as scanned,
    explicit recorded coverage counts for minified assets, sourcemaps and
    compressed archives, explicit scan-result lists, a manifest bound to
    the SAME image identity and platform it claims to have scanned, and
    zero marker or covered-content hits. Unresolved matches keep the
    classification open as a pending gap; a malformed record is an
    integrity failure. This validates supplied qualification results --
    it is never a waiver.
    """
    fic = ctx.get("final_image_check") or {}
    iid = str(fic.get("image_id") or "")
    errs = _fic_shape_failures(label, fic)
    man, man_errs = _fic_manifest(root, label, fic)
    if man is None:
        return errs + man_errs
    # R4-NGINX-01: the manifest must identify the image it actually scanned
    if str(man.get("image_id") or "") != iid:
        errs.append(f"containers: {label}: scan manifest not bound to the "
                    "inspected image identity")
    if str(man.get("platform") or "") != str(fic.get("platform") or ""):
        errs.append(f"containers: {label}: scan manifest not bound to the "
                    "inspected image platform")
    errs.extend(_fic_coverage_failures(label, man))
    hits = man.get("marker_hits") or []
    covered = man.get("covered_content_hits") or []
    if hits or covered:
        # R3: the scan CONFIRMED retained occurrences -- the documented
        # contract makes retained forbidden bytes in the shipped image a
        # HARD failure, never a pending gap
        errs.append(f"containers: {label}: final image inspection confirmed "
                    f"retained occurrences (markers: {hits}; covered contents: "
                    f"{covered}) at {iid} -- retained forbidden bytes in the "
                    "shipped image are a hard failure")
    return errs


def _pinned_service_failures(root: Path, by_digest: dict, subjects: dict, services: dict) -> list:
    """Every operator-pulled quickstart service binds ONE subject row.

    R4-COMPOSE-01 effective-value gate for ALL pulled services, not just
    redis: services that build their image locally (a direct build: child)
    are exempt from pull-pinning because their exact built identities are the
    pending quickstart-images gap; a pulled service (no build:) must carry
    exactly ONE effective digest-pinned image value -- a commented-out pin
    does not count, a duplicated image key is ambiguity, and a service with
    no effective image executes no silent no-op.

    R2: the record bound by the service digest must be THAT subject's single
    row -- repository, digest, notice and every subject-specific check bind
    to the SAME record. A service pointing at another subject's pin (pg
    inheriting the Redis notice) is a cross-subject binding and fails."""
    fails = []
    # R3: the pulled-service SET is itself a gate -- deleting an expected
    # service (or hiding it behind a direct build:) removes its checks and
    # must fail, and an unexpected pulled service fails via the subject
    # map below
    pulled = {name for name, svc in services.items() if not svc["build"]}
    for name in sorted(set(_COMPOSE_SERVICE_SUBJECTS) - pulled):
        fails.append(f"containers: compose: expected pulled service {name} is "
                     "absent from the compose file (deleting the service or "
                     "hiding it behind build: removes its binding checks)")
    for name, svc in sorted(services.items()):
        if svc["build"]:
            continue
        if len(svc["images"]) != 1:
            fails.append(f"containers: compose: {name}: pulled service must bind "
                         f"exactly one effective image (found {len(svc['images'])})")
            if not svc["images"]:
                continue
        expected = _COMPOSE_SERVICE_SUBJECTS.get(name)
        if expected is None:
            fails.append(f"containers: compose: {name}: pulled service is not "
                         "bound to an expected operator subject (extend "
                         "_COMPOSE_SERVICE_SUBJECTS deliberately)")
            continue
        for v in svc["images"]:
            m = _COMPOSE_IMAGE_PIN.match(v)
            if m is None:
                fails.append(f"containers: compose: {name} service image '{v}' "
                             "is not an effective digest pin")
                continue
            # R3: the Compose repository itself (tag stripped) must be the
            # expected subject -- a foreign repository carrying this
            # subject's digest is not a binding
            repo = m.group(1).split(":")[0]
            if repo != expected:
                fails.append(f"containers: compose image {name}='{v}': repository "
                             f"{repo!r} is not the expected subject {expected!r} "
                             "(foreign repository at this digest is not a binding)")
                continue
            digest = m.group(2)
            rec = by_digest.get(digest)
            if rec is None:
                fails.append(f"containers: compose image {name}@{digest}: "
                             "no evidence record")
                continue
            if rec.get("repo_ref") != expected:
                fails.append(f"containers: compose image {name}@{digest}: bound "
                             f"record is for subject {rec.get('repo_ref')!r}, not "
                             f"the expected {expected!r} (cross-subject binding "
                             "refused)")
                continue
            if subjects.get(expected) is not rec:
                fails.append(f"containers: compose image {name}@{digest}: record is "
                             f"not the single {expected} subject row (split records "
                             "refused; notice and subject checks bind to one row)")
                continue
            fails.extend(_notice_failures(root, name, rec))
    return fails


def _redis_failures(rec: dict | None) -> list:
    """redis stays on the fixed BSD-licensed 7.2.17 pin."""
    if rec is None:
        return ["containers: redis: required evidence record missing"]
    fails = []
    if rec.get("version") != REDIS_FIXED["version"]:
        fails.append("containers: redis: version is not the BSD-licensed 7.2 branch")
    if rec.get("license") != "BSD-3-Clause":
        fails.append("containers: redis: license not recorded as BSD-3-Clause")
    if rec.get("index_digest") != REDIS_FIXED["digest"]:
        fails.append("containers: redis: digest is not the fixed 7.2.17 pin")
    notice = rec.get("notice")
    if not isinstance(notice, dict) or notice.get("sha256") != REDIS_FIXED["copying_sha256"]:
        fails.append("containers: redis: COPYING notice is not bound to the fixed 7.2.17 "
                     "sha256")
    return fails


def _compose_service_images(root: Path, service: str) -> list:
    return _compose_services(root).get(service, {}).get("images", [])


def _redis_pin_failures(root: Path, services: dict | None = None) -> list:
    """The EFFECTIVE quickstart compose redis image is the exact fixed pin.

    R4-COMPOSE-01: reads services.redis.image as an effective scalar -- a
    commented correct pin never satisfies an unpinned or wrong active value,
    a quoted valid pin is accepted, and duplicate or variable values are
    rejected as ambiguous/non-immutable."""
    subject = "redis:7.2-alpine"
    if services is None:
        services = _compose_services(root)
    values = services.get("redis", {}).get("images", [])
    if len(values) != 1:
        return ["containers: compose: redis service image is not a single "
                f"effective image value ({len(values)} found)"]
    v = values[0]
    if "${" in v:
        return ["containers: compose: redis service image is a variable, "
                "not an immutable pin"]
    name, sep, digest = v.rpartition("@")
    unpinned = not sep or not digest.startswith("sha256:")
    if unpinned and v.split("@")[0] != subject:
        return [f"containers: compose: redis pinned under ['{v.split('@')[0]}'] instead "
                "of the exact redis:7.2-alpine subject"]
    if unpinned:
        return ["containers: compose: redis service image is not digest-pinned"]
    if name != subject:
        return [f"containers: compose: redis pinned under ['{name}'] instead of the "
                "exact redis:7.2-alpine subject"]
    if digest != REDIS_FIXED["digest"]:
        return [f"containers: compose: redis pin {digest} is not the fixed 7.2.17 digest"]
    return []


def _pgvector_control_failures(root: Path, rec: dict) -> list:
    """Bind the record to the pinned pgvector tuple (R4-PG-PROOF-01).

    Canonical control path, the independently fixed upstream control SHA,
    the reviewed pgvector image digest and the extension version are ONE
    tuple of PINNED CONSTANTS. A substituted vector.control with the same
    default_version but different bytes fails here even when the evidence
    sha was regenerated to match the substituted bytes."""
    control = rec.get("extension_control")
    if not isinstance(control, dict):
        return ["containers: pgvector: extension_control record missing"]
    fails = []
    if control.get("path") != PGVECTOR_CONTROL_REL:
        fails.append("containers: pgvector: extension_control path is not the pinned "
                     "vector.control path")
    p = root / PGVECTOR_CONTROL_REL
    if not p.is_file():
        fails.append(f"containers: pgvector: pinned {PGVECTOR_CONTROL_REL} file absent")
        return fails
    if control.get("sha256") != PGVECTOR_FIXED["control_sha256"]:
        fails.append("containers: pgvector: extension_control sha256 is not the pinned "
                     "vector.control constant")
    if sha256_file(p) != PGVECTOR_FIXED["control_sha256"]:
        fails.append("containers: pgvector: vector.control bytes drifted from the "
                     "pinned upstream constant (substituted control?)")
    if rec.get("index_digest") != PGVECTOR_FIXED["digest"]:
        fails.append("containers: pgvector: record digest is not the reviewed pgvector "
                     "image digest of the pinned tuple")
    return fails


def _pg_collection_identity_failures(rec: dict, col: dict) -> list:
    """Bind runtime, OCI index, platform manifest and config identities.

    Docker may report the index as its local image ID. That identity must not
    be confused with the selected linux/amd64 manifest or its config."""
    fails = []
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(col.get("image_id") or "")):
        return ["containers: pgvector: extension_collection image_id is not an "
                "immutable collected image identity"]
    cfg = rec.get("config_digest")
    if cfg != PGVECTOR_FIXED["config_digest"]:
        fails.append("containers: pgvector: evidence row config_digest is not the "
                     "pinned OCI config identity")
    elif col.get("image_id") not in (rec.get("index_digest"), cfg):
        fails.append("containers: pgvector: extension_collection image_id is neither "
                     "the pinned index nor its config (an unrelated digest is not a "
                     "binding)")
    man = col.get("manifest")
    if (not isinstance(man, dict)
            or str(man.get("digest") or "") != PGVECTOR_FIXED["manifest_digest"]
            or rec.get("index_digest") != PGVECTOR_FIXED["digest"]):
        fails.append("containers: pgvector: extension_collection does not carry the "
                     "pinned image's index->manifest->config chain (the platform "
                     "manifest must be the selected linux/amd64 child, not the index)")
    elif (not isinstance(man.get("config"), dict)
          or man["config"].get("digest") != cfg):
        fails.append("containers: pgvector: extension_collection manifest config "
                     "descriptor does not resolve to the pinned OCI config")
    if not str(col.get("platform") or "").strip():
        fails.append("containers: pgvector: extension_collection platform missing")
    elif col.get("platform") != _PG_PLATFORM:
        fails.append("containers: pgvector: extension_collection platform is not the "
                     f"pinned resolution platform ({_PG_PLATFORM})")
    return fails


def _pgvector_collection_failures(rec: dict | None) -> list:
    """Hash-bound image collection record for the extracted control bytes.

    The provenance sentence is not proof: accepting the extraction requires
    the actual collected image identity (immutable ID), its platform, the
    extraction method and the same pinned control sha. A MISSING record
    keeps an explicit PENDING gap (never a generated pass); a present but
    malformed or unbound record is a hard failure."""
    col = (rec or {}).get("extension_collection")
    if not isinstance(col, dict):
        return ["PENDING gap: containers: pgvector: vector.control extraction "
                "unproven: no hash-bound image collection record (actual image "
                "identity, platform and extraction method); the provenance "
                "sentence alone is not proof"]
    fails = _pg_collection_identity_failures(rec, col)
    method = str(col.get("method") or "")
    if "vector.control" not in method or not re.search(r"docker (create|run)", method):
        fails.append("containers: pgvector: extension_collection method does not name "
                     "the extraction (docker create/run + cp of vector.control)")
    if col.get("control_sha256") != PGVECTOR_FIXED["control_sha256"]:
        fails.append("containers: pgvector: extension_collection control_sha256 is "
                     "not the pinned vector.control constant")
    if col.get("index_digest") != PGVECTOR_FIXED["digest"]:
        fails.append("containers: pgvector: extension_collection is not bound to the "
                     "reviewed pgvector image digest")
    return fails


def _pgvector_failures(root: Path, rec: dict | None) -> list:
    """pgvector evidence is bound to the pinned image's vector.control."""
    if rec is None:
        return ["containers: pgvector: required evidence record missing"]
    fails = _pgvector_control_failures(root, rec)
    p = root / PGVECTOR_CONTROL_REL
    m = re.search(r"^default_version\s*=\s*'([^']+)'",
                  p.read_text(errors="replace"), re.M) if p.is_file() else None
    if not m:
        fails.append("containers: pgvector: vector.control default_version unreadable")
    elif rec.get("extension_version") != m.group(1):
        fails.append("containers: pgvector: extension_version does not match the pinned "
                     "vector.control default_version")
    if m and m.group(1) != PGVECTOR_FIXED["extension_version"]:
        fails.append("containers: pgvector: vector.control default_version is not the "
                     "pinned 0.8.7 constant of the tuple")
    if rec.get("extension_version") != PGVECTOR_FIXED["extension_version"]:
        fails.append("containers: pgvector: extension_version is not the pinned 0.8.7 "
                     "constant of the tuple")
    binding = rec.get("extension_binding")
    if not isinstance(binding, str) or "vector.control" not in binding or "default_version" not in binding:
        fails.append("containers: pgvector: extension_binding does not name the "
                     "vector.control default_version provenance")
    fails.extend(_pgvector_collection_failures(rec))
    return fails


def _builder_records_failures(root: Path, by_digest: dict) -> list:
    """Every digest-pinned Dockerfile base image has a bound record."""
    fails = []
    for rel, ref in pinned_builders(root):
        digest = ref.rsplit("@", 1)[-1]
        rec = by_digest.get(digest)
        if rec is None:
            fails.append(f"containers: builder base {ref} ({rel}) has no evidence record")
        else:
            fails.extend(_notice_failures(root, f"builder {ref}", rec))
    return fails


def _alpine_manifest_failures(root: Path, recs: list) -> list:
    """The committed core-image corpus MANIFEST binds the pinned base digest."""
    fails = []
    for r in recs:
        if r.get("repo_ref") != "alpine" or "core" not in str(r.get("role", "")):
            continue
        man = root / "scripts/release/image-os-notices/MANIFEST.json"
        if man.is_file() and load_json(man).get("base_index_digest") != r.get("index_digest"):
            fails.append("containers: alpine corpus MANIFEST base digest does not "
                         "match the pinned base")
    return fails


def _records_by_digest(recs: list) -> tuple:
    """(digest -> its single first record, split-record failures).

    R4-DUP-01: one digest bound to several rows is a SPLIT record and is
    refused instead of letting a later row shadow an earlier one."""
    out, fails = {}, []
    for rec in recs:
        d = rec.get("index_digest")
        if d is None:
            continue
        if d in out:
            fails.append(f"containers: split evidence records for {d}: one digest "
                         "bound to several rows; refusing instead of selecting one")
            continue
        out[d] = rec
    return out, fails


def _operator_subject_records(recs: list) -> tuple:
    """(subject -> its single record, duplicate-record failures).

    R4-DUP-01: every operator-pulled subject must have EXACTLY ONE record;
    split rows (one carrying the valid notice, another the subject fields,
    in either order) are refused -- the notice, version, license and
    subject-specific checks all bind to that SAME record."""
    out, fails = {}, []
    for rec in recs:
        subject = rec.get("repo_ref")
        if subject not in _OPERATOR_SUBJECTS:
            continue
        if subject in out:
            fails.append(f"containers: {subject}: multiple evidence records for one "
                         "operator-pulled subject (split records are refused; all "
                         "checks bind to exactly one record)")
            continue
        out[subject] = rec
    return out, fails


def _dashboard_builder_pin(root: Path):
    """The node builder pin re-derived from web/dashboard/Dockerfile."""
    f = root / "web/dashboard/Dockerfile"
    if not f.is_file():
        return None
    m = re.search(r"^FROM\s+(node\S*@sha256:[0-9a-f]{64})\s+AS\s+builder",
                  f.read_text(), re.M)
    return m.group(1) if m else None


def _fic_input_failures(root: Path, label: str, fic: dict) -> list:
    """R3: the scan names its INPUTS, re-derived from the tree.

    A scan that does not name this tree's dashboard builder image (the
    node FROM pin), the aggregate builder LICENSE hash and the covered
    auxiliary files has not reported what it scanned."""
    inputs = fic.get("inputs")
    if not isinstance(inputs, dict) or not inputs:
        return [f"containers: {label}: final_image_check scan inputs not "
                "recorded (builder image + license hash + covered files)"]
    fails = []
    pin = _dashboard_builder_pin(root)
    if pin is None:
        fails.append(f"containers: {label}: cannot re-derive the dashboard "
                     "builder pin from web/dashboard/Dockerfile to bind the "
                     "scan inputs")
    elif inputs.get("builder_image") != pin:
        fails.append(f"containers: {label}: scan inputs do not name this tree's "
                     f"dashboard builder image ({pin})")
    if not re.fullmatch(r"[0-9a-f]{64}", str(inputs.get("builder_license_sha256")
                                              or "")):
        fails.append(f"containers: {label}: scan inputs lack the aggregate "
                     "builder LICENSE hash")
    cov = inputs.get("covered_files")
    if not isinstance(cov, list) or not cov:
        fails.append(f"containers: {label}: scan inputs do not record the "
                     "covered auxiliary files")
    return fails


def _dashboard_scan_subject(ev: dict) -> tuple:
    """(image_id, platform, layer set) of the candidate dashboard subject."""
    qi = ev.get("distribution", {}).get("quickstart_images") or []
    dash_row = next((q for q in qi
                     if isinstance(q, dict) and q.get("name") == "dashboard"), None)
    build = (ev.get("distribution") or {}).get("quickstart_build") or {}
    layers = (build.get("layers") or {}).get("dashboard") \
        if isinstance(build.get("layers"), dict) else None
    return ((dash_row or {}).get("image_id"), (dash_row or {}).get("platform"),
            layers)


def _fic_candidate_binding_failures(root: Path, ev: dict) -> list:
    """R2/R3: every final-image inspection binds to the candidate's dashboard.

    A hash-bound scan manifest that agrees only with its own wrapper record
    proves nothing about THIS candidate: the inspected image must be the
    dashboard quickstart subject built for this candidate (the nginx
    final-image scan target) at the SAME platform, the scanned layers must
    be exactly the dashboard build record's layer set, and the scan inputs
    must name this tree's builder image, license hash and covered files."""
    dash, dash_platform, layers = _dashboard_scan_subject(ev)
    fails = []
    for rec in ev.get("containers", []):
        for ctx in (rec.get("notice_forbidden_contexts") or []):
            fic = (ctx or {}).get("final_image_check") or {}
            if not fic:
                continue
            label = f"{rec.get('repo_ref')}"
            fails.extend(_fic_identity_failures(label, fic, dash, dash_platform))
            fails.extend(_fic_input_failures(root, label, fic))
            fails.extend(_fic_layer_binding_failures(root, label, fic, layers))
    return fails


def _fic_identity_failures(label: str, fic: dict, dash, dash_platform) -> list:
    """The inspected image IS the candidate dashboard subject, same platform."""
    fails = []
    if dash is None or fic.get("image_id") != dash:
        fails.append(f"containers: {label}: final_image_check "
                     "is not bound to the candidate dashboard quickstart "
                     "image (the nginx final-image scan target)")
    # R3: the platform comparison the verdict discarded -- an arm64
    # wrapper+manifest pair is not this amd64 candidate's image
    if dash_platform is None or fic.get("platform") != dash_platform:
        fails.append(f"containers: {label}: final_image_check platform is "
                     f"not the candidate dashboard platform "
                     f"({dash_platform})")
    return fails


def _fic_layer_binding_failures(root: Path, label: str, fic: dict,
                                layers) -> list:
    """The scanned layer set IS the dashboard build record's layer set."""
    man, _ = _fic_manifest(root, label, fic)
    if man is None:
        return []
    # R3: one unrelated digest-shaped layer scanned SOMETHING, not this
    # image -- the scan must cover exactly the built image's layers
    if not isinstance(layers, list) or not layers:
        return [f"containers: {label}: dashboard build record "
                "carries no layer set to bind the scan to"]
    if set(man.get("layers_scanned") or []) != set(layers):
        return [f"containers: {label}: final_image_check "
                "layers_scanned is not the dashboard build "
                "record's layer set"]
    return []


def container_failures(root: Path, ev: dict) -> list:
    recs = ev.get("containers", [])
    by_digest, split = _records_by_digest(recs)
    subjects, dupes = _operator_subject_records(recs)
    fails = split + dupes
    services, errors = _compose_model(root)
    fails.extend("containers: " + f for f in errors)
    fails.extend(_pinned_service_failures(root, by_digest, subjects, services))
    fails.extend(_redis_failures(subjects.get("redis")))
    fails.extend(_redis_pin_failures(root, services))
    fails.extend(_pgvector_failures(root, subjects.get("pgvector/pgvector")))
    fails.extend(_builder_records_failures(root, by_digest))
    fails.extend(_alpine_manifest_failures(root, recs))
    fails.extend(_fic_candidate_binding_failures(root, ev))
    return fails


def negative_control_failures(root: Path, ev: dict) -> list:
    """The retained restricted Redis case keeps failing -- canonically.

    R4-NC-PROOF-01: the negative control is the REAL upstream Redis 7.4.12
    dual-license text (RSALv2 or SSPLv1) at its canonical upstream path with
    the independently pinned upstream sha256 (the same bytes are committed
    at scripts/release/testdata/release-evidence/upstream/redis-7.4.12/
    LICENSE.txt). An arbitrary marker-bearing text at a self-chosen path
    with a matching self-hash is NOT the control; restricted.txt remains
    only the separate marker-section fixture for notice-context tests."""
    nc = ev.get("negative_controls", {}).get("redis_restricted_retained")
    if not isinstance(nc, dict):
        return ["negative control: redis restricted-case record absent"]
    canonical = REDIS_NEGATIVE["license_path"]
    if nc.get("license_path") != canonical:
        return [f"negative control: redis restricted license_path is not the canonical "
                f"7.4.12 upstream path ({canonical})"]
    p = root / canonical
    if not p.is_file():
        return ["negative control: redis restricted upstream license text absent at "
                "the canonical path"]
    if sha256_file(p) != REDIS_NEGATIVE["license_sha256"]:
        return ["negative control: redis restricted license bytes are not the pinned "
                "upstream 7.4.12 text (substituted bytes?)"]
    hits = forbidden_hits(p.read_text(errors="replace"))
    if not {"RSAL", "SSPL"} <= set(hits):
        return ["negative control: redis restricted text no longer hits RSAL+SSPL markers"]
    if nc.get("version") != REDIS_NEGATIVE["version"] or nc.get("index_digest") != REDIS_NEGATIVE["digest"]:
        return ["negative control: redis restricted record drifted"]
    if nc.get("license_sha256") != REDIS_NEGATIVE["license_sha256"]:
        return ["negative control: redis restricted license_sha256 is not the pinned "
                "upstream 7.4.12 constant"]
    return []


def _astra_failures(root: Path, actual: dict) -> list:
    src = root / "design/astra-tokens.css"
    imp = root / "web/dashboard/src/index.css"
    if not src.is_file() or not imp.is_file():
        return ["assets: astra token source or import site missing"]
    itext = imp.read_text(errors="replace")
    if "@import" not in itext or "design/astra-tokens.css" not in itext:
        return ["assets: index.css no longer imports design/astra-tokens.css"]
    decls = re.findall(r"--astra-[A-Za-z0-9-]+\s*:[^;]+;", src.read_text(errors="replace"))
    if not decls:
        return ["assets: no --astra-* declarations in design/astra-tokens.css"]
    emitted = "".join((root / rel).read_text(errors="replace")
                      for rel in actual if rel.endswith(".css"))
    missing = [d for d in decls
               if not dashboard_evidence.equivalence_match(d, emitted)]
    if missing:
        return [f"assets: {len(missing)}/{len(decls)} astra token declarations not "
                f"present in emitted css (only the recorded 140ms -> .14s "
                f"equivalence is accepted)"]
    return []


def _dist_file_set_failures(actual: dict, listed: dict) -> list:
    """The evidence file set and the emitted dist tree match both ways."""
    fails = []
    for path, digest in actual.items():
        if path not in listed:
            fails.append(f"assets: emitted file missing from evidence: {path}")
        elif listed[path] != digest:
            fails.append(f"assets: sha drift for {path}")
    for path in listed:
        if path not in actual:
            fails.append(f"assets: evidence lists non-emitted file: {path}")
    return fails


def _retained_rel(twin_rel: str, suffix: str = "") -> str:
    """Canonical retained build-artifact path: the build output mirrored
    into dist-sourcemaps/ (raw twins keep no suffix, maps gain ".map").

    The nginx stage ships dist/ only (Dockerfile copies dist/ into the
    image), so raw twins and maps are retained as build artifacts in the
    sibling dist-sourcemaps/ tree -- never inside dist/.
    """
    return twin_rel.replace("/dist/", "/dist-sourcemaps/", 1) + suffix


def _map_receipt_failures(root: Path, twin_rel: str, c: dict) -> list:
    """R4-MAP-01 map-receipt invariant: sha256(retained map bytes) == map_sha256.

    The receipt is not self-certifying: a different valid sha256, stale,
    swapped or missing retained map bytes all fail this same binding. The
    retained map's sources must also equal the recorded sources -- a map
    that does not name the recorded inputs proves nothing about them.
    """
    rel = _retained_rel(twin_rel, ".map")
    mfile = root / rel
    if not mfile.is_file():
        return [f"assets: chunk map receipt not bound to the retained "
                f"sourcemap artifact (missing): {rel}"]
    if sha256_file(mfile) != c.get("map_sha256"):
        return [f"assets: chunk map receipt not bound to the retained "
                f"sourcemap artifact (sha drift): {twin_rel}"]
    try:
        sources = (load_json(mfile) or {}).get("sources")
    except ValueError:
        return [f"assets: retained sourcemap artifact is not valid JSON: {rel}"]
    if sources != c.get("sources"):
        return [f"assets: chunk sources are not the retained map's sources: "
                f"{twin_rel}"]
    return []


def _raw_twin_failures(root: Path, twin_rel: str, dist_sha: str, c: dict) -> list:
    """R2 raw-twin invariant: the stripped retained twin IS the dist chunk.

    The recorded twin_sha256 and map_twin_raw_sha256 are not self-certifying:
    the verifier re-reads the retained marker-carrying twin bytes, re-hashes
    them, and re-applies the generator's own strict strip rule
    (dashboard_evidence.strip_map_comment) -- the stripped result must equal
    the emitted dist bytes hash-for-hash. Appending marker-free code to the
    emitted chunk (updating dist_files/twin_sha256) therefore fails here:
    the retained raw twin no longer strips to the shipped code.
    """
    rel = _retained_rel(twin_rel)
    raw = root / rel
    if not raw.is_file():
        return [f"assets: chunk raw map twin not retained (missing): {rel}"]
    data = raw.read_bytes()
    if hashlib.sha256(data).hexdigest() != c.get("map_twin_raw_sha256"):
        return [f"assets: chunk raw twin sha drift (map_twin_raw_sha256 "
                f"not the retained bytes): {twin_rel}"]
    # R3: the twin's own sourceMappingURL comment must name the recorded
    # map -- a twin whose comment names other.js.map while the record
    # says app.js.map is a cross-wired identity
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    m = dashboard_evidence._MAP_COMMENT_LINE.fullmatch(lines[-1]) \
        if lines else None
    comment_name = m.group(1).decode(errors="replace") if m else None
    if comment_name != c.get("map_name"):
        return [f"assets: retained raw twin's sourceMappingURL names "
                f"{comment_name!r}, not the recorded map_name "
                f"{c.get('map_name')!r}: {twin_rel}"]
    try:
        stripped = dashboard_evidence.strip_map_comment(data)
    except ValueError as exc:
        return [f"assets: retained raw twin violates the map-comment rule "
                f"({exc}): {rel}"]
    if hashlib.sha256(stripped).hexdigest() != dist_sha:
        return [f"assets: emitted chunk is not the stripped retained twin "
                f"(code bytes drifted from the map twin): {twin_rel}"]
    return []


def _chunk_binding_failures(root: Path, actual: dict, chunks: dict) -> list:
    """Every emitted JS chunk is twin-bound; twins are emitted files only.

    R4-MAP-01: a chunk record whose twin sha merely matches the dist sha is
    NOT binding. The record must be the generator's successful map-binding
    shape (no strip error, no missing-map record), the emitted bytes must
    BE the stripped twin -- a successfully stripped chunk never still
    carries a sourceMappingURL marker -- and the map inputs stay recorded
    (map name, hash-bound map, non-empty sources) with the map_sha256
    receipt bound to the RETAINED map artifact bytes (the map-receipt
    counterexample: a different valid sha, stale/missing/wrong map bytes
    all violate the same invariant)."""
    fails = []
    for path, sha in actual.items():
        if not path.endswith(".js"):
            continue
        c = chunks.get(path)
        if c is None:
            fails.append(f"assets: emitted chunk unbound (no map twin): {path}")
            continue
        if c.get("missing_map") or c.get("strip_error"):
            fails.append(f"assets: chunk map binding not proven (strip error or "
                         f"missing map): {path}")
            continue
        if c.get("twin_sha256") != sha:
            fails.append(f"assets: chunk twin sha drift (map-comment equivalence): "
                         f"{path}")
        if c.get("equivalence") != dashboard_evidence.MAP_EQUIVALENCE:
            fails.append(f"assets: chunk equivalence is not the recorded "
                         f"map-comment rule: {path}")
        data = (root / path).read_bytes()
        if b"//# sourceMappingURL=" in data:
            fails.append(f"assets: chunk twin retains the sourceMappingURL marker "
                         f"(not a generator-shaped stripped twin): {path}")
        fails.extend(_map_receipt_failures(root, path, c))
        fails.extend(_raw_twin_failures(root, path, sha, c))
        if c.get("map_name") != Path(path).name + ".map":
            fails.append(f"assets: chunk map_name is not the twin's map: {path}")
        if not c.get("sources"):
            fails.append(f"assets: chunk records no sourcemap sources: {path}")
    for twin in chunks:
        if twin not in actual:
            fails.append(f"assets: chunk map references non-emitted twin: {twin}")
    return fails


def _retained_marker_failures(root: Path, actual: dict) -> list:
    """Retained-content control: shipped files carry no forbidden marker text."""
    fails = []
    for path in actual:
        hits = forbidden_hits((root / path).read_text(errors="replace"))
        if hits:
            fails.append(f"assets: emitted dashboard file contains forbidden marker "
                         f"({','.join(hits)}): {path} (retained in shipped content)")
    return fails


def _lucide_binding_failures(root: Path, a: dict, chunks: dict) -> list:
    """lucide/Feather origin and the lucide-react LICENSE stay hash-bound."""
    fails = []
    if not any(c.get("has_lucide") for c in chunks.values()):
        fails.append("assets: lucide/Feather origin not proven in chunk map")
    luc = a.get("lucide_react") or {}
    lic = root / "web/dashboard/node_modules/lucide-react/LICENSE"
    if not lic.is_file() or sha256_file(lic) != (luc.get("legal_file_hashes") or {}).get("LICENSE"):
        fails.append("assets: lucide-react LICENSE binding failed")
    return fails


def _package_record_failures(pkgs: list) -> list:
    """Each contributing-package record has identity, version, legal texts."""
    fails, recorded = [], set()
    for pkg in pkgs:
        name = str(pkg.get("name") or "").strip()
        if not name:
            fails.append("assets: contributing package record without a name")
            continue
        if name in recorded:
            fails.append(f"assets: contributing package recorded twice: {name}")
        recorded.add(name)
        if str(pkg.get("version") or "").strip().lower() in ("", "*", "latest",
                                                             "unknown", "n/a"):
            fails.append(f"assets: contributing package has no concrete version: {name}")
        if not pkg.get("legal_files"):
            fails.append(f"assets: contributing package records no legal text: {name}")
    return fails


def _package_binding_failures(root: Path, pkgs: list) -> list:
    """Every recorded package legal text exists and matches its sha.

    R3: the recorded file must be INSIDE the package's own node_modules
    directory -- a package row naming another package's license bytes
    (lucide-react pointing at the clsx license) is a wrong-subject
    binding, even though the sha matches those bytes."""
    fails = []
    for pkg in pkgs:
        name = str(pkg.get("name") or "")
        for f in pkg.get("legal_files", []):
            rel = str(f.get("file", "-"))
            fp = root / rel
            if not fp.is_file() or sha256_file(fp) != f.get("sha256"):
                fails.append(f"assets: package notice binding failed: "
                             f"{name}:{rel}")
            elif f"node_modules/{name}/" not in rel:
                fails.append(f"assets: package legal file is not inside the "
                             f"package's node_modules directory: {name}:{rel}")
    return fails


_NODE_MODULES_PKG = re.compile(r"node_modules/((?:@[^/]+/)?[^/]+)/")


def _packages_from_sources(sources: list) -> set:
    """Package names derived from the map's own source paths."""
    out = set()
    for src in sources or []:
        m = _NODE_MODULES_PKG.search(str(src))
        if m:
            out.add(m.group(1))
    return out


def _package_set_failures(chunks: dict, pkgs: list) -> list:
    """Chunk-origin packages and package records name exactly the same set.

    R3: the required set is DERIVED from the verified map sources (the
    node_modules packages the emitted code actually came from), not from
    the recorded c['packages'] label -- removing a package from both the
    records and its delivery while its sources still ship is caught."""
    recorded = {str(p.get("name") or "").strip() for p in pkgs
                if str(p.get("name") or "").strip()}
    derived = set()
    fails = []
    for c in chunks.values():
        src_pkgs = _packages_from_sources(c.get("sources"))
        derived.update(src_pkgs)
        # the recorded label list must agree with its own map sources
        labels = {str(x) for x in (c.get("packages") or [])}
        for name in sorted(labels - src_pkgs):
            fails.append(f"assets: chunk labels name package absent from its "
                         f"map sources: {name}")
        for name in sorted(src_pkgs - labels):
            fails.append(f"assets: map sources name package the chunk labels "
                         f"do not list: {name}")
    for name in sorted(derived - recorded):
        fails.append(f"assets: map sources name unrecorded package: {name}")
    for name in sorted(recorded - derived):
        fails.append(f"assets: contributing package absent from map sources: {name}")
    return fails


def _token_reach_failures(root: Path, a: dict) -> list:
    """A recorded emitted css file still carries the design tokens."""
    reach = a.get("css_token_reach") or []
    ok = bool(reach) and (root / reach[0]["file"]).is_file() and any(
        t in (root / reach[0]["file"]).read_text(errors="replace")
        for t in reach[0].get("tokens_sample", []))
    if not ok:
        return ["assets: design token reach in emitted css unproven"]
    return []


def asset_failures(root: Path, ev: dict) -> list:
    a = ev.get("assets", {})
    dist = root / "web/dashboard/dist"
    if not dist.is_dir():
        return ["assets: web/dashboard/dist absent (run the dashboard build)"]
    actual = {str(p.relative_to(root)): sha256_file(p)
              for p in sorted(dist.rglob("*")) if p.is_file()}
    listed = {f.get("path"): f.get("sha256") for f in a.get("dist_files", [])}
    chunks = {c.get("twin_rel"): c for c in (a.get("chunk_origins") or {}).values()
              if isinstance(c, dict)}
    pkgs = a.get("contributing_packages") or []
    fails = _dist_file_set_failures(actual, listed)
    # R3: maps are RETAINED artifacts under dist-sourcemaps -- a .map
    # inside the public dist tree (even one listed in dist_files) is a
    # shipped sourcemap nginx would serve
    fails.extend(f"assets: sourcemap emitted inside the public dist tree: "
                 f"{path}" for path in sorted(actual) if path.endswith(".map"))
    fails.extend(_chunk_binding_failures(root, actual, chunks))
    fails.extend(_retained_marker_failures(root, actual))
    fails.extend(_lucide_binding_failures(root, a, chunks))
    if not pkgs:
        fails.append("assets: contributing_packages missing or empty")
    fails.extend(_package_record_failures(pkgs))
    fails.extend(_package_binding_failures(root, pkgs))
    fails.extend(_package_set_failures(chunks, pkgs))
    fails.extend(_token_reach_failures(root, a))
    fails.extend(_astra_failures(root, actual))
    return fails


def notice_failures(root: Path, ev: dict) -> list:
    text = (root / "NOTICE").read_text()
    fails = []
    if "enterprise/LICENSE" in text:
        fails.append("notice: still references enterprise/LICENSE")
    if "owner decision D1" in text:
        fails.append("notice: still carries the absent-dated D1 wording")
    if "LICENSING.md" not in text:
        fails.append("notice: does not reference LICENSING.md")
    if "Apache License, Version 2.0" not in text:
        fails.append("notice: Apache-2.0 statement missing")
    if text.count("Project-authored code is licensed under the Apache License") != 1:
        fails.append("notice: Apache statement must appear exactly once")
    if ev.get("notice_reconciliation", {}).get("notice_sha256") != sha256_file(root / "NOTICE"):
        fails.append("notice: sha drift versus evidence")
    return fails


def _commit_records(args: list) -> list:
    """Adding commits with their REAL Signed-off-by trailers.

    R2: the trailer list comes from git's own trailer-block parser
    (%(trailers:key=Signed-off-by,valueonly)), not a body-wide regex -- a
    prose line like "Example Signed-off-by: Ada <ada@example.invalid>"
    inside the commit body is not a trailer and must not count."""
    fmt = "%H%x1f%an%x1f%ae%x1f%(trailers:key=Signed-off-by,valueonly,separator=%x01)%x1e"
    raw = git_out("log", "--diff-filter=A", f"--format={fmt}", *args)
    out = []
    for rec in raw.split("\x1e"):
        rec = rec.strip("\n")
        if not rec:
            continue
        fields = rec.split("\x1f", 3)
        if len(fields) != 4:
            continue
        out.append({"commit": fields[0], "author": fields[1], "email": fields[2],
                    "signed_off_by": [t.strip() for t in fields[3].split("\x01")
                                      if t.strip()]})
    return out


def _added_paths(commit: str) -> list:
    # R4: raw bytes, decoded once surrogateescape -- added paths with CR
    # or non-UTF-8 bytes must survive byte-for-byte into the provenance
    # comparison instead of being newline-translated or re-encoded
    raw = git_bytes("diff-tree", "--no-commit-id", "--name-only", "-r",
                    "--diff-filter=A", "-z", commit).decode(
                        "utf-8", "surrogateescape")
    return [p for p in raw.split("\0") if p]


_SIGNOFF_PAIR = re.compile(r"^(.+?)\s*<([^<>]+)>\s*$")


def _dco_matches(rec: dict) -> bool:
    """Exact DCO trailer match: 'Signed-off-by: AUTHOR <EMAIL>'.

    R4-PROVENANCE-01: a signoff line merely CONTAINING the author email as
    a substring (the old `email in s` check) is not the DCO trailer -- the
    name and email pair must match the commit author exactly."""
    want = (str(rec.get("author") or "").strip(), str(rec.get("email") or "").strip())
    if not (want[0] and want[1]):
        return False
    for s in rec.get("signed_off_by") or []:
        m = _SIGNOFF_PAIR.match(str(s).strip())
        if m and (m.group(1).strip(), m.group(2).strip()) == want:
            return True
    return False


def provenance_added() -> list:
    rows = []
    for rec in _commit_records([f"{TASK_BASE}..HEAD"]):
        for path in _added_paths(rec["commit"]):
            rows.append({"path": path, **rec})
    for req in REQUIRED_ADDED:
        if any(r["path"] == req for r in rows):
            continue
        oldest = _commit_records(["--reverse", "--", req])
        if oldest:
            rows.append({"path": req, **oldest[0]})
    for r in rows:
        r["dco_present"] = _dco_matches(r)
        r["employer_rights"] = "not assessed (DCO signoff is not employer-rights proof)"
    return rows


def _listed_provenance_rows(ev: dict) -> tuple:
    """(rows, failures) for the evidence's provenance.added list.

    Rows are unique per (path, commit); a non-boolean dco_present is
    refused (string coercion), and each row keeps its FULL trailer list
    for the tuple comparison."""
    listed, fails, seen = [], [], set()
    for r in ev.get("provenance", {}).get("added", []):
        key = (r.get("path"), r.get("commit"))
        if key in seen:
            fails.append(f"provenance: duplicate row for {key[0]} at "
                         f"{str(key[1])[:12]} (split/duplicated provenance refused)")
            continue
        seen.add(key)
        dco = r.get("dco_present")
        if not isinstance(dco, bool):
            # R2: "false"/"true" strings coerce truthy under bool(); a DCO
            # claim must be an actual boolean or the row is refused.
            fails.append(f"provenance: {key[0]}: dco_present must be a boolean "
                         f"(string coercion refused)")
            continue
        sob = r.get("signed_off_by")
        # R4: signed_off_by must be an ARRAY OF STRINGS before any
        # comparison -- iterating a JSON object coerces its KEYS into the
        # trailer list, so a dict row can fabricate a matching trailer
        # tuple and never surface as a type lie
        if not isinstance(sob, list) or not all(isinstance(x, str) for x in sob):
            fails.append(f"provenance: {key[0]}: signed_off_by must be an array "
                         f"of strings (object/number elements refused)")
            continue
        listed.append((r.get("path"), r.get("commit"), r.get("author"),
                       r.get("email"), dco, tuple(sob)))
    return listed, fails


def provenance_failures(ev: dict) -> list:
    """Two-way binding of every (path, commit) provenance row.

    R4-PROVENANCE-01: rows are unique per (path, commit) and compared as
    full tuples (path, commit, author, email, dco) -- the old {path: rec}
    last-wins maps let a duplicate or drifted row shadow the real one."""
    # R3: the FULL trailer list rides in the tuple -- a row that keeps
    # dco_present=true while its recorded signed_off_by list lies (empty
    # or swapped) drifts from the re-derived trailers and fails
    actual = sorted((r["path"], r["commit"], r["author"], r["email"],
                     r["dco_present"],
                     tuple(str(x) for x in (r.get("signed_off_by") or [])))
                    for r in provenance_added())
    listed, row_fails = _listed_provenance_rows(ev)
    fails = row_fails
    listed.sort()
    for row in actual:
        if row not in listed:
            fails.append(f"provenance: added path missing from evidence (or author/"
                         f"commit/dco drifted): {row[0]} at {row[1][:12]}")
    for row in listed:
        if row not in actual:
            fails.append(f"provenance: evidence lists non-added/stale row: {row[0]} "
                         f"at {str(row[1])[:12]}")
    for path, commit, author, email, dco, _trailers in actual:
        if not dco:
            fails.append(f"provenance: {path}: no exact DCO signoff matching author "
                         f"{author} <{email}> (recorded fact; rights assessment "
                         "is separate)")
    if REQUIRED_ADDED[0] not in {r[0] for r in actual}:
        fails.append(f"provenance: required path {REQUIRED_ADDED[0]} unbound")
    return fails


def _payload_file_failures(payload: Path, listed: dict, name: str) -> list:
    """Listed legal files are confined and sha-bound; no unlisted files."""
    fails = []
    for rel, sha in sorted(listed.items()):
        problem = _confined(payload, payload / rel)
        if problem:
            fails.append(f"distribution: {name}: file {rel}: {problem}")
        elif sha256_file(payload / rel) != sha:
            fails.append(f"distribution: {name}: file {rel}: sha mismatch")
    ondisk = {str(p.relative_to(payload)) for p in payload.rglob("*")
              if p.is_file() and p.name != "inventory.json"}
    for rel in sorted(ondisk - set(listed)):
        fails.append(f"distribution: {name}: unlisted payload file: {rel}")
    return fails


_MODULE_FIELDS = ("path", "version", "source_path", "source_version", "source_sum")
_MODULE_LEGAL_NAME = re.compile(
    r"(?:licen[cs]es?|copying|notices?|patents?|copyright|authors)(?:\.(?:txt|md|rst))?",
    re.IGNORECASE,
)


def _module_tuple(row: dict) -> tuple:
    values = tuple(row[key] for key in _MODULE_FIELDS)
    if not all(isinstance(value, str) and value for value in values):
        raise ValueError("missing module identity or checksum")
    return values


def _build_module_tuple(dep: dict) -> tuple:
    source = dep.get("Replace") or dep
    return _module_tuple(dict(path=dep["Path"], version=dep["Version"],
                              source_path=source["Path"], source_version=source["Version"],
                              source_sum=source["Sum"]))


def _binary_module_set(binary: Path):
    """Read the actual toolchain's linked dependencies, including versioned replacements."""
    try:
        proc = subprocess.run(["go", "version", "-m", "-json", str(binary)],
                              capture_output=True, text=True, timeout=60, check=True)
        info = json.loads(proc.stdout)
        if not info["GoVersion"] or not info["Path"] or not isinstance(info["Deps"], list):
            raise ValueError("incomplete Go build metadata")
        rows = [_build_module_tuple(dep) for dep in info["Deps"]]
        if len(rows) != len(set(rows)):
            raise ValueError("repeated linked module")
        return set(rows), None
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, AttributeError) as exc:
        return None, str(exc)


def _module_prefix(identity: tuple) -> str:
    # Apply the Go module cache ASCII uppercase escape to the effective source.
    key = f"{identity[2]}@{identity[3]}"
    return "modules/" + re.sub(r"[A-Z]", lambda m: "!" + m.group().lower(), key) + "/"


def _payload_coverage_failures(listed: dict, name: str, recorded: set) -> list:
    fails = [f"distribution: {name}: inventory missing {path}"
             for path in ("project/LICENSE", "project/NOTICE", "go-toolchain/LICENSE")
             if path not in listed]
    remaining = {path for path in listed if path.startswith("modules/")}
    for prefix in sorted({_module_prefix(row) for row in recorded}):
        paths = {path for path in remaining if path.startswith(prefix)}
        if not paths:
            fails.append(f"distribution: {name}: linked module {prefix.rstrip('/')} has no listed legal file")
        remaining -= paths
        for path in sorted(paths):
            if not _MODULE_LEGAL_NAME.fullmatch(PurePosixPath(path).name):
                fails.append(f"distribution: {name}: module legal file has a non-legal name: {path}")
    return fails + [f"distribution: {name}: extra module source file: {p}" for p in sorted(remaining)]


def _recorded_module_set(modules: list, name: str) -> tuple:
    if not isinstance(modules, list) or not modules:
        return set(), [f"distribution: {name}: no linked-module notices recorded"]
    try:
        records = [_module_tuple(row) for row in modules]
    except (KeyError, TypeError, ValueError):
        return set(), [f"distribution: {name}: incomplete linked-module identity"]
    fails = [] if len(records) == len(set(records)) else [f"distribution: {name}: duplicate module"]
    return set(records), fails


def _module_binding_failures(binary: Path, recorded: set, name: str) -> list:
    derived, err = _binary_module_set(binary)
    if err is not None:
        return [f"PENDING gap: distribution: {name}: linked module set not "
                f"re-derived from build info ({err})"]
    missing = [f"distribution: {name}: build info names linked module absent from the inventory: "
               f"{row[0]}@{row[1]} ({row[2]}@{row[3]} {row[4]})" for row in sorted(derived - recorded)]
    extra = [f"distribution: {name}: inventory lists unlinked module identity: {row!r}"
             for row in sorted(recorded - derived)]
    return missing + extra


def _payload_failures(payload: Path, binary: Path, binary_sha: str,
                      name: str) -> list:
    """Exhaustive per-binary notice payload binding via inventory.json."""
    inv_p = payload / "inventory.json"
    if not inv_p.is_file():
        return [f"distribution: {name}: inventory.json absent"]
    inv = load_json(inv_p)
    fails = []
    if inv.get("binary_sha256") != binary_sha:
        fails.append(f"distribution: {name}: inventory binary_sha256 != release binary sha")
    listed = {f.get("path"): f.get("sha256") for f in inv.get("files", [])}
    if not listed:
        fails.append(f"distribution: {name}: inventory lists no legal files")
    fails.extend(_payload_file_failures(payload, listed, name))
    recorded, row_errors = _recorded_module_set(inv.get("modules"), name)
    fails.extend(row_errors)
    fails.extend(_module_binding_failures(binary, recorded, name))
    fails.extend(_payload_coverage_failures(listed, name, recorded))
    return fails


def _binary_binding_failures(root: Path, dist: Path, actual: dict,
                              evb: dict) -> list:
    """Each release binary is sums-bound, evidence-bound and payload-bound."""
    fails = []
    for name in BINARIES:
        if name not in actual:
            fails.append(f"distribution: {name} missing from SHA256SUMS")
            continue
        p = dist / name
        if not p.is_file() or sha256_file(p) != actual[name]:
            fails.append(f"distribution: {name} sha drift versus SHA256SUMS")
        rec = evb.get(name)
        if rec is None:
            fails.append(f"distribution: no evidence record for {name}")
        elif rec.get("sha256") != actual[name]:
            fails.append(f"distribution: evidence sha drift for {name}")
        fails.extend(_payload_failures(
            root / "artifacts/release-evidence/image-notices" / name,
            p, actual[name], name))
    return fails


def _notice_binding_failures(root: Path, dist: Path, d: dict) -> list:
    """dist NOTICE copy and NOTICE draft stay byte/hash-bound."""
    fails = []
    dn = dist / "NOTICE"
    if not dn.is_file() or dn.read_bytes() != (root / "NOTICE").read_bytes():
        fails.append("distribution: dist/release/NOTICE is not the current root NOTICE "
                     "(stale build; rebuild before binding)")
    draft = dist / "THIRD-PARTY-NOTICES.md"
    if not draft.is_file() or sha256_file(draft) != d.get("notice_draft_sha256"):
        fails.append("distribution: NOTICE draft binding failed")
    if not d.get("notice_draft_identifier_only"):
        fails.append("distribution: identifier-only status of NOTICE draft not recorded")
    return fails


def distribution_failures(root: Path, ev: dict) -> list:
    d = ev.get("distribution", {})
    dist = root / "dist/release"
    sums = dist / "SHA256SUMS"
    if not sums.is_file():
        return ["distribution: dist/release/SHA256SUMS absent (run release-artifacts.sh)"]
    actual = {}
    for line in sums.read_text().splitlines():
        digest, _, name = line.partition("  ")
        actual[name.strip()] = digest
    evb = {b.get("name"): b for b in d.get("binaries", [])}
    fails = _binary_binding_failures(root, dist, actual, evb)
    fails.extend(_notice_binding_failures(root, dist, d))
    return fails


def _head_binding_failures(state: dict, ev: dict) -> list:
    ev_head = str((ev.get("freshness") or {}).get("head") or "")
    fails = []
    if not re.fullmatch(r"[0-9a-f]{40,64}", ev_head):
        fails.append("freshness: evidence records no HEAD of its own (stale or "
                     "malformed evidence; regenerate)")
    elif state["head"] != ev_head:
        fails.append(f"freshness: HEAD {state['head'][:12]} does not match the "
                     f"evidence-recorded HEAD {ev_head[:12]}; regenerate the "
                     "evidence after the change")
    if "head" in ev and str(ev["head"]) != ev_head:
        fails.append("freshness: top-level head disagrees with freshness.head")
    return fails


def _expected_head_failures(state: dict, expected_head: str | None) -> list:
    if expected_head is None:
        return []
    if not re.fullmatch(r"[0-9a-f]{40,64}", expected_head):
        return ["freshness: --expected-head is not a valid commit id"]
    if state["head"] != expected_head:
        return [f"freshness: HEAD {state['head'][:12]} does not match the "
                f"explicit expected HEAD {expected_head[:12]}"]
    return []


def _recipe_binding_failures(root: Path, state: dict, ev: dict) -> list:
    recipe_p = root / "dist/release/recipe.json"
    recipe = load_json(recipe_p) if recipe_p.is_file() else {}
    fails = []
    if recipe.get("git_commit") != state["head"]:
        fails.append("freshness: recipe git_commit does not match HEAD (stale build)")
    rec_sha = str((ev.get("distribution") or {}).get("recipe_sha256") or "")
    if recipe_p.is_file():
        if not rec_sha:
            fails.append("freshness: evidence records no recipe.json sha "
                         "(regenerate the evidence)")
        elif sha256_file(recipe_p) != rec_sha:
            fails.append("freshness: recipe.json sha drift versus evidence "
                         "(recipe content mutated or stale)")
    return fails


def _tree_binding_failures(state: dict, ev: dict) -> list:
    fresh = ev.get("freshness") or {}
    fails = []
    if state.get("parse_error"):
        # R3: the re-derived status stream was refused -- comparing the
        # (empty) maps would ACCEPT a truncated stream as a clean tree
        return [f"freshness: git status parse refused: "
                f"{state['parse_error']}"]
    if fresh.get("dirty") != state["dirty"]:
        fails.append("freshness: dirty tracked set drift versus evidence")
    if fresh.get("untracked") != state["untracked"]:
        # R2: the snapshot records per-file sha256; editing an already
        # recorded untracked file in place is content drift, not just a
        # set change.
        fails.append("freshness: untracked source drift versus evidence "
                     "(set or in-place content hash)")
    if state["dirty"] or state["untracked"]:
        fails.append(f"freshness: dirty review snapshot ({len(state['dirty'])} dirty, "
                     f"{len(state['untracked'])} untracked source files): review-only, "
                     "not acceptance state; acceptance requires a clean committed tree")
    return fails


def freshness_failures(root: Path, ev: dict, expected_head: str | None = None) -> list:
    """Bind HEAD to the evidence-recorded HEAD; --expected-head is additive.

    No hardcoded acceptance commit: follow-up commits regenerate the
    evidence instead of failing forever. The evidence must always carry its
    own HEAD (an explicit --expected-head is an additional assertion, never
    a substitute for the evidence's own binding), the top-level head, if
    retained, must agree, and recipe.json must match HEAD both by commit id
    and by content hash. Final verification requires a clean tree; a dirty
    snapshot is labeled review-only and fails.
    """
    state = git_state()
    fails = _head_binding_failures(state, ev)
    fails.extend(_expected_head_failures(state, expected_head))
    fails.extend(_recipe_binding_failures(root, state, ev))
    fails.extend(_tree_binding_failures(state, ev))
    return fails


def _compose_surface(root: Path) -> dict:
    """Text of every Compose file in the shipped surface, by repo path."""
    paths = sorted((root / "deploy").glob("**/*.yml"))
    paths += sorted((root / "deploy").glob("**/*.yaml"))
    paths += sorted(root.glob("docker-compose*.yml"))
    return {str(p.relative_to(root)): p.read_text(errors="replace")
            for p in paths if p.is_file()}


def _compose_ref_failures(texts: dict) -> list:
    """Standard dockerfile refs only; the quickstart builds via core+dashboard."""
    fails = []
    for rel, text in sorted(texts.items()):
        if "Dockerfile.hardened" in text:
            fails.append(f"scope basis: {rel} references Dockerfile.hardened "
                         "(hardened path is inside the Compose surface)")
    refs = set()
    for text in texts.values():
        refs.update(m.group(1).strip()
                    for m in re.finditer(r"^\s*dockerfile:\s*(\S+)", text, re.M))
    nonstandard = refs - STANDARD_COMPOSE_DOCKERFILES
    if nonstandard:
        fails.append("scope basis: Compose references non-standard dockerfiles: "
                     + ", ".join(sorted(nonstandard)))
    qs = texts.get("deploy/quickstart/docker-compose.yml")
    if qs is None:
        fails.append("scope basis: deploy/quickstart/docker-compose.yml missing "
                     "(quickstart acceptance path unproven)")
    else:
        qs_refs = {m.group(1).strip()
                   for m in re.finditer(r"^\s*dockerfile:\s*(\S+)", qs, re.M)}
        for need in ("Dockerfile", "web/dashboard/Dockerfile"):
            if need not in qs_refs:
                fails.append(f"scope basis: quickstart Compose no longer builds "
                             f"via {need}")
    return fails


def _binary_subject_failures(ev: dict) -> list:
    """The recorded host-binary subject set is exactly the five binaries."""
    names = {b.get("name") for b in (ev.get("distribution", {}).get("binaries") or [])
             if isinstance(b, dict) and b.get("sha256")}
    if names != set(BINARIES):
        return ["scope basis: host-binary subject set is not exactly the five "
                "release binaries (" + ", ".join(BINARIES) + ")"]
    return []


def _scope_basis_failures(root: Path, ev: dict) -> list:
    """Machine-check the basis for the single recorded out-of-scope note.

    A supplied JSON scope claim proves nothing by itself: the note is
    emitted only when the tree shows the quickstart acceptance basis --
    every Compose dockerfile reference is a standard one, no Compose file
    references Dockerfile.hardened, the quickstart builds via the core
    Dockerfile and the dashboard Dockerfile, and the recorded host-binary
    subject set is exactly the five release binaries. Anything else leaves
    the required gap in force.
    """
    texts = _compose_surface(root)
    if not texts:
        return ["scope basis: no Compose surface found under deploy/ (unproven)"]
    return _compose_ref_failures(texts) + _binary_subject_failures(ev)


# R4-IMAGE-01: the three built quickstart subjects that must be bound to
# the candidate by name, immutable image ID and platform.
_QUICKSTART_IMAGE_SUBJECTS = ("core", "mock-provider", "dashboard")


_QUICKSTART_PENDING = ("PENDING gap: quickstart built images (Core, mock, dashboard) "
                       "are not bound to this candidate by platform and immutable "
                       "image ID/digest (docker build + digest record; bounded "
                       "follow-up, no source change required)")


def _quickstart_shape_failures(qi) -> tuple:
    """(validated entries, ok) for the three-subject image list."""
    ok = isinstance(qi, list) and len(qi) == len(_QUICKSTART_IMAGE_SUBJECTS)
    names: set = set()
    entries = []
    if ok:
        for q in qi:
            if (not isinstance(q, dict)
                    or q.get("name") not in _QUICKSTART_IMAGE_SUBJECTS
                    or q.get("name") in names
                    or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(q.get("image_id", "")))
                    or not re.fullmatch(r"\S+/\S+", str(q.get("platform", "")))):
                ok = False
                break
            names.add(q["name"])
            entries.append(q)
    return entries, ok


_QS_PLATFORM = "linux/amd64"


def _quickstart_build_shape_ok(build) -> bool:
    return (isinstance(build, dict)
            and bool(str(build.get("head") or "").strip())
            and isinstance(build.get("subjects"), dict)
            and isinstance(build.get("platforms"), dict)
            and isinstance(build.get("inputs"), dict)
            and re.fullmatch(r"[0-9a-f]{40,64}",
                             str(build.get("tree_sha256") or "")))


def _quickstart_tree_failures(root: Path, head, build) -> list:
    """R3: bind the record to the source TREE of the recorded head.

    Head equality alone accepts a previous build's IDs copied next to the
    current head; the commit's tree object hash is re-derived from git and
    must match, so a record minted at a different tree cannot pose as this
    candidate's build."""
    try:
        # git at the EVIDENCE root (git_out is bound to the module ROOT)
        out = subprocess.run(["git", "-C", str(root), "rev-parse", "--verify",
                              f"{head}^{{tree}}"], check=True, capture_output=True,
                             text=True).stdout.strip()
    except Exception:
        return ["distribution: quickstart_build: cannot re-derive the source "
                "tree of the recorded head (no git facts at the evidence root)"]
    if out != build.get("tree_sha256"):
        return ["distribution: quickstart_build.tree_sha256 is not the source "
                "tree of this candidate's head (a record minted at another "
                "tree is not this candidate's build)"]
    return []


def _quickstart_input_failures(root: Path, inputs, model=None, pins=None) -> list:
    """R3: the build record names its real inputs, re-derived from the tree.

    The compose services that build locally and the pinned Dockerfile FROM
    bases are what the candidate images were built FROM; a record that does
    not name them is not describing this tree's build."""
    services, errors = model if model is not None else _compose_model(root)
    fails = ["distribution: quickstart_build: " + f for f in errors]
    expect_builders = sorted(s for s, svc in services.items() if svc["build"])
    if inputs.get("compose_build_services") != expect_builders:
        fails.append("distribution: quickstart_build.inputs.compose_build_services "
                     f"is not this tree's compose build set ({expect_builders})")
    expect_pins = sorted(map(list, pinned_builders(root) if pins is None else pins))
    if inputs.get("pinned_builders") != expect_pins:
        fails.append("distribution: quickstart_build.inputs.pinned_builders is not "
                     f"this tree's pinned FROM set ({expect_pins})")
    return fails


def _quickstart_build_failures(root: Path, ev: dict, entries: list) -> list:
    """R2/R3: the image list is bound to THIS candidate by a build record.

    Three digest-shaped rows with the right names prove nothing on their
    own: the candidate's build record (quickstart_build) must carry the
    source head the evidence is verified against, the head's tree object
    hash, the build inputs re-derived from the tree (compose build services
    and pinned Dockerfile FROM bases), each subject's built image id and
    platform. Absent or shapeless evidence stays a PENDING gap; a present
    record that does not bind is a hard failure."""
    build = ev.get("distribution", {}).get("quickstart_build")
    if build is not None and not _quickstart_build_shape_ok(build):
        return ["distribution: invalid quickstart build record"]
    if build is None:
        return ["PENDING gap: " + _QUICKSTART_PENDING[len("PENDING gap: "):]
                + " -- no candidate build record (quickstart_build.head + "
                "tree_sha256 + inputs + per-subject built image ids and "
                "platforms)"]
    fails = []
    for key in ("subjects", "platforms"):
        if set(build[key]) != set(_QUICKSTART_IMAGE_SUBJECTS):
            fails.append(f"distribution: quickstart_build.{key} must name exactly the three image roles")
    head = (ev.get("freshness") or {}).get("head")
    if not str(head or "").strip():
        fails.append("distribution: quickstart candidate binding: evidence carries "
                     "no source head to bind the build record to")
    elif build.get("head") != head:
        fails.append("distribution: quickstart_build.head is not this candidate's "
                     "source head (built images not bound to THIS candidate)")
    else:
        fails.extend(_quickstart_tree_failures(root, str(head), build))
    model, pins = _compose_model(root), pinned_builders(root)
    fails.extend(_quickstart_input_failures(root, build["inputs"], model, pins))
    fails.extend(oci_build_receipt.failures(root, entries, head, model[0], pins))
    for q in entries:
        if build["subjects"].get(q["name"]) != q["image_id"]:
            fails.append(f"distribution: quickstart image {q['name']} is not the "
                         "candidate build's image (quickstart_build.subjects "
                         "mismatch)")
        if (build["platforms"].get(q["name"]) != q["platform"]
                or q["platform"] != _QS_PLATFORM):
            fails.append(f"distribution: quickstart image {q['name']} platform is "
                         f"not the recorded candidate platform ({_QS_PLATFORM})")
    return fails


def _quickstart_images_gap(root: Path, ev: dict) -> list:
    entries, ok = _quickstart_shape_failures(
        ev.get("distribution", {}).get("quickstart_images"))
    if not ok:
        if ev.get("distribution", {}).get("quickstart_build") is not None:
            return ["distribution: claimed quickstart build requires exactly three complete image rows"]
        return [_QUICKSTART_PENDING]
    return _quickstart_build_failures(root, ev, entries)


def _out_of_scope_lines(root: Path, r: dict, ev: dict) -> list:
    """The one recorded out-of-scope note, or its suppressed-gap forms.

    No generic scope-based waiver: the note is reserved for the one
    recorded distroless limitation and only with a machine proof of the
    quickstart acceptance basis.
    """
    line = f"{r.get('repo_ref')}: {r['revision_gap']}"
    if r.get("repo_ref") != DISTROLESS_REPO:
        return ["PENDING gap: " + line,
                f"scope: out-of-scope claim on {r.get('repo_ref')}: "
                f"only the recorded {DISTROLESS_REPO} limitation may carry it "
                "(no generic scope waiver)"]
    basis = _scope_basis_failures(root, ev)
    if basis:
        return (["PENDING gap: " + line]
                + ["scope: out-of-scope note suppressed (unproven basis): " + b
                   for b in basis])
    return [f"OUT-OF-SCOPE (unassessed): {line} -- explicit scope limitation, "
            "not a Preview2 blocker, no hardened readiness claim; machine basis "
            "verified (standard Compose refs only, no Dockerfile.hardened in "
            "the Compose surface, five host-binary subjects)"]


def _revision_gap_lines(root: Path, r: dict, ev: dict) -> list:
    if not r.get("revision_gap"):
        return []
    if (r.get("scope") or {}).get("preview2") == "out-of-scope":
        return _out_of_scope_lines(root, r, ev)
    return ["PENDING gap: " + f"{r.get('repo_ref')}: {r['revision_gap']}"]


_ALPINE_MOCK_ROLE = "runtime base (mock image)"
_MOCK_FROM = re.compile(r"^FROM\s+alpine:([0-9][0-9a-zA-Z.-]*)", re.M)


def _mock_alpine_version(root: Path):
    """The alpine tag the mock-provider Dockerfile actually pins."""
    f = root / "deploy/mock-provider/Dockerfile"
    if not f.is_file():
        return None
    m = _MOCK_FROM.search(f.read_text(errors="replace"))
    return m.group(1) if m else None


def _container_gaps(root: Path, ev: dict) -> list:
    fails = []
    mock_from = _mock_alpine_version(root)
    for r in ev.get("containers", []):
        # R2: the mock-image blocker fires on the RECORD ROLE, not on a
        # filename substring -- renaming the apk inventory artifact must
        # not clear the gap
        if str(r.get("role") or "") == _ALPINE_MOCK_ROLE:
            # R3: the record must match the Dockerfile's own alpine pin
            # and keep the role text -- editing the version or laundering
            # the role to dodge the mock gap is a hard failure, not a
            # silently narrowed blocker
            if mock_from is not None and str(r.get("version") or "") != mock_from:
                fails.append(f"containers: mock-provider alpine record version "
                             f"{r.get('version')!r} is not the Dockerfile pin "
                             f"alpine:{mock_from}")
            fails.append("PENDING gap: mock-provider alpine 3.21 base has only an apk "
                         "inventory, no license text corpus; closing requires mapping "
                         "the installed Alpine package versions to delivered "
                         "licenses and the matching source companion")
        elif (mock_from is not None
              and str(r.get("version") or "") == mock_from
              and "alpine" in str(r.get("repo_ref") or "")
              and str(r.get("index_digest") or "").startswith("sha256:")):
            # R3: the mock alpine at the Dockerfile's pin wearing a
            # DIFFERENT role is the blocker laundered, not a different
            # base image
            fails.append(f"containers: alpine {mock_from} record evades the "
                         f"mock-provider role binding ({_ALPINE_MOCK_ROLE!r} "
                         "expected for the apk inventory blocker)")
        fails.extend(_revision_gap_lines(root, r, ev))
    return fails


def _core_notice_manifest(root: Path, cin: dict):
    """(manifest, failures) for the hash-bound Core notice manifest.

    R3: the manifest's OWN image_id is returned too -- a manifest from
    another image that merely agrees with the wrapper is not a binding."""
    ciid = str(cin.get("image_id") or "")
    cmp_ = root / str(cin.get("manifest_rel") or "")
    if (re.fullmatch(r"sha256:[0-9a-f]{64}", ciid) and cmp_.is_relative_to(root)
            and cmp_.is_file() and sha256_file(cmp_) == cin.get("manifest_sha256")):
        man = load_json(cmp_)
        return man if isinstance(man, dict) else None, []
    return None, []


def _core_notice_entry_failures(root: Path, man: dict) -> list:
    """Manifest entries carry content hashes bound to the recorded payload.

    R3: a 64-hex string proves nothing -- every entry's sha must be one of
    the core binary's recorded inventory payload hashes (the bytes the
    image stage actually copies under /usr/share/licenses/yabanin), with a
    matching basename, so a manifest from another image cannot clear the
    gate by shape alone."""
    files = man.get("files") or []
    fails = []
    core_payload = root / "artifacts/release-evidence/image-notices/yabanin"
    inv = load_json(core_payload / "inventory.json") \
        if (core_payload / "inventory.json").is_file() else {}
    known = {str(f.get("sha256") or ""): str(f.get("path") or "")
             for f in inv.get("files") or [] if isinstance(f, dict)}
    for f in files:
        sha = str(f.get("sha256") or "")
        path = str(f.get("path") or "")
        if not re.fullmatch(r"[0-9a-f]{64}", sha):
            fails.append("distribution: core_image_notices manifest entry without "
                         f"a content hash: {path}")
        elif sha not in known or (PurePosixPath(known[sha]).name
                                  != PurePosixPath(path).name):
            fails.append("distribution: core_image_notices manifest entry is not "
                         f"bound to the recorded core payload bytes: {path}")
    return fails


def _notice_identity_mismatch(cin, core) -> bool:
    return (not isinstance(cin, dict) or not isinstance(core, dict)
            or str(cin.get("image_id") or "") != str(core.get("image_id") or "")
            or str(cin.get("platform") or "") != str(core.get("platform") or ""))


def _core_notice_identity_failures(ev: dict, cin) -> list:
    """The recorded identity must BE the Core quickstart subject's."""
    qi = ev.get("distribution", {}).get("quickstart_images") or []
    core = next((q for q in qi if isinstance(q, dict) and q.get("name") == "core"),
                None)
    if _notice_identity_mismatch(cin, core):
        return ["distribution: core_image_notices identity is not the Core "
                "quickstart image subject (image_id/platform mismatch)"]
    return []


def _core_notice_paths_confined(man) -> bool:
    """Every manifest entry is directly under /usr/share/licenses/yabanin."""
    paths = [str(f.get("path") or "") for f in (man or {}).get("files") or []]
    return bool(paths) and all(
        re.fullmatch(r"/usr/share/licenses/yabanin/[^/]+", p) for p in paths)


def _core_image_notices_gap(root: Path, ev: dict) -> list:
    """Core notice bytes must be bound to the Core image identity.

    R4-IMAGE-01: the manifest entries carry confined notice paths WITH
    content hashes (a bare path with the expected prefix proves nothing),
    and the recorded image identity must BE the Core quickstart subject's
    immutable image ID and platform."""
    cin = ev.get("distribution", {}).get("core_image_notices")
    man, _ = _core_notice_manifest(root, cin) if isinstance(cin, dict) else (None, [])
    # R2: EXACT confinement -- a file directly under the yabanin licenses
    # directory, so a sibling like /usr/share/licenses/yabanin-other/x is
    # not accepted by prefix accident
    if not _core_notice_paths_confined(man):
        return ["PENDING gap: Core quickstart image notice bytes under "
                "/usr/share/licenses/yabanin unbound (verify the actual "
                "notice bytes in the built Core image; requires an "
                "image-bound content manifest)"]
    qi = ev.get("distribution", {}).get("quickstart_images") or []
    core = next((q for q in qi if isinstance(q, dict) and q.get("name") == "core"),
                None)
    if (man or {}).get("image_id") != (core or {}).get("image_id"):
        return ["PENDING gap: Core quickstart image notice manifest is not bound "
                "to the Core candidate image (manifest image_id is not the "
                "quickstart core subject; an agreeing wrapper is not the "
                "manifest's own identity)"]
    return (_core_notice_entry_failures(root, man)
            + _core_notice_identity_failures(ev, cin))


def _delivery_entry_verifiable(root: Path, pkgs: set, legal: dict, e) -> bool:
    """One manifest entry: recorded package, delivered INSIDE dist, legal bytes.

    R2: the delivered file must live inside the built output tree
    (web/dashboard/dist/ -- a notice stashed elsewhere does not accompany
    the delivery), and its hash must be one of the package's RECORDED
    legal-file hashes (binding the delivered bytes to the legal bytes,
    Feather attribution included), not just any self-consistent file."""
    rel = str((e or {}).get("path") or "")
    fp = root / rel
    pkg = str((e or {}).get("package") or "")
    # R3: path-normalized containment -- 'web/dashboard/dist/../...' escapes
    # the served tree while passing the old startswith prefix check
    parts = PurePosixPath(rel).parts
    inside_dist = (parts[:3] == ("web", "dashboard", "dist")
                   and ".." not in parts and not PurePosixPath(rel).is_absolute())
    return (pkg in pkgs
            and inside_dist and fp.is_file()
            and sha256_file(fp) == (e or {}).get("sha256")
            and (e or {}).get("sha256") in legal.get(pkg, set()))


def _delivery_manifest_gap(root: Path, nd: dict, ev: dict):
    """The bound-delivery PENDING gap line, or None when verifiable.

    R4-NPM-01: status="bound" with an empty unresolved list is a CLAIM --
    clearing the gap requires a manifest of package -> delivered notice
    file, each entry hash-bound and each package part of the recorded
    contributing set."""
    manifest = nd.get("manifest")
    if not isinstance(manifest, list) or not manifest:
        return ("PENDING gap: dashboard npm package notice delivery claimed "
                "bound without a package-to-delivered-notice manifest")
    contributing = ev.get("assets", {}).get("contributing_packages") or []
    pkgs = {str(p.get("name") or "").strip() for p in contributing}
    legal = {str(p.get("name") or "").strip():
             {str(f.get("sha256") or "") for f in p.get("legal_files") or []}
             for p in contributing}
    gap = _delivery_coverage_gap(pkgs, manifest)
    if gap:
        return gap
    for e in manifest:
        if not _delivery_entry_verifiable(root, pkgs, legal, e):
            return ("PENDING gap: dashboard npm package notice delivery "
                    f"manifest entry unverifiable: {e}")
    return None


def _delivery_coverage_gap(pkgs: set, manifest: list):
    """R2: EVERY contributing package must be covered -- a manifest row for
    one package (clsx) while another contributing package (lucide-react)
    ships no delivered notice is not a bound delivery."""
    covered = {str(e.get("package") or "") for e in manifest}
    missing = sorted(pkgs - covered)
    if missing:
        return ("PENDING gap: dashboard npm package notice delivery bound "
                f"without delivered notices for contributing package(s): "
                f"{', '.join(missing)}")
    return None


def _unresolved_gap_lines(ev: dict, nd_detail) -> list:
    fails = []
    for u in ev.get("assets", {}).get("unresolved", []):
        if nd_detail and (str(u) in nd_detail or nd_detail in str(u)):
            continue  # same fact already reported once via notice_delivery
        fails.append(f"PENDING gap: assets: {u}")
    return fails


def _notice_delivery_gaps(root: Path, ev: dict) -> list:
    """npm notice delivery needs a verifiable package-to-notice manifest."""
    nd = ev.get("assets", {}).get("notice_delivery") or {}
    nd_detail = None
    if nd.get("status") != "bound":
        nd_detail = str(nd.get("detail") or
                        "dashboard npm package notices do not accompany the "
                        "built output")
    else:
        gap = _delivery_manifest_gap(root, nd, ev)
        if gap:
            return [gap]
    fails = _unresolved_gap_lines(ev, nd_detail)
    return ([f"PENDING gap: {nd_detail}"] if nd_detail else []) + fails


def gap_failures(root: Path, ev: dict) -> list:
    """Required-but-missing facts stay failures; a documented gap is not a pass."""
    fails = _quickstart_images_gap(root, ev)
    fails.extend(_container_gaps(root, ev))
    fails.extend(_core_image_notices_gap(root, ev))
    fails.extend(_notice_delivery_gaps(root, ev))
    return fails


def review_failures(ev: dict) -> list:
    """Structure only; approval authenticity is human scope, not machine scope."""
    fails = []
    for area in AREAS:
        rec = (ev.get("reviews") or {}).get(area)
        if not isinstance(rec, dict):
            fails.append(f"reviews: {area} record missing")
            continue
        for key in ("owner", "reason", "evidence"):
            if not isinstance(rec.get(key), str) or not rec[key].strip():
                fails.append(f"reviews: {area}.{key} empty")
        if not isinstance(rec.get("approved"), bool):
            fails.append(f"reviews: {area}.approved must be a boolean")
    return fails


def fingerprint_failures(ev: dict, with_fingerprint: bool) -> list:
    if ev.get("task_base") != TASK_BASE:
        return ["evidence task_base mismatch"]
    if not with_fingerprint:
        return []
    fp = license_check.source_fingerprint(license_check.source_files())
    return [] if ev.get("source_sha256") == fp else \
        ["source_sha256 does not match the current tree fingerprint"]


def verify(root: Path, ev: dict, with_fingerprint: bool,
            expected_head: str | None = None) -> list:
    fails = []
    for fn in (lambda: container_failures(root, ev),
               lambda: negative_control_failures(root, ev),
               lambda: asset_failures(root, ev),
               lambda: notice_failures(root, ev),
               lambda: provenance_failures(ev),
               lambda: distribution_failures(root, ev),
               lambda: freshness_failures(root, ev, expected_head),
               lambda: gap_failures(root, ev),
               lambda: review_failures(ev),
               lambda: fingerprint_failures(ev, with_fingerprint)):
        fails.extend(fn())
    return fails


def pending_reviews() -> dict:
    note = ("PENDING scoped human review; machine-generated placeholder, "
            "not an approval or rights clearance")
    return {area: {"approved": False, "owner": note, "reason": note,
                   "evidence": "see machine facts in this file; review not yet performed"}
            for area in AREAS}


def _norm(rec: dict) -> dict:
    """Normalize the two registry-resolve JSON shapes (key names differ)."""
    out = dict(rec)
    out.setdefault("config_env", rec.get("env") or [])
    out.setdefault("amd64_annotations", rec.get("annotations") or {})
    return out


def collect_containers() -> list:
    cfg = load_json(ARTS / "image-configs.json")
    redis = _norm(load_json(ARTS / "redis-72-resolve.json"))
    distroless = _norm(load_json(ARTS / "upstream/distroless-resolve.json"))
    out = []

    def base(rec, name, role, license_id, notice_rel, extra=None):
        ann = rec.get("amd64_annotations", {})
        entry = {"repo_ref": name, "role": role,
                 "index_digest": rec["index_digest"],
                 "amd64_manifest_digest": rec.get("amd64_manifest_digest"),
                 "config_digest": rec.get("config_digest"),
                 "version": next((e.split("=", 1)[1] for e in rec.get("config_env", [])
                                  if e.startswith(("REDIS_VERSION", "PG_VERSION", "GOLANG_VERSION",
                                                   "NODE_VERSION", "NGINX_VERSION"))),
                                 ann.get("org.opencontainers.image.version", "")),
                 "license": license_id,
                 "notice": ({"path": notice_rel,
                             "sha256": sha256_file(ROOT / notice_rel)} if notice_rel else None),
                 "created": rec.get("created"), "annotations": ann}
        if extra:
            entry.update(extra)
        out.append(entry)

    base(redis, "redis", "operator-pulled service", "BSD-3-Clause",
         "artifacts/release-evidence/upstream/redis-7.2.17/COPYING")
    pg_extra = None
    control = ARTS / "upstream/pgvector/vector.control"
    if control.is_file():
        # R4-PG-PROOF-01: generation fails on a substituted control -- the
        # same default_version with different bytes must not become its own
        # reference through regeneration.
        if sha256_file(control) != PGVECTOR_FIXED["control_sha256"]:
            raise SystemExit(
                "generate: pgvector vector.control bytes do not match the pinned "
                f"upstream constant {PGVECTOR_FIXED['control_sha256']} "
                "(substituted control?)")
        m = re.search(r"^default_version\s*=\s*'([^']+)'", control.read_text(), re.M)
        if m:
            pg_extra = {"extension_version": m.group(1),
                        "extension_control": {"path": PGVECTOR_CONTROL_REL,
                                              "sha256": PGVECTOR_FIXED["control_sha256"]},
                        "extension_binding": "vector.control default_version read from the "
                                             "locally pinned upstream control bytes "
                                             "(hash-bound); image-filesystem extraction "
                                             "pending: no hash-bound collection record "
                                             "yet (docker create + cp not run)"}
        # no extension_collection is fabricated here: without a real
        # hash-bound image collection record the extraction stays a PENDING
        # gap at verification, never a generated pass
    base(cfg["pgvector-service"], "pgvector/pgvector", "operator-pulled service",
         "PostgreSQL License (postgres server + pgvector extension)",
         "artifacts/release-evidence/upstream/pgvector/LICENSE", pg_extra)
    base(cfg["golang-builder"], "golang", "build stage (not retained)", "BSD-3-Clause (Go)",
         "artifacts/release-evidence/upstream/go/LICENSE")
    base(distroless, "gcr.io/distroless/static-debian12",
         "runtime base (Dockerfile.hardened; not used by the quickstart compose)",
         "Apache-2.0 (distroless tooling) over Debian package contents",
         "artifacts/release-evidence/upstream/distroless/LICENSE",
         {"version": "nonroot (image exposes no version metadata; digest pin is the binding)",
          "revision_gap": "distroless images carry no revision label; LICENSE bound to "
                          "GoogleContainerTools/distroless master at fetch time",
          "scope": {"preview2": "out-of-scope",
                    "basis": "Preview2 acceptance scope is "
                             "install/provider/request/inspect/recovery; the "
                             "acceptance artifact is the standard Compose quickstart "
                             "plus the five host binaries, and Dockerfile.hardened "
                             "is used by neither",
                    "assessment": "explicit unassessed limitation; no hardened "
                                  "readiness claim; the digest pin and notice "
                                  "binding above remain enforced gates"}})
    base(cfg["alpine-core-runtime"], "alpine", "runtime base (core image)",
         "Alpine base packages per scripts/release/image-os-notices corpus",
         "scripts/release/image-os-notices/MANIFEST.json",
         {"note": "committed text corpus; MANIFEST binds base_index_digest"})
    base(cfg["alpine-mock-runtime"], "alpine", "runtime base (mock image)",
         "Alpine 3.21 packages per apk inventory",
         "artifacts/release-evidence/apk-mock.txt",
         {"note": "full 3.21 text corpus not assembled; recorded as a pending gap"})
    base(cfg["node-dashboard-builder"], "node", "build stage (not retained)", "MIT (Node)",
         "artifacts/release-evidence/upstream/node/LICENSE",
         {"notice_forbidden_contexts": [
             {"markers": ["GPL"],
              "sections": ["File: aclocal.m4 (only for ICU4C)",
                           "File: config.guess (only for ICU4C)"],
              "retained_check": "dashboard-runtime-dist-only",
              "detail": "Node's aggregated LICENSE embeds ICU4C third-party notices "
                        "for autoconf aux scripts (pkg.m4 GPLv2+, config.guess GPLv3+, "
                        "each with the autoconf exception). Node is a build stage that "
                        "is not retained in the shipped dashboard image; the hit is a "
                        "recorded machine-checked fact; the classification stays "
                        "open until the exact final nginx image inspection"}]})
    base(cfg["nginx-dashboard-serve"], "nginx", "serve stage (dashboard static)",
         "BSD-2-Clause (nginx) + alpine packages",
         "artifacts/release-evidence/upstream/nginx/LICENSE")
    return out


def collect_distribution() -> dict:
    dist = ROOT / "dist/release"
    sums = {}
    for line in (dist / "SHA256SUMS").read_text().splitlines():
        digest, _, name = line.partition("  ")
        sums[name.strip()] = digest
    binaries = []
    for name in BINARIES:
        payload = ARTS / "image-notices" / name
        inv = load_json(payload / "inventory.json")
        binaries.append({"name": name, "sha256": sums.get(name),
                         "buildinfo": f"dist/release/{name}.buildinfo",
                         "buildinfo_sha256": sha256_file(dist / f"{name}.buildinfo"),
                         "notices_payload": str(payload.relative_to(ROOT)),
                         "notices_files": len(inv.get("files", []))})
    return {"binaries": binaries,
            "notice_draft": "dist/release/THIRD-PARTY-NOTICES.md",
            "notice_draft_sha256": sha256_file(dist / "THIRD-PARTY-NOTICES.md"),
            "notice_draft_identifier_only": True,
            "full_texts_via": "artifacts/release-evidence/image-notices/<binary>/ (build-info driven)",
            "recipe_sha256": sha256_file(dist / "recipe.json"),
            "unsigned": True,
            "quickstart_images": [],
            "quickstart_images_note": "not docker-built in this evidence lane; binding via "
                                      "Dockerfile pins + base digests only; exact image "
                                      "digests pending a bounded docker-build follow-up",
            "pulled_images_verified_via_registry": [
                "pgvector/pgvector:pg16", "redis:7.2-alpine",
                "gcr.io/distroless/static-debian12:nonroot"]}


def generate() -> int:
    assets = load_json(ARTS / "dashboard-assets.json")
    ev = {"schema": "yabanin.release-evidence/1",
          "task_base": TASK_BASE,
          "head": git_out("rev-parse", "HEAD").strip(),
          "generated_at": datetime.now(timezone.utc).isoformat(),
          "freshness": git_state(),
          "containers": collect_containers(),
          "negative_controls": {"redis_restricted_retained": {
              "version": REDIS_NEGATIVE["version"],
              "index_digest": REDIS_NEGATIVE["digest"],
              "license": "RSALv2 or SSPLv1 (both forbidden markers present)",
               "license_path": REDIS_NEGATIVE["license_path"],
               "license_sha256": REDIS_NEGATIVE["license_sha256"],
              "finding": "original quickstart pin resolved to 7.4.12; superseded by the "
                         "7.2.17 BSD pin; retained as the restricted negative case"}},
          "assets": {k: assets[k] for k in ("dist_files", "chunk_origins",
                                            "contributing_packages", "lucide_react",
                                            "css_token_reach", "notice_delivery",
                                            "bindings", "unresolved")},
          "assets_gaps": assets.get("unresolved", []),
          "provenance": {"base": TASK_BASE, "added": provenance_added(),
                         "note": "DCO signoff presence is not proof of employer rights"},
          "distribution": collect_distribution(),
          "notice_reconciliation": {"notice_sha256": sha256_file(ROOT / "NOTICE"),
                                    "enterprise_reference_removed": True,
                                    "basis": "root LICENSING.md: project-authored Core "
                                             "Apache-2.0; no Enterprise implementation in "
                                             "this repository"},
          "reviews": pending_reviews()}
    ev["source_sha256"] = license_check.source_fingerprint(license_check.source_files())
    dest = ROOT / EVIDENCE_REL
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(ev, indent=2, sort_keys=True) + "\n")
    print(f"evidence written: {EVIDENCE_REL} (source_sha256={ev['source_sha256'][:16]}...)")
    return 0


def _split_verify_lines(lines: list):
    """(out-of-scope notes, failure lines) preserving production order."""
    notes, fails = [], []
    for line in lines:
        (notes if line.startswith("OUT-OF-SCOPE") else fails).append(line)
    return notes, fails


def _verify_verdict(fails: list, notes: list, pending: list, hard: list) -> str:
    verdict = ("PASS" if not fails
               else f"{len(hard)} hard failure(s), {len(pending)} pending gap(s)")
    label = "REVIEW-ONLY: " if any("review-only" in f for f in hard) else ""
    suffix = f"; {len(notes)} out-of-scope note(s)" if notes else ""
    return f"{label}release evidence verify: {verdict}{suffix}"


def _print_verify(lines: list) -> int:
    # OUT-OF-SCOPE lines are explicit unassessed limitations surfaced for
    # the scope review, not blockers: printed as notes, excluded from counts.
    notes, fails = _split_verify_lines(lines)
    pending = [f for f in fails if f.startswith("PENDING gap")]
    hard = [f for f in fails if not f.startswith("PENDING gap")]
    for f in fails:
        print(f"FAIL: {f}")
    for f in notes:
        print(f"NOTE: {f}")
    print(_verify_verdict(fails, notes, pending, hard))
    return 0 if not fails else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("command", choices=("generate", "verify"))
    ap.add_argument("--expected-head", metavar="COMMIT", default=None,
                    help="additional assertion: HEAD must match this commit and "
                         "the evidence's own recorded HEAD (never a substitute)")
    args = ap.parse_args()
    if args.command == "generate":
        return generate()
    ev = load_json(ROOT / EVIDENCE_REL)
    lines = verify(ROOT, ev, with_fingerprint=True, expected_head=args.expected_head)
    return _print_verify(lines)


if __name__ == "__main__":
    sys.exit(main())

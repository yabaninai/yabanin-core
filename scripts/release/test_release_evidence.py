#!/usr/bin/env python3
"""Negative controls for release_evidence.verify: tampered evidence must fail.

Fixtures build a minimal fake tree that mirrors the REAL binding syntax
(digest-pinned compose images, digest-pinned Dockerfile FROM lines, per-binary
inventory.json notice payloads, dashboard dist with a map-bound JS chunk and
design-token css incl. the recorded 140ms -> .14s equivalence, root NOTICE)
plus a matching evidence object, then assert that each deliberate defect fails
the verifier while the intact fixture produces no failures at all.

Real-repository legs (provenance, freshness, source fingerprint) cannot be
fixture-tested: their "provenance:", "freshness:" and "source_sha256" failure
lines are filtered here and exercised by the actual generate -> verify run.
Separate tests use real temporary Git repositories to check provenance
regardless of the contributor history of the checkout running this suite.

Review semantics: the verifier checks STRUCTURE only, so a well-formed
approved=true record is NOT rejected (approval authenticity is human scope);
missing areas, blank fields and non-boolean approved flags do fail.

Generation-side twin binding has its own controls here: the strict
strip_map_comment shape (exactly one final sourceMappingURL comment at EOF)
rejects appended code/payload, empty names and mid-file markers, so those
twins can never be recorded as byte-equal.
"""
import base64
import hashlib
import json
import re
import sys
import tempfile
import subprocess
import unittest
from unittest.mock import patch
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import release_evidence as re_ev  # noqa: E402

# Committed byte-exact real upstream bytes (redis 7.2.17 COPYING, pgvector
# vector.control, pgvector LICENSE), independently sha256-verified at commit
# time; tests read these, never the git-ignored artifacts/ tree.
TESTDATA = HERE / "testdata/release-evidence"

PG_DIGEST = "sha256:0dd3149a06e4579a0d70d8fef9945636cd514005e7237deb27f9b67886f8dc4f"
GO_DIGEST = "sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf"
ALPINE_DIGEST = "sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf"
BSD = "Redistribution and use in source and binary forms\n(BSD notice text fixture)\n"
GO_LICENSE = ("Copyright (c) 2009 The Go Authors\n"
              "Redistribution and use in source and binary forms\n(Go BSD fixture)\n")
ALPINE_NOTICE = ("Alpine Linux fixture notice\n"
                 "Redistribution and use in source and binary forms\n")
PG_NOTICE = ("PostgreSQL Database Management System fixture\n"
             "(PostgreSQL Licence text fixture)\n")
RSAL = ("bundled third-party notice bundle fixture\n"
        "    ----------------------------------------------------------------------\n"
        "\n"
        "    File: redis-license.txt (upstream 7.4.12)\n"
        "Redis Source Available License 2.0 (RSALv2) fixture\n"
        "    ----------------------------------------------------------------------\n"
        "\n"
        "    File: server-side.txt (dual licensing)\n"
        "Server Side Public License (SSPLv1) fixture\n"
        "    ----------------------------------------------------------------------\n")
NOTICE = ("Yabanin Gateway preview fixture\nCopyright 2026 Yabanin contributors\n\n"
          "Project-authored code is licensed under the Apache License, Version 2.0;\n"
          "see LICENSE and LICENSING.md for licensing scope.\n")
DRAFT = "identifier-only third-party notice draft fixture\n"
LUC_LICENSE = "ISC License fixture (includes Feather MIT portions)\n"
CLSX_LICENSE = "MIT License fixture (clsx)\n"
# R4-MAP-01: the emitted dist chunk is the STRIPPED twin (no marker); the
# marker-carrying bytes are the map twin recorded via map_twin_raw_sha256.
APP_JS = b'console.log("app fixture");\n'
APP_JS_RAW_TWIN = (b'console.log("app fixture");\n'
                   b'//# sourceMappingURL=app.js.map\n')
APP_MAP = (b'{"version":3,"file":"app.js",'
           b'"sources":["../../node_modules/lucide-react/dist/esm/icon.js",'
           b'"../../node_modules/clsx/dist/clsx.js"],"sourcesContent":null}\n')
APP_CSS = ":root{--astra-ink:#010203;--astra-duration:.14s;}body{color:var(--astra-ink)}\n"
TOKENS_CSS = ":root {\n  --astra-ink:#010203;\n  --astra-duration:140ms;\n}\n"
MODULE_LICENSE = "Example module BSD fixture\nRedistribution and use in source and binary forms\n"
TOOLCHAIN_LICENSE = "Go toolchain BSD fixture\nRedistribution and use in source and binary forms\n"


def sha_text(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def notice_rec(path: str, text: str) -> dict:
    return {"path": path, "sha256": sha_text(text)}


def bind_real_upstream_fixtures(td, ev):
    """Bind the INTACT fixture to the committed real upstream bytes in
    TESTDATA (never the git-ignored artifacts/ tree): redis COPYING, the
    pgvector pinned tuple (control sha/path/version are the verifier's
    PINNED CONSTANTS, not recomputed expectations), the pgvector LICENSE,
    and the canonical redis 7.4.12 negative-control text. R4-FIXTURE-01:
    this binding runs BEFORE any ev_mutator, so a mutator can no longer
    have its deliberate corruptions silently restored."""
    td = Path(td)
    nc = ev.setdefault("negative_controls", {}).setdefault("redis_restricted_retained", {})
    if nc.get("license_path") == re_ev.REDIS_NEGATIVE["license_path"]:
        data = (TESTDATA / "upstream/redis-7.4.12/LICENSE.txt").read_bytes()
        dst = td / re_ev.REDIS_NEGATIVE["license_path"]
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(data)
        nc["license_sha256"] = re_ev.REDIS_NEGATIVE["license_sha256"]
    for rec in ev.get("containers", []):
        if rec.get("repo_ref") == "redis" and rec.get("notice"):
            rel = rec["notice"].get("path")
            if rel == "artifacts/release-evidence/upstream/redis/COPYING":
                data = (TESTDATA / "upstream/redis-7.2.17/COPYING").read_bytes()
                (td / rel).write_bytes(data)
                rec["notice"]["sha256"] = re_ev.REDIS_FIXED["copying_sha256"]
    control = TESTDATA / "upstream/pgvector/vector.control"
    if control.is_file():
        data = control.read_bytes()
        (td / re_ev.PGVECTOR_CONTROL_REL).parent.mkdir(parents=True, exist_ok=True)
        (td / re_ev.PGVECTOR_CONTROL_REL).write_bytes(data)
        default_version = next(l.split("'")[1] for l in data.decode().splitlines()
                               if l.startswith("default_version"))
        lic_rel = "artifacts/release-evidence/upstream/pgvector/LICENSE"
        (td / lic_rel).parent.mkdir(parents=True, exist_ok=True)
        (td / lic_rel).write_bytes((TESTDATA / "upstream/pgvector/LICENSE").read_bytes())
        pg = next((r for r in ev["containers"]
                   if r.get("repo_ref") == "pgvector/pgvector"), None)
        if pg is not None:
            pg["extension_version"] = re_ev.PGVECTOR_FIXED["extension_version"]
            assert default_version == re_ev.PGVECTOR_FIXED["extension_version"]
            pg["extension_binding"] = ("vector.control default_version read from the "
                                       "locally pinned upstream control bytes "
                                       "(hash-bound); image-filesystem extraction "
                                       "pending: no hash-bound collection record "
                                       "yet (docker create + cp not run)")
            pg["extension_control"] = {"path": re_ev.PGVECTOR_CONTROL_REL,
                                       "sha256": re_ev.PGVECTOR_FIXED["control_sha256"]}
            pg["config_digest"] = re_ev.PGVECTOR_FIXED["config_digest"]
            pg.setdefault("extension_collection", {
                "image_id": re_ev.PGVECTOR_FIXED["digest"], "platform": "linux/amd64",
                "method": "docker create + docker cp of /usr/share/postgresql16/"
                          "extension/vector.control from the pinned image",
                "control_sha256": re_ev.PGVECTOR_FIXED["control_sha256"],
                "index_digest": re_ev.PGVECTOR_FIXED["digest"],
                "manifest": {"digest": re_ev.PGVECTOR_FIXED["manifest_digest"],
                             "config": {"digest": pg["config_digest"],
                                        "size": 12345}}})
            pg["notice"] = {"path": lic_rel, "sha256": re_ev.sha256_file(td / lic_rel)}
    return ev


def _generator_tree(root):
    """Self-contained collect_containers() inputs: committed real upstream
    bytes for redis COPYING and pgvector control/LICENSE, synthetic minimal
    notices/resolve JSON elsewhere. No host artifacts/, no Docker, no repo."""
    import shutil
    arts = root / "artifacts/release-evidence"
    # the pgvector-service config carries the REVIEWED compose pin digest:
    # the pinned tuple (digest + control bytes + version) must be one tuple
    # in the generator lane too, not a synthetic per-key digest
    cfg = {key: {"index_digest":
                 re_ev.PGVECTOR_FIXED["digest"] if key == "pgvector-service"
                 else "sha256:" + key[0] * 64,
                  "config_env": [],
                  "amd64_annotations": {"org.opencontainers.image.version": "fixture"}}
           for key in ("pgvector-service", "golang-builder", "alpine-core-runtime",
                       "alpine-mock-runtime", "node-dashboard-builder",
                       "nginx-dashboard-serve")}
    arts.mkdir(parents=True, exist_ok=True)
    (arts / "image-configs.json").write_text(json.dumps(cfg))
    (arts / "redis-72-resolve.json").write_text(json.dumps(
        {"index_digest": "sha256:" + "r" * 64, "env": ["REDIS_VERSION=7.2.17"]}))
    (arts / "upstream").mkdir(parents=True, exist_ok=True)
    (arts / "upstream/distroless-resolve.json").write_text(json.dumps(
        {"index_digest": "sha256:" + "d" * 64}))
    for rel in ("redis-7.2.17/COPYING", "pgvector/LICENSE", "pgvector/vector.control"):
        dst = arts / "upstream" / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(TESTDATA / "upstream" / rel, dst)
    for rel, text in {"upstream/go/LICENSE": GO_LICENSE,
                      "upstream/distroless/LICENSE": "Apache License 2.0 distroless fixture\n",
                      "upstream/node/LICENSE": "MIT License node fixture\n",
                      "upstream/nginx/LICENSE":
                          "Redistribution and use in source and binary forms\n"
                          "(nginx BSD fixture)\n",
                      "apk-mock.txt": "alpine mock apk inventory fixture\n"}.items():
        p = arts / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    man = root / "scripts/release/image-os-notices/MANIFEST.json"
    man.parent.mkdir(parents=True, exist_ok=True)
    man.write_text(json.dumps({"base_index_digest": ALPINE_DIGEST}) + "\n")


def fixture_image(td, role, head, context, recipe, *, selected_platform="amd64", omit_subject=False,
                  image_schema=2, attestation_schema=2, omit_config=False, conflicting_inline=False, bases=(GO_DIGEST, ALPINE_DIGEST)):
    # Build the content graph independently from the implementation under test.
    store = td / "artifacts/release-evidence/build-receipts" / role
    store.mkdir(parents=True, exist_ok=True)
    manifest_type = "application/vnd.oci.image.manifest.v1+json"
    slsa = "https://slsa.dev/provenance/v1"

    def write(record, media):
        data = json.dumps(record, sort_keys=True).encode()
        digest = hashlib.sha256(data).hexdigest()
        (store / digest).write_bytes(data)
        return {"digest": "sha256:" + digest, "size": len(data), "mediaType": media}

    config = write({"os": "linux", "architecture": selected_platform, "config": {"role": role}},
                   "application/vnd.oci.image.config.v1+json")
    child = write({"schemaVersion": image_schema, "mediaType": manifest_type, "config": config, "layers": []}, manifest_type)
    child["platform"] = {"os": "linux", "architecture": selected_platform}
    source = {"revision": head, "localdir:context": context, "localdir:dockerfile": str(Path(recipe).parent)}
    request = {"configSource": {"path": Path(recipe).name},
               "request": {"root": {"request": {"args": {"vcs:" + k: v for k, v in source.items()}}}}}
    build = {"externalParameters": request, "internalParameters": {"targetPlatform": "linux/" + selected_platform},
             "buildType": "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
             "resolvedDependencies": [{"uri": "pkg:docker/base", "digest": {"sha256": p[7:]}} for p in bases]}
    subjects = [] if omit_subject else [{"digest": {"sha256": child["digest"][7:]}}]
    statement = write({"_type": "https://in-toto.io/Statement/v1", "predicateType": slsa,
                       "subject": subjects, "predicate": {"buildDefinition": build, "runDetails": {
                           "metadata": {"buildkit_metadata": {"vcs": source}}}}}, "application/vnd.in-toto+json")
    statement["annotations"] = {"in-toto.io/predicate-type": slsa}
    content = (store / statement["digest"][7:]).read_bytes()
    if conflicting_inline:
        content = b"!" + content[1:]
    statement["data"] = base64.b64encode(content).decode("ascii")
    attestation = {"schemaVersion": attestation_schema, "mediaType": manifest_type,
                   "subject": child, "layers": [statement]}
    if not omit_config:
        attestation["config"] = {"digest": "sha256:" + hashlib.sha256(b"{}").hexdigest(), "size": 2,
                                 "mediaType": "application/vnd.oci.empty.v1+json", "data": "e30="}
    att = write(attestation, manifest_type)
    att["annotations"] = {"vnd.docker.reference.type": "attestation-manifest",
                          "vnd.docker.reference.digest": child["digest"]}
    index_type = "application/vnd.oci.image.index.v1+json"
    return write({"schemaVersion": 2, "mediaType": index_type, "manifests": [child, att]}, index_type)["digest"]


def fixture_subjects(td, ev, head):
    images = {"core": fixture_image(td, "core", head, ".", "Dockerfile"),
              "mock-provider": fixture_image(td, "mock-provider", head, "deploy/mock-provider",
                                             "deploy/mock-provider/Dockerfile"),
              "dashboard": fixture_image(td, "dashboard", head, ".", "web/dashboard/Dockerfile")}
    dist = ev["distribution"]
    for row in dist["quickstart_images"]:
        row["image_id"] = images[row["name"]]
    wrapper = dist["core_image_notices"]
    wrapper["image_id"] = images["core"]
    manifest = td / wrapper["manifest_rel"]
    contents = json.loads(manifest.read_text())
    contents["image_id"] = images["core"]
    payload = json.dumps(contents, indent=1) + "\n"
    manifest.write_text(payload)
    wrapper["manifest_sha256"] = sha_text(payload)
    return images


def build_fixture(td: Path, ev_mutator=None):
    td = Path(td)
    (td / "deploy/quickstart").mkdir(parents=True)
    # R4-COMPOSE-01 fixture shape: blank lines and full-comment lines INSIDE
    # the services block, plus a nested (non-direct) image key -- the reader
    # under test must survive both (the pre-fix reader reset its services
    # state on the blank lines and returned zero images for the real file).
    (td / "deploy/quickstart/docker-compose.yml").write_text(
        "services:\n"
        "\n"
        "  # full-comment lines and blank lines inside services must never\n"
        "  # reset the effective-image reader (R4-COMPOSE-01)\n"
        "  redis:\n"
        "\n"
        "    image: redis:7.2-alpine@" + re_ev.REDIS_FIXED["digest"] + "\n"
        "  postgres:\n"
        "    image: pgvector/pgvector:pg16@" + PG_DIGEST + "\n"
        "    environment:\n"
        "      # a nested image key is not the direct service image\n"
        "      image: not-the-service-image\n"
        "  db-app-role:\n"
        "    image: pgvector/pgvector:pg16@" + PG_DIGEST + "\n")
    compose = td / "deploy/quickstart/docker-compose.yml"
    with compose.open("a") as stream:
        for service in ("yabanin", "seed", "migrate"):
            stream.write(f"  {service}:\n    build: {{context: ../.., dockerfile: Dockerfile}}\n")
        stream.write("  dashboard:\n    build: {context: ../.., dockerfile: web/dashboard/Dockerfile}\n"
                     "  mock-openai:\n    build: {context: ../../deploy/mock-provider, dockerfile: Dockerfile}\n")
    (td / "Dockerfile").write_text(
        "FROM golang:1.27.4-alpine@" + GO_DIGEST + " AS builder\n"
        "COPY . .\n"
        "FROM alpine:3.24.4@" + ALPINE_DIGEST + "\n")
    # R3: the mock-provider base pin the mock-alpine record must match
    (td / "deploy/mock-provider").mkdir(parents=True, exist_ok=True)
    (td / "deploy/mock-provider/Dockerfile").write_text(
        "FROM golang:1.27.4-alpine@" + GO_DIGEST + " AS builder\n"
        "COPY . .\n"
        "FROM alpine:3.21.10@" + ALPINE_DIGEST + "\n")
    (td / "NOTICE").write_text(NOTICE)
    up = td / "artifacts/release-evidence/upstream"
    for rel, text in {"redis/COPYING": BSD, "golang/LICENSE": GO_LICENSE,
                      "alpine/COPYING": ALPINE_NOTICE, "postgres/COPYRIGHT": PG_NOTICE,
                      "restricted.txt": RSAL}.items():
        p = up / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    man = td / "scripts/release/image-os-notices/MANIFEST.json"
    man.parent.mkdir(parents=True, exist_ok=True)
    man.write_text(json.dumps({"base_index_digest": ALPINE_DIGEST}) + "\n")

    dr = td / "dist/release"
    dr.mkdir(parents=True)
    sums, bin_shas = [], {}
    for name in re_ev.BINARIES:
        data = b"binary-fixture-" + name.encode()
        (dr / name).write_bytes(data)
        bin_shas[name] = hashlib.sha256(data).hexdigest()
        (dr / (name + ".buildinfo")).write_text("go toolchain fixture\n")
        sums.append(bin_shas[name] + "  " + name)
    (dr / "SHA256SUMS").write_text("\n".join(sums) + "\n")
    (dr / "THIRD-PARTY-NOTICES.md").write_text(DRAFT)
    (dr / "NOTICE").write_text(NOTICE)
    recipe_bytes = json.dumps({"git_commit": "0123456789" * 4}) + "\n"
    (dr / "recipe.json").write_text(recipe_bytes)
    payload_files = {"project/LICENSE": "Apache License 2.0 project fixture\n",
                     "project/NOTICE": "project NOTICE fixture\n",
                     "go-toolchain/LICENSE": TOOLCHAIN_LICENSE,
                     "modules/example.com/pkg@v1.2.3/LICENSE": MODULE_LICENSE}
    for name in re_ev.BINARIES:
        payload = td / "artifacts/release-evidence/image-notices" / name
        for rel, text in payload_files.items():
            p = payload / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text)
        inv = {"schema_version": 1, "binary_sha256": bin_shas[name],
               "go_version": "1.27.4 (fixture)",
               "modules": [{"path": "example.com/pkg", "version": "v1.2.3",
                            "source_path": "example.com/pkg", "source_version": "v1.2.3",
                            "source_sum": "h1:fixture"}],
               "files": [{"path": rel, "sha256": sha_text(text)}
                         for rel, text in sorted(payload_files.items())]}
        (payload / "inventory.json").write_text(json.dumps(inv, indent=2) + "\n")
    # R3: a PATH shim standing in for the go toolchain -- the verifier's
    # `go version -m` module-set re-derivation is exercised against canned
    # build info matching the fixture inventories. Writing the marker
    # file below adds a module ONLY to the build info (not the inventory).
    fakebin = td / ".fakebin"
    fakebin.mkdir(parents=True, exist_ok=True)
    build_info = {"GoVersion": "go1.27.4", "Path": "example.com/main",
                  "Main": {"Path": "example.com", "Version": "(devel)"},
                  "Deps": [{"Path": "example.com/pkg", "Version": "v1.2.3", "Sum": "h1:fixture"}]}
    (fakebin / "modules.json").write_text(json.dumps(build_info))
    build_info["Deps"].append({"Path": "example.com/extra", "Version": "v9.9.9", "Sum": "h1:extra"})
    (fakebin / "extra.json").write_text(json.dumps(build_info))
    (fakebin / "go").write_text(
        '#!/bin/sh\n'
        'test "$1 $2 $3" = "version -m -json" || exit 1\n'
        'base=${0%/*}\n'
        'if test -f "$base/extra-mods"; then cat "$base/extra.json"; else cat "$base/modules.json"; fi\n')
    (fakebin / "go").chmod(0o755)

    cin_man = td / "artifacts/release-evidence/core-image-notices.json"
    cin_man.parent.mkdir(parents=True, exist_ok=True)
    cin_bytes = (json.dumps({"image_id": "sha256:" + "a" * 64, "files": [
        {"path": "/usr/share/licenses/yabanin/LICENSE",
         "sha256": sha_text("Apache License 2.0 project fixture\n")},
        {"path": "/usr/share/licenses/yabanin/NOTICE",
         "sha256": sha_text("project NOTICE fixture\n")}]},
        indent=1) + "\n").encode()
    cin_man.write_bytes(cin_bytes)

    da = td / "web/dashboard/dist/assets"
    da.mkdir(parents=True)
    (td / "web/dashboard/Dockerfile").write_bytes((td / "Dockerfile").read_bytes())
    (da / "app.js").write_bytes(APP_JS)
    (da / "app.css").write_text(APP_CSS)
    # R4-MAP-01/R2: canonical retained build artifacts -- the marker-carrying
    # raw twin and the map live OUTSIDE dist (nginx ships dist/ only).
    sm = td / "web/dashboard/dist-sourcemaps/assets"
    sm.mkdir(parents=True)
    (sm / "app.js").write_bytes(APP_JS_RAW_TWIN)
    (sm / "app.js.map").write_bytes(APP_MAP)
    deliv = td / "web/dashboard/dist/notices"
    deliv.mkdir(parents=True)
    (deliv / "lucide-react-LICENSE").write_text(LUC_LICENSE)
    (deliv / "clsx-LICENSE").write_text(CLSX_LICENSE)
    (td / "web/dashboard/src").mkdir(parents=True)
    (td / "web/dashboard/src/index.css").write_text(
        "@import '../../../design/astra-tokens.css';\nbody{margin:0}\n")
    (td / "design").mkdir()
    (td / "design/astra-tokens.css").write_text(TOKENS_CSS)
    luc = td / "web/dashboard/node_modules/lucide-react"
    luc.mkdir(parents=True)
    (luc / "LICENSE").write_text(LUC_LICENSE)
    clsx = td / "web/dashboard/node_modules/clsx"
    clsx.mkdir(parents=True)
    (clsx / "license").write_text(CLSX_LICENSE)

    ev = {"schema": "yabanin.release-evidence/1", "task_base": re_ev.TASK_BASE,
          "containers": [
              {"repo_ref": "redis", "role": "operator-pulled service",
               "index_digest": re_ev.REDIS_FIXED["digest"],
               "version": re_ev.REDIS_FIXED["version"], "license": "BSD-3-Clause",
               "notice": notice_rec(
                   "artifacts/release-evidence/upstream/redis/COPYING", BSD)},
              {"repo_ref": "pgvector/pgvector", "role": "operator-pulled service",
               "index_digest": PG_DIGEST, "version": "16.15",
               "license": "PostgreSQL License",
               "notice": notice_rec(
                   "artifacts/release-evidence/upstream/postgres/COPYRIGHT", PG_NOTICE)},
              {"repo_ref": "golang", "role": "build stage",
               "index_digest": GO_DIGEST, "version": "1.27.4",
               "license": "BSD-3-Clause (Go)",
               "notice": notice_rec(
                   "artifacts/release-evidence/upstream/golang/LICENSE", GO_LICENSE)},
              {"repo_ref": "alpine", "role": "runtime base (core image)",
               "index_digest": ALPINE_DIGEST, "version": "3.24.4",
               "license": "Alpine notice corpus",
               "notice": notice_rec(
                   "artifacts/release-evidence/upstream/alpine/COPYING", ALPINE_NOTICE)}],
          "negative_controls": {"redis_restricted_retained": {
              "version": re_ev.REDIS_NEGATIVE["version"],
              "index_digest": re_ev.REDIS_NEGATIVE["digest"],
              # R4-NC-PROOF-01: the canonical upstream path is the only
              # accepted negative-control license location; restricted.txt
              # stays the separate marker-section fixture only.
              "license_path": re_ev.REDIS_NEGATIVE["license_path"]}},
          "assets": {
              "dist_files": [
                  {"path": "web/dashboard/dist/assets/app.js",
                   "sha256": hashlib.sha256(APP_JS).hexdigest()},
                  {"path": "web/dashboard/dist/assets/app.css",
                   "sha256": sha_text(APP_CSS)},
                  # R2: delivered notices are emitted files INSIDE dist
                  {"path": "web/dashboard/dist/notices/lucide-react-LICENSE",
                   "sha256": sha_text(LUC_LICENSE)},
                  {"path": "web/dashboard/dist/notices/clsx-LICENSE",
                   "sha256": sha_text(CLSX_LICENSE)}],
              # R4-MAP-01: generator-shaped chunk record -- the successful
              # map-binding fields of dashboard_evidence._chunk_record, not
              # just a twin sha equal to the dist sha.
              "chunk_origins": {"assets/app.js.map": {
                  "twin_rel": "web/dashboard/dist/assets/app.js",
                  "equivalence": re_ev.dashboard_evidence.MAP_EQUIVALENCE,
                  "twin_sha256": hashlib.sha256(APP_JS).hexdigest(),
                  "map_twin_raw_sha256": hashlib.sha256(APP_JS_RAW_TWIN).hexdigest(),
                  "map_name": "app.js.map",
                  "map_sha256": hashlib.sha256(APP_MAP).hexdigest(),
                  "sources": ["../../node_modules/lucide-react/dist/esm/icon.js",
                              "../../node_modules/clsx/dist/clsx.js"],
                  "strip_error": "",
                  "dist_twin_exists": True,
                  "dist_twin_matches": True,
                  "has_lucide": True,
                  "packages": ["clsx", "lucide-react"]}},
              "contributing_packages": [
                  {"name": "clsx", "version": "2.1.1",
                   "legal_files": [{"file": "web/dashboard/node_modules/clsx/license",
                                    "sha256": sha_text(CLSX_LICENSE)}]},
                  {"name": "lucide-react", "version": "0.544.0",
                   "legal_files": [{"file": "web/dashboard/node_modules/lucide-react/LICENSE",
                                    "sha256": sha_text(LUC_LICENSE)}]}],
              "lucide_react": {"legal_file_hashes": {"LICENSE": sha_text(LUC_LICENSE)}},
              "css_token_reach": [{"file": "web/dashboard/dist/assets/app.css",
                                   "token_count": 2,
                                   "tokens_sample": ["--astra-duration", "--astra-ink"]}],
              # R4-NPM-01: bound delivery carries the verifiable
              # package-to-delivered-notice manifest (files written below)
              "notice_delivery": {"status": "bound", "manifest": [
                  {"package": "lucide-react",
                   "path": "web/dashboard/dist/notices/lucide-react-LICENSE",
                   "sha256": sha_text(LUC_LICENSE)},
                  {"package": "clsx",
                   "path": "web/dashboard/dist/notices/clsx-LICENSE",
                   "sha256": sha_text(CLSX_LICENSE)}]},
              "bindings": {"astra_tokens": {"ok": True}},
              "unresolved": []},
          "notice_reconciliation": {"notice_sha256": sha_text(NOTICE)},
          "provenance": {"added": []},
          "distribution": {
              "binaries": [{"name": n, "sha256": bin_shas[n]} for n in re_ev.BINARIES],
              "notice_draft": "dist/release/THIRD-PARTY-NOTICES.md",
              "notice_draft_sha256": sha_text(DRAFT),
              "notice_draft_identifier_only": True,
              # R4-IMAGE-01: exactly the three built subjects, each with an
              # immutable image ID and platform
              "quickstart_images": [
                  {"name": "core", "image_id": "sha256:" + "a" * 64,
                   "platform": "linux/amd64"},
                  {"name": "mock-provider", "image_id": "sha256:" + "c" * 64,
                   "platform": "linux/amd64"},
                  {"name": "dashboard", "image_id": "sha256:" + "d" * 64,
                   "platform": "linux/amd64"}],
              # identity must BE the Core subject above (same image id and
              # platform), not a detached self-consistent record
              "core_image_notices": {
                  "image_id": "sha256:" + "a" * 64,
                  "platform": "linux/amd64",
                  "manifest_rel": "artifacts/release-evidence/core-image-notices.json",
                  "manifest_sha256": hashlib.sha256(cin_bytes).hexdigest()},
              # R3: filled after the fixture git commit (real head +
              # tree hash + re-derived build inputs)
              "quickstart_build": None,
              "recipe_sha256": sha_text(recipe_bytes)},
          "quickstart_build": None,
          "freshness": {"head": "f" * 40, "dirty": {}, "untracked": {}},
          "reviews": {a: {"approved": False, "owner": "pending human review",
                          "reason": "pending human review",
                          "evidence": "pending human review"} for a in re_ev.AREAS}}
    # R4-FIXTURE-01: bind the intact fixture FIRST, then let the mutator
    # corrupt it -- a mutator can no longer have wrong/restored values
    # silently repaired by the binding step (the original false pass).
    bind_real_upstream_fixtures(td, ev)
    # R3: a real (throwaway) git history so the candidate build record
    # binds to an actual head + tree object hash, like the real repo
    import subprocess as _sp
    _g = ["git", "-C", str(td)]
    _sp.run(_g + ["init", "-q"], check=True)
    _sp.run(_g + ["add", "-A"], check=True)
    _sp.run(_g + ["-c", "user.name=fixture", "-c", "user.email=fixture@example.invalid",
                  "commit", "-q", "-m", "fixture candidate"], check=True)
    head = _sp.run(_g + ["rev-parse", "HEAD"], check=True, capture_output=True,
                   text=True).stdout.strip()
    tree = _sp.run(_g + ["rev-parse", "HEAD^{tree}"], check=True,
                   capture_output=True, text=True).stdout.strip()
    ev["freshness"]["head"] = head
    build = {"head": head, "tree_sha256": tree,
             "inputs": {"compose_build_services":
                        sorted(svc for svc, rec in re_ev._compose_services(td).items()
                               if rec["build"]),
                        "pinned_builders": sorted([list(x) for x in
                                                   re_ev.pinned_builders(td)])},
             "platforms": {n: "linux/amd64"
                           for n in re_ev._QUICKSTART_IMAGE_SUBJECTS},
             "subjects": fixture_subjects(td, ev, head)}
    ev["distribution"]["quickstart_build"] = build
    ev["quickstart_build"] = build
    if ev_mutator:
        ev_mutator(td, ev)
    return td, ev

def run_verify(td, ev):
    # R3: the fixture's go shim rides first on PATH so the build-info
    # module-set derivation sees the canned `go version -m` output
    import os
    saved = os.environ.get("PATH") or ""
    os.environ["PATH"] = str(td / ".fakebin") + os.pathsep + saved
    try:
        out = [f for f in re_ev.verify(td, ev, with_fingerprint=False)
               if not f.startswith(("provenance:", "source_sha256",
                                    "freshness:"))]
    finally:
        os.environ["PATH"] = saved
    return out


class ReleaseEvidenceNegativeControls(unittest.TestCase):
    maxDiff = None

    def verify_fails(self, mutator, *needles):
        with tempfile.TemporaryDirectory() as td:
            fails = run_verify(*build_fixture(Path(td), mutator))
            self.assertTrue(fails, "expected failures, got none")
            for needle in needles:
                self.assertTrue(any(needle in f for f in fails),
                                "no failure mentions %r; got: %s" % (needle, fails))
            return fails

    def test_intact_fixture_passes(self):
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(run_verify(*build_fixture(Path(td))), [])

    def test_missing_notice_fails(self):
        self.verify_fails(
            lambda td, ev: ev["containers"][0].__setitem__("notice", None),
            "notice file missing")

    def test_wrong_redis_version_fails(self):
        self.verify_fails(
            lambda td, ev: ev["containers"][0].__setitem__("version", "7.4.12"),
            "7.2 branch")

    def test_wrong_digest_fails(self):
        self.verify_fails(
            lambda td, ev: ev["containers"][0].__setitem__(
                "index_digest", "sha256:" + "0" * 64),
            "no evidence record")

    def test_missing_emitted_asset_fails(self):
        self.verify_fails(
            lambda td, ev: ev["assets"].__setitem__("dist_files", []),
            "emitted file missing from evidence")

    def test_forbidden_context_annotation_is_machine_checked(self):
        # An annotation whose section strings do not occur in the notice text
        # must not rescue the hit: it stays a hard forbidden failure.
        self.verify_fails(
            lambda td, ev: (
                ev["containers"][0].__setitem__(
                    "notice",
                    notice_rec("artifacts/release-evidence/upstream/restricted.txt", RSAL)),
                ev["containers"][0].__setitem__(
                    "notice_forbidden_contexts",
                    [{"markers": ["RSAL", "SSPL"], "sections": ["Not A Real Section"]}]))[-1],
            "notice text hits forbidden markers")

        # Sections genuinely present as full bounded lines downgrade the hit
        # to a named pending gap (still a failure, never an approval).
        with tempfile.TemporaryDirectory() as td:
            td, ev = build_fixture(Path(td))
            ev["containers"][0]["notice"] = notice_rec(
                "artifacts/release-evidence/upstream/restricted.txt", RSAL)
            ev["containers"][0]["notice_forbidden_contexts"] = [
                {"markers": ["RSAL", "SSPL"],
                 "sections": ["File: redis-license.txt (upstream 7.4.12)",
                              "File: server-side.txt (dual licensing)"]}]
            lines = run_verify(td, ev)
            self.assertFalse(any("notice text hits forbidden markers" in f for f in lines),
                             lines)
            self.assertTrue(
                any(f.startswith("PENDING gap: containers: redis:")
                    and "scoped decision pending" in f and "RSAL" in f for f in lines),
                lines)

        # A deliberate extra marker past the last closing boundary sits in an
        # unbounded trailing section that covers nothing: hard failure.
        with tempfile.TemporaryDirectory() as td:
            td, ev = build_fixture(Path(td))
            extra = RSAL + ("    File: stray-addendum.txt (trailing, unbounded)\n"
                            "Commons Clause fixture line\n")
            (td / "artifacts/release-evidence/upstream/restricted.txt").write_text(extra)
            ev["containers"][0]["notice"] = notice_rec(
                "artifacts/release-evidence/upstream/restricted.txt", extra)
            ev["containers"][0]["notice_forbidden_contexts"] = [
                {"markers": ["RSAL", "SSPL", "Commons-Clause"],
                 "sections": ["File: redis-license.txt (upstream 7.4.12)",
                              "File: server-side.txt (dual licensing)"]}]
            lines = run_verify(td, ev)
            self.assertTrue(any("notice text hits forbidden markers" in f for f in lines),
                            lines)

    def test_contributing_package_set_bound_both_directions(self):
        # Deleting the entire array must fail: origins naming an
        # unrecorded package must fail, and a record no origin contributes
        # must fail.
        self.verify_fails(
            lambda td, ev: ev["assets"].__setitem__("contributing_packages", []),
            "contributing_packages missing or empty", "unrecorded package")
        self.verify_fails(
            lambda td, ev: ev["assets"]["chunk_origins"]["assets/app.js.map"]
                .__setitem__("packages", ["clsx", "lucide-react", "d3-array"]),
            "labels name package absent from its map sources: d3-array")
        self.verify_fails(
            lambda td, ev: ev["assets"]["contributing_packages"].append(
                {"name": "left-pad", "version": "1.3.0",
                 "legal_files": [{"file": "web/dashboard/node_modules/left-pad/LICENSE",
                                  "sha256": sha_text(CLSX_LICENSE)}]}),
            "absent from map sources: left-pad")

    def test_contributing_package_version_and_legal_text_required(self):
        self.verify_fails(
            lambda td, ev: ev["assets"]["contributing_packages"][0]
                .__setitem__("version", ""),
            "no concrete version: clsx")
        self.verify_fails(
            lambda td, ev: ev["assets"]["contributing_packages"][1]
                .__setitem__("version", "latest"),
            "no concrete version: lucide-react")
        self.verify_fails(
            lambda td, ev: ev["assets"]["contributing_packages"][0]
                .__setitem__("legal_files", []),
            "records no legal text: clsx")

    def test_stale_evidence_head_with_correct_expected_head(self):
        # An explicit --expected-head is an additional assertion,
        # never a substitute for the evidence's own recorded HEAD.
        with tempfile.TemporaryDirectory() as td:
            td, ev = build_fixture(Path(td))
            head = re_ev.git_state()["head"]
            lines = re_ev.freshness_failures(td, ev, expected_head=head)
            self.assertTrue(any("does not match the evidence-recorded HEAD" in f
                                for f in lines), lines)
            self.assertFalse(any("explicit expected HEAD" in f for f in lines), lines)
            ev["freshness"]["head"] = head
            ev["head"] = head
            lines = re_ev.freshness_failures(td, ev, expected_head=head)
            self.assertFalse(any("evidence-recorded HEAD" in f for f in lines), lines)
            self.assertFalse(any("explicit expected HEAD" in f for f in lines), lines)
            self.assertFalse(any("top-level head disagrees" in f for f in lines), lines)
            lines = re_ev.freshness_failures(td, ev, expected_head="0" * 64)
            self.assertTrue(any("does not match the explicit expected HEAD" in f
                                for f in lines), lines)
            ev["head"] = "e" * 40
            lines = re_ev.freshness_failures(td, ev, expected_head=head)
            self.assertTrue(any("top-level head disagrees" in f for f in lines), lines)

    def test_recipe_content_mutation_fails_hash_binding(self):
        # Recipe content mutated while git_commit stays unchanged
        # must fail the sha binding; a zeroed evidence recipe sha must fail.
        with tempfile.TemporaryDirectory() as td:
            td, ev = build_fixture(Path(td))
            rp = td / "dist/release/recipe.json"
            rec = json.loads(rp.read_text())
            rec["git_commit"] = re_ev.git_state()["head"]  # commit id stays correct
            rec["go_version"] = "go9.9.9 (mutated)"
            rp.write_text(json.dumps(rec) + "\n")
            lines = re_ev.freshness_failures(td, ev)
            self.assertTrue(any("recipe.json sha drift" in f for f in lines), lines)
            self.assertFalse(any("recipe git_commit does not match" in f for f in lines),
                             lines)
        with tempfile.TemporaryDirectory() as td:
            td, ev = build_fixture(Path(td))
            ev["distribution"]["recipe_sha256"] = "0" * 64
            lines = re_ev.freshness_failures(td, ev)
            self.assertTrue(any("recipe.json sha drift" in f for f in lines), lines)
        with tempfile.TemporaryDirectory() as td:
            td, ev = build_fixture(Path(td))
            ev["distribution"].pop("recipe_sha256")
            lines = re_ev.freshness_failures(td, ev)
            self.assertTrue(any("records no recipe.json sha" in f for f in lines), lines)

    GOOD_DF = ("FROM node:20-alpine@sha256:%s AS builder\n"
               "WORKDIR /src/web/dashboard\n"
               "RUN npm run build\n"
               "FROM nginx:alpine@sha256:%s\n"
               "COPY --from=builder /src/web/dashboard/dist /usr/share/nginx/html\n"
               "COPY web/dashboard/nginx.conf /etc/nginx/conf.d/default.conf\n"
               % ("b" * 64, "c" * 64))

    def test_dashboard_runtime_retention_proof(self):
        rec = {"repo_ref": "node",
               "retained_check": "dashboard-runtime-dist-only"}
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "web/dashboard").mkdir(parents=True)
            (td / "web/dashboard/Dockerfile").write_text(self.GOOD_DF)
            # an unbound retention proof is never proof: a wrong repo_ref or
            # a missing repo_ref fails binding before any file check
            for unbound in ({"repo_ref": "redis",
                             "retained_check": "dashboard-runtime-dist-only"},
                            {"retained_check": "dashboard-runtime-dist-only"}):
                f = re_ev._retention_failures(td, unbound)
                self.assertTrue(any("not bound" in x for x in f), f)
            self.assertEqual(re_ev._retention_failures(td, rec), [])
            # node as the final/runtime stage -> retained -> hard failure
            (td / "web/dashboard/Dockerfile").write_text(
                self.GOOD_DF.split("FROM nginx")[0])
            self.assertTrue(any("final/runtime stage" in f
                                for f in re_ev._retention_failures(td, rec)))
            # copying builder content outside the dist tree -> hard failure
            (td / "web/dashboard/Dockerfile").write_text(
                self.GOOD_DF + "COPY --from=builder /usr/local/lib/node_modules "
                "/node_modules\n")
            self.assertTrue(any("outside the dist tree" in f
                                for f in re_ev._retention_failures(td, rec)))
            # same violation via the numeric stage index
            (td / "web/dashboard/Dockerfile").write_text(
                self.GOOD_DF.replace("--from=builder", "--from=0")
                + "COPY --from=0 /etc/nginx /copied\n")
            self.assertTrue(any("outside the dist tree" in f
                                for f in re_ev._retention_failures(td, rec)))
            # nothing copied from the builder at all -> unbound -> failure
            (td / "web/dashboard/Dockerfile").write_text(
                self.GOOD_DF.replace(
                    "COPY --from=builder /src/web/dashboard/dist "
                    "/usr/share/nginx/html\n", ""))
            self.assertTrue(any("copies nothing" in f
                                for f in re_ev._retention_failures(td, rec)))
            # missing Dockerfile -> unproven -> failure
            (td / "web/dashboard/Dockerfile").unlink()
            self.assertTrue(any("characterization unproven" in f
                                for f in re_ev._retention_failures(td, rec)))

    NODE_LICENSE = ("Node.js binary distribution license\n"
                    "MIT-style license body\n"
                    "    ----------------------------------------------------------------------\n"
                    "\n"
                    "    File: aclocal.m4 (only for ICU4C)\n"
                    "GNU General Public License, version 2, with the autoconf "
                    "exception\n"
                    "    ----------------------------------------------------------------------\n"
                    "\n"
                    "    File: config.guess (only for ICU4C)\n"
                    "GNU General Public License, version 3, with the autoconf "
                    "exception\n"
                    "    ----------------------------------------------------------------------\n")

    def _node_record(self, td, ctx_retained="dashboard-runtime-dist-only",
                     record_retained=False):
        import hashlib
        rel = "artifacts/upstream/node-LICENSE"
        data = self.NODE_LICENSE.encode()
        (td / rel).parent.mkdir(parents=True, exist_ok=True)
        (td / rel).write_bytes(data)
        ctx = {"markers": ["GPL"],
               "sections": ["File: aclocal.m4 (only for ICU4C)",
                            "File: config.guess (only for ICU4C)"],
               "detail": "ICU4C autoconf aux notices"}
        if ctx_retained is not None:
            ctx["retained_check"] = ctx_retained
        rec = {"repo_ref": "node", "version": "20.20.2",
               "notice": {"path": rel, "sha256": hashlib.sha256(data).hexdigest()},
               "notice_forbidden_contexts": [ctx]}
        if record_retained:
            rec["retained_check"] = "dashboard-runtime-dist-only"
        return rec

    def test_retention_check_unknown_value_is_hard_failure(self):
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "web/dashboard").mkdir(parents=True)
            (td / "web/dashboard/Dockerfile").write_text(self.GOOD_DF)
            for bad in ({"repo_ref": "node",
                         "retained_check": "trust-me-it-is-not-retained"},
                        {"repo_ref": "node", "retained_check": ""},
                        {"repo_ref": "node"}):
                f = re_ev._retention_failures(td, bad)
                self.assertTrue(any("unsupported retained_check" in x for x in f), f)
            # unbound records fail binding before the value is even assessed
            for unbound in ({"repo_ref": "redis", "retained_check": "x"},
                            {"retained_check": "x"}):
                f = re_ev._retention_failures(td, unbound)
                self.assertTrue(any("not bound" in x for x in f), f)
            self.assertEqual(
                re_ev._retention_failures(td, {"repo_ref": "node",
                                               "retained_check":
                                               "dashboard-runtime-dist-only"}), [])

    def test_retention_check_binds_to_explaining_context(self):
        label = "builder node:20-alpine@sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "web/dashboard").mkdir(parents=True)
            (td / "web/dashboard/Dockerfile").write_text(self.GOOD_DF)
            # Dockerfile-only closure is rejected. The source
            # proof passing keeps the classification OPEN as a pending gap
            # naming the final-image inspection contract; no hard failures.
            f = re_ev._notice_failures(td, label, self._node_record(td))
            self.assertTrue(any(x.startswith("PENDING gap")
                                and "final nginx image inspection is pending" in x
                                for x in f), f)
            self.assertEqual([x for x in f if not x.startswith("PENDING gap")], [], f)
            # record-level shortcut is not honored: placement failure plus the
            # pending gap return (annotation without a bound proof)
            f = re_ev._notice_failures(td, label,
                                       self._node_record(td, ctx_retained=None,
                                                         record_retained=True))
            self.assertTrue(any("record-level retained_check" in x for x in f), f)
            self.assertTrue(any(x.startswith("PENDING gap") for x in f), f)
            # unsupported context value: hard failure, never proof
            f = re_ev._notice_failures(td, label,
                                       self._node_record(td, ctx_retained="waive-all"))
            self.assertTrue(any("unsupported retained_check" in x for x in f), f)
            self.assertTrue(any("hits forbidden markers" in x for x in f), f)
            # proof itself failing (node retained as runtime stage)
            (td / "web/dashboard/Dockerfile").write_text(
                self.GOOD_DF.split("FROM nginx")[0])
            f = re_ev._notice_failures(td, label, self._node_record(td))
            self.assertTrue(any("final/runtime stage" in x for x in f), f)

    def test_real_shape_context_only_retained_check_pending_gap(self):
        # Real record shape: retained_check lives only on the explaining
        # context (record-level retained_check is rejected elsewhere); with
        # no final_image_check the only outcome is the final-image PENDING
        # gap -- never an unsupported-None or forbidden-marker error.
        label = "builder node:20-alpine@sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "web/dashboard").mkdir(parents=True)
            (td / "web/dashboard/Dockerfile").write_text(self.GOOD_DF)
            rec = self._node_record(td)
            self.assertNotIn("retained_check", rec)
            self.assertEqual(rec["notice_forbidden_contexts"][0]["retained_check"],
                             "dashboard-runtime-dist-only")
            f = re_ev._notice_failures(td, label, rec)
            self.assertEqual(len(f), 1, f)
            self.assertTrue(f[0].startswith("PENDING gap: containers: "), f)
            self.assertIn("final nginx image inspection is pending", f[0])
            self.assertNotIn("unsupported", f[0])
            self.assertNotIn("forbidden markers", f[0])

    def test_compose_redis_pin_is_exact_subject(self):
        with tempfile.TemporaryDirectory() as td:
            td, ev = build_fixture(td)
            self.assertEqual(re_ev.container_failures(Path(td), ev), [])
            compose = Path(td) / "deploy/quickstart/docker-compose.yml"
            df = compose.read_text()
            compose.write_text(df.replace("redis:7.2-alpine@", "redis:7.4-alpine@"))
            self.assertTrue(any("instead of the exact redis:7.2-alpine subject" in x
                                for x in re_ev.container_failures(Path(td), ev)))
            compose.write_text(df.replace("redis:7.2-alpine@" + re_ev.REDIS_FIXED["digest"],
                                          "redis:7.2-alpine"))
            self.assertTrue(any("redis service image is not digest-pinned" in x
                                for x in re_ev.container_failures(Path(td), ev)))
            compose.write_text(df.replace(re_ev.REDIS_FIXED["digest"], "sha256:" + "0" * 64))
            self.assertTrue(any("is not the fixed 7.2.17 digest" in x
                                for x in re_ev.container_failures(Path(td), ev)))

    def test_compose_redis_effective_image_scalar(self):
        # R4-COMPOSE-01: only the EFFECTIVE services.redis.image scalar
        # counts. Original false results (independently reproduced): a
        # commented correct pin passed while the service was unpinned, and
        # a quoted valid pin was rejected as not digest-pinned.
        with tempfile.TemporaryDirectory() as tmp:
            td, ev = build_fixture(tmp)
            compose = Path(td) / "deploy/quickstart/docker-compose.yml"
            pinned_value = "redis:7.2-alpine@" + re_ev.REDIS_FIXED["digest"]
            pinned = "    image: " + pinned_value
            good = compose.read_text()
            # a commented correct pin must not satisfy an unpinned service
            compose.write_text(good.replace(pinned, "    # image: " + pinned_value
                                            + "\n    image: redis:7.2-alpine"))
            self.assertTrue(any("redis service image is not digest-pinned" in x
                                for x in re_ev.container_failures(td, ev)))
            # isolated: the comment must not rescue a wrong active digest either
            compose.write_text(good.replace(pinned, "    # image: " + pinned_value
                                            + "\n    image: redis:7.2-alpine@"
                                            + "sha256:" + "0" * 64))
            self.assertTrue(any("is not the fixed 7.2.17 digest" in x
                                for x in re_ev.container_failures(td, ev)))
            # a quoted valid pin is an effective scalar and must pass
            compose.write_text(good.replace(pinned, '    image: "' + pinned_value + '"'))
            self.assertEqual(re_ev.container_failures(td, ev), [])
            # duplicate effective image keys are ambiguous, in either order
            compose.write_text(good.replace(pinned, pinned + "\n    image: redis:7.2-alpine"))
            self.assertTrue(any("docker compose config rejected a duplicate mapping key" in x
                                for x in re_ev.container_failures(td, ev)))
            compose.write_text(good.replace(pinned, "    image: redis:7.2-alpine\n"
                                            + pinned))
            self.assertTrue(any("docker compose config rejected a duplicate mapping key" in x
                                for x in re_ev.container_failures(td, ev)))
            # variable interpolation is not an immutable pin
            compose.write_text(good.replace(pinned, "    image: ${REDIS_IMAGE}"))
            self.assertTrue(any("variable, not an immutable pin" in x
                                for x in re_ev.container_failures(td, ev)))
            # intact fixture still passes with the effective-scalar reader
            compose.write_text(good)
            self.assertEqual(re_ev.container_failures(td, ev), [])

    def test_compose_real_tree_exactly_one_effective_image(self):
        # R4-COMPOSE-01 regression against the ACTUAL checked-in compose
        # (the file whose sha256 59a084718e80a3a96dab8b26bb2c641c1658ea26
        # c3b43ee0b30993ecf048207b previously yielded zero images and a
        # nonzero failure): the real file keeps blank lines inside services
        # and its redis service yields EXACTLY ONE effective direct image
        # and zero pin failures. Do not relax this to >=1.
        root = re_ev.ROOT
        compose = root / "deploy/quickstart/docker-compose.yml"
        text = compose.read_text()
        # keep the regression surface: blank line + comment block inside the
        # services block of the real file
        self.assertIn("\n\n  redis:\n", text)
        self.assertRegex(text, r"services:\n(?:[^\n]*\n)*?\n  #")
        pinned_value = "redis:7.2-alpine@" + re_ev.REDIS_FIXED["digest"]
        self.assertEqual(re_ev._compose_service_images(root, "redis"), [pinned_value])
        self.assertEqual(re_ev._redis_pin_failures(root), [])
        # R2: the expected-subject map covers EXACTLY the real pulled
        # services (migrate/seed/yabanin build locally and are exempt; a
        # new pulled service or a removed one must update the map)
        pulled = {n for n, s in re_ev._compose_services(root).items()
                  if not s["build"]}
        self.assertEqual(pulled, set(re_ev._COMPOSE_SERVICE_SUBJECTS), pulled)
        for n, subj in re_ev._COMPOSE_SERVICE_SUBJECTS.items():
            images = re_ev._compose_service_images(root, n)
            self.assertEqual(len(images), 1, (n, images))
            self.assertTrue(images[0].startswith(subj), (n, images))
        ps = re_ev.pinned_services(root)
        self.assertEqual(ps.get("redis"), [re_ev.REDIS_FIXED["digest"]])
        self.assertEqual(ps.get("postgres"), [PG_DIGEST])
        self.assertEqual(ps.get("db-app-role"), [PG_DIGEST])
        for locally_built in ("migrate", "seed", "yabanin", "dashboard", "mock-openai"):
            self.assertNotIn(locally_built, ps)

    def test_shipped_compose_is_verifiable_with_service_profiles(self):
        root = Path(__file__).resolve().parents[2]
        # Exercise the same release decision that consumes the effective Compose model.
        expected_builds = ["dashboard", "migrate", "mock-openai", "seed", "yabanin"]
        inputs = {"compose_build_services": expected_builds,
                  "pinned_builders": sorted(map(list, re_ev.pinned_builders(root)))}
        self.assertEqual(re_ev._quickstart_input_failures(root, inputs), [])
        services = re_ev._compose_services(root)
        self.assertEqual({k for k, v in services.items() if v["build"]},
                         {"yabanin", "migrate", "seed", "mock-openai", "dashboard"})
        self.assertEqual({k for k, v in services.items() if not v["build"]},
                         {"redis", "postgres", "db-app-role"})

    def test_compose_merge_and_quoted_build_are_classified_by_compose(self):
        with tempfile.TemporaryDirectory() as tmp:
            td, ev = build_fixture(tmp)
            compose = td / "deploy/quickstart/docker-compose.yml"
            source = compose.read_text()
            for build in ('    "build": .', '    <<: *localbuild'):
                with self.subTest(build=build):
                    compose.write_text("x-build: &localbuild {build: .}\n" + source.replace(
                        "  postgres:\n", "  postgres:\n" + build + "\n"))
                    self.assertTrue(re_ev._compose_services(td)["postgres"]["build"])
                    self.assertTrue(any("postgres" in f and "build" in f for f in
                                        re_ev.container_failures(td, ev)))

    def test_compose_blank_lines_never_reset_services_state(self):
        # Isolated defect: a blank or full-comment line inside services: must
        # not deactivate the enclosing service (the pre-fix reader returned
        # ZERO images for a compose shaped like the real one).
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            (td / "deploy/quickstart").mkdir(parents=True)
            pinned_value = "redis:7.2-alpine@" + re_ev.REDIS_FIXED["digest"]
            (td / "deploy/quickstart/docker-compose.yml").write_text(
                "name: blank-line-fixture\n"
                "\n"
                "# header comment block\n"
                "\n"
                "services:\n"
                "\n"
                "  # comment between services: and the first service\n"
                "\n"
                "  redis:\n"
                "\n"
                "    # comment between the service key and its image\n"
                "\n"
                "    image: " + pinned_value + "\n"
                "\n"
                "  other:\n"
                "    build:\n"
                "      context: .\n"
                "\n"
                "    image: other-local\n"
                "\n"
                "networks:\n"
                "  default:\n")
            self.assertEqual(re_ev._compose_service_images(td, "redis"), [pinned_value])
            self.assertEqual(re_ev._redis_pin_failures(td), [])
            # the trailing unpinned image belongs to a build: service (local
            # build), so it is exempt from the pull-pin gate, and a service
            # declared after blank/comment lines is still parsed
            self.assertEqual(re_ev._compose_service_images(td, "other"), ["other-local"])

    def test_compose_nested_image_keys_are_not_service_images(self):
        # R4-COMPOSE-01: ONLY direct services.<svc>.image keys at the service
        # child depth count -- a nested image: under environment: must never
        # satisfy the pin nor create a phantom pinned service, digest-bearing
        # or not.
        with tempfile.TemporaryDirectory() as tmp:
            td, ev = build_fixture(tmp)
            compose = Path(td) / "deploy/quickstart/docker-compose.yml"
            good = compose.read_text()
            nested = "      image: not-the-service-image\n"
            self.assertIn(nested, good)
            # a digest-bearing nested image key creates no phantom pin
            compose.write_text(good.replace(
                nested, "      image: nested/sneaky@sha256:" + "9" * 64 + "\n"))
            self.assertEqual(re_ev.container_failures(td, ev), [])
            self.assertNotIn("nested/sneaky", str(re_ev.pinned_services(td)))
            # nested-only redis (direct image demoted into environment:) ->
            # zero DIRECT images, the pin gate fails with (0 found)
            pinned_value = "redis:7.2-alpine@" + re_ev.REDIS_FIXED["digest"]
            compose.write_text(good.replace(
                "    image: " + pinned_value + "\n",
                "    environment:\n      image: " + pinned_value + "\n"))
            fails = re_ev.container_failures(td, ev)
            self.assertTrue(any("not a single effective image value (0 found)" in x
                                for x in fails), fails)
            compose.write_text(good)
            self.assertEqual(re_ev.container_failures(td, ev), [])

    def test_compose_service_row_binding(self):
        # R2-1: a pulled service binds its digest to EXACTLY ONE subject
        # row, and repository, digest, notice and subject-specific checks
        # all bind to THAT row. Original false result: pg.image pointed at
        # the exact redis pin while the pgvector record lost its notice --
        # the redis notice was read for the pg service and everything
        # passed; a duplicated pinned pg.image also passed; a pulled
        # service with zero parsed images executed zero checks.
        with tempfile.TemporaryDirectory() as tmp:
            td, ev = build_fixture(tmp)
            compose = Path(td) / "deploy/quickstart/docker-compose.yml"
            good = compose.read_text()
            pg_pin = "pgvector/pgvector:pg16@" + PG_DIGEST
            no_notice = [dict(r) for r in ev["containers"]]
            for r in no_notice:
                if r["repo_ref"] == "pgvector/pgvector":
                    r.pop("notice")
            ev2 = {"containers": no_notice}
            # R3: a foreign REPOSITORY carrying this subject's digest is
            # not a binding (postgres.image renamed to the redis repo at
            # the pgvector pin)
            compose.write_text(good.replace(
                pg_pin, "pgvector/evil@" + PG_DIGEST))
            fails = re_ev.container_failures(td, ev2)
            self.assertTrue(any("foreign repository at this digest is not a binding"
                                in x for x in fails), fails)
            # pg pulls the EXACT redis pin under its own repository: the
            # redis record answers the digest but is not the pgvector
            # subject row -- the redis notice must NOT be inherited, even
            # with the notice gone
            compose.write_text(good.replace(
                pg_pin, "pgvector/pgvector:pg16@" + re_ev.REDIS_FIXED["digest"]))
            fails = re_ev.container_failures(td, ev2)
            self.assertTrue(any("cross-subject binding refused" in x for x in fails),
                            fails)
            # R3: deleting an expected pulled service entirely (or hiding
            # it behind build:) removes its checks and must fail
            compose.write_text(good.replace(
                '  postgres:\n    image: pgvector/pgvector:pg16@' + PG_DIGEST
                + '\n    environment:\n      # a nested image key is not the '
                'direct service image\n      image: not-the-service-image\n', ""))
            fails = re_ev.container_failures(td, ev)
            self.assertTrue(any("expected pulled service postgres is absent" in x
                                for x in fails), fails)
            # hiding the same service behind a direct build: is the same
            # escape and must fail the same way
            compose.write_text(good.replace(
                '  postgres:\n    image: pgvector/pgvector:pg16@' + PG_DIGEST
                + '\n    environment:\n      # a nested image key is not the '
                'direct service image\n      image: not-the-service-image\n',
                '  postgres:\n    build:\n      context: .\n'))
            fails = re_ev.container_failures(td, ev)
            self.assertTrue(any("expected pulled service postgres is absent" in x
                                for x in fails), fails)
            # duplicated, correctly pinned pg.image is ambiguity
            compose.write_text(good.replace(
                "    image: " + pg_pin, "    image: " + pg_pin + "\n    image: " + pg_pin))
            fails = re_ev.container_failures(td, ev)
            self.assertTrue(any("docker compose config rejected a duplicate mapping key" in x
                                for x in fails), fails)
            # a pulled service with zero effective images runs real checks
            compose.write_text(good.replace("    image: " + pg_pin + "\n", "", 1))
            fails = re_ev.container_failures(td, ev)
            self.assertTrue(any("postgres" in x and "exactly one effective image (found 0)" in x
                                for x in fails), fails)
            # with the correct pin, the notice still binds to the pg row
            # itself: dropping it fails
            compose.write_text(good)
            fails = re_ev.container_failures(td, ev2)
            self.assertTrue(any("postgres: notice file missing" in x for x in fails),
                            fails)
            # intact fixture still passes
            self.assertEqual(re_ev.container_failures(td, ev), [])

    def test_compose_commented_pin_does_not_satisfy_pulled_service(self):
        # R4-COMPOSE-01 for the non-redis pulled services: a commented-out
        # digest pin is not an effective pin (the old file-wide regex reader
        # counted it), and a QUOTED pin is (the old reader could not see it).
        with tempfile.TemporaryDirectory() as tmp:
            td, ev = build_fixture(tmp)
            compose = Path(td) / "deploy/quickstart/docker-compose.yml"
            good = compose.read_text()
            pg_line = "    image: pgvector/pgvector:pg16@" + PG_DIGEST + "\n"
            self.assertIn(pg_line, good)
            compose.write_text(good.replace(pg_line,
                                            "    # image: pgvector/pgvector:pg16@"
                                            + PG_DIGEST + "\n"
                                            "    image: pgvector/pgvector:pg16\n"))
            fails = re_ev.container_failures(td, ev)
            self.assertTrue(any("'pgvector/pgvector:pg16' is not an effective digest pin"
                                in x for x in fails), fails)
            compose.write_text(good.replace(
                pg_line, '    image: "pgvector/pgvector:pg16@' + PG_DIGEST + '"\n'))
            self.assertEqual(re_ev.container_failures(td, ev), [])
            compose.write_text(good)
            self.assertEqual(re_ev.container_failures(td, ev), [])

    def test_redis_record_gates_isolated(self):
        with tempfile.TemporaryDirectory() as td:
            td, ev = build_fixture(td)
            redis = next(r for r in ev["containers"] if r.get("repo_ref") == "redis")
            others = [r for r in ev["containers"] if r.get("repo_ref") != "redis"]
            fails = re_ev.container_failures(Path(td), dict(ev, containers=others))
            self.assertTrue(any("containers: redis: required evidence record missing" in x
                                for x in fails))
            fails = re_ev.container_failures(Path(td), dict(
                ev, containers=others + [dict(redis, version="7.2.20")]))
            self.assertTrue(any("version is not the BSD-licensed 7.2 branch" in x
                                for x in fails))
            fails = re_ev.container_failures(Path(td), dict(
                ev, containers=others + [dict(redis, notice=dict(redis["notice"],
                                                                 sha256="0" * 64))]))
            self.assertTrue(any("COPYING notice is not bound to the fixed 7.2.17" in x
                                for x in fails))

    def test_pgvector_control_binding_and_negative_control_sha(self):
        with tempfile.TemporaryDirectory() as td:
            td, ev = build_fixture(td)
            pg = next(r for r in ev["containers"]
                      if r.get("repo_ref") == "pgvector/pgvector")
            others = [r for r in ev["containers"]
                      if r.get("repo_ref") != "pgvector/pgvector"]
            fails = re_ev.container_failures(Path(td), dict(ev, containers=others))
            self.assertTrue(any("containers: pgvector: required evidence record missing" in x
                                for x in fails))
            stale = {k: v for k, v in pg.items() if k != "extension_control"}
            fails = re_ev.container_failures(Path(td), dict(ev, containers=others + [stale]))
            self.assertTrue(any("extension_control record missing" in x for x in fails))
            bad = dict(pg, extension_control=dict(pg["extension_control"], sha256="0" * 64))
            fails = re_ev.container_failures(Path(td), dict(ev, containers=others + [bad]))
            self.assertTrue(any("extension_control sha256 is not the pinned "
                                "vector.control constant" in x for x in fails), fails)
            # R4-PG-PROOF-01: a SUBSTITUTED control (same default_version,
            # different bytes) fails even when the evidence sha was
            # regenerated to match the substituted bytes.
            sub = Path(td) / re_ev.PGVECTOR_CONTROL_REL
            real_bytes = sub.read_bytes()
            sub.write_bytes(real_bytes + b"\n")
            self.assertNotEqual(re_ev.sha256_file(sub),
                                re_ev.PGVECTOR_FIXED["control_sha256"])
            forged = dict(pg, extension_control=dict(
                pg["extension_control"], sha256=re_ev.sha256_file(sub)))
            fails = re_ev.container_failures(Path(td), dict(ev, containers=others + [forged]))
            self.assertTrue(any("vector.control bytes drifted from the pinned upstream "
                                "constant (substituted control?)" in x for x in fails), fails)
            self.assertTrue(any("extension_control sha256 is not the pinned "
                                "vector.control constant" in x for x in fails), fails)
            sub.write_bytes(real_bytes)
            # the reviewed tuple binds the record digest too
            wrong_digest = dict(pg, index_digest="sha256:" + "9" * 64)
            fails = re_ev.container_failures(Path(td), dict(ev, containers=[wrong_digest]))
            self.assertTrue(any("record digest is not the reviewed pgvector image "
                                "digest of the pinned tuple" in x for x in fails), fails)
            wrong = dict(pg, extension_version="0.8.8")
            fails = re_ev.container_failures(Path(td), dict(ev, containers=others + [wrong]))
            self.assertTrue(any("extension_version does not match the pinned vector.control "
                                "default_version" in x for x in fails))
            nc = ev["negative_controls"]["redis_restricted_retained"]
            stale_nc = {k: v for k, v in nc.items() if k != "license_sha256"}
            fails = re_ev.negative_control_failures(Path(td), dict(
                ev, negative_controls={"redis_restricted_retained": stale_nc}))
            self.assertTrue(any("license_sha256 is not the pinned upstream 7.4.12 "
                                "constant" in x for x in fails), fails)
            fails = re_ev.negative_control_failures(Path(td), dict(
                ev, negative_controls={"redis_restricted_retained":
                                       dict(nc, license_sha256="0" * 64)}))
            self.assertTrue(any("license_sha256 is not the pinned upstream 7.4.12 "
                                "constant" in x for x in fails), fails)
            # substituted bytes at the canonical path (self-consistent hash
            # regenerated) are still refused -- the pinned upstream sha is
            # the reference, not the tree's current bytes
            lic = Path(td) / re_ev.REDIS_NEGATIVE["license_path"]
            real = lic.read_bytes()
            lic.write_bytes(real + b"\n")
            fails = re_ev.negative_control_failures(Path(td), dict(
                ev, negative_controls={"redis_restricted_retained":
                                       dict(nc, license_sha256=re_ev.sha256_file(lic))}))
            self.assertTrue(any("license bytes are not the pinned upstream 7.4.12 text "
                                "(substituted bytes?)" in x for x in fails), fails)
            lic.write_bytes(real)
            self.assertEqual(re_ev.negative_control_failures(Path(td), ev), [])

    def test_split_container_records_refused(self):
        # R4-DUP-01: two records for ONE operator-pulled subject are refused
        # in EITHER order -- previously next(..., None) took the first row
        # and dict-building let the last digest row shadow earlier ones, so
        # the notice could live on one row and the subject checks on another.
        with tempfile.TemporaryDirectory() as td:
            td, ev = build_fixture(td)
            redis = next(r for r in ev["containers"] if r.get("repo_ref") == "redis")
            pg = next(r for r in ev["containers"]
                      if r.get("repo_ref") == "pgvector/pgvector")
            others = [r for r in ev["containers"]
                      if r.get("repo_ref") not in ("redis", "pgvector/pgvector")]
            notice_free = {k: v for k, v in redis.items() if k != "notice"}
            fields_free = {k: v for k, v in redis.items()
                           if k not in ("version", "index_digest")}
            for combo in ([redis, notice_free], [notice_free, redis]):
                fails = re_ev.container_failures(Path(td), dict(
                    ev, containers=others + list(combo)))
                self.assertTrue(any("containers: redis: multiple evidence records for "
                                    "one operator-pulled subject" in x
                                    for x in fails), fails)
            pg_notice_free = {k: v for k, v in pg.items()
                              if k not in ("extension_control", "extension_version")}
            for combo in ([pg, pg_notice_free], [pg_notice_free, pg]):
                fails = re_ev.container_failures(Path(td), dict(
                    ev, containers=others + list(combo)))
                self.assertTrue(any("containers: pgvector/pgvector: multiple evidence "
                                    "records for one operator-pulled subject" in x
                                    for x in fails), fails)
            # same digest split across two rows is refused outright (the
            # last-wins shadowing bug)
            twin = dict(fields_free, index_digest=redis["index_digest"])
            fails = re_ev.container_failures(Path(td), dict(
                ev, containers=others + [redis, twin]))
            self.assertTrue(any("split evidence records for " in x
                                and ": one digest bound to several rows" in x
                                for x in fails), fails)
            # the intact single-record set still passes
            self.assertEqual(re_ev.container_failures(Path(td), ev), [])

    def test_fixture_mutations_survive_binding(self):
        # R4-FIXTURE-01: the real-bytes binding runs BEFORE the mutator, so
        # a deliberately corrupted value can no longer be silently restored
        # by the binding step (the original false-pass ordering bug).
        def corrupt_pg_control(td, ev):
            pg = next(r for r in ev["containers"]
                      if r.get("repo_ref") == "pgvector/pgvector")
            pg["extension_control"] = dict(pg["extension_control"], sha256="0" * 64)
        self.verify_fails(corrupt_pg_control,
                          "extension_control sha256 is not the pinned "
                          "vector.control constant")

        def drop_redis_notice(td, ev):
            rec = next(r for r in ev["containers"] if r.get("repo_ref") == "redis")
            rec["notice"] = None
        self.verify_fails(drop_redis_notice, "notice file missing")

    def test_extension_collection_image_id_binds_config_digest(self):
        # Runtime may name the index or config, while the OCI config and
        # selected platform manifest remain separately pinned.
        with tempfile.TemporaryDirectory() as tmp:
            td, ev = build_fixture(Path(tmp))
            self.assertEqual(re_ev.container_failures(td, ev), [])
            pg = next(r for r in ev["containers"]
                      if r["repo_ref"] == "pgvector/pgvector")
            bad = dict(pg, extension_collection=dict(
                pg["extension_collection"], image_id="sha256:" + "f" * 64))
            fails = re_ev._pgvector_failures(td, bad)
            self.assertTrue(any("image_id is neither the pinned index nor its config"
                                in x for x in fails), fails)
            nod = {k: v for k, v in pg.items() if k != "config_digest"}
            fails = re_ev._pgvector_failures(td, nod)
            self.assertTrue(any("config_digest is not the pinned OCI config identity"
                                in x for x in fails), fails)
            arm = dict(pg, extension_collection=dict(
                pg["extension_collection"], platform="linux/arm64"))
            fails = re_ev._pgvector_failures(td, arm)
            self.assertTrue(any("platform is not the pinned resolution platform"
                                in x for x in fails), fails)
            rogue = "sha256:" + "7" * 64
            both = dict(pg, config_digest=rogue, extension_collection=dict(
                pg["extension_collection"], image_id=rogue))
            fails = re_ev._pgvector_failures(td, both)
            self.assertTrue(any("manifest config descriptor does not resolve to "
                                "the pinned OCI config" in x for x in fails), fails)
            forged = dict(pg, extension_collection=dict(
                pg["extension_collection"],
                manifest={"digest": rogue, "config": {"digest": rogue, "size": 1}}))
            fails = re_ev._pgvector_failures(td, forged)
            self.assertTrue(any("index->manifest->config chain" in x for x in fails),
                            fails)
            self.assertIn("docker create + cp not run", pg["extension_binding"])

    def test_pgvector_oci_platform_chain(self):
        import copy
        with tempfile.TemporaryDirectory() as td:
            _, ev = build_fixture(Path(td))
        pg = next(r for r in ev["containers"] if r.get("repo_ref") == "pgvector/pgvector")
        col = copy.deepcopy(pg["extension_collection"])
        self.assertEqual(re_ev._pg_collection_identity_failures(pg, col), [])
        col["image_id"] = re_ev.PGVECTOR_FIXED["config_digest"]
        self.assertEqual(re_ev._pg_collection_identity_failures(pg, col), [])
        col = copy.deepcopy(pg["extension_collection"])
        col["manifest"]["digest"] = re_ev.PGVECTOR_FIXED["digest"]
        self.assertTrue(any("platform manifest" in f for f in
                            re_ev._pg_collection_identity_failures(pg, col)))
        col = copy.deepcopy(pg["extension_collection"])
        col["image_id"] = "sha256:" + "f" * 64
        self.assertTrue(any("neither the pinned index nor its config" in f for f in
                            re_ev._pg_collection_identity_failures(pg, col)))
        col = copy.deepcopy(pg["extension_collection"])
        col["manifest"]["config"]["digest"] = "sha256:" + "0" * 64
        self.assertTrue(any("pinned OCI config" in f for f in
                            re_ev._pg_collection_identity_failures(pg, col)))

    def test_missing_extension_collection_is_pending_gap(self):
        # R4-PG-PROOF-01: without a real hash-bound image collection record
        # the vector.control extraction stays an explicit PENDING gap at
        # verification -- never silently accepted, and never a hard failure
        # either (the record must come from a real collection run).
        def drop_collection(td, ev):
            pg = next(r for r in ev["containers"]
                      if r.get("repo_ref") == "pgvector/pgvector")
            pg.pop("extension_collection", None)
        with tempfile.TemporaryDirectory() as td:
            lines = run_verify(*build_fixture(Path(td), drop_collection))
        hard = [x for x in lines if not x.startswith("PENDING gap")]
        self.assertEqual(hard, [], hard)
        self.assertTrue(any("no hash-bound image collection record" in x
                            for x in lines), lines)

    def test_collect_containers_binds_pgvector_extension_control(self):
        # Generator-level twin: the generator itself must emit the
        # extension_control binding from self-contained inputs (committed
        # testdata bytes only -- no host artifacts/, no Docker), and the
        # emitted record must pass the verifier gate it feeds.
        real_root, real_arts = re_ev.ROOT, re_ev.ARTS
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _generator_tree(root)
            re_ev.ROOT = root
            re_ev.ARTS = root / "artifacts/release-evidence"
            try:
                recs = re_ev.collect_containers()
                pg = [r for r in recs if r["repo_ref"] == "pgvector/pgvector"]
                # exactly one emitted pg record (split records are refused at
                # verification, so the generator must not emit them either)
                self.assertEqual(len(pg), 1)
                pg = pg[0]
                self.assertEqual(pg["extension_control"]["path"], re_ev.PGVECTOR_CONTROL_REL)
                self.assertEqual(pg["extension_control"]["sha256"],
                                 re_ev.PGVECTOR_FIXED["control_sha256"])
                self.assertEqual(pg["extension_version"], "0.8.7")
                # R2: the generator must not claim an image-filesystem read
                # it did not perform -- the local hash-bound observation is
                # recorded and the extraction claim stays pending
                self.assertIn("docker create + cp not run", pg["extension_binding"])
                self.assertNotIn("pinned image filesystem (docker create + cp)",
                                 pg["extension_binding"])
                # honest generator: NO fabricated image collection record --
                # the extraction stays an explicit PENDING gap, never a
                # generated pass
                self.assertNotIn("extension_collection", pg)
                fails = re_ev._pgvector_failures(root, pg)
                self.assertEqual([x for x in fails if not x.startswith("PENDING gap")], [])
                self.assertTrue(any("no hash-bound image collection record" in x
                                    for x in fails), fails)
                stale = {k: v for k, v in pg.items() if k != "extension_control"}
                self.assertIn("extension_control record missing",
                              " ".join(re_ev._pgvector_failures(root, stale)))
                bad = dict(pg, extension_control=dict(pg["extension_control"],
                                                      sha256="0" * 64))
                self.assertIn("extension_control sha256 is not the pinned "
                              "vector.control constant",
                              " ".join(re_ev._pgvector_failures(root, bad)))
                # a forged collection record must be hash-bound to the pinned
                # tuple or it fails
                forged = dict(pg, extension_collection={
                    "image_id": "not-an-immutable-id", "platform": "linux/amd64",
                    "method": "guessed", "control_sha256": "0" * 64,
                    "index_digest": pg["index_digest"]})
                fails = re_ev._pgvector_failures(root, forged)
                self.assertTrue(any("image_id is not an immutable collected image "
                                    "identity" in x for x in fails), fails)
                self.assertTrue(any("method does not name the extraction" in x
                                    for x in fails), fails)
                self.assertTrue(any("control_sha256 is not the pinned vector.control "
                                    "constant" in x for x in fails), fails)
                # R4-PG-PROOF-01 generation gate: a substituted control (same
                # default_version, different bytes) fails generation itself
                control = root / "artifacts/release-evidence/upstream/pgvector/vector.control"
                real = control.read_bytes()
                control.write_bytes(real + b"\n")
                try:
                    with self.assertRaises(SystemExit) as caught:
                        re_ev.collect_containers()
                    self.assertIn("vector.control bytes do not match the pinned upstream "
                                  "constant", str(caught.exception))
                finally:
                    control.write_bytes(real)
            finally:
                re_ev.ROOT, re_ev.ARTS = real_root, real_arts

    def _scope_ev(self, repo, binaries=None):
        return {"containers": [{"repo_ref": repo, "revision_gap": "gap text",
                                "scope": {"preview2": "out-of-scope",
                                          "basis": "claim", "assessment": "claim"}}],
                "distribution": {"binaries": binaries if binaries is not None else
                                 [{"name": n, "sha256": "0" * 64}
                                  for n in re_ev.BINARIES]}}

    def _scope_tree(self, hardened=False):
        td = Path(tempfile.mkdtemp())
        qs = td / "deploy/quickstart/docker-compose.yml"
        qs.parent.mkdir(parents=True)
        qs.write_text(
            "services:\n"
            "  core:\n"
            "    build:\n"
            "      context: ..\n"
            "      dockerfile: Dockerfile\n"
            "  dashboard:\n"
            "    build:\n"
            "      context: ..\n"
            "      dockerfile: web/dashboard/Dockerfile\n")
        if hardened:
            qs.write_text(qs.read_text() +
                          "  hard:\n"
                          "    build:\n"
                          "      context: ..\n"
                          "      dockerfile: Dockerfile.hardened\n")
        return td

    def test_distroless_scope_note_requires_machine_proof(self):
        import shutil
        # positive: exact repo + proven basis -> NOTE line only
        td = self._scope_tree()
        try:
            lines = re_ev.gap_failures(td, self._scope_ev(re_ev.DISTROLESS_REPO))
            notes = [x for x in lines if x.startswith("OUT-OF-SCOPE")]
            self.assertEqual(len(notes), 1, lines)
            self.assertIn("machine basis verified", notes[0])
            self.assertFalse([x for x in lines
                              if "scope waiver" in x or "unproven basis" in x], lines)
            self.assertFalse([x for x in lines
                              if x.startswith("PENDING gap: " + re_ev.DISTROLESS_REPO)],
                             lines)
        finally:
            shutil.rmtree(td)
        # wrong repo carrying the same claim -> gap stays + integrity failure
        td = self._scope_tree()
        try:
            lines = re_ev.gap_failures(td, self._scope_ev("redis"))
            self.assertTrue(any(x.startswith("PENDING gap: redis: gap text")
                                for x in lines), lines)
            self.assertTrue(any("no generic scope waiver" in x for x in lines), lines)
            self.assertFalse([x for x in lines if x.startswith("OUT-OF-SCOPE")], lines)
        finally:
            shutil.rmtree(td)
        # unproven basis: hardened referenced in the Compose surface
        td = self._scope_tree(hardened=True)
        try:
            lines = re_ev.gap_failures(td, self._scope_ev(re_ev.DISTROLESS_REPO))
            self.assertTrue(any(x.startswith("PENDING gap: " + re_ev.DISTROLESS_REPO)
                                for x in lines), lines)
            self.assertTrue(any("references Dockerfile.hardened" in x for x in lines),
                            lines)
            self.assertFalse([x for x in lines if x.startswith("OUT-OF-SCOPE")], lines)
        finally:
            shutil.rmtree(td)
        # unproven basis: not the five host-binary subjects
        td = self._scope_tree()
        try:
            lines = re_ev.gap_failures(td, self._scope_ev(
                re_ev.DISTROLESS_REPO,
                binaries=[{"name": "yabanin", "sha256": "0" * 64}]))
            self.assertTrue(any("five release binaries" in x for x in lines), lines)
            self.assertFalse([x for x in lines if x.startswith("OUT-OF-SCOPE")], lines)
        finally:
            shutil.rmtree(td)

    def _fic_manifest(self, td, marker_hits=None, covered_hits=None,
                       drop_key=None):
        man = {"image_id": "sha256:" + "d" * 64, "platform": "linux/amd64",
               "layers_scanned": ["sha256:" + "1" * 64, "sha256:" + "2" * 64],
               "scanned_minified_assets": 12, "scanned_sourcemaps": 12,
               "scanned_compressed_archives": 0,
               "marker_hits": marker_hits or [],
               "covered_content_hits": covered_hits or []}
        if drop_key:
            man.pop(drop_key)
        rel = "artifacts/release-evidence/node-final-image-scan.json"
        mp = td / rel
        mp.parent.mkdir(parents=True, exist_ok=True)
        data = (json.dumps(man, indent=1) + "\n").encode()
        mp.write_bytes(data)
        import hashlib
        return {"image_id": "sha256:" + "d" * 64, "platform": "linux/amd64",
                "scan_manifest": rel,
                "scan_manifest_sha256": hashlib.sha256(data).hexdigest(),
                # R3: the scan names its inputs -- this tree's builder pin,
                # the aggregate builder LICENSE hash and the covered files
                "inputs": {"builder_image": "node:20-alpine@sha256:" + "b" * 64,
                           "builder_license_sha256": "3" * 64,
                           "covered_files": ["node/LICENSE"]}}

    def test_final_image_inspection_contract(self):
        label = "builder node:20-alpine@sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "web/dashboard").mkdir(parents=True)
            (td / "web/dashboard/Dockerfile").write_text(self.GOOD_DF)
            rec = self._node_record(td)
            # complete, hash-bound inspection with zero hits closes
            rec["notice_forbidden_contexts"][0]["final_image_check"] = \
                self._fic_manifest(td)
            self.assertEqual(re_ev._notice_failures(td, label, rec), [])
            # R3: confirmed retained hits are HARD failures (the shipped
            # image retains forbidden bytes), never a pending gap
            rec = self._node_record(td)
            rec["notice_forbidden_contexts"][0]["final_image_check"] = \
                self._fic_manifest(td, marker_hits=["GPL@/usr/share/nginx/html/x.js"])
            f = re_ev._notice_failures(td, label, rec)
            self.assertTrue(any("confirmed retained occurrences" in x
                                and not x.startswith("PENDING gap") for x in f), f)
            self.assertEqual([x for x in f if x.startswith("PENDING gap")], [], f)
            # R3: JSON true is not a coverage count (bool subclasses int in
            # Python, but a scan did not count 'true' assets)
            rec = self._node_record(td)
            fic = self._fic_manifest(td)
            man_p = td / fic["scan_manifest"]
            man = json.loads(man_p.read_text())
            man["scanned_minified_assets"] = True
            blob = (json.dumps(man, indent=1) + "\n").encode()
            man_p.write_bytes(blob)
            fic["scan_manifest_sha256"] = hashlib.sha256(blob).hexdigest()
            rec["notice_forbidden_contexts"][0]["final_image_check"] = fic
            f = re_ev._notice_failures(td, label, rec)
            self.assertTrue(any("lacks scanned_minified_assets coverage count"
                                in x for x in f), f)
            # malformed: not an exact image digest -> integrity failure
            rec = self._node_record(td)
            fic = self._fic_manifest(td)
            fic["image_id"] = "latest"
            rec["notice_forbidden_contexts"][0]["final_image_check"] = fic
            f = re_ev._notice_failures(td, label, rec)
            self.assertTrue(any("not an exact immutable image digest" in x
                                for x in f), f)
            # manifest hash drift -> integrity failure
            rec = self._node_record(td)
            fic = self._fic_manifest(td)
            fic["scan_manifest_sha256"] = "0" * 64
            rec["notice_forbidden_contexts"][0]["final_image_check"] = fic
            f = re_ev._notice_failures(td, label, rec)
            self.assertTrue(any("scan manifest sha drift" in x for x in f), f)
            # missing coverage key -> integrity failure
            rec = self._node_record(td)
            rec["notice_forbidden_contexts"][0]["final_image_check"] = \
                self._fic_manifest(td, drop_key="scanned_sourcemaps")
            f = re_ev._notice_failures(td, label, rec)
            self.assertTrue(any("scanned_sourcemaps" in x for x in f), f)
            # final_image_check without a bound retained_check is rejected
            rec = self._node_record(td)
            rec["notice_forbidden_contexts"][0].pop("retained_check")
            rec["notice_forbidden_contexts"][0]["final_image_check"] = \
                self._fic_manifest(td)
            f = re_ev._notice_failures(td, label, rec)
            self.assertTrue(any("requires a retained_check" in x for x in f), f)
            # R2: the record-level contract alone carries no candidate
            # identity -- the same well-formed fic must also be checked
            # against the candidate's dashboard subject through the
            # container-level binding
            rec = self._node_record(td)
            rec["notice_forbidden_contexts"][0]["final_image_check"] = \
                self._fic_manifest(td)
            self.assertEqual(re_ev._fic_candidate_binding_failures(
                td, {"containers": [rec], "distribution": {
                    "quickstart_images": [
                        {"name": "dashboard",
                         "image_id": rec["notice_forbidden_contexts"]
                         [0]["final_image_check"]["image_id"],
                         "platform": "linux/amd64"}],
                    "quickstart_build": {"layers": {
                        "dashboard": ["sha256:" + "1" * 64,
                                      "sha256:" + "2" * 64]}}}}), [])
            self.assertTrue(any("not bound to the candidate dashboard quickstart "
                                "image" in x for x in re_ev._fic_candidate_binding_failures(
                                    td, {"containers": [rec]})),
                            "no subject: must fail")

    def test_final_image_check_binds_candidate_dashboard(self):
        # R2: a hash-bound scan manifest that agrees only with its own
        # wrapper is not a candidate binding -- the inspected image must
        # BE the candidate's dashboard quickstart subject, layers must be
        # immutable digests (not 'unknown'), and a scan covering zero
        # assets scanned nothing.
        label = "builder node:20-alpine@sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            (td / "web/dashboard").mkdir(parents=True)
            (td / "web/dashboard/Dockerfile").write_text(self.GOOD_DF)

            def rewritten(over):
                rec = self._node_record(td)
                fic = self._fic_manifest(td)
                man = json.loads((td / fic["scan_manifest"]).read_text())
                man.update(over)
                data = (json.dumps(man, indent=1) + "\n").encode()
                (td / fic["scan_manifest"]).write_bytes(data)
                fic["scan_manifest_sha256"] = hashlib.sha256(data).hexdigest()
                rec["notice_forbidden_contexts"][0]["final_image_check"] = fic
                return rec, fic

            # a layer named 'unknown' is not a scanned layer
            rec, _ = rewritten({"layers_scanned": ["unknown"]})
            f = re_ev._notice_failures(td, label, rec)
            self.assertTrue(any("not immutable layer digests" in x for x in f), f)
            # layers listed but zero assets covered scanned nothing
            rec, _ = rewritten({"scanned_minified_assets": 0,
                                "scanned_sourcemaps": 0,
                                "scanned_compressed_archives": 0})
            f = re_ev._notice_failures(td, label, rec)
            self.assertTrue(any("covers zero assets" in x for x in f), f)
            # self-consistent but NON-dashboard image: the manifest and
            # wrapper agree with each other (record-level checks pass),
            # yet the record is not bound to the candidate's dashboard
            rec, fic = rewritten({"image_id": "sha256:" + "c" * 64})
            fic["image_id"] = "sha256:" + "c" * 64
            self.assertEqual(re_ev._notice_failures(td, label, rec), [])
            ev_dash = {"containers": [rec],
                       "distribution": {"quickstart_images": [
                           {"name": "dashboard", "image_id": "sha256:" + "d" * 64,
                            "platform": "linux/amd64"}],
                           "quickstart_build": {
                               "layers": {"dashboard": ["sha256:" + "1" * 64,
                                                        "sha256:" + "2" * 64]}}}}
            rec_ok, _ = rewritten({})
            ev_dash["containers"] = [rec_ok]
            self.assertEqual(re_ev._fic_candidate_binding_failures(td, ev_dash), [])
            # R3: an arm64 wrapper+manifest pair is not this amd64
            # candidate's image (the platform comparison the verdict
            # found discarded)
            rec, fic = rewritten({"platform": "linux/arm64"})
            fic["platform"] = "linux/arm64"
            ev_arm = json.loads(json.dumps(
                {"containers": [], "distribution": dict(ev_dash["distribution"])}))
            ev_arm["containers"] = [rec]
            f = re_ev._fic_candidate_binding_failures(td, ev_arm)
            self.assertTrue(any("platform is not the candidate dashboard platform"
                                in x for x in f), f)
            # R3: one unrelated digest-shaped layer scanned SOMETHING, not
            # this image -- the layer set must be the build record's
            rec, _ = rewritten({"layers_scanned": ["sha256:" + "1" * 64,
                                                   "sha256:" + "9" * 64]})
            ev_lay = json.loads(json.dumps(
                {"containers": [], "distribution": dict(ev_dash["distribution"])}))
            ev_lay["containers"] = [rec]
            f = re_ev._fic_candidate_binding_failures(td, ev_lay)
            self.assertTrue(any("layers_scanned is not the dashboard build "
                                "record's layer set" in x for x in f), f)
            # R3: scan inputs that do not name this tree's builder image
            rec, fic = rewritten({})
            fic["inputs"] = {"builder_image": "node:20-alpine@sha256:" + "0" * 64,
                             "builder_license_sha256": "3" * 64,
                             "covered_files": ["node/LICENSE"]}
            ev_in = json.loads(json.dumps(
                {"containers": [], "distribution": dict(ev_dash["distribution"])}))
            ev_in["containers"] = [rec]
            f = re_ev._fic_candidate_binding_failures(td, ev_in)
            self.assertTrue(any("scan inputs do not name this tree's dashboard "
                                "builder image" in x for x in f), f)
            # ... and the non-dashboard id still fails the candidate binding
            rec_bad, fic_bad = rewritten({"image_id": "sha256:" + "c" * 64})
            fic_bad["image_id"] = "sha256:" + "c" * 64
            self.assertTrue(any("not bound to the candidate dashboard quickstart "
                                "image" in x
                                for x in re_ev._fic_candidate_binding_failures(td, {
                                    **ev_dash, "containers": [rec_bad]})))

    def test_core_image_notices_required(self):
        def drop(td, ev):
            ev["distribution"].pop("core_image_notices")
        self.verify_fails(drop, "Core quickstart image notice bytes under "
                                "/usr/share/licenses/yabanin unbound")
        def stray(td, ev):
            man = td / "artifacts/release-evidence/core-image-notices.json"
            man.write_text(json.dumps({"files": [
                {"path": "/etc/not-here", "sha256": "0" * 64}]}) + "\n")
        self.verify_fails(stray, "Core quickstart image notice bytes under "
                                "/usr/share/licenses/yabanin unbound")

    def test_emitted_marker_is_retained_failure(self):
        # A forbidden marker inside an emitted (shipped) file is a retained
        # runtime occurrence and stays a hard failure regardless of any
        # build-stage characterization.
        def inject(td, ev):
            (td / "web/dashboard/dist/assets/app.js").write_bytes(
                APP_JS + b"/* GNU General Public License fixture */\n")
        self.verify_fails(inject, "emitted dashboard file contains forbidden marker")

    def test_restricted_negative_control_abuse_fails(self):
        def swap(td, ev):
            rec = ev["containers"][0]
            rec["version"] = "7.4.12"
            rec["notice"] = notice_rec(
                "artifacts/release-evidence/upstream/restricted.txt", RSAL)
        self.verify_fails(swap, "forbidden", "7.2 branch")

        # R4-NC-PROOF-01: pointing the RETAINED negative control at an
        # unrelated marker-bearing text at a self-chosen path with its own
        # matching hash must NOT satisfy the canonical 7.4.12 upstream case.
        def hijack(td, ev):
            nc = ev["negative_controls"]["redis_restricted_retained"]
            nc["license_path"] = "artifacts/release-evidence/upstream/restricted.txt"
            nc["license_sha256"] = re_ev.sha256_file(
                Path(td) / "artifacts/release-evidence/upstream/restricted.txt")
        self.verify_fails(hijack, "license_path is not the canonical 7.4.12 "
                                 "upstream path")

        # a file that merely carries the markers at the canonical path but
        # is not the real upstream text (self-hash) is refused
        def forged(td, ev):
            p = Path(td) / re_ev.REDIS_NEGATIVE["license_path"]
            p.write_text(RSAL + "\n")
            nc = ev["negative_controls"]["redis_restricted_retained"]
            nc["license_sha256"] = re_ev.sha256_file(p)
        self.verify_fails(forged, "license bytes are not the pinned upstream 7.4.12 "
                                  "text (substituted bytes?)")

    def test_stale_notice_wording_fails(self):
        def stale(td, ev):
            (td / "NOTICE").write_text(
                "stale: see enterprise/LICENSE (owner decision D1 pending)\n"
                "Project-authored code is licensed under the Apache License, Version 2.0;\n"
                "Project-authored code is licensed under the Apache License, Version 2.0;\n")
        self.verify_fails(stale, "notice:")

    def test_review_structure_enforced(self):
        def drop_area(td, ev):
            del ev["reviews"]["models"]
        self.verify_fails(drop_area, "reviews: models record missing")

        def blank_owner(td, ev):
            ev["reviews"]["containers"]["owner"] = " "
        self.verify_fails(blank_owner, "reviews: containers.owner empty")

        def nonbool(td, ev):
            ev["reviews"]["assets"]["approved"] = "yes"
        self.verify_fails(nonbool, "reviews: assets.approved must be a boolean")

    def test_review_structured_approval_not_rejected(self):
        def approve(td, ev):
            for rec in ev["reviews"].values():
                rec.update({"approved": True, "owner": "human reviewer",
                            "reason": "scoped review done",
                            "evidence": "review record reference"})
        with tempfile.TemporaryDirectory() as td:
            fails = run_verify(*build_fixture(Path(td), approve))
            self.assertFalse([f for f in fails if f.startswith("reviews:")])

    def test_builder_pin_drift_fails(self):
        def drift(td, ev):
            (td / "Dockerfile").write_text(
                "FROM golang:1.27.4-alpine@" + GO_DIGEST + " AS builder\n"
                "FROM alpine:3.24.4@sha256:" + "e" * 64 + "\n")
        self.verify_fails(drift, "builder base", "no evidence record")

    def test_module_notice_delete_fails(self):
        def drop(td, ev):
            (td / "artifacts/release-evidence/image-notices/yabanin"
             "/modules/example.com/pkg@v1.2.3/LICENSE").unlink()
        self.verify_fails(drop, "not a regular confined file")

    def test_unbound_chunk_fails(self):
        def extra(td, ev):
            (td / "web/dashboard/dist/assets/extra.js").write_text("x\n")
        self.verify_fails(extra, "emitted chunk unbound")

    def test_chunk_marker_carrying_twin_refused(self):
        # R4-MAP-01: the ORIGINAL false-pass shape -- dist bytes still carry
        # the sourceMappingURL marker while the chunk twin sha "matches".
        # A successfully stripped twin never contains the marker, so this
        # is not a generator-shaped record.
        def marker_twin(td, ev):
            p = td / "web/dashboard/dist/assets/app.js"
            p.write_bytes(APP_JS_RAW_TWIN)
            ev["assets"]["dist_files"] = [
                f for f in ev["assets"]["dist_files"]
                if f["path"] != "web/dashboard/dist/assets/app.js"]
            ev["assets"]["dist_files"].append({
                "path": "web/dashboard/dist/assets/app.js",
                "sha256": hashlib.sha256(APP_JS_RAW_TWIN).hexdigest()})
            ev["assets"]["chunk_origins"]["assets/app.js.map"]["twin_sha256"] = \
                hashlib.sha256(APP_JS_RAW_TWIN).hexdigest()
        self.verify_fails(marker_twin,
                          "retains the sourceMappingURL marker "
                          "(not a generator-shaped stripped twin)")

        # R2: each hash relationship is checked IN ISOLATION -- removing
        # the raw-twin receipt alone (everything else intact) must fail on
        # the raw-twin invariant, not pass because other fields are truthy.
        def no_raw_twin_hash(td, ev):
            c = ev["assets"]["chunk_origins"]["assets/app.js.map"]
            c.pop("map_twin_raw_sha256", None)
        self.verify_fails(no_raw_twin_hash, "raw twin sha drift")

        def no_map_receipt(td, ev):
            c = ev["assets"]["chunk_origins"]["assets/app.js.map"]
            c.pop("map_sha256", None)
        self.verify_fails(no_map_receipt, "map receipt not bound to the "
                                          "retained sourcemap artifact")

        # recorded sources must be the retained map's own sources
        def wrong_sources(td, ev):
            c = ev["assets"]["chunk_origins"]["assets/app.js.map"]
            c["sources"] = ["../../node_modules/never-seen/pkg.js"]
        self.verify_fails(wrong_sources,
                          "chunk sources are not the retained map's sources")

        # appending marker-free code to the emitted chunk and re-hashing
        # dist_files/twin_sha256 (the R2 counterexample) cannot pass: the
        # retained raw twin no longer strips to the shipped bytes
        def appended_code(td, ev):
            p = td / "web/dashboard/dist/assets/app.js"
            new = APP_JS + b'extraStatement();\n'
            p.write_bytes(new)
            ev["assets"]["dist_files"] = [
                f for f in ev["assets"]["dist_files"]
                if f["path"] != "web/dashboard/dist/assets/app.js"]
            ev["assets"]["dist_files"].append({
                "path": "web/dashboard/dist/assets/app.js",
                "sha256": hashlib.sha256(new).hexdigest()})
            ev["assets"]["chunk_origins"]["assets/app.js.map"]["twin_sha256"] = \
                hashlib.sha256(new).hexdigest()
        self.verify_fails(appended_code,
                          "emitted chunk is not the stripped retained twin")

        # stale retained map bytes with the receipt unchanged
        def stale_map_bytes(td, ev):
            (td / "web/dashboard/dist-sourcemaps/assets/app.js.map").write_bytes(
                b'{"version":3,"file":"app.js","sources":["x"]}\n')
        self.verify_fails(stale_map_bytes,
                          "map receipt not bound to the retained sourcemap "
                          "artifact (sha drift)")

        # missing retained map artifact
        def missing_map(td, ev):
            (td / "web/dashboard/dist-sourcemaps/assets/app.js.map").unlink()
        self.verify_fails(missing_map,
                          "retained sourcemap artifact (missing)")

        # missing retained raw twin
        def missing_raw(td, ev):
            (td / "web/dashboard/dist-sourcemaps/assets/app.js").unlink()
        self.verify_fails(missing_raw, "raw map twin not retained (missing)")

        # R3: a raw twin whose comment names other.js.map while the
        # record's map_name says app.js.map is a cross-wired identity --
        # re-hash the twin so ONLY the identity check fires
        def crosswired_comment(td, ev):
            f = td / "web/dashboard/dist-sourcemaps/assets/app.js"
            code = re_ev.dashboard_evidence.strip_map_comment(f.read_bytes())
            data = code + b"//# sourceMappingURL=other.js.map\n"
            f.write_bytes(data)
            ev["assets"]["chunk_origins"]["assets/app.js.map"][
                "map_twin_raw_sha256"] = hashlib.sha256(data).hexdigest()
        self.verify_fails(crosswired_comment,
                          "sourceMappingURL names 'other.js.map', not the "
                          "recorded map_name")

        # shipping the map inside dist is refused by the dist file-set
        # binding (maps must never be exposed in production nginx)
        def map_in_dist(td, ev):
            (td / "web/dashboard/dist/assets/app.js.map").write_bytes(APP_MAP)
        self.verify_fails(map_in_dist, "emitted file missing from evidence")

        # R3: LISTING the stray map in dist_files clears the file-set
        # mismatch -- a shipped sourcemap stays a hard failure regardless
        def map_in_dist_listed(td, ev):
            f = td / "web/dashboard/dist/assets/app.js.map"
            f.write_bytes(APP_MAP)
            ev["assets"]["dist_files"].append(
                {"path": "web/dashboard/dist/assets/app.js.map",
                 "sha256": re_ev.sha256_file(f)})
        self.verify_fails(map_in_dist_listed,
                          "sourcemap emitted inside the public dist tree")

        # a strip-error record cannot buy binding with a matching sha
        def errored_record(td, ev):
            c = ev["assets"]["chunk_origins"]["assets/app.js.map"]
            c["strip_error"] = "expected exactly one //# sourceMappingURL marker"
            c["twin_sha256"] = hashlib.sha256(APP_JS).hexdigest()
        self.verify_fails(errored_record, "chunk map binding not proven "
                                          "(strip error or missing map)")

    def test_content_bound_build_receipts(self):
        with tempfile.TemporaryDirectory() as tmp:
            td, ev = build_fixture(tmp)
            dist = ev["distribution"]
            build = dist["quickstart_build"]
            row = next(r for r in dist["quickstart_images"] if r["name"] == "mock-provider")
            role = row["name"]
            head = ev["freshness"]["head"]
            context, recipe = "deploy/mock-provider", "deploy/mock-provider/Dockerfile"
            self.assertEqual(re_ev._quickstart_images_gap(td, ev), [])

            def bind(image):
                row["image_id"] = image
                build["subjects"][role] = image

            for label, kwargs, message in (
                ("stale image in both records", {"head": "f" * 40}, "source revision"),
                ("same-revision Core recipe", {"context": ".", "recipe": "Dockerfile"}, "build context"),
                ("different recipe", {"recipe": "deploy/mock-provider/alternate"}, "different Dockerfile"),
                ("arm64 receipt reported as amd64", {"selected_platform": "arm64"}, "absent platform"),
                ("wrong image manifest schema", {"image_schema": 1}, "invalid OCI image manifest"),
                ("wrong attestation manifest schema", {"attestation_schema": 1}, "invalid OCI image manifest"),
                ("conflicting inline provenance bytes", {"conflicting_inline": True}, "inline descriptor digest mismatch"),
                ("missing attestation config", {"omit_config": True}, "invalid OCI descriptor media type"),
                ("missing in-toto subject", {"omit_subject": True}, "in-toto subject"),
                ("different pinned base", {"bases": (GO_DIGEST,)}, "pinned base images"),
            ):
                with self.subTest(label):
                    args = {"head": head, "context": context, "recipe": recipe, **kwargs}
                    bind(fixture_image(td, role, **args))
                    self.assertTrue(any(message in s for s in re_ev._quickstart_images_gap(td, ev)), label)

            # Use the literal Core digest and its genuine receipt, copied into the mock
            # store. Both image-ID declarations agree. Only its verified context differs.
            store = td / "artifacts/release-evidence/build-receipts"
            for file in (store / "core").iterdir():
                (store / role / file.name).write_bytes(file.read_bytes())
            bind(build["subjects"]["core"])
            self.assertTrue(any("different build context" in s for s in re_ev._quickstart_images_gap(td, ev)))
            digest = fixture_image(td, role, head, context, recipe)
            bind(digest)
            blob = store / role / digest[7:]
            payload = blob.read_bytes()
            blob.unlink()
            self.assertTrue(any("missing regular receipt blob" in s for s in re_ev._quickstart_images_gap(td, ev)))
            blob.write_bytes(payload + b" ")
            self.assertTrue(any("descriptor hash mismatch" in s for s in re_ev._quickstart_images_gap(td, ev)))
            blob.write_bytes(payload)
            self.assertEqual(re_ev._quickstart_images_gap(td, ev), [])

            compose = td / "deploy/quickstart/docker-compose.yml"
            compose.write_text(compose.read_text().replace("context: ../../deploy/mock-provider", "context: ../.."))
            self.assertTrue(any("unexpected Compose context" in s for s in re_ev._quickstart_images_gap(td, ev)))

    def test_claimed_build_requires_all_and_only_known_rows(self):
        with tempfile.TemporaryDirectory() as tmp:
            td, ev = build_fixture(tmp)
            dist = ev["distribution"]
            row = dist["quickstart_images"].pop()
            self.assertEqual(re_ev._quickstart_images_gap(td, ev),
                             ["distribution: claimed quickstart build requires exactly three complete image rows"])
            dist["quickstart_images"].append(row)
            build = dist["quickstart_build"]
            for key, extra in (("subjects", row["image_id"]), ("platforms", row["platform"])):
                build[key]["unverified-extra"] = extra
                self.assertEqual(re_ev._quickstart_images_gap(td, ev),
                                 [f"distribution: quickstart_build.{key} must name exactly the three image roles"])
                del build[key]["unverified-extra"]
            dist.pop("quickstart_build")
            dist["quickstart_images"].pop()
            self.assertTrue(re_ev._quickstart_images_gap(td, ev)[0].startswith("PENDING gap:"))

    def test_quickstart_images_bound_to_candidate_build(self):
        # R2/R3: three digest-shaped rows with the right names are not a
        # binding -- the candidate's build record (source head + tree +
        # re-derived inputs + per-subject ids and platforms) must tie them
        # to THIS candidate.
        with tempfile.TemporaryDirectory() as tmp:
            td, ev = build_fixture(Path(tmp))
            dist = ev["distribution"]
            good = dist["quickstart_build"]

            def variant(**over):
                rec = json.loads(json.dumps(good))
                rec.update(over)
                return rec
            # no build record -> explicit pending gap
            dist.pop("quickstart_build")
            lines = re_ev._quickstart_images_gap(td, ev)
            self.assertEqual(len(lines), 1)
            self.assertTrue(lines[0].startswith("PENDING gap"), lines)
            self.assertIn("no candidate build record", lines[0])
            # wrong head -> hard failure (not bound to THIS candidate)
            dist["quickstart_build"] = variant(head="e" * 40)
            fails = re_ev._quickstart_images_gap(td, ev)
            self.assertTrue(any("not this candidate's source head" in x
                                for x in fails), fails)
            # R3: the verdict's attack -- a PREVIOUS build's subject ids
            # copied next to the current head. The tree of the head no
            # longer matches the record minted at the other tree (and the
            # ids are also not this tree's build)
            stale = variant(tree_sha256="f" * 40,
                            subjects={"core": "sha256:" + "9" * 64,
                                      "mock-provider": "sha256:" + "8" * 64,
                                      "dashboard": "sha256:" + "7" * 64})
            dist["quickstart_build"] = stale
            fails = re_ev._quickstart_images_gap(td, ev)
            self.assertTrue(any("tree_sha256 is not the source tree" in x
                                for x in fails), fails)
            self.assertTrue(any("quickstart_build.subjects mismatch" in x
                                for x in fails), fails)
            # R3: wrong tree hash alone (record minted at another tree)
            dist["quickstart_build"] = variant(tree_sha256="f" * 40)
            fails = re_ev._quickstart_images_gap(td, ev)
            self.assertTrue(any("tree_sha256 is not the source tree" in x
                                for x in fails), fails)
            # R3: inputs that are not this tree's build surface
            dist["quickstart_build"] = variant(inputs={
                "compose_build_services": ["phantom-service"],
                "pinned_builders": [["Dockerfile", "golang:1.27.4-alpine@"
                                     + "sha256:" + "0" * 64]]})
            fails = re_ev._quickstart_images_gap(td, ev)
            self.assertTrue(any("inputs.pinned_builders is not this tree's "
                                "pinned FROM set" in x for x in fails), fails)
            self.assertTrue(any("inputs.compose_build_services is not this "
                                "tree's compose build set" in x for x in fails),
                            fails)
            # R3: a subject recorded at a different platform than the row
            # (or the required candidate platform) is not this build
            dist["quickstart_build"] = variant(platforms={
                "core": "linux/amd64", "mock-provider": "linux/arm64",
                "dashboard": "linux/amd64"})
            fails = re_ev._quickstart_images_gap(td, ev)
            self.assertTrue(any("platform is not the recorded candidate "
                                "platform" in x for x in fails), fails)
            # subject mismatch -> the listed image is not the built one
            dist["quickstart_build"] = variant(subjects={
                "core": "sha256:" + "a" * 64,
                "mock-provider": "sha256:" + "c" * 64,
                "dashboard": "sha256:" + "e" * 64})
            fails = re_ev._quickstart_images_gap(td, ev)
            self.assertTrue(any("quickstart_build.subjects mismatch" in x
                                for x in fails), fails)
            # no evidence head to bind to -> hard failure
            saved = ev.pop("freshness")
            dist["quickstart_build"] = variant()
            fails = re_ev._quickstart_images_gap(td, ev)
            self.assertTrue(any("no source head to bind the build record to" in x
                                for x in fails), fails)
            ev["freshness"] = saved
            # the honest binding stays intact
            dist["quickstart_build"] = good
            self.assertEqual(re_ev._quickstart_images_gap(td, ev), [])

    def test_core_notice_paths_exactly_confined(self):
        # R2: a sibling like /usr/share/licenses/yabanin-other/x must not
        # pass by prefix accident, even when the manifest hash binding is
        # intact (the confinement check is isolated from the hash check).
        def sibling(td, ev):
            man = td / "artifacts/release-evidence/core-image-notices.json"
            man.write_text(json.dumps({"files": [
                {"path": "/usr/share/licenses/yabanin-other/NOTICE",
                 "sha256": "0" * 64}]}) + "\n")
            cin = ev["distribution"]["core_image_notices"]
            cin["manifest_sha256"] = hashlib.sha256(man.read_bytes()).hexdigest()
        self.verify_fails(sibling, "/usr/share/licenses/yabanin unbound")
        def nested(td, ev):
            man = td / "artifacts/release-evidence/core-image-notices.json"
            man.write_text(json.dumps({"files": [
                {"path": "/usr/share/licenses/yabanin/sub/NOTICE",
                 "sha256": "0" * 64}]}) + "\n")
            cin = ev["distribution"]["core_image_notices"]
            cin["manifest_sha256"] = hashlib.sha256(man.read_bytes()).hexdigest()
        self.verify_fails(nested, "/usr/share/licenses/yabanin unbound")

    def test_quickstart_images_need_all_three_subjects(self):
        # R4-IMAGE-01: reject incomplete, extra or duplicate rows in a claimed build.
        def no_platform(td, ev):
            ev["distribution"]["quickstart_images"] = [
                {"name": "core", "image_id": "sha256:" + "a" * 64},
                {"name": "mock-provider", "image_id": "sha256:" + "c" * 64,
                 "platform": "linux/amd64"},
                {"name": "dashboard", "image_id": "sha256:" + "d" * 64,
                 "platform": "linux/amd64"}]
        self.verify_fails(no_platform, "claimed quickstart build requires exactly three complete image rows")

        def wrong_subject(td, ev):
            ev["distribution"]["quickstart_images"] = [
                {"name": "core", "image_id": "sha256:" + "a" * 64,
                 "platform": "linux/amd64"},
                {"name": "extra", "image_id": "sha256:" + "c" * 64,
                 "platform": "linux/amd64"},
                {"name": "dashboard", "image_id": "sha256:" + "d" * 64,
                 "platform": "linux/amd64"}]
        self.verify_fails(wrong_subject, "claimed quickstart build requires exactly three complete image rows")

        def duplicate_subject(td, ev):
            qi = ev["distribution"]["quickstart_images"]
            ev["distribution"]["quickstart_images"] = [qi[0], qi[0], qi[2]]
        self.verify_fails(duplicate_subject, "claimed quickstart build requires exactly three complete image rows")

    def test_core_notice_identity_binding_enforced(self):
        # R4-IMAGE-01: a self-consistent notice record bound to a DIFFERENT
        # image identity than the Core quickstart subject is refused.
        def detached(td, ev):
            ev["distribution"]["core_image_notices"]["image_id"] = \
                "sha256:" + "e" * 64
        self.verify_fails(detached, "core_image_notices identity is not the "
                                    "Core quickstart image")

        def no_platform_match(td, ev):
            ev["distribution"]["core_image_notices"]["platform"] = "linux/arm64"
        self.verify_fails(no_platform_match, "identity is not the Core "
                                             "quickstart image")

        def bare_prefix_entry(td, ev):
            man = td / "artifacts/release-evidence/core-image-notices.json"
            data = json.dumps({"image_id": ev["distribution"]["core_image_notices"]["image_id"], "files": [
                {"path": "/usr/share/licenses/yabanin/LICENSE"}]}, indent=1) + "\n"
            man.write_text(data)
            ev["distribution"]["core_image_notices"]["manifest_sha256"] = \
                hashlib.sha256(data.encode()).hexdigest()
        self.verify_fails(bare_prefix_entry, "manifest entry without a content hash")

        # R3: a manifest from ANOTHER image that agrees with the wrapper on
        # shape (paths + 64-hex hashes) is not the Core candidate's bytes
        def foreign_manifest(td, ev):
            man = td / "artifacts/release-evidence/core-image-notices.json"
            data = json.dumps({"image_id": "sha256:" + "9" * 64, "files": [
                {"path": "/usr/share/licenses/yabanin/NOTICE",
                 "sha256": "0" * 64}]}, indent=1) + "\n"
            man.write_text(data)
            ev["distribution"]["core_image_notices"]["manifest_sha256"] = \
                hashlib.sha256(data.encode()).hexdigest()
        self.verify_fails(foreign_manifest, "manifest is not bound to the Core "
                                            "candidate image")

        # R3: 64 zeroes is a well-shaped hash bound to nothing -- the entry
        # must be one of the recorded core payload hashes
        def zero_hash_entry(td, ev):
            man = td / "artifacts/release-evidence/core-image-notices.json"
            data = json.loads(man.read_text())
            data["files"][0]["sha256"] = "0" * 64
            blob = json.dumps(data, indent=1) + "\n"
            man.write_text(blob)
            ev["distribution"]["core_image_notices"]["manifest_sha256"] = \
                hashlib.sha256(blob.encode()).hexdigest()
        self.verify_fails(zero_hash_entry, "not bound to the recorded core "
                                           "payload bytes")

    def test_scan_manifest_must_report_and_identify_itself(self):
        # R4-NGINX-01: absent hit lists are not zero-hit scan results...
        label = "builder node:20-alpine@sha256:" + "a" * 64
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "web/dashboard").mkdir(parents=True)
            (td / "web/dashboard/Dockerfile").write_text(self.GOOD_DF)
            rec = self._node_record(td)
            rec["notice_forbidden_contexts"][0]["final_image_check"] = \
                self._fic_manifest(td, drop_key="marker_hits")
            f = re_ev._notice_failures(td, label, rec)
            self.assertTrue(any("lacks explicit marker_hits scan results" in x
                                for x in f), f)
            rec = self._node_record(td)
            rec["notice_forbidden_contexts"][0]["final_image_check"] = \
                self._fic_manifest(td, drop_key="covered_content_hits")
            f = re_ev._notice_failures(td, label, rec)
            self.assertTrue(any("lacks explicit covered_content_hits scan "
                                "results" in x for x in f), f)
            # ...and the manifest must be bound to the identity it scanned
            rec = self._node_record(td)
            rec["notice_forbidden_contexts"][0]["final_image_check"] = \
                self._fic_manifest(td)
            rec["notice_forbidden_contexts"][0]["final_image_check"]["image_id"] = \
                "sha256:" + "9" * 64
            f = re_ev._notice_failures(td, label, rec)
            self.assertTrue(any("not bound to the inspected image identity" in x
                                for x in f), f)
            rec = self._node_record(td)
            fic = self._fic_manifest(td)
            fic["platform"] = "linux/arm64"
            rec["notice_forbidden_contexts"][0]["final_image_check"] = fic
            f = re_ev._notice_failures(td, label, rec)
            self.assertTrue(any("not bound to the inspected image platform" in x
                                for x in f), f)

    def test_notice_delivery_bound_requires_manifest(self):
        # R4-NPM-01: status="bound" plus an empty unresolved list is a
        # claim, not delivery.
        def claim_only(td, ev):
            ev["assets"]["notice_delivery"] = {"status": "bound"}
        self.verify_fails(claim_only, "claimed bound without a "
                                       "package-to-delivered-notice manifest")

        def drifted_entry(td, ev):
            (td / "web/dashboard/dist/notices/clsx-LICENSE").write_text(
                "swapped bytes\n")
        self.verify_fails(drifted_entry, "manifest entry unverifiable")

        # R2: delivered notices must live INSIDE the built output tree
        def stashed_outside_dist(td, ev):
            import shutil
            src = td / "web/dashboard/dist/notices"
            dst = td / "web/dashboard/notices-delivered"
            shutil.rmtree(dst, ignore_errors=True)
            dst.mkdir(parents=True)
            for f in src.iterdir():
                shutil.copy2(f, dst / f.name)
            for f in src.iterdir():
                f.unlink()
            for e in ev["assets"]["notice_delivery"]["manifest"]:
                e["path"] = e["path"].replace("dist/notices/",
                                              "notices-delivered/")
            ev["assets"]["dist_files"] = [
                d for d in ev["assets"]["dist_files"]
                if not d["path"].startswith("web/dashboard/dist/notices/")]
        self.verify_fails(stashed_outside_dist, "manifest entry unverifiable")

        # R2: one package's row cannot stand in for another contributing
        # package -- clsx-only coverage stays a pending gap
        def clsx_only(td, ev):
            man = ev["assets"]["notice_delivery"]["manifest"]
            ev["assets"]["notice_delivery"]["manifest"] = [
                e for e in man if e["package"] == "clsx"]
        self.verify_fails(clsx_only,
                          "without delivered notices for contributing "
                          "package(s): lucide-react")

        # R2: delivered bytes must be the package's RECORDED legal bytes
        def wrong_bytes(td, ev):
            p = td / "web/dashboard/dist/notices/lucide-react-LICENSE"
            other = re_ev.sha256_file(td / "web/dashboard/node_modules/clsx/license")
            p.write_text(CLSX_LICENSE)
            for e in ev["assets"]["notice_delivery"]["manifest"]:
                if e["package"] == "lucide-react":
                    e["sha256"] = other
        self.verify_fails(wrong_bytes, "manifest entry unverifiable")

        def unknown_package(td, ev):
            man = ev["assets"]["notice_delivery"]["manifest"]
            # keep the real package covered so the COVERAGE gate stays
            # green and the unknown package hits entry verification
            man.append(dict(man[0]))
            man[0]["package"] = "never-recorded-pkg"
        self.verify_fails(unknown_package, "manifest entry unverifiable")

        # R3: a traversal path 'web/dashboard/dist/../notices/x' escapes
        # the served tree while satisfying the old prefix check
        def traversal_path(td, ev):
            man = ev["assets"]["notice_delivery"]["manifest"]
            victim = td / "web/dashboard/node_modules/clsx/license"
            outside = td / "web/dashboard/notices-outside"
            outside.mkdir(parents=True, exist_ok=True)
            target = outside / "clsx-LICENSE"
            target.write_bytes(victim.read_bytes())
            for e in man:
                if e["package"] == "clsx":
                    e["path"] = "web/dashboard/dist/../notices-outside/clsx-LICENSE"
        self.verify_fails(traversal_path, "manifest entry unverifiable")

        # R3: a package row pointing at ANOTHER package's license bytes
        # (lucide-react naming the clsx license file) is a wrong-subject
        # binding even though the sha matches those bytes
        def wrong_subject_legal_file(td, ev):
            for pkg in ev["assets"]["contributing_packages"]:
                if pkg["name"] == "lucide-react":
                    pkg["legal_files"][0]["file"] = \
                        "web/dashboard/node_modules/clsx/license"
                    pkg["legal_files"][0]["sha256"] = sha_text(CLSX_LICENSE)
        self.verify_fails(wrong_subject_legal_file,
                          "legal file is not inside the package's "
                          "node_modules directory: lucide-react")

    def test_quickstart_gap_fails(self):
        def absent(td, ev):
            ev["distribution"].pop("quickstart_build")
            ev["distribution"]["quickstart_images"] = []
        self.verify_fails(absent, "PENDING gap: quickstart")

    def test_mock_alpine_apk_inventory_gap_fails(self):
        def add(td, ev):
            ev["containers"].append({
                "repo_ref": "alpine", "role": "runtime base (mock image)",
                "index_digest": "sha256:" + "b" * 64, "version": "3.21.10",
                "notice": {"path": "artifacts/release-evidence/apk-mock.txt"}})
        self.verify_fails(add, "PENDING gap: mock-provider alpine")

    def test_mock_alpine_record_matches_dockerfile_pin(self):
        # R3: the mock alpine record must match the Dockerfile's own FROM
        # pin -- an edited version or a laundered role is a hard failure,
        # not a narrowed blocker
        def wrong_version(td, ev):
            ev["containers"].append({
                "repo_ref": "alpine", "role": re_ev._ALPINE_MOCK_ROLE,
                "index_digest": "sha256:" + "b" * 64, "version": "3.99.0",
                "notice": {"path": "artifacts/release-evidence/apk-mock.txt"}})
        self.verify_fails(wrong_version,
                          "record version '3.99.0' is not the Dockerfile pin")

        def laundered_role(td, ev):
            ev["containers"].append({
                "repo_ref": "alpine", "role": "runtime base",
                "index_digest": "sha256:" + "b" * 64, "version": "3.21.10",
                "notice": {"path": "artifacts/release-evidence/apk-mock.txt"}})
        self.verify_fails(laundered_role,
                          "evades the mock-provider role binding")

    def test_mock_alpine_gap_survives_notice_rename(self):
        # R2: the mock-image blocker binds to the record ROLE -- renaming
        # the apk inventory artifact (or pointing the notice elsewhere)
        # must not clear the gap.
        def renamed(td, ev):
            import hashlib as _hl
            dst = td / "artifacts/release-evidence/apk-inventory.txt"
            dst.parent.mkdir(parents=True, exist_ok=True)
            dst.write_text("alpine mock apk inventory fixture (renamed)\n")
            ev["containers"].append({
                "repo_ref": "alpine", "role": "runtime base (mock image)",
                "index_digest": "sha256:" + "b" * 64, "version": "3.21.10",
                "notice": {"path": "artifacts/release-evidence/apk-inventory.txt",
                           "sha256": _hl.sha256(dst.read_bytes()).hexdigest()}})
        self.verify_fails(renamed, "PENDING gap: mock-provider alpine")

    def test_payload_module_coverage_is_per_module(self):
        # R2: one modules/ legal file does not satisfy coverage -- every
        # module the inventory records as linked must have a listed legal
        # file.
        def second_module_uncovered(td, ev):
            inv_p = td / "artifacts/release-evidence/image-notices/yabanin/inventory.json"
            inv = json.loads(inv_p.read_text())
            inv["modules"].append({"path": "example.com/other", "version": "v0.9.9",
                                   "source_path": "example.com/other", "source_version": "v0.9.9",
                                   "source_sum": "h1:other"})
            inv_p.write_text(json.dumps(inv, indent=2) + "\n")
        self.verify_fails(second_module_uncovered,
                          "example.com/other@v0.9.9 has no listed legal file")
        def no_module_rows(td, ev):
            inv_p = td / "artifacts/release-evidence/image-notices/yabanin/inventory.json"
            inv = json.loads(inv_p.read_text())
            inv["modules"] = []
            inv["files"] = [f for f in inv["files"]
                            if not f["path"].startswith("modules/")]
            import shutil as _sh
            mods = inv_p.parent / "modules"
            _sh.rmtree(mods, ignore_errors=True)
            inv_p.write_text(json.dumps(inv, indent=2) + "\n")
        self.verify_fails(no_module_rows, "no linked-module notices recorded")

    def test_real_linked_module_replacement(self):
        import os
        import subprocess
        from zipfile import ZipFile

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            original, fork = "example.test/original", "example.test/ReviewFork"
            version = "v1.2.0"
            source = {"go.mod": f"module {fork}\ngo 1.22\n",
                      "fork.go": "package probe\nfunc Message() string {return \"ok\"}\n",
                      "LICENSE.md": "Copyright fixture authors\n"}
            versions = root / "proxy/example.test/!review!fork/@v"
            versions.mkdir(parents=True)
            (versions / (version + ".info")).write_text(json.dumps(
                {"Version": version, "Time": "2020-01-01T00:00:00Z"}))
            (versions / (version + ".mod")).write_text(source["go.mod"])
            with ZipFile(versions / (version + ".zip"), "w") as zipped:
                for path, body in source.items():
                    zipped.writestr(f"{fork}@{version}/{path}", body)
            (root / "go.mod").write_text(f"module example.test/probe\ngo 1.22\n"
                                         f"require {original} v1.0.0\n"
                                         f"replace {original} => {fork} {version}\n")
            (root / "main.go").write_text(f'package main\nimport "{original}"\n'
                                          'func main(){println(probe.Message())}\n')
            env = dict(os.environ, GOWORK="off", GOPROXY=(root / "proxy").as_uri(),
                       GOTOOLCHAIN="local", GOSUMDB="off", GOMODCACHE=str(root / "cache"))
            subprocess.run(["go", "build", "-mod=mod", "-o", "consumer", "."],
                           cwd=root, env=env, check=True, capture_output=True)
            checksum = next(line.split()[2] for line in (root / "go.sum").read_text().splitlines()
                            if line.split()[:2] == [fork, version])
            row = (original, "v1.0.0", fork, version, checksum)
            expected = {row}
            self.assertEqual(re_ev._binary_module_set(root / "consumer"), (expected, None))
            self.assertEqual(re_ev._module_binding_failures(root / "consumer", expected, "probe"), [])
            for column, value in enumerate(("other", "v0.1.0", "other", "v0.1.0", "h1:other")):
                changed = list(row)
                changed[column] = value
                failures = re_ev._module_binding_failures(root / "consumer", {tuple(changed)}, "probe")
                self.assertTrue(any("absent from the inventory" in message for message in failures))
                self.assertTrue(any("unlinked module identity" in message for message in failures))
            self.assertEqual(re_ev._module_prefix(row), "modules/example.test/!review!fork@v1.2.0/")

    def test_module_set_derived_from_build_info(self):
        # R3: the module LIST is re-derived from the binary's build info
        # (`go version -m`, PATH shim in the fixture) -- a module linked
        # in the binary but absent from the inventory fails
        def extra_in_build_info(td, ev):
            (td / ".fakebin/extra-mods").write_text("on\n")
        self.verify_fails(extra_in_build_info,
                          "build info names linked module absent from the "
                          "inventory: example.com/extra")

        # R3: a module deleted from BOTH the inventory and the payload
        # while still linked in the binary is caught by the derivation
        def deleted_module(td, ev):
            inv_p = td / "artifacts/release-evidence/image-notices/yabanin/inventory.json"
            inv = json.loads(inv_p.read_text())
            inv["modules"] = []
            inv["files"] = [f for f in inv["files"]
                            if not f["path"].startswith("modules/")]
            import shutil as _sh
            _sh.rmtree(inv_p.parent / "modules", ignore_errors=True)
            inv_p.write_text(json.dumps(inv, indent=2) + "\n")
        self.verify_fails(deleted_module,
                          "build info names linked module absent from the "
                          "inventory: example.com/pkg")

        # R3: a non-legal file under modules/<mod>@<ver>/ is payload
        # content, not a notice
        def smuggled_module_file(td, ev):
            payload = td / "artifacts/release-evidence/image-notices/yabanin"
            f = payload / "modules/example.com/pkg@v1.2.3/README.txt"
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text("smuggled\n")
            inv_p = payload / "inventory.json"
            inv = json.loads(inv_p.read_text())
            inv["files"].append({"path": "modules/example.com/pkg@v1.2.3/README.txt",
                                 "sha256": sha_text("smuggled\n")})
            inv_p.write_text(json.dumps(inv, indent=2) + "\n")
        self.verify_fails(smuggled_module_file,
                          "module legal file has a non-legal name")

        # R3: with NO go toolchain reachable the derivation degrades to an
        # honest PENDING line -- never to a silent pass
        with tempfile.TemporaryDirectory() as tmp:
            td, ev = build_fixture(Path(tmp))
            import os
            saved = os.environ.get("PATH") or ""
            os.environ["PATH"] = ""
            try:
                # distribution_failures alone -- the full verify needs git
                # on PATH for its other bindings
                fails = re_ev.distribution_failures(td, ev)
            finally:
                os.environ["PATH"] = saved
            self.assertTrue(any(f.startswith("PENDING gap: distribution: "
                                             "yabanin: linked module set not "
                                             "re-derived from build info")
                                for f in fails), fails)

    def bind_provenance_fixture(self):
        root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        def git(*args):
            return subprocess.check_output(["git", "-C", root, *args]).strip().decode()
        git("init", "-q")
        git("config", "user.name", "Fixture Author")
        git("config", "user.email", "fixture@example.invalid")
        git("-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "baseline")
        base = git("rev-parse", "HEAD")
        required = root / re_ev.REQUIRED_ADDED[0]
        required.parent.mkdir(parents=True)
        required.write_text("fixture input\n")
        odd_path = "line\rbreak.txt"
        (root / odd_path).write_text("second fixture input\n")
        git("add", "--all")
        git("-c", "commit.gpgsign=false", "commit", "-q", "-s", "-m", "fixture inputs")
        self.enterContext(patch.multiple(re_ev, ROOT=root, TASK_BASE=base))
        expected = {"commit": git("rev-parse", "HEAD"), "author": "Fixture Author",
                    "email": "fixture@example.invalid", "dco_present": True,
                    "signed_off_by": ["Fixture Author <fixture@example.invalid>"]}
        rows = [dict(expected, path=path) for path in (re_ev.REQUIRED_ADDED[0], odd_path)]
        self.assertEqual(re_ev.provenance_failures({"provenance": {"added": rows}}), [])
        return rows

    def test_git_status_clean_and_porcelain_codes(self):
        self.bind_provenance_fixture()
        state = re_ev.git_state()
        self.assertEqual(state, {"head": re_ev.git_out("rev-parse", "HEAD").strip(),
                                 "dirty": {}, "untracked": {}})
        self.assertEqual(re_ev._tree_binding_failures(
            state, {"freshness": {"dirty": {}, "untracked": {}}}), [])
        for code in (" T", "RM", "C ", "DU", "AA", "??"):
            self.assertEqual(re_ev._porcelain_entry(code + " file"), (code, "file"))
        for code in ("..", "M?", "  ", "U ", "A?", "!!"):
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, "malformed"):
                re_ev._porcelain_entry(code + " file")

    def test_provenance_signers_require_a_string_list(self):
        rows = self.bind_provenance_fixture()
        for value in ({"Fixture Author <fixture@example.invalid>": False}, None, [7]):
            modified = [dict(rows[0], signed_off_by=value), rows[1]]
            failures = re_ev.provenance_failures({"provenance": {"added": modified}})
            self.assertTrue(any("signed_off_by must be an array of strings" in f
                                for f in failures), failures)

    def test_current_repository_provenance_matches_git(self):
        rows = re_ev.provenance_added()
        self.assertIn(re_ev.REQUIRED_ADDED[0], {row["path"] for row in rows})
        expected = []
        for commit in {row["commit"] for row in rows}:
            author = re_ev.git_out("show", "-s", "--format=%an <%ae>", commit).strip()
            message = re_ev.git_bytes("show", "-s", "--format=%B", commit)
            trailers = subprocess.check_output(
                ["git", "interpret-trailers", "--parse"], input=message).decode().splitlines()
            signers = [value.strip() for line in trailers for key, _, value in [line.partition(":")]
                       if key.lower() == "signed-off-by"]
            for row in (row for row in rows if row["commit"] == commit):
                self.assertEqual(row["signed_off_by"], signers)
                self.assertEqual(row["dco_present"], author in signers)
                if author not in signers:
                    expected.append(f"provenance: {row['path']}: no exact DCO signoff matching "
                                    f"author {author} (recorded fact; rights assessment is separate)")
        self.assertCountEqual(re_ev.provenance_failures({"provenance": {"added": rows}}), expected)

    def test_provenance_recorded_trailer_list_compared(self):
        # R3: the evidence's signed_off_by list is compared to the commit's
        # ACTUAL trailer list -- a row keeping dco_present=true with a
        # lying trailer list drifts, not just the boolean.
        real = self.bind_provenance_fixture()
        self.assertTrue(real)
        lying = [dict(r) for r in real]
        lying[0]["signed_off_by"] = ["Impostor <i@example.invalid>"]
        fails = re_ev.provenance_failures({"provenance": {"added": lying}})
        self.assertTrue(any("missing from evidence (or author/commit/dco "
                            "drifted)" in f for f in fails), fails)
        self.assertTrue(any("non-added/stale row" in f for f in fails), fails)
        blanked = [dict(r) for r in real]
        blanked[0]["signed_off_by"] = []
        fails = re_ev.provenance_failures({"provenance": {"added": blanked}})
        self.assertTrue(any("drifted" in f or "non-added/stale" in f
                            for f in fails), fails)

    def test_provenance_extra_row_fails(self):
        rows = self.bind_provenance_fixture() + [
            {"path": "scripts/never-added.py", "commit": "f" * 40,
             "email": "ghost@example.invalid", "author": "Ghost",
             "signed_off_by": ["Ghost <ghost@example.invalid>"], "dco_present": True,
             "employer_rights": "fabricated"}]
        fails = re_ev.provenance_failures({"provenance": {"added": rows}})
        self.assertTrue(any("non-added/stale row" in f for f in fails))
        self.assertFalse([f for f in fails if "missing from evidence" in f
                          or "no exact DCO signoff" in f
                          or "duplicate row" in f], fails)
        self.assertTrue(any(r["path"] == re_ev.REQUIRED_ADDED[0] for r in rows))

    def test_provenance_duplicate_and_drifted_rows_refused(self):
        # R4-PROVENANCE-01: rows are unique per (path, commit); a duplicated
        # row is refused, and a drifted author/email/dco tuple no longer
        # shadows the real row (the old {path: rec} maps collapsed both).
        real = re_ev.provenance_added()
        self.assertTrue(real)
        dup = real + [dict(real[0])]
        fails = re_ev.provenance_failures({"provenance": {"added": dup}})
        self.assertTrue(any("duplicate row for" in f for f in fails), fails)
        drifted = [dict(r) for r in real]
        drifted[0] = dict(drifted[0], author="Impostor Name")
        fails = re_ev.provenance_failures({"provenance": {"added": drifted}})
        self.assertTrue(any("missing from evidence" in f
                            or "non-added/stale row" in f for f in fails), fails)

    def test_dco_trailers_parsed_from_git_not_body_prose(self):
        # R2: "Example Signed-off-by: Ada <ada@example.invalid>" inside
        # commit BODY PROSE is not a trailer; only the real trailer block
        # counts, and the evidence dco_present must be a boolean.
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def g(*args):
                subprocess.run(["git", "-C", str(root), *args],
                               check=True, capture_output=True, text=True)
            g("init", "-q")
            g("config", "user.name", "Ada")
            g("config", "user.email", "ada@example.invalid")
            (root / "a.txt").write_text("a\n")
            g("add", "a.txt")
            g("commit", "-q", "-m", "prose only",
              "-m", "Example Signed-off-by: Ada <ada@example.invalid> "
              "appears in ordinary prose here.")
            (root / "b.txt").write_text("b\n")
            g("add", "b.txt")
            g("commit", "-q", "-m", "real trailer",
              "-m", "Body text.",
              "-s")
            real_root = re_ev.ROOT
            re_ev.ROOT = root
            try:
                recs = {r["commit"]: r for r in re_ev._commit_records(["--all"])}
            finally:
                re_ev.ROOT = real_root
            prose = [r for r in recs.values() if r["signed_off_by"] == []]
            signed = [r for r in recs.values()
                      if r["signed_off_by"] == ["Ada <ada@example.invalid>"]]
            self.assertEqual(len(prose), 1,
                             "prose sign-off must not be parsed as a trailer")
            self.assertEqual(len(signed), 1,
                             "the real trailer block must be extracted")
            self.assertFalse(re_ev._dco_matches(prose[0]))
            self.assertTrue(re_ev._dco_matches(signed[0]))

        # the evidence-side counterexample: signed_off_by deleted and
        # dco_present replaced by the STRING "false" (bool("false") is
        # True) must be refused, not coerced.
        rows = re_ev.provenance_added()
        self.assertTrue(rows)
        poisoned = [dict(r) for r in rows]
        poisoned[0].pop("signed_off_by", None)
        poisoned[0]["dco_present"] = "false"
        fails = re_ev.provenance_failures({"provenance": {"added": poisoned}})
        self.assertTrue(any("dco_present must be a boolean" in f
                            for f in fails), fails)

    def test_dco_requires_exact_author_trailer(self):
        # R4-PROVENANCE-01: substring containment is not the DCO trailer.
        rec = {"author": "Ada", "email": "ada@example.invalid",
               "signed_off_by": [
                   "Ada <not-ada@example.invalid>",           # wrong email
                   "Evil <hacker+ada@example.invalid>",        # email substring
                   "Different Name <ada@example.invalid>"]}    # wrong name
        self.assertFalse(re_ev._dco_matches(rec))
        ok = dict(rec, signed_off_by=["  Ada <ada@example.invalid>  "])
        self.assertTrue(re_ev._dco_matches(ok))
        self.assertFalse(re_ev._dco_matches({"author": "", "email": "",
                                             "signed_off_by": [" <>"]}))
        self.assertFalse(re_ev._dco_matches(dict(rec, signed_off_by=[])))

    def test_git_state_tombstones_nested_untracked_renames(self):
        # R4-STATUS-01: untracked DIRECTORY contents must be enumerated
        # (--untracked-files=all), deleted tracked files recorded as
        # tombstones (not silently dropped), rename rows bound to both
        # paths, and the parse itself NUL-separated.
        import subprocess
        real_root = re_ev.ROOT
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            def g(*args):
                return subprocess.run(["git", "-C", str(root), *args],
                                      check=True, capture_output=True, text=True).stdout
            g("init", "-q")
            g("config", "user.name", "T")
            g("config", "user.email", "t@example.invalid")
            (root / "keep.txt").write_text("keep\n")
            (root / "gone.txt").write_text("gone\n")
            (root / "renamed old.txt").write_text("ren\n")  # path with a space
            g("add", "-A")
            g("commit", "-q", "-m", "base")
            (root / "gone.txt").unlink()                      # tombstone
            g("mv", "renamed old.txt", "renamed-new.txt")     # rename pair
            nested = root / "new dir" / "deep"
            nested.mkdir(parents=True)
            (nested / "file with space.txt").write_text("x\n")
            (nested / "inner.txt").write_text("y\n")
            re_ev.ROOT = root
            try:
                state = re_ev.git_state()
            finally:
                re_ev.ROOT = real_root
            self.assertTrue(re.fullmatch(r"[0-9a-f]{40}", state["head"]))
            self.assertIn("tombstone (deleted from worktree)", state["dirty"].values())
            self.assertIn("tombstone (renamed away in worktree)",
                          state["dirty"].values())
            # renamed-new.txt is a present dirty file with a real sha; the
            # original rename source is recorded as a tombstone
            self.assertTrue(state["dirty"]["renamed-new.txt"],
                            state["dirty"])
            self.assertNotEqual(state["dirty"]["renamed-new.txt"], "")
            self.assertTrue(state["dirty"]["renamed old.txt"].startswith("tombstone"),
                            state["dirty"])
            # nested untracked files enumerated, not the abbreviated dir row
            self.assertIn("new dir/deep/file with space.txt", state["untracked"])
            self.assertIn("new dir/deep/inner.txt", state["untracked"])
            self.assertNotIn("new dir/", state["untracked"])
            self.assertNotIn("new dir/deep/", state["untracked"])

            # R2: a staged rename EDITED in the worktree ("RM") still
            # consumes the original-path field (the old parser matched
            # only a bare "R" and misread the original path as a new
            # status row).
            g("mv", "renamed-new.txt", "rm2.txt")
            (root / "rm2.txt").write_text("edited after staging\n")
            re_ev.ROOT = root
            try:
                state2 = re_ev.git_state()
            finally:
                re_ev.ROOT = real_root
            self.assertIn("tombstone (renamed away in worktree)",
                          state2["dirty"].values())
            self.assertTrue(state2["dirty"]["rm2.txt"] != ""
                            and "tombstone" not in state2["dirty"]["rm2.txt"],
                            state2["dirty"])
            # every dirty key must look like a real path (no misparsed
            # two-field rows leaking the original path as a code column)
            for k in state2["dirty"]:
                self.assertTrue(k.endswith(".txt"), state2["dirty"])

            # R2: detected copies label the still-present source as
            # remaining (git status only emits C rows under copy
            # detection, so the parser is exercised on its exact bytes)
            payload = "C  copy-dst.txt\0copy-src.txt\0"
            d, u = re_ev._parse_porcelain(payload, root)
            self.assertEqual(d["copy-src.txt"], "copied (source remains)")
            self.assertIn("copy-dst.txt", d)
            payload_rm = "RM rm-dst.txt\0rm-src.txt\0?? new dir/deep/inner.txt\0"
            d2, u2 = re_ev._parse_porcelain(payload_rm, root)
            self.assertEqual(d2["rm-src.txt"], "tombstone (renamed away in worktree)")
            self.assertIn("rm-dst.txt", d2)
            self.assertIn("new dir/deep/inner.txt", u2)

            # R3: a TRUNCATED rename row (origin field cut off) used to
            # pass as a plain dirty row -- it is refused now
            with self.assertRaises(ValueError, msg="truncated rename/copy row"):
                re_ev._parse_porcelain("RM new.txt\0", root)
            # R3: a stream missing its final NUL is a truncated read,
            # never parseable as a clean tree
            with self.assertRaises(ValueError, msg="missing final NUL"):
                re_ev._parse_porcelain(" M edited.txt", root)
            # R3: malformed entries (short row, missing separator) are
            # refused instead of silently eating path bytes
            with self.assertRaises(ValueError, msg="malformed porcelain entry"):
                re_ev._parse_porcelain("M x\0", root)
            with self.assertRaises(ValueError, msg="malformed porcelain entry"):
                re_ev._parse_porcelain("Mno-space.txt\0", root)
            # R3: a refused parse surfaces as a failure, not empty maps
            # accepted as clean
            fails = re_ev._tree_binding_failures(
                {"parse_error": "porcelain stream is truncated "
                                "(missing final NUL)", "dirty": {}, "untracked": {}},
                {"freshness": {"dirty": {}, "untracked": {}}})
            self.assertTrue(any("git status parse refused" in f
                                and "missing final NUL" in f for f in fails), fails)

            # R2: editing an already-recorded untracked file in place is
            # untracked CONTENT drift, not just a set change
            snap = {"dirty": {}, "untracked": dict(state2["untracked"])}
            (root / "new dir/deep/inner.txt").write_text("changed bytes\n")
            re_ev.ROOT = root
            try:
                state3 = re_ev.git_state()
            finally:
                re_ev.ROOT = real_root
            fails = re_ev._tree_binding_failures(state3, {"freshness": snap})
            self.assertTrue(any("untracked source drift" in f for f in fails),
                            fails)
            fails = re_ev._tree_binding_failures(state2, {"freshness": snap})
            self.assertFalse([f for f in fails if "untracked source drift" in f],
                             fails)

    def test_astra_token_removal_fails(self):
        def strip_token(td, ev):
            css = td / "web/dashboard/dist/assets/app.css"
            css.write_text(":root{--astra-duration:.14s;}body{color:#000}\n")
            ev["assets"]["dist_files"] = [
                f for f in ev["assets"]["dist_files"]
                if f["path"] != "web/dashboard/dist/assets/app.css"]
            ev["assets"]["dist_files"].append({
                "path": "web/dashboard/dist/assets/app.css",
                "sha256": re_ev.sha256_file(css)})
        self.verify_fails(strip_token, "astra token declarations not present")

    def test_dist_notice_copy_stale_fails(self):
        def stale(td, ev):
            (td / "dist/release/NOTICE").write_text("stale build NOTICE\n")
        self.verify_fails(stale, "not the current root NOTICE")

    def test_inventory_binary_sha_drift(self):
        def drift(td, ev):
            p = td / "artifacts/release-evidence/image-notices/yabanin/inventory.json"
            inv = json.loads(p.read_text())
            inv["binary_sha256"] = "0" * 64
            p.write_text(json.dumps(inv, indent=2) + "\n")
        self.verify_fails(drift, "inventory binary_sha256")

    def test_alpine_corpus_manifest_drift_fails(self):
        def drift(td, ev):
            (td / "scripts/release/image-os-notices/MANIFEST.json").write_text(
                json.dumps({"base_index_digest": "sha256:" + "d" * 64}) + "\n")
        self.verify_fails(drift, "MANIFEST base digest does not match")

    def test_retained_build_artifacts_bind_receipts(self):
        # R4-MAP-01/R2 generator side: retention copies the raw twin and
        # map verbatim, and the chunk record's map_sha256 receipt is the
        # sha256 of the RETAINED artifact bytes.
        sde = re_ev.dashboard_evidence
        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            mr = td / "maproot/assets"
            mr.mkdir(parents=True)
            raw = b'console.log("x");\n//# sourceMappingURL=app.js.map\n'
            mp = (b'{"version":3,"file":"app.js","sources":["a.js","b.js"]}\n')
            (mr / "app.js").write_bytes(raw)
            (mr / "app.js.map").write_bytes(mp)
            retained = td / "retained"
            counts = sde.retain_build_artifacts(td / "maproot", dest=retained)
            self.assertEqual(counts, {"raw_twins": 1, "maps": 1})
            self.assertEqual((retained / "assets/app.js").read_bytes(), raw)
            self.assertEqual((retained / "assets/app.js.map").read_bytes(), mp)
            rec = sde._chunk_record(td / "maproot", mr / "app.js.map",
                                    retained_root=retained)
            self.assertEqual(rec["map_sha256"],
                             hashlib.sha256(mp).hexdigest())
            self.assertEqual(rec["map_twin_raw_sha256"],
                             hashlib.sha256(raw).hexdigest())
            self.assertEqual(rec["twin_sha256"],
                             hashlib.sha256(b'console.log("x");\n').hexdigest())
            # stripping the retained raw twin reproduces the receipt chain
            stripped = sde.strip_map_comment(
                (retained / "assets/app.js").read_bytes())
            self.assertEqual(hashlib.sha256(stripped).hexdigest(),
                             rec["twin_sha256"])

    def test_map_comment_strip_rejects_trailing_bytes(self):
        sde = re_ev.dashboard_evidence
        good = b"console.log(1);\n//# sourceMappingURL=app.js.map\n"
        self.assertEqual(sde.strip_map_comment(good), b"console.log(1);\n")
        self.assertEqual(sde.strip_map_comment(good[:-1]), b"console.log(1);\n")
        bad = [
            # code appended after the final comment line
            b"console.log(1);\n//# sourceMappingURL=app.js.map\nmalicious();\n",
            # raw payload bytes after the comment (no trailing newline)
            b"console.log(1);\n//# sourceMappingURL=app.js.map\n\x00payload",
            # empty map name
            b"console.log(1);\n//# sourceMappingURL=\n",
            # second marker: arbitrary suffix removal must not rescue it
            b"console.log(1);\n//# sourceMappingURL=app.js.map"
            b"\n//# sourceMappingURL=other.map\n",
            # no comment at all
            b"console.log(1);\n",
        ]
        for payload in bad:
            with self.assertRaises(ValueError):
                sde.strip_map_comment(payload)

    def test_task_base_drift_fails(self):
        self.verify_fails(
            lambda td, ev: ev.__setitem__("task_base", "0" * 40),
            "task_base mismatch")


if __name__ == "__main__":
    unittest.main(verbosity=2)

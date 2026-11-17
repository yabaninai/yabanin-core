# SPDX-License-Identifier: Apache-2.0
"""Validate the immutable postgres image references of the Preview1 recovery
rehearsal's two phase compose files.

The upgrade contract requires the SAME supported PostgreSQL major family
(currently pg16) from the pgvector extension image in both phases; immutable
digests may differ. check_pair rejects unsupported majors (e.g. pg15),
non-pgvector images, unpinned or malformed references and ambiguous family
tags BEFORE any volume is created, and never selects a convenience tag.
"""
from __future__ import annotations

import re
import sys

SUPPORTED_MAJORS = ("16",)

# Exactly repo pgvector/pgvector, tag pg<major>, immutable sha256 digest.
_REF_RE = re.compile(r"^pgvector/pgvector:pg(?P<major>\d+)@sha256:(?P<digest>[0-9a-f]{64})$")


def parse(ref: str) -> dict:
    """Parse one immutable reference or raise ValueError with a precise reason."""
    ref = ref.strip()
    m = _REF_RE.match(ref)
    if not m:
        if not ref.startswith("pgvector/pgvector:"):
            raise ValueError(f"not the pgvector/pgvector image family: {ref!r}")
        if "@sha256:" not in ref:
            raise ValueError(f"unpinned reference (immutable digest required): {ref!r}")
        if not re.search(r"@sha256:[0-9a-f]{64}$", ref):
            raise ValueError(f"malformed sha256 digest: {ref!r}")
        raise ValueError(f"malformed or ambiguous family reference: {ref!r}")
    major = m.group("major")
    if major not in SUPPORTED_MAJORS:
        supported = ", ".join("pg" + s for s in SUPPORTED_MAJORS)
        raise ValueError(f"postgres major pg{major} is not supported ({supported}): {ref!r}")
    return {"ref": ref, "major": major, "digest": m.group("digest")}


def check_pair(ref1: str, ref2: str) -> dict:
    """Both references valid and sharing one supported major; digests may differ."""
    a, b = parse(ref1), parse(ref2)
    if a["major"] != b["major"]:
        raise ValueError(f"phase majors differ: pg{a['major']} vs pg{b['major']} (same supported major required)")
    return {"major": a["major"], "refs": (a["ref"], b["ref"]), "digests": (a["digest"], b["digest"])}


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print("usage: pg_image_refs.py REF1 REF2", file=sys.stderr)
        return 2
    try:
        result = check_pair(argv[1], argv[2])
    except ValueError as exc:
        print(f"pg image refs not compatible: {exc}", file=sys.stderr)
        return 1
    print(f"major={result['major']}")
    print(f"ref1={result['refs'][0]}")
    print(f"ref2={result['refs'][1]}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

# SPDX-License-Identifier: Apache-2.0
"""Qualification for the Preview1 recovery postgres compatibility oracle.

Covers the reference validator (scripts/quality/pg_image_refs.py): the two
rehearsed phase references share the supported pg16 major with distinct
immutable digests, while unsupported majors, non-pgvector images, unpinned
or malformed references and ambiguous family tags are rejected.

Also exercises the harness runtime assertions (assert_pg_runtime,
assert_container_image in scripts/quickstart/preview1_recovery.sh) at their
command boundaries with stub query/docker commands: query failures must be
failures (never read as absence), a missing pg_extension.extversion must
fail even when the extension is merely available, live major mismatches
against both the compose family and the recorded Preview1 major must fail,
and a running container's image must equal the recorded image ID. Positive
startup proofs remain the harness's own runtime job.
"""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[3]
HELPER = ROOT / "scripts/quality" / "pg_image_refs.py"
HARNESS = ROOT / "scripts/quickstart" / "preview1_recovery.sh"

SPEC = importlib.util.spec_from_file_location("pg_image_refs", HELPER)
pg_image_refs = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(pg_image_refs)

# The exact immutable references pinned by the two rehearsed phase sources.
REF_P1 = "pgvector/pgvector:pg16@sha256:7b822b0aac60967beb1ea5e576b8602c94c300a157d187f385ae3e0da199b90a"
REF_CAND = "pgvector/pgvector:pg16@sha256:0dd3149a06e4579a0d70d8fef9945636cd514005e7237deb27f9b67886f8dc4f"

HEX64 = "a" * 64


def ref_pg(major: str, digest: str = HEX64) -> str:
    return f"pgvector/pgvector:pg{major}@sha256:{digest}"


class PairAcceptanceTests(unittest.TestCase):
    def test_accepts_the_rehearsed_distinct_pg16_digests(self):
        result = pg_image_refs.check_pair(REF_P1, REF_CAND)
        self.assertEqual(result["major"], "16")
        self.assertEqual(result["refs"], (REF_P1, REF_CAND))
        self.assertNotEqual(*result["digests"], "distinct immutable digests must be allowed")

    def test_accepts_identical_pins_too(self):
        self.assertEqual(pg_image_refs.check_pair(REF_P1, REF_P1)["major"], "16")


class PairRejectionTests(unittest.TestCase):
    def assert_reject(self, ref1, ref2, reason_fragment):
        with self.assertRaises(ValueError) as ctx:
            pg_image_refs.check_pair(ref1, ref2)
        self.assertIn(reason_fragment, str(ctx.exception))

    def test_rejects_pg15(self):
        self.assert_reject(ref_pg("15"), ref_pg("15"), "not supported")

    def test_rejects_mixed_majors_with_the_real_parser_error(self):
        # parse() enforces SUPPORTED_MAJORS before pair comparison, so a pg15
        # second reference surfaces as "not supported" — the exact real error.
        self.assert_reject(ref_pg("16"), ref_pg("15"), "pg15 is not supported")

    def test_rejects_non_pgvector_image(self):
        self.assert_reject(f"postgres:16@sha256:{HEX64}", ref_pg("16"), "image family")

    def test_rejects_unpinned_reference(self):
        self.assert_reject("pgvector/pgvector:pg16", ref_pg("16"), "unpinned")

    def test_rejects_malformed_digest(self):
        self.assert_reject(ref_pg("16", "a" * 63), ref_pg("16"), "malformed sha256 digest")
        self.assert_reject(ref_pg("16", "A" * 64), ref_pg("16"), "malformed")

    def test_rejects_ambiguous_family_tag(self):
        self.assert_reject(f"pgvector/pgvector:pg16-v0.7.1@sha256:{HEX64}", ref_pg("16"), "malformed or ambiguous")


class CliTests(unittest.TestCase):
    def run_helper(self, *args):
        return subprocess.run(
            [sys.executable, str(HELPER), *args], capture_output=True, text=True, check=False
        )

    def test_cli_accepts_the_rehearsed_pair(self):
        proc = self.run_helper(REF_P1, REF_CAND)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("major=16", proc.stdout)
        self.assertIn(REF_P1, proc.stdout)
        self.assertIn(REF_CAND, proc.stdout)

    def test_cli_rejects_pg15_with_reason(self):
        proc = self.run_helper(ref_pg("15"), ref_pg("15"))
        self.assertEqual(proc.returncode, 1)
        self.assertIn("not supported", proc.stderr)

    def test_cli_usage_error_is_distinct(self):
        proc = self.run_helper(REF_P1)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("usage", proc.stderr)


class HarnessRuntimeOracleTests(unittest.TestCase):
    """Failure modes of the harness's live-server assertions, using the REAL
    shipped helper bytes extracted from the harness and stub command
    boundaries (no Docker daemon, no database)."""

    # FAULT must be captured from the environment BEFORE MODE="$2" overwrites
    # the ambient MODE variable; qf injects the fault on that captured value.
    DRIVER = textwrap.dedent("""\
        set -u
        REAL_H="$1"; MODE="$2"; WANT="${3:-16}"; BIN="$4"
        FAULT="${FAULT:-}"
        extract() { awk -v fn="$1" '$0 ~ "^"fn"\\\\(\\\\)", /^}/' "$REAL_H"; }
        { extract fail; extract assert_pg_runtime; extract assert_container_image; } > "$BIN/helpers.sh"
        source "$BIN/helpers.sh"
        CURRENT_CASE=tst; CURRENT_STEP=t; PG_MAJ="${PG_MAJ:-16}"; RECORD="$BIN/record"
        qf() {
          case "$1" in
            *server_version_num*) [[ "$FAULT" == query-fail ]] && exit 42; echo "${VERNUM:-160004}" ;;
            *pg_extension*)       [[ "$FAULT" == ext-fail ]] && exit 42; echo "${EXT:-}" ;;
            *pg_available_extensions*) echo "${AVAIL:-0.10.0}" ;;
          esac
        }
        case "$MODE" in
          pg)          out=$(assert_pg_runtime qf lbl "$WANT") ;;
          img)         assert_container_image cont "sha256:EXPECTED" lbl ;;
          inspect-fail) assert_container_image cont "sha256:EXPECTED" lbl ;;
        esac
        rc=$?
        echo "$rc" > "$BIN/rc"
        printf '%s' "$out" > "$BIN/out"
        """)

    def run_driver(self, mode, fault=None, vernum=None, ext=None, avail=None,
                   pg_maj=None, want="16", docker_stub=None):
        with tempfile.TemporaryDirectory() as tmp_raw:
            tmp = Path(tmp_raw)
            stub = tmp / "docker"
            stub.write_text(docker_stub or "#!/usr/bin/env bash\nexit 1\n")
            stub.chmod(0o755)
            driver = tmp / "driver.sh"
            driver.write_text(self.DRIVER)
            (tmp / "record").write_text("")
            env = {"PATH": f"{tmp}:/usr/bin:/bin", "HOME": str(tmp)}
            if fault is not None:
                env["FAULT"] = fault
            if vernum is not None:
                env["VERNUM"] = vernum
            if ext is not None:
                env["EXT"] = ext
            if avail is not None:
                env["AVAIL"] = avail
            if pg_maj is not None:
                env["PG_MAJ"] = pg_maj
            proc = subprocess.run(
                ["bash", str(driver), str(HARNESS), mode, want, str(tmp)],
                capture_output=True, text=True, check=False, env=env,
            )
            rc = (tmp / "rc").read_text().strip() if (tmp / "rc").exists() else "none"
            out = (tmp / "out").read_text() if (tmp / "out").exists() else ""
            record = (tmp / "record").read_text()
            return proc, rc, out, record

    def test_query_failure_is_a_failure_not_absence(self):
        proc, rc, _, _ = self.run_driver("pg", fault="query-fail", vernum="160004")
        self.assertEqual(rc, "1")
        self.assertIn("SHOW server_version_num query failed", proc.stderr)

    def test_vector_query_transport_error_is_a_failure_not_absence(self):
        proc, rc, _, _ = self.run_driver("pg", fault="ext-fail", vernum="160004", ext="0.8.0")
        self.assertEqual(rc, "1")
        self.assertIn("vector extversion query failed", proc.stderr)

    def test_missing_extversion_fails_even_when_available(self):
        proc, rc, _, _ = self.run_driver("pg", vernum="160004", ext="", avail="0.10.0")
        self.assertEqual(rc, "1")
        self.assertIn("NOT installed", proc.stderr)
        self.assertIn("availability is not installation", proc.stderr)

    def test_major_mismatch_against_recorded_preview1_major(self):
        # Live 17 matches the compose family (PG_MAJ=17) so the earlier
        # family check passes and the recorded-major branch is what fires.
        proc, rc, _, _ = self.run_driver("pg", pg_maj="17", vernum="170004", ext="0.8.0", want="16")
        self.assertEqual(rc, "1")
        self.assertIn("live server major 17 != preview1's recorded 16", proc.stderr)

    def test_major_mismatch_against_compose_family(self):
        proc, rc, _, _ = self.run_driver("pg", pg_maj="17", vernum="160004", ext="0.8.0")
        self.assertEqual(rc, "1")
        self.assertIn("live server major 16 != compose pg17 family", proc.stderr)

    def test_image_id_mismatch_fails(self):
        stub = "#!/usr/bin/env bash\nprintf 'sha256:WRONGID\\n'\n"
        proc, _, _, _ = self.run_driver("img", docker_stub=stub)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("image sha256:WRONGID != expected sha256:EXPECTED", proc.stderr)

    def test_inspect_failure_fails_closed(self):
        proc, _, _, _ = self.run_driver("inspect-fail", docker_stub="#!/usr/bin/env bash\nexit 3\n")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("docker inspect cont failed", proc.stderr)

    def test_wiring_positive(self):
        # Extraction/sourcing sanity only; the real positive proof is the
        # harness's own startup assertions in the executed rehearsal.
        proc, rc, out, record = self.run_driver("pg", vernum="160004", ext="0.8.0")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(rc, "0")
        self.assertEqual(out, "16")
        self.assertIn("pg_lbl_server_version_num 160004", record)
        self.assertIn("pg_lbl_vector_extversion 0.8.0", record)


if __name__ == "__main__":
    unittest.main()

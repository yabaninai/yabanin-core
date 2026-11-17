#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Focused no-Docker qualification for the recovery harness phase-env and
project-name setup oracles.

Contract under test, executed against REAL harness bytes (extraction, not
copies) and the REAL product init-env.sh:
- provision_phase_env: secrets are generated exactly once through the real
  init-env.sh; IDENTICAL mode-600 bytes are installed into BOTH phase
  project dirs (compose declares `env_file: .env`, project-relative);
  pre-existing phase envs are the authority — never regenerated, never
  rewritten, mode tightened to 600 without byte changes; every failure is
  loud and precedes any Compose call; secret values never reach harness
  output.
- require_phase_env: rollback resume reuses the upgrade run's recorded
  fingerprint verbatim — bytes, mode and fingerprint are all checked and
  nothing is rewritten.
- project_name_ok: strict lowercase docker-safe subset, enforced at the gate
  before any docker object is named.

No Docker daemon is used. An orchestration fixture runs the REAL harness
through PF1..PF5 under a recording docker stub: listing/build/inspect
operations are simulated, while any project-state-changing invocation
(compose up/exec/..., docker run/exec/...) is recorded to a canary and
fails. That proves the failure paths and the env provisioning are ordered
BEFORE the first state-changing compose call.

Secret handling: the tests read generated .env values inside the test
process to verify they were really generated and never echoed; all such
assertions are boolean so no assertion message can contain a value, and
files are compared via sha256/mode only.
"""

import hashlib
import os
import pathlib
import re
import shutil
import stat
import subprocess
import textwrap
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parents[3]
REAL_H = REPO / "scripts" / "quickstart" / "preview1_recovery.sh"
REAL_INIT_ENV = REPO / "scripts" / "quickstart" / "init-env.sh"
REAL_EXAMPLE = REPO / "deploy" / "quickstart" / ".env.example"
PREVIEW1_COMMIT = "7b85b18963ce764aea1f9631a7d47104b09550aa"
CANDIDATE_COMMIT = "3a73e8e08b532df2b51a5fb47f19fbdbdff2f045"
KEYS = ("YABANIN_SESSION_KEY", "YABANIN_CACHE_HMAC_SECRET", "YABANIN_ENCRYPTION_KEY")
LOOP_TOOLS = ("docker", "ss", "curl", "sha256sum", "timeout", "sed", "grep",
              "awk", "comm", "stat", "tar", "date", "head", "od", "git",
              "python3", "openssl", "cmp", "cp")

DOCKER_STUB = r'''#!/usr/bin/env bash
# Recording docker stub (no daemon). Listing/build/inspect/pull ops are
# simulated deterministically; any project-state-changing invocation is
# recorded to $CANARY and fails. env facts are recorded as mode/mode600
# boolean plus sha256 fingerprint only.
set -u
pd=""; pn=""
args=("$@")
i=0
while [ $i -lt ${#args[@]} ]; do
  a=${args[$i]}
  if [ "$a" = "--project-directory" ]; then pd=${args[$((i+1))]}; fi
  if [ "$a" = "--project-name" ]; then pn=${args[$((i+1))]}; fi
  i=$((i+1))
done
cmd=${args[0]}
case "$cmd" in
  compose)
    sub=""; j=1; skip=0
    while [ $j -lt ${#args[@]} ]; do
      t=${args[$j]}
      if [ $skip -eq 1 ]; then skip=0
      else
        case "$t" in
          --project-name|--project-directory|-f|--file|--profile) skip=1 ;;
          -*) ;;
          *) if [ -z "$sub" ]; then sub=$t; fi ;;
        esac
      fi
      j=$((j+1))
    done
    if [ "$sub" = "ls" ]; then printf 'allowed compose ls\n' >> "$LOG"; exit 0; fi
    f="$pd/.env"; ok=0; h=none
    if [ -s "$f" ] && [ "$(stat -c %a "$f" 2>/dev/null)" = "600" ]; then
      ok=1; h=$(sha256sum "$f" | cut -d' ' -f1)
    fi
    printf 'COMPOSE-CALL sub=%s project=%s project_dir=%s env_present_mode600=%s env_sha=%s\n' \
      "$sub" "$pn" "$pd" "$ok" "$h" >> "$CANARY"
    exit 3 ;;
  build) printf 'allowed build\n' >> "$LOG"; exit 0 ;;
  pull)  printf 'allowed pull %s\n' "$pd" >> "$LOG"; exit 0 ;;
  volume) [ "$2" = "ls" ] && exit 0
          printf 'STATE-OP %s\n' "$*" >> "$CANARY"; exit 3 ;;
  network)
    if [ "$2" = "ls" ]; then echo "yabanin-quickstart_default"; exit 0; fi
    if [ "$2" = "inspect" ]; then
      printf '%s\n' "${HELD_SUBNETS:-10.207.0.0/24 }"; exit 0
    fi
    printf 'STATE-OP %s\n' "$*" >> "$CANARY"; exit 3 ;;
  image)
    if [ "$2" = "inspect" ]; then
      ref=${args[2]}
      printf 'allowed image inspect %s\n' "$ref" >> "$LOG"
      printf 'sha256:%s' "$ref" | sha256sum | cut -d' ' -f1 | sed 's/^/sha256:/' ; exit 0
    fi
    printf 'STATE-OP %s\n' "$*" >> "$CANARY"; exit 3 ;;
  *) printf 'STATE-OP %s\n' "$*" >> "$CANARY"; exit 3 ;;
esac
'''

GIT_STUB = r'''#!/usr/bin/env bash
# git forwarding stub: object operations are real; the worktree-clean gate
# (diff --quiet / diff --cached --quiet) is satisfied to simulate the
# post-review committed state, and optionally the Preview1 archive is
# filtered to carry a failing init-env.sh (failure-injection fixture).
set -u
isd=0; iq=0; arch=0
for a in "$@"; do
  [ "$a" = "diff" ] && isd=1
  [ "$a" = "--quiet" ] && iq=1
  [ "$a" = "archive" ] && arch=1
done
if [ $isd -eq 1 ] && [ $iq -eq 1 ]; then
  printf 'git-stub simulated clean gate\n' >> "$LOG"; exit 0
fi
if [ "$INJECT_INITENV_FAIL" = "1" ] && [ $arch -eq 1 ]; then
  for a in "$@"; do
    if [ "$a" = "$PREVIEW1_COMMIT" ]; then
      tmp=$(mktemp -d "${TMPDIR:-/tmp}/gxf.XXXXXX")
      "$REAL_GIT" "$@" > "$tmp/a.tar"
      mkdir "$tmp/x"; tar -xf "$tmp/a.tar" -C "$tmp/x"
      printf '#!/usr/bin/env bash\nexit 3\n' > "$tmp/x/scripts/quickstart/init-env.sh"
      chmod 700 "$tmp/x/scripts/quickstart/init-env.sh"
      tar -cf - -C "$tmp/x" .
      rm -rf "$tmp"
      exit 0
    fi
  done
fi
exec "$REAL_GIT" "$@"
'''


def _extract_from(text: str, fn: str) -> str:
    """Shared exact-boundary function extraction over given harness text."""
    lines = text.splitlines()
    prefix = fn + "()"
    cand = [k for k, ln in enumerate(lines)
            if ln.startswith(prefix) and ln[len(prefix):].lstrip().startswith("{")]
    if not cand:
        raise AssertionError(f"harness function not found: {fn}")
    i = cand[0]
    if lines[i].rstrip().endswith("}"):
        return lines[i] + "\n"
    j = i + 1
    while j < len(lines) and lines[j] != "}":
        j += 1
    if j >= len(lines):
        raise AssertionError(f"harness function boundary not found: {fn}")
    return "\n".join(lines[i:j + 1]) + "\n"


def extract(fn: str) -> str:
    """Deterministic exact-boundary extraction of a harness function.

    The returned text is REAL harness source: the exact `fn() {` line (extra
    spacing between `()` and `{` tolerated) through the next column-zero `}`
    line. A single-line `fn() { ...; }` function returns just that line. Fails
    loudly if any boundary is missing so a mis-extraction can never silently
    pull unrelated main-flow text in.
    """
    return _extract_from(REAL_H.read_text(), fn)


# Import-time extraction sanity: sha_file is a single-line function whose
# extraction must never pull project_name_ok or any main-flow text through a
# mis-detected boundary.
_SHA_FILE = extract("sha_file")
assert "sha256sum" in _SHA_FILE, _SHA_FILE
assert len(_SHA_FILE.strip().splitlines()) == 1, _SHA_FILE
for _unrelated in ("project_name_ok", "docker compose", "mkdir", "phase_env"):
    assert _unrelated not in _SHA_FILE, _unrelated


def gate_region() -> str:
    body = subprocess.run(
        ["awk", '$0 ~ /^MODE=/, /^done$/', str(REAL_H)],
        capture_output=True, text=True, check=True,
    ).stdout
    assert 'project_name_ok "$PROJECT"' in body and "command -v" in body
    return body


# Absolute trusted interpreter: stub-only PATH fixtures (missing-cp preflight
# test) cannot resolve `bash` for subprocess spawn; resolve it here first.
BASH = shutil.which("bash")


def run_bash(script: str, env_extra=None):
    env = dict(os.environ)
    env.update(env_extra or {})
    return subprocess.run(
        [BASH, "-c", script], capture_output=True, text=True, env=env)


def make_docker_canary(dir_: pathlib.Path):
    """Executable docker stub that records any invocation and fails."""
    d = dir_ / "bin-canary"
    d.mkdir(parents=True, exist_ok=True)
    canary = d / "invocations.txt"
    stub = d / "docker"
    stub.write_text(
        '#!/usr/bin/env bash\n'
        'printf "docker %s\\n" "$*" >> "$CANARY"\n'
        'exit 3\n')
    stub.chmod(0o700)
    return d, canary


def sha256_of(path: pathlib.Path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_secret_values(path: pathlib.Path):
    """Read YABANIN_* values from an env file into the test process.

    The values stay in memory; assertions on them are boolean-only so no
    failure message can echo a value back.
    """
    vals = {}
    for line in path.read_text().splitlines():
        m = re.match(r"^(YABANIN_[A-Z_]+)=(.+)$", line)
        if m:
            vals[m.group(1)] = m.group(2)
    return vals


class SetupFixture:
    """Temp archive layout + phase dirs; secrets never leave the temp dir."""

    def __init__(self, root: pathlib.Path, init_env=None, example=True,
                 archive_env=None):
        self.root = root
        self.src = root / "src-preview1"
        self.p1 = root / "preview1"
        self.cnd = root / "candidate"
        for d in (self.src / "scripts" / "quickstart",
                  self.src / "deploy" / "quickstart", self.p1, self.cnd):
            d.mkdir(parents=True, exist_ok=True)
        init_env_path = self.src / "scripts" / "quickstart" / "init-env.sh"
        if init_env is None:
            init_env_path.write_bytes(REAL_INIT_ENV.read_bytes())
        else:
            init_env_path.write_text(init_env)
        init_env_path.chmod(0o700)
        if example:
            (self.src / "deploy" / "quickstart" / ".env.example").write_bytes(
                REAL_EXAMPLE.read_bytes())
        if archive_env is not None:
            (self.src / "deploy" / "quickstart" / ".env").write_text(archive_env)

    def run_provision(self, env_extra=None):
        script = f"""
        {extract('fail')}
        {extract('sha_file')}
        {extract('provision_phase_env')}
        CURRENT_CASE=tst; CURRENT_STEP=t
        provision_phase_env "$SRC" "$P1" "$CND"
        """
        env = {"SRC": str(self.src), "P1": str(self.p1), "CND": str(self.cnd)}
        env.update(env_extra or {})
        return run_bash(script, env)

    def run_require(self, identity_text):
        ident = self.root / "identity.txt"
        ident.write_text(identity_text)
        script = f"""
        {extract('fail')}
        {extract('sha_file')}
        {extract('require_phase_env')}
        CURRENT_CASE=tst; CURRENT_STEP=t
        require_phase_env "$P1" "$CND" "$IDENT"
        """
        return run_bash(script, {
            "P1": str(self.p1), "CND": str(self.cnd), "IDENT": str(ident)})


class ProvisionTests(unittest.TestCase):
    def test_real_init_env_produces_identical_mode600_phase_envs_without_secret_output(self):
        with tempfile.TemporaryDirectory(prefix="p1r-setup-") as td:
            fx = SetupFixture(pathlib.Path(td))
            r = fx.run_provision()
            self.assertEqual(r.returncode, 0, r.stderr)
            e1, e2 = fx.p1 / ".env", fx.cnd / ".env"
            self.assertTrue(e1.is_file() and e2.is_file())
            self.assertEqual(sha256_of(e1), sha256_of(e2))
            for f in (e1, e2):
                self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600)
            # stdout is exactly the fingerprint (init-env chatter goes to stderr)
            self.assertEqual(r.stdout.strip(), sha256_of(e1))
            # real generated values, not the example placeholders (boolean
            # assertions only — no value can leak through a failure message)
            example_vals = read_secret_values(REAL_EXAMPLE)
            got = read_secret_values(e1)
            for k in KEYS:
                self.assertTrue(k in got, k)
                self.assertTrue(bool(got[k]), k)
                self.assertFalse(got[k] == example_vals.get(k, ""), k)
            # secret values never appear in captured harness output
            out = r.stdout + r.stderr
            for v in got.values():
                self.assertFalse(v in out)

    def test_init_env_failure_fails_loudly_before_any_phase_env_or_compose_call(self):
        with tempfile.TemporaryDirectory(prefix="p1r-setup-") as td:
            root = pathlib.Path(td)
            fx = SetupFixture(root, init_env="#!/usr/bin/env bash\nexit 3\n")
            bindir, canary = make_docker_canary(root)
            r = fx.run_provision(env_extra={
                "PATH": f"{bindir}:{os.environ['PATH']}", "CANARY": str(canary)})
            self.assertEqual(r.returncode, 1)
            self.assertIn("init-env.sh failed", r.stderr)
            self.assertFalse((fx.p1 / ".env").exists())
            self.assertFalse((fx.cnd / ".env").exists())
            self.assertFalse(canary.exists())

    def test_missing_example_is_a_failure_not_a_bogus_env(self):
        with tempfile.TemporaryDirectory(prefix="p1r-setup-") as td:
            fx = SetupFixture(pathlib.Path(td), example=False)
            r = fx.run_provision()
            self.assertEqual(r.returncode, 1)
            self.assertIn("init-env.sh failed", r.stderr)
            self.assertFalse((fx.cnd / ".env").exists())

    def test_existing_phase_envs_are_the_authority_and_are_never_regenerated(self):
        env_bytes = b"YABANIN_SESSION_KEY=kept-secret-1\n"
        env_hash = hashlib.sha256(env_bytes).hexdigest()
        with tempfile.TemporaryDirectory(prefix="p1r-setup-") as td:
            # canary init-env would exit 3; the authority branch must not run it
            fx = SetupFixture(pathlib.Path(td),
                              init_env="#!/usr/bin/env bash\nexit 3\n",
                              example=False)
            (fx.p1 / ".env").write_bytes(env_bytes)
            (fx.cnd / ".env").write_bytes(env_bytes)
            for f in (fx.p1 / ".env", fx.cnd / ".env"):
                f.chmod(0o600)
            r = fx.run_provision()
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.strip(), env_hash)
            self.assertEqual(sha256_of(fx.p1 / ".env"), env_hash)
            self.assertEqual(sha256_of(fx.cnd / ".env"), env_hash)

    def test_reuse_enforces_mode600_without_changing_bytes(self):
        env_bytes = b"YABANIN_SESSION_KEY=mode-drift\n"
        env_hash = hashlib.sha256(env_bytes).hexdigest()
        with tempfile.TemporaryDirectory(prefix="p1r-setup-") as td:
            fx = SetupFixture(pathlib.Path(td), example=False)
            (fx.p1 / ".env").write_bytes(env_bytes)
            (fx.cnd / ".env").write_bytes(env_bytes)
            for f in (fx.p1 / ".env", fx.cnd / ".env"):
                f.chmod(0o644)
            r = fx.run_provision()
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.strip(), env_hash)
            for f in (fx.p1 / ".env", fx.cnd / ".env"):
                self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600)
                self.assertEqual(sha256_of(f), env_hash)

    def test_half_present_phase_env_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="p1r-setup-") as td:
            fx = SetupFixture(pathlib.Path(td))
            (fx.p1 / ".env").write_text("YABANIN_SESSION_KEY=x\n")
            (fx.p1 / ".env").chmod(0o600)
            r = fx.run_provision()
            self.assertEqual(r.returncode, 1)
            self.assertIn("only one phase .env exists", r.stderr)

    def test_archive_env_divergence_from_installed_phase_env_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="p1r-setup-") as td:
            fx = SetupFixture(pathlib.Path(td),
                              archive_env="YABANIN_SESSION_KEY=other\n")
            (fx.p1 / ".env").write_text("YABANIN_SESSION_KEY=kept\n")
            (fx.cnd / ".env").write_text("YABANIN_SESSION_KEY=kept\n")
            for f in (fx.p1 / ".env", fx.cnd / ".env"):
                f.chmod(0o600)
            r = fx.run_provision()
            self.assertEqual(r.returncode, 1)
            self.assertIn("archive .env differs", r.stderr)

    def test_corrupted_second_copy_is_detected(self):
        real_cp = shutil.which("cp")
        self.assertTrue(real_cp)
        with tempfile.TemporaryDirectory(prefix="p1r-setup-") as td:
            root = pathlib.Path(td)
            fx = SetupFixture(root)
            stub = root / "bin-cp"
            stub.mkdir()
            (stub / "cp").write_text(
                '#!/usr/bin/env bash\n'
                'n=$(cat "$N" 2>/dev/null || echo 0); n=$((n+1)); echo $n > "$N"\n'
                'if [ "$n" -eq 2 ]; then printf "corrupted\\n" > "$2"; exit 0; fi\n'
                'exec "$REAL_CP" "$@"\n')
            (stub / "cp").chmod(0o700)
            r = fx.run_provision(env_extra={
                "PATH": f"{stub}:{os.environ['PATH']}",
                "REAL_CP": real_cp, "N": str(root / "n")})
            self.assertEqual(r.returncode, 1)
            self.assertIn("bytes differ", r.stderr)


class RequireTests(unittest.TestCase):
    ENV = b"YABANIN_SESSION_KEY=resume-secret\nYABANIN_ENCRYPTION_KEY=resume-enc\n"
    ENV_HASH = hashlib.sha256(ENV).hexdigest()

    def _install(self, fx, p1=None, cnd=None, mode=0o600):
        (fx.p1 / ".env").write_bytes(p1 if p1 is not None else self.ENV)
        (fx.cnd / ".env").write_bytes(cnd if cnd is not None else self.ENV)
        (fx.p1 / ".env").chmod(mode)
        (fx.cnd / ".env").chmod(mode)

    def test_resume_reuses_recorded_env_verbatim_without_rewriting(self):
        with tempfile.TemporaryDirectory(prefix="p1r-setup-") as td:
            fx = SetupFixture(pathlib.Path(td))
            self._install(fx)
            m1 = (fx.p1 / ".env").stat().st_mtime_ns
            m2 = (fx.cnd / ".env").stat().st_mtime_ns
            r = fx.run_require(f"phase_env_sha256 {self.ENV_HASH}\n")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout, self.ENV_HASH)
            self.assertEqual((fx.p1 / ".env").stat().st_mtime_ns, m1)
            self.assertEqual((fx.cnd / ".env").stat().st_mtime_ns, m2)
            self.assertEqual(sha256_of(fx.p1 / ".env"), self.ENV_HASH)
            self.assertEqual(sha256_of(fx.cnd / ".env"), self.ENV_HASH)

    def test_resume_rejects_missing_phase_env(self):
        with tempfile.TemporaryDirectory(prefix="p1r-setup-") as td:
            fx = SetupFixture(pathlib.Path(td))
            self._install(fx)
            (fx.cnd / ".env").unlink()
            r = fx.run_require("phase_env_sha256 x\n")
            self.assertEqual(r.returncode, 1)
            self.assertIn("phase .env missing", r.stderr)

    def test_resume_rejects_diverging_phase_envs(self):
        with tempfile.TemporaryDirectory(prefix="p1r-setup-") as td:
            fx = SetupFixture(pathlib.Path(td))
            self._install(fx, cnd=b"YABANIN_SESSION_KEY=other\n")
            r = fx.run_require("phase_env_sha256 x\n")
            self.assertEqual(r.returncode, 1)
            self.assertIn("bytes differ", r.stderr)

    def test_resume_rejects_modified_env_vs_recorded_fingerprint(self):
        with tempfile.TemporaryDirectory(prefix="p1r-setup-") as td:
            fx = SetupFixture(pathlib.Path(td))
            # BOTH phase envs carry the modified value (byte-identical) so the
            # earlier bytes-differ guard stays silent and the fingerprint
            # comparison itself is what must fire.
            mod = b"YABANIN_SESSION_KEY=rewritten\n"
            self._install(fx, mod, cnd=mod)
            r = fx.run_require("phase_env_sha256 deadbeef\n")
            self.assertEqual(r.returncode, 1)
            self.assertIn("differs from the upgrade run's recorded", r.stderr)

    def test_resume_rejects_missing_recorded_fingerprint(self):
        with tempfile.TemporaryDirectory(prefix="p1r-setup-") as td:
            fx = SetupFixture(pathlib.Path(td))
            self._install(fx)
            r = fx.run_require("postgres_major 16\n")
            self.assertEqual(r.returncode, 1)
            self.assertIn("no phase_env_sha256 recorded", r.stderr)

    def test_resume_rejects_wrong_mode(self):
        with tempfile.TemporaryDirectory(prefix="p1r-setup-") as td:
            fx = SetupFixture(pathlib.Path(td))
            self._install(fx, mode=0o644)
            r = fx.run_require(f"phase_env_sha256 {self.ENV_HASH}\n")
            self.assertEqual(r.returncode, 1)
            self.assertIn("mode drift", r.stderr)
            self.assertIn("600/600", r.stderr)


class ProjectNameTests(unittest.TestCase):
    def test_rule_accepts_strict_lowercase_subset(self):
        for name in ("qs-p1recovery", "qs-p1recovery-r3", "a1", "a-b_c9"):
            r = run_bash(
                extract("project_name_ok")
                + f'project_name_ok "{name}" && echo OK\n')
            self.assertEqual(r.returncode, 0, name)
            self.assertEqual(r.stdout.strip(), "OK")

    def test_rule_rejects_everything_else(self):
        for name in ("", "Bad", "UP", "-lead", "_x", "qs/x", "qs x",
                     "qs..x", "QS-R3", "qsé3"):
            r = run_bash(
                extract("project_name_ok")
                + f'project_name_ok "{name}" || echo REJECTED\n')
            self.assertEqual(r.stdout.strip(), "REJECTED", name)


class ExecutableWiringTests(unittest.TestCase):
    """Real gate wiring executed with a docker canary on PATH."""

    def _run_gate(self, root, project):
        bindir, canary = make_docker_canary(root)
        script = f"""
        {extract('fail')}
        {extract('project_name_ok')}
        CURRENT_CASE=tst; CURRENT_STEP=t
        set -- all
        PROJECT="{project}"
        {gate_region()}
        echo GATE-PASSED
        """
        r = run_bash(script, {
            "PATH": f"{bindir}:{os.environ['PATH']}", "CANARY": str(canary)})
        return r, canary

    def test_invalid_project_fails_at_the_gate_before_any_compose_call(self):
        with tempfile.TemporaryDirectory(prefix="p1r-setup-") as td:
            r, canary = self._run_gate(pathlib.Path(td), "Bad Project")
            self.assertEqual(r.returncode, 1)
            self.assertIn("invalid QS_RECOVERY_PROJECT", r.stderr)
            self.assertFalse(canary.exists())

    def test_valid_project_passes_the_gate_without_touching_compose(self):
        with tempfile.TemporaryDirectory(prefix="p1r-setup-") as td:
            r, canary = self._run_gate(pathlib.Path(td), "qs-p1recovery-r3")
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(r.stdout.strip(), "GATE-PASSED")
            self.assertFalse(canary.exists())

    def test_missing_cp_fails_the_tool_preflight_before_compose(self):
        with tempfile.TemporaryDirectory(prefix="p1r-setup-") as td:
            root = pathlib.Path(td)
            bindir, canary = make_docker_canary(root)
            for t in LOOP_TOOLS:
                if t == "cp":
                    continue  # deliberately absent
                target = bindir / t
                if not target.exists():
                    os.symlink(shutil.which(t), target)
            script = f"""
            {extract('fail')}
            {extract('project_name_ok')}
            CURRENT_CASE=tst; CURRENT_STEP=t
            set -- all
            PROJECT="qs-p1recovery-r3"
            {gate_region()}
            """
            r = run_bash(script, {
                "PATH": f"{bindir}", "CANARY": str(canary)})
            self.assertEqual(r.returncode, 1)
            self.assertIn("required tool missing: cp", r.stderr)
            self.assertFalse(canary.exists())


class FullHarnessOrchestrationTests(unittest.TestCase):
    """The REAL harness (working-copy bytes) driven through PF1..PF5 and the
    first compose call under recording docker/ss/git stubs. No daemon, no
    fake success: the run is EXPECTED to stop at the first state-changing
    compose call (the stub fails it), which is exactly the ordering oracle.
    """

    def _run_harness(self, inject_initenv_fail=False, project=None,
                     held_subnets=None):
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="p1r-orch-"))
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        bindir = tmp / "bin-stub"
        bindir.mkdir()
        (bindir / "docker").write_text(DOCKER_STUB)
        (bindir / "ss").write_text("#!/usr/bin/env bash\nexit 0\n")
        (bindir / "git").write_text(GIT_STUB)
        for name in ("docker", "ss", "git"):
            (bindir / name).chmod(0o700)
        tmpdir = tmp / "tmp"
        tmpdir.mkdir()
        canary = tmp / "compose-canary.txt"
        log = tmp / "docker-ops.log"
        env = dict(os.environ)
        env.update({
            "PATH": f"{bindir}:{os.environ['PATH']}",
            "QS_RECOVERY_EXECUTE": "1",
            "QS_RECOVERY_TMPDIR": str(tmp / "runtmp"),
            "QS_RECOVERY_PROJECT": project or "p1r-fxt-orchestra",
            "QS_GATEWAY_PORT": "48197",
            "QS_ADMIN_PORT": "48198",
            "TMPDIR": str(tmpdir),
            "REAL_GIT": shutil.which("git"),
            "INJECT_INITENV_FAIL": "1" if inject_initenv_fail else "0",
            "PREVIEW1_COMMIT": PREVIEW1_COMMIT,
            "LOG": str(log),
            "CANARY": str(canary),
        })
        if held_subnets is not None:
            env["HELD_SUBNETS"] = held_subnets
        r = subprocess.run(
            [BASH, str(REAL_H)], capture_output=True, text=True,
            env=env, cwd=REPO, timeout=180)
        return r, tmp, canary

    def test_injected_initenv_failure_stops_at_pf5_before_any_compose_call(self):
        r, tmp, canary = self._run_harness(inject_initenv_fail=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("phase env: init-env.sh failed inside", r.stderr)
        # the injected stub really is what ran
        injected = (tmp / "runtmp" / "src-preview1" / "scripts" / "quickstart"
                    / "init-env.sh").read_text()
        self.assertEqual(injected, "#!/usr/bin/env bash\nexit 3\n")
        # no phase env was invented and no state-changing op was attempted
        self.assertFalse((tmp / "runtmp" / "preview1" / ".env").exists())
        self.assertFalse((tmp / "runtmp" / "candidate" / ".env").exists())
        self.assertFalse(canary.exists())

    def test_pf1_selects_first_free_later_subnet_when_201_204_held(self):
        # R7 reality: 10.207.201-204 are held by earlier runs and the shared
        # 10.207.0.0/24 is always reported held. The deterministic candidate
        # order must select 10.207.205.0/24 (mock .9) and proceed to UP1.
        held = ("10.207.0.0/24 10.207.201.0/24 10.207.202.0/24 "
                "10.207.203.0/24 10.207.204.0/24 ")
        project = "p1r-fxt-subnet205"
        r, tmp, canary = self._run_harness(project=project, held_subnets=held)
        self.assertEqual(r.returncode, 1)
        self.assertIn("QS-UPGRADE-P1/UP1", r.stderr)
        self.assertIn("scratch subnet 10.207.205.0/24 mock ip 10.207.205.9",
                      r.stdout)
        self.assertTrue(canary.is_file())  # a compose up was reached

    def test_pf1_fails_closed_when_all_candidate_subnets_held(self):
        # every scratch candidate (201-208) plus the shared subnet is held:
        # PF1 must refuse BEFORE any compose call, staying fail-closed
        # rather than touching an occupied network.
        held = "10.207.0.0/24 " + " ".join(
            f"10.207.{n}.0/24" for n in range(201, 209)) + " "
        r, tmp, canary = self._run_harness(held_subnets=held)
        self.assertEqual(r.returncode, 1)
        self.assertIn("no free scratch subnet available "
                      "(10.207.201-208 all held)", r.stderr)
        self.assertFalse(canary.exists())  # no compose call ever attempted

    def test_first_compose_call_observes_ready_phase_envs(self):
        project = "p1r-fxt-firstup"
        r, tmp, canary = self._run_harness(project=project)
        # the stub fails the first up: the harness must fail exactly there
        self.assertEqual(r.returncode, 1)
        self.assertIn("QS-UPGRADE-P1/UP1", r.stderr)
        self.assertIn("preview1 up --wait failed", r.stderr)
        self.assertTrue(canary.is_file())
        lines = canary.read_text().splitlines()
        self.assertEqual(len(lines), 1, lines)
        m = re.search(
            r"COMPOSE-CALL sub=(\S+) project=(\S+) project_dir=(\S+) "
            r"env_present_mode600=(\S+) env_sha=(\S+)", lines[0])
        self.assertIsNotNone(m, lines[0])
        self.assertEqual(m.group(1), "up")
        self.assertEqual(m.group(2), project)  # QS_RECOVERY_PROJECT propagated
        self.assertEqual(m.group(4), "1")      # env ready before first up
        sha = m.group(5)
        self.assertRegex(sha, r"^[0-9a-f]{64}$")
        # both phase envs on disk: present, mode 600, identical to the stub's
        # observation at the command boundary
        for phase in ("preview1", "candidate"):
            f = tmp / "runtmp" / phase / ".env"
            self.assertTrue(f.is_file(), phase)
            self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o600, phase)
            self.assertEqual(sha256_of(f), sha, phase)
        self.assertEqual(sha256_of(tmp / "runtmp" / "preview1" / ".env"),
                         sha256_of(tmp / "runtmp" / "candidate" / ".env"))
        # the identity evidence recorded the fingerprint at PF5
        ident = (tmp / "runtmp" / "protected" / "identity.txt").read_text()
        self.assertIn(f"phase_env_sha256 {sha}", ident)


class ArchivedComposeContractTests(unittest.TestCase):
    def test_both_frozen_composes_declare_project_relative_dotenv_only(self):
        for commit in (PREVIEW1_COMMIT, CANDIDATE_COMMIT):
            compose = subprocess.run(
                ["git", "-C", str(REPO), "show",
                 f"{commit}:deploy/quickstart/docker-compose.yml"],
                capture_output=True, text=True, check=True).stdout
            lines = compose.splitlines()
            found = 0
            for i, line in enumerate(lines):
                if line.strip() == "env_file:":
                    nxt = lines[i + 1].strip()
                    self.assertEqual(nxt, "- .env", f"{commit} line {i}")
                    found += 1
            self.assertGreaterEqual(found, 3, commit)  # gateway/admin/pg


class PhaseImageRewriteTests(unittest.TestCase):
    """PF3 app-image rewrite against the REAL archived compose sources.

    The r3 run proved the failure mechanism: compose kept the shared mutable
    yabanin-quickstart:local ref, so UP1 ran fleet-built bytes (6998f57d)
    instead of the archived Preview1 image (3171a922). These cases qualify
    the correction on the real frozen compose text, including the invariant
    failure for a partially rewritten file.
    """

    TAG = "qs-fxt-p1:preview1"
    SHARED = "image: yabanin-quickstart:local"

    @staticmethod
    def _archived_compose(commit):
        return subprocess.run(
            ["git", "-C", str(REPO), "show",
             f"{commit}:deploy/quickstart/docker-compose.yml"],
            capture_output=True, text=True, check=True).stdout

    def _run(self, fn, script_tail):
        # mkdtemp + addCleanup (not a with-block): the caller must read the
        # rewritten compose after run_bash returns, so the directory must
        # outlive this method.
        td = tempfile.mkdtemp(prefix="p1r-setup-")
        self.addCleanup(shutil.rmtree, td, ignore_errors=True)
        f = pathlib.Path(td) / "docker-compose.yml"
        f.write_text(self._archived_compose(PREVIEW1_COMMIT))
        script = (
            extract("fail") + extract("require_phase_images")
            + extract("rewrite_phase_images")
            + "CURRENT_CASE=t; CURRENT_STEP=t\n"
            + script_tail.format(f=f, tag=self.TAG, fn=fn) + "\n")
        return run_bash(script), f

    def test_original_archived_composes_have_exactly_three_shared_app_refs(self):
        # the r3 proof: both frozen composes really do carry the three shared
        # refs (migrate, seed, yabanin) that PF3 must pin per phase
        for commit in (PREVIEW1_COMMIT, CANDIDATE_COMMIT):
            n = self._archived_compose(commit).count(self.SHARED)
            self.assertEqual(n, 3, commit)

    def test_rewrite_pins_all_three_app_refs_and_leaves_immutable_refs_alone(self):
        r, f = self._run(
            "rewrite_phase_images",
            'rewrite_phase_images "{tag}" "{f}" "tst"\necho REWRITE-OK')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.strip(), "REWRITE-OK")
        after = f.read_text()
        self.assertEqual(after.count(f"image: {self.TAG}"), 3)
        self.assertNotIn(self.SHARED, after)
        # immutable postgres/redis digest refs and total image count unchanged
        before = self._archived_compose(PREVIEW1_COMMIT)
        immut = [ln for ln in before.splitlines()
                 if ln.strip().startswith("image:")
                 and "yabanin-quickstart:local" not in ln]
        self.assertTrue(immut)
        for ln in immut:
            self.assertIn(ln, after.splitlines(), ln)
        self.assertEqual(
            before.count("image:"), after.count("image:"))

    def test_partial_rewrite_fails_the_shared_image_invariant_not_a_setup_error(self):
        with tempfile.TemporaryDirectory(prefix="p1r-setup-") as td:
            f = pathlib.Path(td) / "docker-compose.yml"
            # replace only TWO of the three shared refs, as a defective
            # correction would leave the file
            seen = 0
            out = []
            for ln in self._archived_compose(PREVIEW1_COMMIT).splitlines():
                if ln.strip() == self.SHARED and seen < 2:
                    out.append(ln.replace(
                        self.SHARED, f"image: {self.TAG}"))
                    seen += 1
                else:
                    out.append(ln)
            f.write_text("\n".join(out) + "\n")
            script = (
                extract("fail") + extract("require_phase_images")
                + "CURRENT_CASE=t; CURRENT_STEP=t\n"
                + f'require_phase_images "{self.TAG}" "{f}" "tst"\n')
            r = run_bash(script)
            self.assertEqual(r.returncode, 1)
            # the shared-image INVARIANT fires — not the archive-shape/setup
            # precheck message
            self.assertIn("shared yabanin-quickstart:local ref(s) remain",
                          r.stderr)
            self.assertIn("shared-image invariant violated", r.stderr)
            self.assertNotIn("expected 3 shared", r.stderr)

    def test_shape_guard_rejects_wrong_shared_ref_count(self):
        with tempfile.TemporaryDirectory(prefix="p1r-setup-") as td:
            f = pathlib.Path(td) / "docker-compose.yml"
            lines = [ln for ln in
                     self._archived_compose(PREVIEW1_COMMIT).splitlines()]
            # drop one shared ref: only two remain -> shape precheck failure
            for i, ln in enumerate(lines):
                if ln.strip() == self.SHARED:
                    del lines[i]
                    break
            f.write_text("\n".join(lines) + "\n")
            script = (
                extract("fail") + extract("require_phase_images")
                + extract("rewrite_phase_images")
                + "CURRENT_CASE=t; CURRENT_STEP=t\n"
                + f'rewrite_phase_images "{self.TAG}" "{f}" "tst"\n')
            r = run_bash(script)
            self.assertEqual(r.returncode, 1)
            self.assertIn("expected 3 shared yabanin-quickstart:local app "
                          "refs, found 2", r.stderr)


class SeedCommandBoundaryTests(unittest.TestCase):
    """Executable command-boundary qualification for P1C/CDC and seed_run.

    External timeout(1) execs an EXECUTABLE command — it can never invoke a
    bash function. The r4 seed transcript (sha256 d8fde5af…, path and hash
    only; contents never read by tests) proved the original
    `timeout 300 p1c …` shape fails with "failed to run command 'p1c'".
    These cases qualify the real wiring under a recording docker stub (no
    daemon): the full arrays carry --profile mock on every phase call,
    --profile seed appears ONLY at the explicit seed_run, and an array
    holding a function name fails the same executable-command invariant.
    """

    OLD_COMMIT = "3aba1fa"

    @staticmethod
    def _old_harness():
        return subprocess.run(
            ["git", "-C", str(REPO), "show",
             "3aba1fa:scripts/quickstart/preview1_recovery.sh"],
            capture_output=True, text=True, check=True).stdout

    def _fixture(self):
        td = tempfile.mkdtemp(prefix="p1r-setup-")
        self.addCleanup(shutil.rmtree, td, ignore_errors=True)
        root = pathlib.Path(td)
        bindir = root / "bin"
        bindir.mkdir()
        log = root / "docker.log"
        stub = bindir / "docker"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            # emit to BOTH the invocation log and stdout: the transcript then
            # carries a non-secret record of the command transport
            'printf "docker %s\\n" "$*" | tee -a "$LOG"\n'
            "exit 0\n")
        stub.chmod(0o700)
        runtmp = root / "runtmp"
        (runtmp / "preview1").mkdir(parents=True)
        (runtmp / "candidate").mkdir(parents=True)
        pw = runtmp / "admin-password"
        pw.write_bytes(b"fixture-password-only\n")
        out = runtmp / "seed-org1.out"
        return root, bindir, log, runtmp, out

    def _run(self, script, bindir, log):
        r = run_bash(script, {
            "PATH": f"{bindir}:{os.environ['PATH']}",
            "LOG": str(log)})
        docker_calls = (log.read_text().splitlines()
                        if log.exists() else [])
        return r, docker_calls

    def test_original_shape_fails_the_executable_command_boundary(self):
        old = self._old_harness()
        root, bindir, log, runtmp, out = self._fixture()
        script = (
            _extract_from(old, "fail") + _extract_from(old, "sha_file")
            + _extract_from(old, "p1c") + _extract_from(old, "seed_run")
            + "CURRENT_CASE=t; CURRENT_STEP=t\n"
            + f'PROJECT=fxt-p1; RUNTMP="{runtmp}"\n'
            + f'seed_run "{out}" --admin-email a@example.invalid\n')
        r, calls = self._run(script, bindir, log)
        self.assertNotEqual(r.returncode, 0)
        # the wrapper failure surfaces on stderr; the REAL external-timeout
        # error is captured in the protected transcript, exactly as r4 proved
        self.assertIn("seed run failed", r.stderr)
        self.assertIn("transcript kept protected", r.stderr)
        transcript = out.read_text()
        self.assertIn("failed to run command", transcript)
        self.assertIn("p1c", transcript)
        # the external timeout never reached any docker invocation
        self.assertEqual(calls, [])
        self.assertTrue(out.exists())  # transcript preserved for diagnosis

    def test_corrected_seed_run_uses_full_array_with_seed_profile_only_there(self):
        root, bindir, log, runtmp, out = self._fixture()
        arrays = "\n".join(
            re.search(rf"^{name}=\(.*\)$", REAL_H.read_text(), re.M).group(0)
            for name in ("P1C", "CDC"))
        # PROJECT/RUNTMP first: bash expands them INTO the arrays at the
        # assignment, so arrays-before-project would embed empty values.
        script = (
            extract("fail") + extract("sha_file")
            + "CURRENT_CASE=t; CURRENT_STEP=t\n"
            + f'PROJECT=fxt-p1; RUNTMP="{runtmp}"\n'
            + arrays + "\n"
            + extract("p1c") + extract("cdc") + extract("seed_run")
            + f'seed_run "{out}" --admin-email a@example.invalid\n'
            + "echo SEED-OK\n")
        r, calls = self._run(script, bindir, log)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("SEED-OK", r.stdout)
        self.assertEqual(len(calls), 1)
        line = calls[0]
        for needle in ("compose", "--project-name fxt-p1",
                       f"--project-directory {runtmp}/preview1",
                       "--profile mock", "--profile seed",
                       "run --rm -T seed"):
            self.assertIn(needle, line)
        # the password never leaks into non-protected output surfaces
        self.assertNotIn("fixture-password-only", r.stdout + r.stderr)
        # transcript is mode 600 and captured the stub transport only
        self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o600)
        self.assertIn("docker compose", out.read_text())

    def test_phase_calls_carry_mock_profile_and_never_seed(self):
        root, bindir, log, runtmp, out = self._fixture()
        arrays = "\n".join(
            re.search(rf"^{name}=\(.*\)$", REAL_H.read_text(), re.M).group(0)
            for name in ("P1C", "CDC"))
        script = (
            f'PROJECT=fxt-p1; RUNTMP="{runtmp}"\n'  # before arrays (see above)
            + arrays + "\n" + extract("p1c") + extract("cdc")
            + "p1c up -d\ncdc ps\n")
        r, calls = self._run(script, bindir, log)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(calls), 2)
        for line in calls:
            self.assertIn("--profile mock", line)
            self.assertNotIn("--profile seed", line)
        self.assertIn(f"--project-directory {runtmp}/preview1", calls[0])
        self.assertIn(f"--project-directory {runtmp}/candidate", calls[1])

    def test_function_name_array_fails_the_same_executable_invariant(self):
        root, bindir, log, runtmp, out = self._fixture()
        script = (
            "p1c() { :; }\nP1C=(p1c)\n"
            'timeout 5 "${P1C[@]}" run --rm -T seed'
            f' < "{runtmp}/admin-password" > "{out}" 2>&1\n')
        r, calls = self._run(script, bindir, log)
        self.assertEqual(r.returncode, 127)
        # the external-timeout error goes to the redirected transcript, not
        # the harness stderr (same evidence shape as the r4 failure)
        transcript = out.read_text()
        self.assertIn("failed to run command", transcript)
        self.assertIn("p1c", transcript)
        self.assertEqual(calls, [])  # never reached docker


class InactiveKeyControlTests(unittest.TestCase):
    """Executable controls for the inactive-key authorization fixture and its
    expected-negative oracle: the inactive denial must be behavioral (exact
    401 with zero provider/ledger effect and no row for its rid), the fixture
    binding must be complete before any denied request, and the active-key
    negative control must MEASURE its own intentional effect (exactly one
    provider hit, one org1 row, one row for the rid it emitted pre-send)."""

    KEY3 = "yb_" + "a1b2c3d4" * 4
    KEY3_FP = hashlib.sha256(KEY3.encode()).hexdigest()

    def _fixture(self, curl_code, effect="1", bindrow="t|t|f|t", ncount="1",
                 await_stub=False, fast_await=False):
        """Assemble the extracted harness helpers plus recording stubs.
        curl_code: HTTP code the stub curl returns. effect: '1' = a 200 also
        makes exactly one provider hit + one org1 row carrying the parsed
        X-Request-ID; '2' = the row appears but the provider hit stays zero
        (independent provider-delta negative); '0' = no simulated effect.
        fast_await replaces the extracted await_reqid with a 2-iteration
        equivalent (same poll-and-return semantics) so row-never-appears
        cases fail in bounded time instead of the real 30s."""
        tmp = tempfile.mkdtemp(prefix="p1r-ik-")
        self.addCleanup(shutil.rmtree, tmp)
        bindir = os.path.join(tmp, "bin")
        os.makedirs(bindir)
        hits, rows, sqllog, code = (os.path.join(tmp, n) for n in
                                    ("hits", "rows", "sql.log", "code"))
        for p, val in ((hits, "0"), (rows, ""), (sqllog, ""), (code, curl_code)):
            with open(p, "w") as fh:
                fh.write(val)
        curl = os.path.join(bindir, "curl")
        with open(curl, "w") as fh:
            fh.write(
                "#!/usr/bin/env bash\n"
                "rid=''\n"
                'for a in "$@"; do case "$a" in "X-Request-ID: "*) '
                'rid=${a#X-Request-ID: };; esac; done\n'
                'c=$(cat "$STATE/code")\n'
                'if [ "$c" = "200" ]; then\n'
                '  if [ "$EFFECT" = "1" ]; then '
                'echo $(( $(cat "$STATE/hits") + 1 )) > "$STATE/hits"; fi\n'
                '  if [ "$EFFECT" = "1" ] || [ "$EFFECT" = "2" ]; then '
                'echo "$rid" >> "$STATE/rows"; fi\n'
                "fi\n"
                "printf '%s' \"$c\"\n")
        os.chmod(curl, 0o755)
        record = os.path.join(tmp, "record")
        keyfile = os.path.join(tmp, "inactive-key.txt")
        await_override = ""
        if await_stub:
            await_override = "await_reqid() { return 1; }\n"
        elif fast_await:
            await_override = (
                "await_reqid() {\n"
                "  for i in 1 2; do\n"
                '    [ "$("$1" "SELECT count(*) FROM request_logs '
                "WHERE request_id = '$2'\")\" = \"1\" ] && return 0\n"
                "    sleep 0.1\n"
                "  done\n"
                "  return 1\n"
                "}\n")
        qfunc = textwrap.dedent('''\
            q() {
              printf "SQL|%s\\n" "$1" >> "$STATE/sql.log"
              case "$1" in
                *"count(*) FROM request_logs WHERE org_id"*)
                  wc -l < "$STATE/rows" | tr -d " " ;;
                *"count(*) FROM request_logs WHERE request_id"*)
                  rid=$(sed -n "s/.*request_id = '\\([^']*\\)'.*/\\1/p" <<<"$1")
                  grep -c "^$rid$" "$STATE/rows" 2>/dev/null || true ;;
                *"SELECT (key_hash ="*) printf "%s" "$BINDROW" ;;
                *"SELECT id::text FROM organizations_teams"*)
                  printf "%s" "$TEAMID" ;;
                *"count(*) FROM api_keys WHERE id"*)
                  printf "%s" "$NCOUNT" ;;
                *"INSERT INTO api_keys"*) echo INSERT-RECORDED ;;
                *) echo 0 ;;
              esac
            }
            ''')
        script = (
            extract("fail") + extract("note") + extract("fingerprint")
            + extract("sha_file") + extract("await_reqid")
            + extract("send_chat") + extract("denied_key_ok")
            + extract("run_active_key_negative") + extract("load_inactive_key")
            + extract("install_inactive_key") + extract("assert_inactive_key")
            + await_override + qfunc
            + f'STATE="{tmp}"\nEFFECT={effect}\n'
            + "export STATE EFFECT\n"  # the curl child process reads these
            + 'mock_hits() { cat "$STATE/hits"; }\n'
            + f'BINDROW="{bindrow}"\nNCOUNT={ncount}\n'
            + "TEAMID=11111111-1111-4111-8111-111111111111\n"
            + "ORG1_ID=00000000-0000-4000-8000-000000000001\n"
            + 'INACTIVE_KEY_ID="77777777-7777-4777-8777-777777770004"\n'
            + f'INACTIVE_KEY_FILE="{keyfile}"\nRECORD="{record}"\n'
            + "CURRENT_CASE=t; CURRENT_STEP=t\n")
        self.script = script
        self.state = {"tmp": tmp, "bindir": bindir, "hits": hits,
                      "rows": rows, "sqllog": sqllog, "record": record,
                      "keyfile": keyfile}

    def _run(self, body, key3=True):
        env_path = self.state["bindir"] + ":" + os.environ["PATH"]
        script = self.script
        if key3:
            script += f'key3="{self.KEY3}"\n'
        return run_bash(script + body, env_extra={"PATH": env_path})

    # ---- denied_key_ok: behavioral inactive denial + pre-send rid emission

    def test_inactive_denial_is_behavioral_401_with_zero_effect(self):
        self._fixture("401")
        r = self._run('denied_key_ok q "$key3" m "T deny"\necho DENIED-OK\n')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("denied (HTTP 401)", r.stdout)
        self.assertIn("provider hits 0 -> 0", r.stdout)
        self.assertIn("no row for the denied request", r.stdout)
        self.assertIn("request_id qs-p1r-deny-", r.stdout)  # emitted pre-send
        self.assertEqual(
            pathlib.Path(self.state["hits"]).read_text().strip(), "0")
        self.assertEqual(pathlib.Path(self.state["rows"]).read_text(), "")

    def test_rid_emitted_even_when_send_does_not_return_401(self):
        self._fixture("500")
        r = self._run('denied_key_ok q "$key3" m "T deny"\n')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("inactive key not denied (HTTP 500)", r.stderr)
        self.assertIn("request_id qs-p1r-deny-", r.stdout)  # before the send

    # ---- run_active_key_negative: measured effect, wrong/missing evidence

    def test_active_negative_measures_its_own_effect(self):
        self._fixture("200", effect="1")
        neglog = os.path.join(self.state["tmp"], "negctl.log")
        r = self._run(f'run_active_key_negative q "yk-active" m "{neglog}" '
                      '"T neg"\n')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("measured: HTTP 200, provider hits 0 -> 1", r.stdout)
        self.assertIn("org1 ledger 0 -> 1", r.stdout)
        self.assertIn("exactly one row for request_id", r.stdout)
        self.assertEqual(
            pathlib.Path(self.state["hits"]).read_text().strip(), "1")
        self.assertEqual(
            len(pathlib.Path(self.state["rows"]).read_text().splitlines()), 1)
        self.assertEqual(
            stat.S_IMODE(os.stat(neglog).st_mode), 0o600)

    def test_active_negative_missing_effect_fails_at_the_await_barrier(self):
        # no row ever lands: the control must fail loudly at the bounded
        # await, never silently pass with an unobserved effect.
        self._fixture("200", effect="0", fast_await=True)
        neglog = os.path.join(self.state["tmp"], "negctl.log")
        r = self._run(f'run_active_key_negative q "yk-active" m "{neglog}" '
                      '"T neg"\n')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("never appeared", r.stderr)

    def test_active_negative_provider_delta_is_measured_not_assumed(self):
        # distinct fixture: the row IS observable (await passes) but the
        # provider hit stays zero — the measured +1 must fail, proving the
        # control does not accept asserted-only effect evidence.
        self._fixture("200", effect="2")
        neglog = os.path.join(self.state["tmp"], "negctl.log")
        r = self._run(f'run_active_key_negative q "yk-active" m "{neglog}" '
                      '"T neg"\n')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("did not make exactly one provider hit (0 -> 0)",
                      r.stderr)

    def test_active_negative_rejects_non_200_failure_reason(self):
        self._fixture("500")
        neglog = os.path.join(self.state["tmp"], "negctl.log")
        r = self._run(f'run_active_key_negative q "yk-active" m "{neglog}" '
                      '"T neg"\n')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("failed for the wrong reason", r.stderr)

    def test_active_negative_fails_when_await_cannot_observe_the_row(self):
        # effect fully present but the await barrier fails: still a loud
        # failure, never a pass (independent of the missing-effect case).
        self._fixture("200", effect="1", await_stub=True)
        neglog = os.path.join(self.state["tmp"], "negctl.log")
        r = self._run(f'run_active_key_negative q "yk-active" m "{neglog}" '
                      '"T neg"\n')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("never appeared", r.stderr)

    # ---- fixture binding: complete before any denied request

    def test_assert_inactive_key_requires_every_binding_column(self):
        cases = {"f|t|f|t": "key_hash", "t|f|f|t": "not owned by org1",
                 "t|t|t|t": "not active=false", "t|t|f|f": "org1-owned team"}
        for bind, msg in cases.items():
            with self.subTest(bind=bind):
                self._fixture("401", bindrow=bind)
                r = self._run('assert_inactive_key q "T assert"\n')
                self.assertNotEqual(r.returncode, 0)
                self.assertIn(msg, r.stderr)
        self._fixture("401")
        r = self._run('assert_inactive_key q "T assert"\necho BIND-OK\n')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("BIND-OK", r.stdout)

    def test_assert_inactive_key_rejects_missing_or_duplicate_row(self):
        for n in ("0", "2"):
            with self.subTest(n=n):
                self._fixture("401", ncount=n)
                r = self._run('assert_inactive_key q "T assert"\n')
                self.assertNotEqual(r.returncode, 0)
                self.assertIn("missing or duplicated", r.stderr)

    def test_install_uses_real_team_table_correct_hash_and_inactive(self):
        self._fixture("401")
        r = self._run('install_inactive_key q\necho INSTALL-OK\n')
        self.assertEqual(r.returncode, 0, r.stderr)
        sql = pathlib.Path(self.state["sqllog"]).read_text()
        self.assertIn("SELECT id::text FROM organizations_teams "
                      "WHERE org_id = ", sql)  # org1's REAL team table
        self.assertIn("INSERT INTO api_keys", sql)
        self.assertIn(self.KEY3_FP, sql)  # correct sha256, not the plaintext
        self.assertNotIn(self.KEY3, sql)
        self.assertIn("'p1 recovery inactive control key', false", sql)

    # ---- protected key file: 0600 gate before reading, fingerprint-only log

    def test_load_inactive_key_refuses_loose_file_mode(self):
        self._fixture("401")
        with open(self.state["keyfile"], "w") as fh:
            fh.write(self.KEY3)
        os.chmod(self.state["keyfile"], 0o644)
        r = self._run("load_inactive_key\necho LOADED\n", key3=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not 0600", r.stderr)
        self.assertNotIn("LOADED", r.stdout)

    def test_load_inactive_key_creates_protected_and_logs_fingerprint_only(self):
        self._fixture("401")
        r = self._run("load_inactive_key\necho LOADED\n", key3=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(
            stat.S_IMODE(os.stat(self.state["keyfile"]).st_mode), 0o600)
        rec = pathlib.Path(self.state["record"]).read_text()
        self.assertIn("inactive_key_fingerprint ", rec)
        leaked = self.KEY3.encode()
        self.assertNotIn(leaked, r.stdout.encode() + r.stderr.encode())
        self.assertNotIn(leaked, rec.encode())

    def test_load_inactive_key_detects_fingerprint_drift_on_resume(self):
        self._fixture("401")
        with open(self.state["keyfile"], "w") as fh:
            fh.write(self.KEY3)
        os.chmod(self.state["keyfile"], 0o600)
        with open(self.state["record"], "w") as fh:
            fh.write("inactive_key_fingerprint %s\n" % ("0" * 64))
        r = self._run("load_inactive_key\necho LOADED\n", key3=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("fingerprint drift", r.stderr)
        self.assertNotIn("LOADED", r.stdout)


class StaticWiringTests(unittest.TestCase):
    """Supplementary static checks; executable proof lives above."""

    def test_harness_static_wiring(self):
        h = REAL_H.read_text()
        self.assertIn('PROJECT="${QS_RECOVERY_PROJECT:-qs-p1recovery}"', h)
        self.assertNotIn("\nPROJECT=qs-p1recovery\n", h)
        for needle in (
                'PHASE_ENV_SHA=$(provision_phase_env "$RUNTMP/src-preview1" '
                '"$RUNTMP/preview1" "$RUNTMP/candidate")',
                'echo "phase_env_sha256 $PHASE_ENV_SHA" >> "$IDENTITY"',
                'require_phase_env "$RUNTMP/preview1" "$RUNTMP/candidate" '
                '"$IDENTITY"',
                'rewrite_phase_images "$phase_tag" "$RUNTMP/$phase/'
                'docker-compose.yml" "$phase"',
                'assert_container_image "${PROJECT}-migrate-1" '
                '"$PRE_IMAGE_ID" "UP1 preview1 migrate"',
                'assert_container_image "${PROJECT}-migrate-1" '
                '"$CAND_IMAGE_ID" "UP8 candidate migrate"',
                'assert_container_image "${PROJECT}-migrate-1" '
                '"$PRE_IMAGE_ID" "RB4 rollback migrate"',
                "for t in docker ss curl sha256sum timeout sed grep awk comm "
                "stat tar date head od git python3 openssl cmp cp; do"):
            self.assertIn(needle, h)

    def test_snapshot_acl_ownership_uses_owner_aware_catalog(self):
        """snapshot_acl must read ownership from the real catalog contract:
        pg_class joined to pg_namespace, public schema, relkind-limited,
        owner resolved via pg_get_userbyid, relkind mapped to the familiar
        table_type strings, ordered by table name. information_schema.tables
        has NO owner column (the R6 failure); grants/policies/RLS must stay."""
        h = extract("snapshot_acl")
        owner_line = [l for l in h.splitlines() if "'owner'," in l]
        self.assertEqual(len(owner_line), 1, "exactly one ownership SELECT")
        o = owner_line[0]
        for needle in (  # the actual catalog contract, positively asserted
                "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace",
                "n.nspname = 'public'",
                "c.relkind IN ('r','v','m','p')",
                "pg_get_userbyid(c.relowner) AS owner",
                "CASE c.relkind WHEN 'r' THEN 'BASE TABLE'",
                "WHEN 'v' THEN 'VIEW'",
                "WHEN 'm' THEN 'MATERIALIZED VIEW'",
                "WHEN 'p' THEN 'PARTITIONED TABLE'",
                "ORDER BY 2"):
            self.assertIn(needle, o)
        # the failed source (no owner column exists in that view) is gone
        # from the ownership SELECT while the other snapshots are preserved
        self.assertNotIn("information_schema.tables", o)
        for preserved in ("pg_roles", "information_schema.role_table_grants",
                          "pg_policies", "pg_tables", "rowsecurity"):
            self.assertIn(preserved, h)


if __name__ == "__main__":
    unittest.main()

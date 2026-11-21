"""Behavioral self-controls for the Preview2 load-input correction (P2-QA-LOAD-01).

Scope and honesty statement:
- These controls execute the actual k6 script bytes (working tree and the
  pinned pre-correction commit) under a node-based k6 shim package that
  records requests/checks/metrics and never opens a network socket.
- They qualify script input validation, request targeting, exact model
  identity, cache-attribution binding, profile preservation and the guarded
  make invocations. They are NOT k6 runtime acceptance and NOT a load
  profile: real k6 inspect/smoke/load execution is a separately gated
  qualification step (pinned k6 OCI under the coordination heavy lease) and
  remains explicitly pending until run there.
- The make invocation control uses a recording fake `k6` executable as a
  controlled boundary to prove safe argument construction; it is not k6
  runtime acceptance either.
- Missing local tooling (node, make, git) is an environment failure that
  fails these controls; it is never reported as a pass or skipped around.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[3]

# Frozen task base: the pre-correction state of both scripts.
ORIGINAL_COMMIT = "fb1b1eeef406488ef8c97c12387a7eb8a8ce5b61"

# Frozen full load profile (must never change semantics via smoke overrides).
FROZEN_CHAT_STAGES = [
    {"duration": "30s", "target": 100},
    {"duration": "2m", "target": 500},
    {"duration": "30s", "target": 1000},
    {"duration": "2m", "target": 1000},
    {"duration": "30s", "target": 0},
]
FROZEN_CHAT_THRESHOLDS = {
    "http_req_duration": ["p(95)<500", "p(99)<1000"],
    "http_req_failed": ["rate<0.01"],
    "checks": ["rate>0.95"],
}
FROZEN_MIXED_STAGES = [
    {"duration": "30s", "target": 100},
    {"duration": "2m", "target": 500},
    {"duration": "30s", "target": 0},
]
FROZEN_MIXED_THRESHOLDS = {
    "http_req_duration": ["p(95)<800", "p(99)<1500"],
    "http_req_failed": ["rate<0.05"],
    "checks": ["rate>0.9"],
}

# A k6 shim package: records HTTP attempts/checks/metrics to a JSON log and
# returns canned responses. It contains no network imports by construction.
K6_PACKAGE_JSON = """
{
  "name": "k6",
  "type": "module",
  "exports": {
    ".": "./index.mjs",
    "./http": "./http.mjs",
    "./metrics": "./metrics.mjs"
  }
}
"""
K6_HTTP_SHIM = """
import fs from 'node:fs';
export function post(url, payload, params) {
  const log = JSON.parse(fs.readFileSync(process.env.K6SHIM_LOG, 'utf8'));
  log.requests.push({
    url,
    authorization: params && params.headers ? params.headers.Authorization : null,
    body: payload,
  });
  fs.writeFileSync(process.env.K6SHIM_LOG, JSON.stringify(log));
  const responses = JSON.parse(process.env.K6SHIM_RESPONSES);
  return responses[(log.requests.length - 1) % responses.length];
}
export default { post };
"""
K6_INDEX_SHIM = """
import fs from 'node:fs';
export function check(res, fns) {
  const log = JSON.parse(fs.readFileSync(process.env.K6SHIM_LOG, 'utf8'));
  let all = true;
  for (const [name, fn] of Object.entries(fns)) {
    let pass = false;
    try { pass = Boolean(fn(res)); } catch { pass = false; }
    log.checks.push({ name, pass });
    if (!pass) all = false;
  }
  fs.writeFileSync(process.env.K6SHIM_LOG, JSON.stringify(log));
  return all;
}
export function sleep() {}
export default { check, sleep };
"""
K6_METRICS_SHIM = """
import fs from 'node:fs';
class Metric {
  constructor(name) { this.name = name; }
  add(v) {
    const log = JSON.parse(fs.readFileSync(process.env.K6SHIM_LOG, 'utf8'));
    log.metrics.push({ name: this.name, value: v });
    fs.writeFileSync(process.env.K6SHIM_LOG, JSON.stringify(log));
  }
}
export class Counter extends Metric {}
export class Rate extends Metric {}
export class Trend extends Metric {}
export default { Counter, Rate, Trend };
"""
RUNNER_SHIM = """
import fs from 'node:fs';
globalThis.__ENV = process.env;
fs.writeFileSync(process.env.K6SHIM_LOG, JSON.stringify({
  requests: [], checks: [], metrics: [], options: null,
}));
const m = await import('./script.mjs');
const log = JSON.parse(fs.readFileSync(process.env.K6SHIM_LOG, 'utf8'));
log.options = m.options || null;
fs.writeFileSync(process.env.K6SHIM_LOG, JSON.stringify(log));
const calls = Number(process.env.K6SHIM_CALLS || '1');
for (let i = 0; i < calls; i++) {
  if (typeof m.default === 'function') m.default();
}
if (typeof m.handleSummary === 'function') {
  const data = {
    metrics: {
      http_req_duration: { values: { 'p(50)': 10, 'p(95)': 20, 'p(99)': 30 } },
      http_reqs: { values: { count: 1 } },
      checks: { values: { rate: 1 } },
      cache_hits: { values: { count: 0 } },
      requests_total: { values: { count: 1 } },
      errors: { values: { count: 0 } },
    },
    state: { duration: 1 },
  };
  const out = m.handleSummary(data);
  if (out && out.stdout) console.log(out.stdout);
}
"""

FAKE_K6 = """#!/bin/sh
# Controlled fake k6 boundary: records argv, requires the key only via the
# inherited environment, prints nothing secret, and exits 0.
printf '%s\\n' "$@" > "$K6FAKE_ARGV"
if [ -z "${TOKENROUTER_API_KEY:-}" ]; then
  echo "fake-k6: TOKENROUTER_API_KEY missing from inherited environment" >&2
  exit 3
fi
exit 0
"""


def tool_path(name):
    return shutil.which(name)


def clean_env(extra):
    """A controlled environment with no ambient TOKENROUTER_* variables."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("TOKENROUTER")}
    env.update(extra)
    return env


def git_show(path):
    proc = subprocess.run(
        ["git", "-C", str(ROOT), "show", f"{ORIGINAL_COMMIT}:{path}"],
        capture_output=True, text=True, timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"cannot read original {path}: {proc.stderr.strip()}")
    return proc.stdout


def run_script(source_text, env_vars, responses, calls=1):
    """Execute actual script bytes under the k6 shim. No network is possible."""
    node = tool_path("node")
    if node is None:
        raise AssertionError(
            "node is required for behavioral script controls; "
            "missing node is an environment failure, not a pass"
        )
    with tempfile.TemporaryDirectory(prefix="p2qa-") as tmp:
        tmp = Path(tmp)
        pkg = tmp / "node_modules/k6"
        pkg.mkdir(parents=True)
        (pkg / "package.json").write_text(K6_PACKAGE_JSON)
        (pkg / "http.mjs").write_text(K6_HTTP_SHIM)
        (pkg / "index.mjs").write_text(K6_INDEX_SHIM)
        (pkg / "metrics.mjs").write_text(K6_METRICS_SHIM)
        (tmp / "run.mjs").write_text(RUNNER_SHIM)
        (tmp / "script.mjs").write_text(source_text)
        log_path = tmp / "log.json"
        env = clean_env(env_vars)
        env.update({
            "K6SHIM_LOG": str(log_path),
            "K6SHIM_RESPONSES": json.dumps(responses),
            "K6SHIM_CALLS": str(calls),
        })
        proc = subprocess.run(
            [node, "run.mjs"], cwd=str(tmp), env=env,
            capture_output=True, text=True, timeout=120,
        )
        log = json.loads(log_path.read_text()) if log_path.exists() else {
            "requests": [], "checks": [], "metrics": [], "options": None,
        }
        return SimpleNamespace(
            rc=proc.returncode, stdout=proc.stdout, stderr=proc.stderr, log=log,
        )


def make_target(target, env_extra, path_extra=None):
    make = tool_path("make")
    if make is None:
        raise AssertionError(
            "make is required for invocation controls; "
            "missing make is an environment failure, not a pass"
        )
    env = clean_env(env_extra)
    env["PATH"] = (f"{path_extra}:" if path_extra else "") + "/usr/bin:/bin"
    return subprocess.run(
        ["make", "-C", str(ROOT), target],
        capture_output=True, text=True, env=env, timeout=120,
    )


def ok_response(model, headers=None):
    return {
        "status": 200,
        "headers": headers or {},
        "body": json.dumps({
            "model": model,
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
        }),
    }


class ToolAvailabilityControls(unittest.TestCase):
    def test_node_make_git_available(self):
        for name in ("node", "make", "git"):
            self.assertIsNotNone(
                tool_path(name),
                f"{name} is required for these behavioral controls; "
                "missing tooling is an environment failure, not a pass",
            )

    def test_shim_contains_no_network_imports(self):
        # Supporting control: the no-socket property is by construction.
        for shim in (K6_HTTP_SHIM, K6_INDEX_SHIM, K6_METRICS_SHIM, RUNNER_SHIM):
            for module in ("node:net", "node:http", "node:dns", "node:dgram", "node:tls"):
                self.assertNotIn(module, shim)


class ChatScriptControls(unittest.TestCase):
    FIXED = None
    ORIGINAL = None

    @classmethod
    def setUpClass(cls):
        cls.FIXED = (ROOT / "tests/load/k6_chat.js").read_text()
        cls.ORIGINAL = git_show("tests/load/k6_chat.js")

    OK_ENV = {"TOKENROUTER_API_KEY": "k6test-key-123", "TOKENROUTER_MODEL": "mock-model"}

    def test_missing_key_refuses_before_requests(self):
        r = run_script(self.FIXED, {"TOKENROUTER_MODEL": "mock-model"}, [ok_response("mock-model")])
        self.assertNotEqual(r.rc, 0)
        self.assertIn("TOKENROUTER_API_KEY", r.stderr)
        self.assertEqual(r.log["requests"], [])

    def test_missing_model_refuses_before_requests(self):
        r = run_script(self.FIXED, {"TOKENROUTER_API_KEY": "k6test-key-123"}, [ok_response("mock-model")])
        self.assertNotEqual(r.rc, 0)
        self.assertIn("TOKENROUTER_MODEL", r.stderr)
        self.assertEqual(r.log["requests"], [])

    def test_bad_base_url_refuses_before_requests(self):
        r = run_script(
            self.FIXED,
            dict(self.OK_ENV, TOKENROUTER_BASE_URL="ftp://example.invalid"),
            [ok_response("mock-model")],
        )
        self.assertNotEqual(r.rc, 0)
        self.assertIn("TOKENROUTER_BASE_URL", r.stderr)
        self.assertEqual(r.log["requests"], [])

    def test_valid_inputs_target_loopback_with_explicit_key_and_model(self):
        r = run_script(self.FIXED, self.OK_ENV, [ok_response("mock-model")])
        self.assertEqual(r.rc, 0, r.stderr)
        self.assertEqual(len(r.log["requests"]), 1)
        req = r.log["requests"][0]
        self.assertEqual(req["url"], "http://127.0.0.1:8082/v1/chat/completions")
        self.assertEqual(req["authorization"], "Bearer k6test-key-123")
        self.assertEqual(json.loads(req["body"])["model"], "mock-model")
        checks = {c["name"]: c["pass"] for c in r.log["checks"]}
        self.assertTrue(checks.get("status is 200"))
        self.assertTrue(checks.get("has choices"))
        self.assertTrue(checks.get("model is exact"))

    def test_wrong_model_response_fails_exact_check(self):
        r = run_script(self.FIXED, self.OK_ENV, [ok_response("some-other-model")])
        self.assertEqual(r.rc, 0, r.stderr)
        checks = {c["name"]: c["pass"] for c in r.log["checks"]}
        self.assertFalse(checks.get("model is exact"))
        self.assertIn({"name": "errors", "value": 1}, r.log["metrics"])

    def test_cache_attribution_discriminators(self):
        # Positive: an explicit hit attribution value counts as a cache hit.
        r = run_script(self.FIXED, self.OK_ENV, [ok_response("mock-model", {"X-Cache": "EXACT"})])
        self.assertIn({"name": "cache_hits", "value": 1}, r.log["metrics"])
        # Absent header is a valid miss: no cache hit counted, no failed check.
        r = run_script(self.FIXED, self.OK_ENV, [ok_response("mock-model")])
        self.assertNotIn({"name": "cache_hits", "value": 1}, r.log["metrics"])
        self.assertTrue(all(c["pass"] for c in r.log["checks"]))
        # Unknown attribution values are not hits.
        r = run_script(self.FIXED, self.OK_ENV, [ok_response("mock-model", {"X-Cache": "FOO"})])
        self.assertNotIn({"name": "cache_hits", "value": 1}, r.log["metrics"])

    def test_original_script_used_implicit_key_host_and_model(self):
        # Original bytes, empty environment: loads and still sends a request
        # with the literal dev key to localhost using hard-coded gpt-4o —
        # the exact unsafe behavior the correction removes.
        r = run_script(self.ORIGINAL, {}, [ok_response("gpt-4o")])
        self.assertEqual(r.rc, 0, r.stderr)
        self.assertEqual(len(r.log["requests"]), 1)
        req = r.log["requests"][0]
        self.assertEqual(req["url"], "http://localhost:8082/v1/chat/completions")
        self.assertEqual(req["authorization"], "Bearer yabanin-dev-key")
        self.assertEqual(json.loads(req["body"])["model"], "gpt-4o")
        self.assertNotIn(
            "model is exact",
            {c["name"] for c in r.log["checks"]},
            "original script must not already pass the exact-model invariant",
        )


class MixedScriptControls(unittest.TestCase):
    FIXED = None
    ORIGINAL = None

    @classmethod
    def setUpClass(cls):
        cls.FIXED = (ROOT / "tests/load/k6_mixed_models.js").read_text()
        cls.ORIGINAL = git_show("tests/load/k6_mixed_models.js")

    OK_ENV = {
        "TOKENROUTER_API_KEY": "k6test-key-123",
        "TOKENROUTER_MODELS": "mock-model,aux-model",
    }

    def test_missing_model_list_refuses_before_requests(self):
        r = run_script(self.FIXED, {"TOKENROUTER_API_KEY": "k6test-key-123"}, [ok_response("mock-model")])
        self.assertNotEqual(r.rc, 0)
        self.assertIn("TOKENROUTER_MODELS", r.stderr)
        self.assertEqual(r.log["requests"], [])

    def test_malformed_model_lists_refuse_before_requests(self):
        for bad in ("mock-model", "mock-model,mock-model", "mock-model,,aux-model", " , "):
            with self.subTest(models=bad):
                r = run_script(
                    self.FIXED,
                    dict(self.OK_ENV, TOKENROUTER_MODELS=bad),
                    [ok_response("mock-model")],
                )
                self.assertNotEqual(r.rc, 0)
                self.assertEqual(r.log["requests"], [])

    def test_valid_two_model_list_round_robins_exactly(self):
        r = run_script(
            self.FIXED, self.OK_ENV,
            [ok_response("mock-model"), ok_response("aux-model")],
            calls=2,
        )
        self.assertEqual(r.rc, 0, r.stderr)
        requested = [json.loads(req["body"])["model"] for req in r.log["requests"]]
        self.assertEqual(requested, ["mock-model", "aux-model"])
        for req in r.log["requests"]:
            self.assertEqual(req["authorization"], "Bearer k6test-key-123")
        checks = {c["name"]: c["pass"] for c in r.log["checks"]}
        self.assertTrue(all(checks.values()))

    def test_prefix_model_match_is_rejected_fixed_and_accepted_by_original(self):
        wrong = ok_response("gpt-4o-mini-preview")
        fixed = run_script(
            self.FIXED,
            dict(self.OK_ENV, TOKENROUTER_MODELS="gpt-4o,aux-model"),
            [wrong],
        )
        checks = {c["name"]: c["pass"] for c in fixed.log["checks"]}
        self.assertFalse(checks.get("model is exact"))
        # Original bytes accept the same wrong model via prefix matching.
        original = run_script(self.ORIGINAL, {}, [wrong])
        original_checks = {c["name"]: c["pass"] for c in original.log["checks"]}
        self.assertTrue(
            original_checks.get("model in response"),
            "original prefix-match check must accept the wrong model (defect demonstration)",
        )

    def test_original_script_used_implicit_key_host_and_models(self):
        r = run_script(self.ORIGINAL, {}, [ok_response("gpt-4o")])
        self.assertEqual(r.rc, 0, r.stderr)
        req = r.log["requests"][0]
        self.assertEqual(req["url"], "http://localhost:8082/v1/chat/completions")
        self.assertEqual(req["authorization"], "Bearer yabanin-dev-key")


class ProfilePreservationControls(unittest.TestCase):
    def chat_run(self, env_extra=None):
        env = {"TOKENROUTER_API_KEY": "k6test-key-123", "TOKENROUTER_MODEL": "mock-model"}
        env.update(env_extra or {})
        return run_script(
            (ROOT / "tests/load/k6_chat.js").read_text(), env, [ok_response("mock-model")],
        )

    def mixed_run(self, env_extra=None):
        env = {
            "TOKENROUTER_API_KEY": "k6test-key-123",
            "TOKENROUTER_MODELS": "mock-model,aux-model",
        }
        env.update(env_extra or {})
        return run_script(
            (ROOT / "tests/load/k6_mixed_models.js").read_text(), env,
            [ok_response("mock-model")],
        )

    def test_chat_full_profile_matches_frozen_contract(self):
        r = self.chat_run()
        self.assertEqual(r.log["options"]["stages"], FROZEN_CHAT_STAGES)
        self.assertEqual(r.log["options"]["thresholds"], FROZEN_CHAT_THRESHOLDS)
        self.assertIn("profile=full", r.stdout)

    def test_mixed_full_profile_matches_frozen_contract(self):
        r = self.mixed_run()
        self.assertEqual(r.log["options"]["stages"], FROZEN_MIXED_STAGES)
        self.assertEqual(r.log["options"]["thresholds"], FROZEN_MIXED_THRESHOLDS)
        self.assertIn("profile=full", r.stdout)

    def test_smoke_and_custom_overrides_change_stages_only_and_are_labeled(self):
        r = self.chat_run({"TOKENROUTER_SMOKE": "1"})
        self.assertEqual(r.log["options"]["stages"], [{"duration": "3s", "target": 1}])
        self.assertEqual(r.log["options"]["thresholds"], FROZEN_CHAT_THRESHOLDS)
        self.assertIn("profile=smoke", r.stdout)
        self.assertIn("not the full load profile", r.stdout)
        r = self.mixed_run({"TOKENROUTER_VUS": "2", "TOKENROUTER_DURATION": "5s"})
        self.assertEqual(r.log["options"]["stages"], [{"duration": "5s", "target": 2}])
        self.assertEqual(r.log["options"]["thresholds"], FROZEN_MIXED_THRESHOLDS)
        self.assertIn("profile=custom", r.stdout)

    def test_partial_profile_override_is_malformed(self):
        r = self.chat_run({"TOKENROUTER_VUS": "2"})
        self.assertNotEqual(r.rc, 0)
        self.assertEqual(r.log["requests"], [])


class MakefileInvocationControls(unittest.TestCase):
    @staticmethod
    def recipe_block(marker):
        text = (ROOT / "Makefile").read_text()
        start = text.index(marker)
        end = text.index("\n\n", start)
        return text[start:end]

    @staticmethod
    def fake_k6_bin(directory):
        directory.mkdir(parents=True, exist_ok=True)
        exe = directory / "k6"
        exe.write_text(FAKE_K6)
        exe.chmod(0o755)
        return exe

    def test_chat_and_mixed_recipes_never_expand_a_key_value(self):
        for marker in ("load-test-chat:", "load-test-mixed:"):
            with self.subTest(target=marker):
                block = self.recipe_block(marker)
                self.assertNotIn("$(KEY)", block)
                self.assertNotIn("$(TOKENROUTER_API_KEY)", block)
                self.assertIn("$${TOKENROUTER_API_KEY:-}", block)

    def test_missing_exported_key_fails_before_invoking_k6(self):
        with tempfile.TemporaryDirectory(prefix="p2qa-fakek6-") as td:
            argv_path = Path(td) / "argv.txt"
            bindir = Path(td) / "bin"
            self.fake_k6_bin(bindir)
            for target in ("load-test-chat", "load-test-mixed"):
                with self.subTest(target=target):
                    proc = make_target(
                        target,
                        {"K6FAKE_ARGV": str(argv_path)},
                        path_extra=str(bindir),
                    )
                    self.assertEqual(proc.returncode, 2)
                    self.assertIn("export TOKENROUTER_API_KEY", proc.stdout)
                    self.assertNotIn("k6 run", proc.stdout)
                    self.assertFalse(
                        argv_path.exists(),
                        "guard must fail before k6 is invoked",
                    )

    def test_missing_model_input_fails_before_invoking_k6(self):
        with tempfile.TemporaryDirectory(prefix="p2qa-fakek6-") as td:
            argv_path = Path(td) / "argv.txt"
            bindir = Path(td) / "bin"
            self.fake_k6_bin(bindir)
            proc = make_target(
                "load-test-chat",
                {"TOKENROUTER_API_KEY": "env-key", "K6FAKE_ARGV": str(argv_path)},
                path_extra=str(bindir),
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("MODEL", proc.stdout)
            self.assertFalse(argv_path.exists())
            proc = make_target(
                "load-test-mixed",
                {"TOKENROUTER_API_KEY": "env-key", "K6FAKE_ARGV": str(argv_path)},
                path_extra=str(bindir),
            )
            self.assertEqual(proc.returncode, 2)
            self.assertIn("MODELS", proc.stdout)
            self.assertFalse(argv_path.exists())

    def test_valid_inputs_invoke_k6_with_safe_args_and_env_only_key(self):
        sentinel = "LEAK-SENTINEL-6f3a"
        expected_argv = [
            "run",
            "--env", "TOKENROUTER_MODEL=mock-model",
            "--env", "TOKENROUTER_BASE_URL=http://127.0.0.1:8082",
            "--env", "TOKENROUTER_SMOKE=1",
            "tests/load/k6_chat.js",
        ]
        with tempfile.TemporaryDirectory(prefix="p2qa-fakek6-") as td:
            argv_path = Path(td) / "argv.txt"
            bindir = Path(td) / "bin"
            self.fake_k6_bin(bindir)
            proc = make_target(
                "load-test-chat",
                {
                    "TOKENROUTER_API_KEY": sentinel,
                    "MODEL": "mock-model",
                    "SMOKE": "1",
                    "K6FAKE_ARGV": str(argv_path),
                },
                path_extra=str(bindir),
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertTrue(argv_path.exists(), "k6 must actually be invoked")
            argv = argv_path.read_text().splitlines()
            self.assertEqual(argv, expected_argv)
            # The key reaches k6 only via the inherited environment: never in
            # argv, never in make's captured output.
            self.assertNotIn(sentinel, argv_path.read_text())
            self.assertNotIn(sentinel, proc.stdout)
            self.assertNotIn(sentinel, proc.stderr)

    def test_valid_mixed_inputs_invoke_k6_with_explicit_model_list(self):
        sentinel = "LEAK-SENTINEL-6f3a"
        with tempfile.TemporaryDirectory(prefix="p2qa-fakek6-") as td:
            argv_path = Path(td) / "argv.txt"
            bindir = Path(td) / "bin"
            self.fake_k6_bin(bindir)
            proc = make_target(
                "load-test-mixed",
                {
                    "TOKENROUTER_API_KEY": sentinel,
                    "MODELS": "mock-model,aux-model",
                    "K6FAKE_ARGV": str(argv_path),
                },
                path_extra=str(bindir),
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            argv = argv_path.read_text().splitlines()
            self.assertIn("TOKENROUTER_MODELS=mock-model,aux-model", argv)
            self.assertEqual(argv[-1], "tests/load/k6_mixed_models.js")
            self.assertNotIn(sentinel, argv_path.read_text())
            self.assertNotIn(sentinel, proc.stdout)
            self.assertNotIn(sentinel, proc.stderr)


if __name__ == "__main__":
    unittest.main()

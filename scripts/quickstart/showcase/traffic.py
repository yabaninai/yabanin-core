# SPDX-License-Identifier: Apache-2.0
"""Populate a fresh quickstart through its HTTP API and reconcile the stored rows."""
import json
import subprocess
import time
import urllib.error
import urllib.request


class LocalOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def call(port, path, key, body=None, labels=None, request_id=None):
    headers = {"Cache-Control": "no-store", "Authorization": "Bearer " + key, "Content-Type": "application/json"}
    if request_id:
        headers["X-Request-ID"] = request_id
    if labels:
        headers["X-Yabanin-Labels"] = labels
    req = urllib.request.Request(f"http://127.0.0.1:{port}" + path,
                                 data=json.dumps(body).encode() if body else None, headers=headers)
    with urllib.request.build_opener(urllib.request.ProxyHandler({}), LocalOnly()).open(req, timeout=15) as res:
        return json.load(res)


def check_access(port, key, model):
    models = call(port, "/v1/models", key)
    if model not in {entry["id"] for entry in models["data"]}:
        raise ValueError("mock model missing from authenticated catalog")
    try:
        call(port, "/v1/models", "invalid-demo-key")
    except urllib.error.HTTPError as err:
        if err.code != 401:
            raise
    else:
        raise ValueError("invalid credential was accepted")


def stored_jobs(cmd, model, run_id):
    sql = ("SELECT labels->>'ci.job_name' FROM request_logs WHERE status_code=200 "
           f"AND model_used='{model}' AND labels->>'ci.pipeline'='{run_id}' "
           "AND org_id=(SELECT id FROM organizations WHERE slug='seed')")
    return subprocess.check_output([*cmd, "exec", "-T", "postgres", "psql", "-XAt",
                                       "-v", "ON_ERROR_STOP=1", "-U", "yabanin", "-d", "yabanin",
                                       "-c", sql], text=True).splitlines()


def demonstrate(cmd, port, key, model, run_id):
    check_access(port, key, model)
    existing = set(stored_jobs(cmd, model, run_id))
    scenarios = {"review": "Explain this small change.", "support": "Summarize this support ticket.",
                 "docs": "Suggest a title for the release notes.", "tools": "[tool-task] search the docs"}
    for task, prompt in scenarios.items():
        if task in existing:
            continue
        reply = call(port, "/v1/chat/completions", key, {"model": model, "stream": False,
                     "messages": [{"role": "user", "content": prompt}]},
                     f"ci.pipeline={run_id},ci.job_name={task},env=demo", f"{run_id}-{task}")
        choice = reply["choices"][0]
        if task == "tools":
            names = [item["function"]["name"] for item in choice["message"]["tool_calls"]]
            if names != ["grep", "read"] or choice["finish_reason"] != "tool_calls":
                raise ValueError("mock tool plan did not match")
        elif not choice["message"]["content"].strip():
            raise ValueError("empty mock response")
    # The run ID is generated locally; a previous stand's rows cannot satisfy this check.
    for _ in range(35):
        rows = stored_jobs(cmd, model, run_id)
        if sorted(rows) == sorted(scenarios):
            print(f"Verified catalog, rejected key, and 4 stored chat requests for {run_id}.")
            return run_id
        time.sleep(1)
    raise ValueError("logger did not persist the expected organization, model and scenario labels")

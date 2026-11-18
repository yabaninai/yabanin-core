#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Build the current checkout and verify a populated local Core quickstart."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import time

from urllib.parse import urlsplit

from console import Console

from traffic import call, demonstrate

ROOT = Path(__file__).resolve().parents[3]
QS = ROOT / "deploy/quickstart"
MOCK = os.environ.get("QS_MODEL") or "mock-model"
EMAIL = os.environ.get("QS_ADMIN_EMAIL") or "admin@localhost"


def run(*args, **kw):
    return subprocess.run(list(args), check=True, **kw)


def write(path, value):
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False, mode="w") as f:
        f.write(value)
    os.replace(f.name, path)


def base_url(value):
    url = value.rstrip("/")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username is not None:
        raise ValueError("provider requires an HTTPS base URL without credentials")
    if parsed.query or parsed.fragment or any(c.isspace() for c in url):
        raise ValueError("invalid provider URL")
    # Accessing port validates both numeric syntax and range.
    if parsed.port == 0:
        raise ValueError("invalid provider port")
    return url


def read_key(path):
    if not path.is_file() or path.stat().st_mode & 0o077:
        raise ValueError("provider key must be a private file (chmod 600)")
    key = path.read_bytes().strip()
    if not key or not all(33 <= c <= 126 for c in key):
        raise ValueError("provider key must be one nonempty ASCII token")
    return key


def provider(row, directory):
    if not isinstance(row, dict) or set(row) != {"model", "base_url", "key_file"}:
        raise ValueError("each entry requires model, base_url and key_file")
    if not all(isinstance(v, str) for v in row.values()):
        raise ValueError("provider entries require string values")
    model = row["model"]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}", model):
        raise ValueError("invalid provider model ID")
    key_path = (directory / row["key_file"]).resolve()
    if directory.resolve() not in key_path.parents:
        raise ValueError("keep provider key files inside the manifest directory")
    return model, base_url(row["base_url"]), read_key(key_path)


def providers(path):
    if path is None:
        return []
    if ROOT in path.resolve().parents:
        raise ValueError("keep the provider manifest and keys outside the Docker build context")
    rows = json.loads(path.read_text())
    if not isinstance(rows, list):
        raise ValueError("providers must be a JSON array")
    result = [provider(row, path.parent) for row in rows]
    names = [MOCK] + [row[0] for row in result]
    if len(set(names)) != len(names):
        raise ValueError("model IDs must be unique and distinct from the seeded mock model")
    return result


def compose_cmd():
    return ["docker", "compose", "--project-directory", str(QS),
            "-f", os.environ.get("QS_COMPOSE_FILE") or str(QS / "docker-compose.yml")]


def configure_gateway(state, rows, args):
    mock_url = os.environ.get("QS_UPSTREAM_URL") or "http://10.207.0.9:8081"
    origins = [urlsplit(url) for url in [mock_url, *(u for _, u, _ in rows)]]
    config = state / "gateway.json"
    write(config, json.dumps({"gateway": {"allowed_upstreams": [o.scheme + "://" + o.netloc for o in origins]}}))
    config.chmod(0o644)
    mounts = [{"type": "bind", "source": str(config), "target": "/quickstart.json", "read_only": True}]
    environment = {"YABANIN_CONFIG": "/quickstart.json"}
    if args.ca_bundle:
        ca = state / "provider-ca.pem"
        write(ca, args.ca_bundle.read_text())
        ca.chmod(0o644)
        mounts.append({"type": "bind", "source": str(ca), "target": "/quickstart-ca.pem", "read_only": True})
        environment["SSL_CERT_FILE"] = "/quickstart-ca.pem"
    overlay = state / "compose.json"
    write(overlay, json.dumps({"services": {"yabanin": {"environment": environment, "volumes": mounts},
                                            "seed": {"logging": {"driver": "none"}}}}))
    return overlay


def seed_credentials(cmd, state):
    password = state / "admin-password"
    if not password.exists():
        write(password, secrets.token_hex(20) + "\n")
    keyfile = state / "gateway-key"
    receipt = state / "seed-output"
    if keyfile.exists():
        return keyfile.read_text().strip()
    pattern = rb"API key \(shown once, store it now\): (\S+)"
    match = re.search(pattern, receipt.read_bytes()) if receipt.exists() else None
    if not match:
        # The native seed is idempotent. Append so a retry never erases a once-issued token.
        with receipt.open("ab") as out:
            run(*cmd, "run", "-T", "--rm", "seed", "--admin-email", EMAIL,
                "--admin-password-stdin", input=password.read_bytes(), stdout=out)
        match = re.search(pattern, receipt.read_bytes())
    if not match:
        raise ValueError("seed key already issued; restore the private gateway-key or use a fresh demo state")
    write(keyfile, match[1].decode() + "\n")
    return keyfile.read_text().strip()


def arguments():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--fresh", action="store_true", help="wipe the local demo database and reissue its keys")
    p.add_argument("--providers", type=Path, help="optional JSON list, use the same file when resuming")
    p.add_argument("--ca-bundle", type=Path, help="optional PEM trust bundle for private HTTPS providers")
    p.add_argument("--probe-providers", action="store_true", help="send one potentially billable chat per model")
    args = p.parse_args()
    args.gateway_port = int(os.environ.get("QS_GATEWAY_PORT") or 8082)
    args.dashboard_port = int(os.environ.get("QS_DASHBOARD_PORT") or 3000)
    return args


def private_state(cmd):
    spec = json.loads(run(*cmd, "config", "--format", "json", "--no-env-resolution", capture_output=True).stdout)
    data = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local/share")
    state = (data / "yabanin" / "quickstart" / spec["name"]).resolve()
    if state == ROOT or ROOT in state.parents:
        raise ValueError("keep demo state outside the checkout")
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    if state.stat().st_mode & 0o077 or state.stat().st_uid != os.getuid():
        raise ValueError("demo state must be private and owned by this user")
    return state


def restrict_catalog(cmd, names):
    # Model IDs passed provider()'s allowlist. Hide stock registry examples in this dedicated demo DB.
    values = ", ".join("'" + m + "'" for m in names)
    sql = ("BEGIN; UPDATE organizations SET routing_mode='disabled' WHERE slug='seed'; "
           f"UPDATE models_registry SET enabled=(model_name IN ({values})); COMMIT;")
    run(*cmd, "exec", "-T", "postgres", "psql", "-Xq", "-v", "ON_ERROR_STOP=1",
        "-U", "yabanin", "-d", "yabanin", input=sql.encode())


def check_catalog(args, rows, gateway_key, console):
    expected = {MOCK, *(m for m, _, _ in rows)}
    for _ in range(35):  # The gateway caches the catalog for 30 seconds.
        catalog = call(args.gateway_port, "/v1/models", gateway_key)
        actual = {entry["id"] for entry in catalog["data"] if not entry.get("alias_of")}
        if actual == expected:
            break
        time.sleep(1)
    else:
        raise ValueError(f"catalog mismatch: missing {sorted(expected - actual)}, unexpected {sorted(actual - expected)}")
    for model, _, _ in rows if args.probe_providers else []:
        rid = "provider-" + secrets.token_hex(8)
        reply = call(args.gateway_port, "/v1/chat/completions", gateway_key, {"model": model,
                     "messages": [{"role": "user", "content": "Reply with OK."}], "max_tokens": 12}, request_id=rid)
        if not reply.get("choices"):
            raise ValueError("provider returned no choices")
        console.verify_route(rid, model)
        print(f"Provider chat completed: {model}")


def configure_stack(state, args):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}", MOCK):
        raise ValueError("invalid QS_MODEL")
    rows = providers(args.providers)
    identity = [os.environ.get("QS_UPSTREAM_URL"), MOCK, EMAIL,
                hashlib.sha256(args.ca_bundle.read_bytes()).hexdigest() if args.ca_bundle else None,
                [(m, u, hashlib.sha256(k).hexdigest()) for m, u, k in rows]]
    frozen = state / "inputs.json"
    encoded = json.dumps(identity)
    if not args.fresh and frozen.exists() and frozen.read_text() != encoded:
        raise ValueError("different stand inputs; use the original inputs or a new state directory")
    overlay = configure_gateway(state, rows, args)
    return rows, overlay, encoded


def prepare_samples(state, cmd, args, gateway_key):
    if not (state / "traffic-verified").exists():
        restrict_catalog(cmd, [MOCK])
        marker = state / "sample-run"
        if not marker.exists():
            write(marker, "demo-" + secrets.token_hex(6))
        run_id = marker.read_text()
        if not re.fullmatch(r"demo-[a-f0-9]{12}", run_id):
            raise ValueError("invalid sample run ID in private state")
        demonstrate(cmd, args.gateway_port, gateway_key, MOCK, run_id)
        write(state / "traffic-verified", run_id)
    return (state / "traffic-verified").read_text()


def prepare_providers(state, cmd, console, rows):
    if not (state / "providers-ready").exists():
        for model, url, secret in rows:
            console.register(model, url, secret)
        restrict_catalog(cmd, [MOCK] + [m for m, _, _ in rows])
        write(state / "providers-ready", "configured\n")
    for model, url, _ in rows:
        console.verify_model(model, url)


def main():
    args = arguments()
    os.umask(0o077)
    cmd = compose_cmd()
    state = private_state(cmd)
    lock = (state / "lock").open("a")
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    rows, overlay, inputs = configure_stack(state, args)
    if args.fresh:
        run(*cmd, "--profile", "*", "down", "-v")
        for name in ("inputs.json", "admin-password", "gateway-key", "seed-output",
                     "sample-run", "traffic-verified", "providers-ready"):
            (state / name).unlink(missing_ok=True)
    write(state / "inputs.json", inputs)
    cmd.extend(["-f", str(overlay)])
    epoch = run("git", "-C", ROOT, "log", "-1", "--format=%ct", capture_output=True, text=True).stdout.strip()
    services = [*cmd, "--profile", "mock", "--profile", "ui"]
    run(*services, "build", "--build-arg", "SOURCE_DATE_EPOCH=" + epoch)
    run(*services, "up", "-d", "--no-build", "--wait")
    gateway_key = seed_credentials(cmd, state)
    run_id = prepare_samples(state, cmd, args, gateway_key)
    console = Console(args.dashboard_port)
    console.sign_in((state / "admin-password").read_text().strip(), EMAIL)
    console.verify_requests(run_id)
    prepare_providers(state, cmd, console, rows)
    check_catalog(args, rows, gateway_key, console)
    print(f"Dashboard http://127.0.0.1:{args.dashboard_port} | {EMAIL} | private credentials: {state}")
    print(f"Gateway http://127.0.0.1:{args.gateway_port}")
    print(f"Requests: http://127.0.0.1:{args.dashboard_port}/#requests-explorer?org={console.org}")
    print(f"Mock traffic verified. External models configured: {len(rows)}. External requests are opt-in.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as exc:
        sys.exit(f"Demo setup failed: {exc}")

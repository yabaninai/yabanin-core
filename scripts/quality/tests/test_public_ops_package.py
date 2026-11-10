# SPDX-License-Identifier: Apache-2.0
# Adapted from Yabanin's Apache-2.0 artifact-verification regression suite.
"""Behavior tests for the isolated package verifier's Docker boundary."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time
import unittest


FAKE_DOCKER = r'''#!/usr/bin/env python3
import io, json, os, pathlib, re, sys, tarfile, time, uuid
state_path = pathlib.Path(os.environ["PKG_VERIFY_STATE"])
state = json.loads(state_path.read_text())
def save(): state_path.write_text(json.dumps(state))
def result(code=0, output=""):
    if output: print(output, end="" if output.endswith("\n") else "\n")
    raise SystemExit(code)
def label_arg(args):
    for i, arg in enumerate(args[:-1]):
        if arg == "--label":
            key, _, value = args[i + 1].partition("=")
            return key, value
    return "", ""
def container_id(token):
    if token in state["containers"]: return token
    for cid, obj in state["containers"].items():
        if obj["name"] == token: return cid
    return None
def image_id(token):
    if token in state["images"]: return token
    for image, obj in state["images"].items():
        if obj["id"] == token: return image
    return None
def network_id(token):
    if token in state["networks"]: return token
    for name, obj in state["networks"].items():
        if obj["id"] == token: return name
    return None
def enumeration_fails(kind):
    state.setdefault("enum_counts", {})
    count = state["enum_counts"].get(kind, 0) + 1
    state["enum_counts"][kind] = count
    save()
    return os.environ.get("PKG_VERIFY_FAIL_FINAL_ENUM") == kind and count == 2
def format_arg(args):
    for i, arg in enumerate(args):
        if arg == "--format" and i + 1 < len(args): return args[i + 1]
        if arg.startswith("--format="): return arg.split("=", 1)[1]
    return ""
args = sys.argv[1:]
if not args: result(2)
cmd = args[0]
if cmd == "info":
    if os.environ.get("PKG_VERIFY_FAIL_INFO"): result(1, "injected docker daemon failure\n")
    result()
if cmd == "build":
    key, value = label_arg(args)
    tag = args[args.index("-t") + 1]
    if tag.startswith("yabanin-package-verify-dashboard:") and os.environ.get("PKG_VERIFY_FAIL_DASHBOARD_BUILD"):
        print("injected dashboard build failure", file=sys.stderr)
        raise SystemExit(1)
    state["images"][tag] = {"id": "img-" + uuid.uuid4().hex, "labels": {key: value}, "removed": False}
    save(); result()
if cmd == "network" and args[1] == "create":
    key, value = label_arg(args)
    name = args[-1]
    state["networks"][name] = {"id": "net-" + uuid.uuid4().hex, "labels": {key: value}, "removed": False}
    save(); result(output=state["networks"][name]["id"] + "\n")
if cmd == "run":
    key, value = label_arg(args)
    name = args[args.index("--name") + 1]
    image_candidates = [(i, a) for i, a in enumerate(args) if a in ("pgvector/pgvector:pg16", "redis:7-alpine")
                        or a.startswith("yabanin-package-verify:")
                        or a.startswith("yabanin-package-verify-dashboard:")]
    if not image_candidates: result(125, "image argument missing\n")
    image_index, image = image_candidates[0]
    trailing = args[image_index + 1:]
    command = trailing[-1] if trailing else ""
    output, exit_code, running, mounts = "", 0, False, []
    if name.startswith("pkgverify-pg-") or name.startswith("pkgverify-redis-"):
        running = True
        volume = "volume-" + uuid.uuid4().hex
        destination = "/var/lib/postgresql/data" if name.startswith("pkgverify-pg-") else "/data"
        state.setdefault("volumes", {})[volume] = {"name": volume, "driver": "local", "removed": False}
        mounts = [{"Type": "volume", "Name": volume, "Source": "/var/lib/docker/volumes/" + volume + "/_data",
                   "Destination": destination, "Driver": "local", "RW": True, "anonymous": True}]
    elif name.startswith("pkgverify-gateway-"):
        running = True
    elif name.startswith("pkgverify-dashboard-"):
        output = os.environ.get("PKG_VERIFY_DASHBOARD_SOURCEMAPS", "") + "\n" if os.environ.get("PKG_VERIFY_DASHBOARD_SOURCEMAPS") else ""
    elif name.startswith("pkgverify-uid-"):
        output = "100\n"
    elif name.startswith("pkgverify-route-"):
        sub = name.split("pkgverify-route-", 1)[1].split("-", 1)[0]
        output = {"gateway": "invalid gateway config", "admin": "YABANIN_PG_URI is required",
                  "loggerd": "invalid loggerd config", "mcp": "YABANIN_PARTNER_API_KEY",
                  "migrate": "pg_uri is required for migrate"}.get(sub, "route marker missing") + "\n"
        exit_code = 1
    elif name.startswith("pkgverify-migrate-"):
        output = "migration applied\n"
    elif name.startswith("pkgverify-version-"):
        output = "yabanin version test-build\n"
        if os.environ.get("PKG_VERIFY_FAIL_INVENTORY") == "version": exit_code = 7
    else:
        result(125, "unexpected owned container name\n")
    cid = "ctr-" + uuid.uuid4().hex
    state["containers"][cid] = {"id": cid, "name": name, "labels": {key: value},
                                "running": running, "exit_code": exit_code,
                                "output": output, "removed": False, "mounts": mounts}
    save()
    if os.environ.get("PKG_VERIFY_BLOCK_RUN") and os.environ["PKG_VERIFY_BLOCK_RUN"] in name:
        state["block_consumed"] = True
        save()
        pathlib.Path(os.environ["PKG_VERIFY_BLOCK_MARKER"]).write_text(name)
        time.sleep(60)
    result(output=cid + "\n")
if cmd == "create":
    key, value = label_arg(args)
    name = args[args.index("--name") + 1]
    cid = "ctr-" + uuid.uuid4().hex
    state["containers"][cid] = {"id": cid, "name": name, "labels": {key: value},
                                "running": False, "exit_code": 0, "output": "", "removed": False,
                                "mounts": []}
    save(); result(output=cid + "\n")
if cmd == "cp":
    pathlib.Path(args[-1]).write_bytes(b"fixture-binary")
    result()
if cmd == "inspect":
    fmt = format_arg(args)
    token = args[-1]
    cid = container_id(token)
    if cid:
        obj = state["containers"][cid]
        target = obj["name"]
        if (os.environ.get("PKG_VERIFY_BLOCK_NAME") and os.environ["PKG_VERIFY_BLOCK_NAME"] in target
                and not state.get("block_consumed")):
            state["block_consumed"] = True
            save()
            pathlib.Path(os.environ["PKG_VERIFY_BLOCK_MARKER"]).write_text(target)
            time.sleep(60)
        if ".Config.Labels" in fmt: result(output=obj["labels"].get("io.yabanin.package-verify.run", "<no value>") + "\n")
        if "json .Mounts" in fmt: result(output=json.dumps(obj.get("mounts", [])) + "\n")
        if ".State.Running" in fmt: result(output=str(obj["running"]).lower() + "\n")
        if ".State.ExitCode" in fmt: result(output=str(obj["exit_code"]) + "\n")
    nid = network_id(token)
    if nid:
        obj = state["networks"][nid]
        if ".Labels" in fmt: result(output=obj["labels"].get("io.yabanin.package-verify.run", "<no value>") + "\n")
    iid = image_id(token)
    if iid:
        obj = state["images"][iid]
        if ".Config.Labels" in fmt: result(output=obj["labels"].get("io.yabanin.package-verify.run", "<no value>") + "\n")
        if ".Id" in fmt: result(output=obj["id"] + "\n")
    result(1, "not found\n")
if cmd == "ps":
    if os.environ.get("PKG_VERIFY_FAIL_ENUM") == "containers": result(2, "injected container enumeration failure\n")
    label = next((a.split("=", 1)[1] for a in args if a.startswith("label=")), None)
    name_filter = next((a.split("=", 1)[1] for a in args if a.startswith("name=")), None)
    if label and enumeration_fails("containers"): result(2, "injected final container enumeration failure\n")
    ids = []
    for cid, obj in state["containers"].items():
        if obj["removed"]: continue
        if label and obj["labels"].get("io.yabanin.package-verify.run") != label.split("=", 1)[1]: continue
        if name_filter and not re.fullmatch(name_filter, "/" + obj["name"]): continue
        ids.append(cid)
    result(output="".join(i + "\n" for i in ids))
if cmd == "rm":
    token = args[-1]
    cid = container_id(token)
    if not cid: result(1, "not found\n")
    if os.environ.get("PKG_VERIFY_FAIL_RM") and state["containers"][cid]["labels"].get("io.yabanin.package-verify.run"):
        result(1, "injected rm failure\n")
    if any(arg.startswith("-") and "v" in arg[1:] for arg in args):
        for mount in state["containers"][cid].get("mounts", []):
            if mount.get("anonymous"):
                state.setdefault("volumes", {})[mount["Name"]]["removed"] = True
                state.setdefault("removed_volumes", []).append(mount["Name"])
    state["containers"][cid]["removed"] = True
    state["removed"]["containers"].append(state["containers"][cid])
    save(); result()
if cmd == "network":
    sub = args[1]
    if sub == "inspect":
        token = args[-1]; name = network_id(token)
        if not name: result(1, "not found\n")
        fmt = format_arg(args)
        if ".Labels" in fmt: result(output=state["networks"][name]["labels"].get("io.yabanin.package-verify.run", "<no value>") + "\n")
    if sub == "rm":
        token=args[-1]; name=network_id(token)
        if not name: result(1, "not found\n")
        obj=state["networks"][name]
        if os.environ.get("PKG_VERIFY_FAIL_RM") and obj["labels"].get("io.yabanin.package-verify.run"): result(1,"injected rm failure\n")
        obj["removed"]=True; state["removed"]["networks"].append(obj); save(); result()
    if sub == "ls":
        if os.environ.get("PKG_VERIFY_FAIL_ENUM") == "networks": result(2, "injected network enumeration failure\n")
        if enumeration_fails("networks"): result(2, "injected final network enumeration failure\n")
        label=next((a.split("=",1)[1] for a in args if a.startswith("label=")),None)
        names=[v["id"] for v in state["networks"].values() if not v["removed"] and (not label or v["labels"].get("io.yabanin.package-verify.run")==label.split("=",1)[1])]
        result(output="".join(n+"\n" for n in names))
if cmd == "image":
    sub=args[1]
    if sub == "inspect":
        fmt=format_arg(args); token=args[-1]; tag=image_id(token)
        if not tag: result(1,"not found\n")
        obj=state["images"][tag]
        if ".Config.Labels" in fmt: result(output=obj["labels"].get("io.yabanin.package-verify.run","<no value>")+"\n")
        if ".Id" in fmt: result(output=obj["id"]+"\n")
    if sub == "ls":
        if os.environ.get("PKG_VERIFY_FAIL_ENUM") == "images": result(2, "injected image enumeration failure\n")
        if enumeration_fails("images"): result(2, "injected final image enumeration failure\n")
        label=next((a.split("=",1)[1] for a in args if a.startswith("label=")),None)
        ids=[v["id"] for v in state["images"].values() if not v["removed"] and (not label or v["labels"].get("io.yabanin.package-verify.run")==label.split("=",1)[1])]
        result(output="".join(i+"\n" for i in ids))
    if sub == "rm":
        tag=args[-1]; key=image_id(tag)
        if not key: result(1,"not found\n")
        obj=state["images"][key]
        if os.environ.get("PKG_VERIFY_FAIL_RM") and obj["labels"].get("io.yabanin.package-verify.run"): result(1,"injected rm failure\n")
        obj["removed"]=True; state["removed"]["images"].append(obj); save(); result()
if cmd == "volume" and args[1] == "ls":
    if os.environ.get("PKG_VERIFY_FAIL_ENUM") == "volumes": result(2, "injected volume enumeration failure\n")
    volumes=state.get("volumes", {})
    result(output="".join(name+"\n" for name,obj in volumes.items() if not obj["removed"]))
if cmd == "logs":
    cid=container_id(args[-1])
    if not cid: result(1,"not found\n")
    result(output=state["containers"][cid]["output"])
if cmd == "exec":
    cid=container_id(args[1]); tail=args[2:]
    if not cid: result(1, "not found\n")
    obj=state["containers"][cid]
    if "pg_isready" in tail: result()
    if "redis-cli" in tail: result(output="PONG\n")
    if "wget" in tail: result(output='{"status":"ok","redis":"up"}\n')
    result(2,"unexpected exec\n")
if cmd == "history":
    # delivered-bytes scanner: per-image history fixture (default clean).
    ref=args[-1]
    env_name="PKG_VERIFY_HISTORY_DASHBOARD" if "dashboard" in ref else "PKG_VERIFY_HISTORY_ROOT"
    text=os.environ.get(env_name) or "RUN /bin/sh -c apk add --no-cache ca-certificates curl\nCMD [\"nginx\", \"-g\", \"daemon off;\"]\n"
    result(output=text if text.endswith("\n") else text + "\n")
if cmd == "save":
    # delivered-bytes scanner: docker save REF -o PATH. Layer contents come
    # from PKG_VERIFY_LAYER_ROOT/<profile>/ when set, else a clean default, in
    # docker-archive layout (<hash>/layer.tar + manifest.json).
    if os.environ.get("PKG_VERIFY_FAIL_SAVE"): result(1, "injected docker save failure\n")
    out_path=args[args.index("-o") + 1]
    profile="dashboard" if "dashboard" in args[-1] else "root"
    layer=io.BytesIO()
    with tarfile.open(fileobj=layer, mode="w") as lt:
        root_env=os.environ.get("PKG_VERIFY_LAYER_ROOT")
        source=pathlib.Path(root_env) / profile if root_env else None
        if source and source.is_dir():
            for path in sorted(source.rglob("*")):
                lt.add(path, arcname=str(path.relative_to(source)), recursive=False)
        else:
            def add(name, data, mode=0o644):
                info=tarfile.TarInfo(name); info.size=len(data); info.mode=mode
                lt.addfile(info, io.BytesIO(data))
            add("etc/os-release", b"NAME=fixture\n")
            add("app/yabanin", b"fixture-binary\n", 0o755)
            add("usr/share/nginx/html/index.html", b"<html>ok</html>\n")
    with tarfile.open(out_path, "w") as outer:
        blob=layer.getvalue()
        info=tarfile.TarInfo("layer0/layer.tar"); info.size=len(blob)
        outer.addfile(info, io.BytesIO(blob))
        manifest=json.dumps({"SchemaVersion": 2, "Layers": ["layer0/layer.tar"]}).encode()
        info=tarfile.TarInfo("manifest.json"); info.size=len(manifest)
        outer.addfile(info, io.BytesIO(manifest))
    result()
result(2, "unsupported docker command: " + " ".join(args) + "\n")
'''

FAKE_TOOL = r'''#!/usr/bin/env python3
import io, json, os, pathlib, sys, tarfile
name=os.environ.get("PKG_VERIFY_TOOL_NAME") or os.path.basename(sys.argv[0])
if name == "go":
    if os.environ.get("PKG_VERIFY_FAIL_INVENTORY") == "go": print("injected go inventory failure",file=sys.stderr); sys.exit(9)
    if len(sys.argv) > 1 and sys.argv[1] == "version":
        if os.environ.get("PKG_VERIFY_FAIL_INVENTORY") == "version": print("injected binary metadata failure",file=sys.stderr); sys.exit(8)
        print("/app/yabanin: go1.27.1")
        print("\tpath\tgithub.com/reireirei/yabanin/cmd/yabanin")
        print("\tmod\tgithub.com/reireirei/yabanin\t(devel)\t")
    else:
        print("example.test/module v1.2.3")
else:
    if len(sys.argv) > 1 and sys.argv[1] == "pack":
        # delivered-bytes scanner: npm pack fixture. Contents come from
        # PKG_VERIFY_NPM_PACK_ROOT (paths under package/) when set, else a
        # minimal clean package.
        dest=pathlib.Path(sys.argv[sys.argv.index("--pack-destination") + 1])
        tarball="fixture-pkg-1.0.0.tgz"
        with tarfile.open(dest / tarball, "w:gz") as tf:
            root=os.environ.get("PKG_VERIFY_NPM_PACK_ROOT")
            if root and os.path.isdir(root):
                base=pathlib.Path(root)
                for path in sorted(base.rglob("*")):
                    tf.add(path, arcname="package/" + str(path.relative_to(base)), recursive=False)
            else:
                data=b'{"name":"fixture"}\n'
                info=tarfile.TarInfo("package/package.json"); info.size=len(data)
                tf.addfile(info, io.BytesIO(data))
                data=b'export const x = 1;\n'
                info=tarfile.TarInfo("package/src/index.ts"); info.size=len(data)
                tf.addfile(info, io.BytesIO(data))
        print(json.dumps([{"filename": tarball, "files": []}]))
        sys.exit(0)
    if os.environ.get("PKG_VERIFY_FAIL_INVENTORY") == "npm": print("injected npm inventory failure",file=sys.stderr); sys.exit(10)
    print(json.dumps({"dependencies": {"fixture": {"version": "1.0.0"}}}))
'''


class PackageVerifyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="package-verify-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        source = Path(__file__).resolve().parent.parent.joinpath("package_verify.sh")
        self.script = self.root / "scripts/quality/package_verify.sh"
        self.script.parent.mkdir(parents=True)
        shutil.copy2(source, self.script)
        self.script.chmod(0o755)
        scan_source = Path(__file__).resolve().parent.parent.joinpath("scan_delivered_bytes.sh")
        scan_path = self.root / "scripts/quality/scan_delivered_bytes.sh"
        shutil.copy2(scan_source, scan_path)
        scan_path.chmod(0o755)
        allow_source = Path(__file__).resolve().parent.parent.joinpath("scan_delivered_bytes.allow")
        allow_path = self.root / "scripts/quality/scan_delivered_bytes.allow"
        if allow_source.is_file():
            shutil.copy2(allow_source, allow_path)
        else:
            allow_path.write_text("# fixture allowlist (empty)\n")
        sdk_project = self.root / "sdks/node"
        sdk_project.mkdir(parents=True)
        (sdk_project / "package.json").write_text('{"name":"fixture-sdk","version":"1.0.0"}\n')
        npm_project = self.root / "web/dashboard"
        npm_project.mkdir(parents=True)
        (npm_project / "package.json").write_text('{"name":"fixture","version":"1.0.0"}\n')
        (self.bin / "docker").write_text(FAKE_DOCKER)
        (self.bin / "docker").chmod(0o755)
        for name in ("go", "npm"):
            path = self.bin / name
            path.write_text(FAKE_TOOL)
            path.chmod(0o755)
        self.state_path = self.root / "state.json"
        self.marker = self.root / "blocked.marker"
        self.state_path.write_text(json.dumps({
            "containers": {"foreign-container": {"id": "foreign-container", "name": "sentinel-container",
                "labels": {"fixture.owner": "foreign"}, "running": True, "exit_code": 0,
                "output": "sentinel", "removed": False, "mounts": [{"Type": "volume", "Name": "sentinel-named-volume",
                "Source": "/fixture/sentinel", "Destination": "/fixture", "Driver": "local", "RW": True, "anonymous": False}]}},
            "networks": {"sentinel-network": {"id": "foreign-network", "labels": {"fixture.owner": "foreign"}, "removed": False}},
            "images": {}, "volumes": {"sentinel-named-volume": {"name": "sentinel-named-volume", "driver": "local", "removed": False}},
            "removed_volumes": [], "removed": {"containers": [], "networks": [], "images": []}}))

    def reset_state(self):
        self.state_path.write_text(json.dumps({
            "containers": {"foreign-container": {"id": "foreign-container", "name": "sentinel-container",
                "labels": {"fixture.owner": "foreign"}, "running": True, "exit_code": 0,
                "output": "sentinel", "removed": False, "mounts": [{"Type": "volume", "Name": "sentinel-named-volume",
                "Source": "/fixture/sentinel", "Destination": "/fixture", "Driver": "local", "RW": True, "anonymous": False}]}},
            "networks": {"sentinel-network": {"id": "foreign-network", "labels": {"fixture.owner": "foreign"}, "removed": False}},
            "images": {}, "volumes": {"sentinel-named-volume": {"name": "sentinel-named-volume", "driver": "local", "removed": False}},
            "removed_volumes": [], "removed": {"containers": [], "networks": [], "images": []}}))
        self.marker.unlink(missing_ok=True)

    def env(self, **overrides):
        env = dict(os.environ)
        # package_verify.sh rejects a missing/non-integer epoch before any
        # docker work (reproducible-image recipe): pin an explicit integer so
        # the ambient environment cannot flip that early-exit branch; callers
        # can still override it per scenario.
        env.update({"PATH": str(self.bin) + os.pathsep + env.get("PATH", ""),
                    "PKG_VERIFY_STATE": str(self.state_path),
                    "PKG_VERIFY_BLOCK_MARKER": str(self.marker),
                    "SOURCE_DATE_EPOCH": "1793834078"})
        env.update({key: str(value) for key, value in overrides.items() if value is not None})
        return env

    def run_script(self, **overrides):
        # a loaded quality run (jobs=3 with Docker gates) 30s produced load
        # flakes that are not script defects. Assertions unchanged.
        return subprocess.run([str(self.script)], cwd=self.root, env=self.env(**overrides),
                              capture_output=True, text=True, timeout=90)

    def state(self):
        return json.loads(self.state_path.read_text())

    def assert_sentinel_unchanged(self, state):
        container = state["containers"]["foreign-container"]
        self.assertEqual((container["id"], container["running"], container["removed"]),
                         ("foreign-container", True, False))
        network = state["networks"]["sentinel-network"]
        self.assertEqual((network["id"], network["removed"]), ("foreign-network", False))
        self.assertFalse(state["volumes"]["sentinel-named-volume"]["removed"])

    def assert_no_owned_resources(self, state, msg=None):
        self.assertFalse(any(not obj["removed"] and obj["labels"].get("io.yabanin.package-verify.run")
                             for obj in state["containers"].values()), msg or repr(state["containers"]))
        self.assertFalse(any(not obj["removed"] and obj["labels"].get("io.yabanin.package-verify.run")
                             for obj in state["networks"].values()))
        self.assertFalse(any(not obj["removed"] and obj["labels"].get("io.yabanin.package-verify.run")
                             for obj in state["images"].values()))
        self.assertFalse(any(not obj["removed"] and name != "sentinel-named-volume"
                             for name, obj in state.get("volumes", {}).items()))

    def test_normal_run_records_inventory_and_removes_only_owned_resources(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        state = self.state()
        self.assert_no_owned_resources(state)
        self.assert_sentinel_unchanged(state)
        removed_names = {obj["name"] for obj in state["removed"]["containers"]}
        self.assertTrue(any(name.startswith("pkgverify-uid-") for name in removed_names))
        run_id = next(part.removeprefix("evidence=artifacts/package-verify/")
                      for part in result.stdout.split()
                      if part.startswith("evidence=artifacts/package-verify/"))
        for group in (state["removed"]["containers"], state["removed"]["networks"], state["removed"]["images"]):
            self.assertTrue(group)
            for obj in group:
                self.assertEqual(obj["labels"].get("io.yabanin.package-verify.run"), run_id)
        for service in ("gateway", "admin", "loggerd", "mcp", "migrate"):
            self.assertTrue(any(name.startswith(f"pkgverify-route-{service}-") for name in removed_names), service)
        for prefix in ("pkgverify-migrate-", "pkgverify-image-info-"):
            self.assertTrue(any(name.startswith(prefix) for name in removed_names), prefix)
        run_dirs = list((self.root / "artifacts/package-verify").glob("*"))
        self.assertEqual(len(run_dirs), 1)
        self.assertTrue((run_dirs[0] / "runtime-uid.txt").read_text().strip().isdigit())
        self.assertTrue((run_dirs[0] / "postgres-mounts.json").exists())
        self.assertTrue((run_dirs[0] / "redis-mounts.json").exists())
        mounts = json.loads((run_dirs[0] / "postgres-mounts.json").read_text()) + json.loads((run_dirs[0] / "redis-mounts.json").read_text())
        owned_volumes = {mount["Name"] for mount in mounts if mount["Type"] == "volume"}
        self.assertEqual(len(owned_volumes), 2)
        provenance = (run_dirs[0] / "owned-anonymous-volumes.txt").read_text()
        self.assertIn("postgres\t", provenance)
        self.assertIn("redis\t", provenance)
        self.assertTrue(owned_volumes.issubset(set(state["removed_volumes"])))
        self.assertTrue(all(state["volumes"][name]["removed"] for name in owned_volumes))
        self.assertFalse(state["volumes"]["sentinel-named-volume"]["removed"])
        self.assertTrue((run_dirs[0] / "version.txt").read_text().strip())
        self.assertTrue((run_dirs[0] / "go-modules.txt").read_text().strip())
        self.assertTrue((run_dirs[0] / "npm-web-dashboard.json").read_text().strip())
        self.assertIn("PostgreSQL ready", (run_dirs[0] / "postgres-readiness.txt").read_text())
        self.assertIn("Redis ready", (run_dirs[0] / "redis-readiness.txt").read_text())
        self.assertIn('"redis":"up"', (run_dirs[0] / "healthz.json").read_text())
        self.assertNotIn("postgres://pkgverify:", result.stdout + result.stderr)

    def test_dashboard_image_is_built_and_sourcemap_gate_is_green(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        state = self.state()
        self.assert_no_owned_resources(state)
        self.assert_sentinel_unchanged(state)
        dash_tags = [tag for tag in state["images"] if tag.startswith("yabanin-package-verify-dashboard:")]
        self.assertEqual(len(dash_tags), 1, sorted(state["images"]))
        self.assertTrue(state["images"][dash_tags[0]]["removed"])
        run_dir = next(self.root.glob("artifacts/package-verify/*"))
        self.assertTrue((run_dir / "dashboard-image-id.txt").read_text().strip())
        self.assertEqual((run_dir / "dashboard-sourcemaps.txt").read_text(), "")
        self.assertTrue((run_dir / "dashboard-build.log").exists())
        self.assertTrue(any(obj["name"].startswith("pkgverify-dashboard-")
                            for obj in state["removed"]["containers"]))

    def test_dashboard_build_failure_fails_closed(self):
        result = self.run_script(PKG_VERIFY_FAIL_DASHBOARD_BUILD=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("FAIL: dashboard image build failed", result.stderr)
        state = self.state()
        self.assert_no_owned_resources(state)
        self.assert_sentinel_unchanged(state)

    def test_sourcemap_in_dashboard_deliverable_fails_closed(self):
        result = self.run_script(PKG_VERIFY_DASHBOARD_SOURCEMAPS="dist/assets/chunk-abc.map")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("sourcemaps present in dashboard deliverable", result.stderr)
        self.assertIn("chunk-abc.map", result.stderr)
        state = self.state()
        self.assert_no_owned_resources(state)
        self.assert_sentinel_unchanged(state)

    def test_delivered_bytes_scan_runs_and_records_evidence(self):
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = next(self.root.glob("artifacts/package-verify/*/bytes-scan/report.txt"))
        text = report.read_text()
        for stage in ("npm\t", "image:root\t", "image:dashboard\t"):
            self.assertIn(stage, text)
        self.assertIn("delivered-bytes scan: clean", result.stdout)
        self.assertNotIn("FAIL\t", text)
        self.assertNotIn("SKIP\t", text)

    def test_delivered_bytes_finding_fails_packaging(self):
        result = self.run_script(
            PKG_VERIFY_HISTORY_ROOT="RUN /bin/sh -c export API_TOKEN=hardcoded-literal")
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("FAIL: delivered-bytes", result.stderr)
        report = next(self.root.glob("artifacts/package-verify/*/bytes-scan/report.txt"))
        self.assertIn("history-credential-value", report.read_text())
        self.assertNotIn("hardcoded-literal", report.read_text())
        state = self.state()
        self.assert_no_owned_resources(state)
        self.assert_sentinel_unchanged(state)

    def test_missing_scanner_fails_before_docker_build(self):
        (self.root / "scripts/quality/scan_delivered_bytes.sh").unlink()
        before = self.state()
        result = self.run_script()
        self.assertEqual(result.returncode, 1)
        self.assertIn("missing delivered-bytes scanner", result.stderr)
        self.assertEqual(self.state(), before)

    def test_docker_daemon_unavailable_fails_closed(self):
        result = self.run_script(PKG_VERIFY_FAIL_INFO=1)
        self.assertEqual(result.returncode, 1)
        self.assertIn("FAIL: Docker daemon unavailable", result.stderr)

    def test_cleanup_failure_fails_and_reports_remaining_owned_resources(self):
        result = self.run_script(PKG_VERIFY_FAIL_RM=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cleanup", result.stderr)
        state = self.state()
        self.assertTrue(any(not obj["removed"] and obj["labels"].get("io.yabanin.package-verify.run")
                            for obj in state["containers"].values()))
        self.assertTrue(any(not obj["removed"] and name != "sentinel-named-volume"
                            for name, obj in state["volumes"].items()))
        self.assert_sentinel_unchanged(state)

    def test_inventory_failures_are_not_reported_as_success(self):
        for point in ("version", "go", "npm"):
            with self.subTest(point=point):
                self.reset_state()
                result = self.run_script(PKG_VERIFY_FAIL_INVENTORY=point)
                self.assertNotEqual(result.returncode, 0, point)
                self.assertIn("FAIL:", result.stderr)
                self.assert_no_owned_resources(self.state())
                self.assert_sentinel_unchanged(self.state())

    def test_cleanup_enumeration_errors_fail_closed(self):
        for point in ("containers", "networks", "images", "volumes"):
            with self.subTest(point=point):
                self.reset_state()
                result = self.run_script(PKG_VERIFY_FAIL_ENUM=point)
                self.assertNotEqual(result.returncode, 0, point)
                self.assertIn("cleanup", result.stderr)
                self.assert_no_owned_resources(self.state())
                self.assert_sentinel_unchanged(self.state())

    def test_cleanup_final_reenumeration_errors_fail_closed(self):
        for point in ("containers", "networks", "images"):
            with self.subTest(point=point):
                self.reset_state()
                result = self.run_script(PKG_VERIFY_FAIL_FINAL_ENUM=point)
                self.assertNotEqual(result.returncode, 0, point)
                self.assertIn("could not verify owned", result.stderr)
                self.assert_sentinel_unchanged(self.state())

    def run_cancel(self, block_name, stage="inspect"):
        block_env = {"PKG_VERIFY_BLOCK_NAME": block_name} if stage == "inspect" else {"PKG_VERIFY_BLOCK_RUN": block_name}
        proc = subprocess.Popen([str(self.script)], cwd=self.root, env=self.env(**block_env),
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                start_new_session=True)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and not self.marker.exists() and proc.poll() is None:
            time.sleep(0.02)
        if not self.marker.exists():
            os.killpg(proc.pid, signal.SIGKILL)
            output, _ = proc.communicate(timeout=3)
            self.fail(f"verifier did not reach cancellation point {block_name}: {output}")
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            output, _ = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            output, _ = proc.communicate(timeout=3)
            self.fail(f"verifier did not clean up after SIGTERM at {block_name}: {output}")
        return proc.returncode, output

    def test_term_during_transient_route_container_cleans_owned_resources(self):
        code, output = self.run_cancel("pkgverify-route-gateway-")
        self.assertEqual(code, 143, output)
        state = self.state()
        self.assert_no_owned_resources(state)
        self.assert_sentinel_unchanged(state)
        self.assertTrue(any(obj["name"].startswith("pkgverify-route-gateway-")
                            for obj in state["removed"]["containers"]))

    def test_term_before_uid_container_id_returns_uses_owned_name_cleanup(self):
        code, output = self.run_cancel("pkgverify-uid-", stage="run")
        self.assertEqual(code, 143, output)
        state = self.state()
        self.assert_no_owned_resources(state, output)
        self.assert_sentinel_unchanged(state)
        self.assertTrue(any(obj["name"].startswith("pkgverify-uid-")
                            for obj in state["removed"]["containers"]))

    def test_term_during_migration_cleans_database_cache_and_migration_container(self):
        code, output = self.run_cancel("pkgverify-migrate-")
        self.assertEqual(code, 143, output)
        state = self.state()
        self.assert_no_owned_resources(state)
        self.assert_sentinel_unchanged(state)
        removed_names = {obj["name"] for obj in state["removed"]["containers"]}
        self.assertTrue(any(name.startswith("pkgverify-migrate-") for name in removed_names))
        self.assertTrue(any(name.startswith("pkgverify-pg-") for name in removed_names))
        self.assertTrue(any(name.startswith("pkgverify-redis-") for name in removed_names))
        mounts = json.loads(next(self.root.glob("artifacts/package-verify/*/postgres-mounts.json")).read_text())
        mounts += json.loads(next(self.root.glob("artifacts/package-verify/*/redis-mounts.json")).read_text())
        owned_volumes = {mount["Name"] for mount in mounts if mount["Type"] == "volume"}
        self.assertTrue(owned_volumes)
        self.assertTrue(owned_volumes.issubset(set(state["removed_volumes"])))
        self.assertTrue(all(state["volumes"][name]["removed"] for name in owned_volumes))
        self.assertFalse(state["volumes"]["sentinel-named-volume"]["removed"])
        self.assertTrue((next(self.root.glob("artifacts/package-verify/*")) / "owned-anonymous-volumes.txt").exists())


if __name__ == "__main__":
    unittest.main()

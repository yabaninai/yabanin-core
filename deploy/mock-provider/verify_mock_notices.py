"""Verify a local mock-provider image and its corresponding Alpine source companion."""

import argparse
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile


CONTEXT = Path(__file__).resolve().parent
PROJECT_FILES = ("LICENSE", "NOTICE", "LICENSING.md")
LEGAL = "usr/share/licenses/yabanin/"
DATABASE = "lib/apk/db/installed"
APK_FIELDS = {"P": "name", "V": "version", "o": "origin", "L": "license",
              "c": "commit", "A": "arch"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def packages(data):
    result = []
    for record in filter(None, data.decode().strip().split("\n\n")):
        fields = dict(line.split(":", 1) for line in record.splitlines())
        result.append({name: fields[key] for key, name in APK_FIELDS.items()})
    return sorted(result, key=lambda package: package["name"])


def exported_files(stream):
    files = {}
    with tarfile.open(fileobj=stream, mode="r|*") as archive:
        for item in archive:
            name = item.name.removeprefix("./")
            if name != DATABASE and not name.startswith(LEGAL):
                continue
            if item.isdir():
                continue
            require(item.isfile() and name not in files, f"invalid image file: {name}")
            files[name] = archive.extractfile(item).read()
    return files


def docker(*args):
    return subprocess.check_output(["docker", *args])


def inspect_image(image, expected_id):
    require(re.fullmatch(r"sha256:[a-f0-9]{64}", expected_id), "expected immutable image ID")
    info, = json.loads(docker("image", "inspect", image))
    require(info["Id"] == expected_id, "unexpected image ID")
    require((info["Os"], info["Architecture"]) == ("linux", "amd64"), "unexpected image platform")
    require(info["Config"]["Entrypoint"] == ["mock-provider"], "unexpected mock entrypoint")
    container = docker("create", "--network", "none", expected_id).decode().strip()
    try:
        return exported_files(io.BytesIO(docker("export", container)))
    finally:
        docker("rm", "-v", container)


def check_packages(manifest, data):
    actual = packages(data)
    require(actual and actual == manifest["packages"], "installed APK inventory mismatch")
    for package in actual:
        source = manifest["sources"].get(package["origin"])
        require(source and source["version"] == package["version"]
                and source["commit"] == package["commit"],
                f"source identity mismatch: {package['name']}")


def check_payload(files, trusted_manifest, repo):
    require(LEGAL + "MANIFEST.json" in files, "missing image notice manifest")
    require(files[LEGAL + "MANIFEST.json"] == trusted_manifest, "image notice manifest mismatch")
    manifest = json.loads(trusted_manifest)
    require(manifest["schema"] == 1 and manifest["platform"] == "linux/amd64", "invalid notice manifest")
    check_packages(manifest, files[DATABASE])
    for name, notice in manifest["notices"].items():
        require(LEGAL + name in files, f"missing notice: {name}")
        require(hashlib.sha256(files[LEGAL + name]).hexdigest() == notice["sha256"],
                f"notice hash mismatch: {name}")
    expected = {LEGAL + name for name in manifest["notices"]}
    require(set(files) == expected | {DATABASE, LEGAL + "MANIFEST.json"}, "unexpected image notice file")
    for name in PROJECT_FILES:
        require(files[LEGAL + name] == (repo / name).read_bytes(), f"project {name} mismatch")
    return manifest


def check_origins(manifest):
    files = manifest["companion_files"]
    for name, source in manifest["sources"].items():
        require(source["notices"] and set(source["notices"]) <= manifest["notices"].keys(),
                f"unmapped notices: {name}")
        require(set(source.get("embedded", [])) <= manifest["sources"].keys(),
                f"missing embedded source: {name}")
        require(source["inputs"] or "recipe_tree" in source, f"missing source: {name}")
        require(set(source["inputs"]) <= files.keys(), f"unmapped source input: {name}")
        if "recipe_tree" in source:
            require(f"aports/{name}/APKBUILD" in files, f"missing recipe: {name}")


def check_file(path, name, manifest):
    links = manifest["recipe_links"]
    if name in links:
        require(path.is_symlink() and str(path.readlink()) == links[name], f"recipe link mismatch: {name}")
    else:
        require(not path.is_symlink(), f"unexpected source link: {name}")
    require(path.is_file(), f"missing source: {name}")
    if name.startswith("aports/") and name not in links:
        require(bool(path.stat().st_mode & 0o111) == (name in manifest["recipe_executables"]),
                f"recipe mode mismatch: {name}")
    with path.open("rb") as handle:
        actual = hashlib.file_digest(handle, "sha256").hexdigest()
    require(actual == manifest["companion_files"][name], f"source hash mismatch: {name}")


def check_companion(root, manifest):
    check_origins(manifest)
    files = manifest["companion_files"]
    for name in files:
        path = root / name
        require(path.resolve().is_relative_to(root.resolve()), f"source escapes companion: {name}")
        check_file(path, name, manifest)
    observed = {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() or p.is_symlink()}
    require(observed == files.keys() | {"SHA256SUMS"}, "unexpected source companion file")
    checksums = "".join(f"{digest}  {name}\n" for name, digest in sorted(files.items()))
    require((root / "SHA256SUMS").read_bytes() == checksums.encode(), "source checksum list mismatch")


def verify(files, trusted_manifest, repo, companion):
    manifest = check_payload(files, trusted_manifest, repo)
    check_companion(companion, manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--expected-image-id", required=True)
    parser.add_argument("--source-companion", required=True, type=Path)
    args = parser.parse_args()
    files = inspect_image(args.image, args.expected_image_id)
    manifest = verify(files, (CONTEXT / "legal/MANIFEST.json").read_bytes(),
                      CONTEXT.parents[1], args.source_companion)
    print(f"{args.expected_image_id} linux/amd64: {len(manifest['packages'])} packages, "
          f"{len(manifest['notices'])} legal files, {len(manifest['companion_files'])} source files")


if __name__ == "__main__":
    try:
        main()
    except (KeyError, OSError, ValueError, tarfile.TarError, subprocess.CalledProcessError) as error:
        sys.exit(f"mock notices: {error}")

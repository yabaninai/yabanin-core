"""Verify the mock-provider legal payload directly from its OCI layers."""
import gzip
import hashlib
from pathlib import Path, PurePosixPath
import sys
import tarfile
import tempfile

import oci_build_receipt as oci

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "deploy/mock-provider"))
import verify_mock_notices as notices

ROLE = "mock-provider"
PLATFORM = "linux/amd64"
PROOF = Path("artifacts/release-evidence/mock-provider-proof")
MANIFEST = Path("deploy/mock-provider/legal/MANIFEST.json")
LAYER = "application/vnd.oci.image.layer.v1.tar"
MAX_LAYER_BYTES = 64 << 20
MAX_NOTICE_BYTES = 4 << 20


def proof_path(root):
    proof = root.resolve() / PROOF
    oci.require(proof.resolve() == proof, "mock-provider proof path escapes the worktree")
    return proof


def present(root):
    proof = proof_path(root)
    return proof.exists() or proof.is_symlink()


def _blob_file(directory, descriptor):
    oci.descriptor_shape(descriptor)
    path = directory / descriptor["digest"][7:]
    oci.require(path.resolve() == path and path.is_file(), "missing regular mock-provider layer")
    size = descriptor["size"]
    oci.require(0 < size <= MAX_LAYER_BYTES and path.stat().st_size == size,
                "mock-provider layer size mismatch")
    return path


def _copy_layer(source, destination):
    remaining = MAX_LAYER_BYTES
    while chunk := source.read(1 << 20):
        remaining -= len(chunk)
        oci.require(remaining >= 0, "mock-provider layer expands beyond the read limit")
        destination.write(chunk)


def _unpack_layer(directory, descriptor, diff_id, destination):
    path = _blob_file(directory, descriptor)
    with path.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
        oci.require("sha256:" + digest == descriptor["digest"], "mock-provider layer digest mismatch")
        source.seek(0)
        media = descriptor["mediaType"]
        if media == LAYER + "+gzip":
            with gzip.GzipFile(fileobj=source) as expanded:
                _copy_layer(expanded, destination)
        else:
            oci.require(media == LAYER, "unsupported mock-provider layer media type")
            _copy_layer(source, destination)
    destination.seek(0)
    digest = hashlib.file_digest(destination, "sha256").hexdigest()
    oci.require("sha256:" + digest == diff_id, "mock-provider layer diff ID mismatch")
    destination.seek(0)


def _path(name):
    path = PurePosixPath(name)
    oci.require(not path.is_absolute() and ".." not in path.parts, "unsafe mock-provider layer path")
    return path.as_posix()


def _is_ancestor(path, child):
    return path == "." or child == path or child.startswith(path + "/")


def _is_payload(path):
    return path == notices.DATABASE or path.startswith(notices.LEGAL)


def _affects_payload(path):
    return _is_payload(path) or any(_is_ancestor(path, target)
                                    for target in (notices.DATABASE, notices.LEGAL.rstrip("/")))


def _whiteout(path):
    name = path.name
    if name == ".wh..wh..opq":
        return path.parent.as_posix()
    if name.startswith(".wh."):
        return (path.parent / name[4:]).as_posix()
    return None


def _payload_entry(archive, member, name):
    if member.isdir():
        return None
    oci.require(member.isreg(), f"nonregular mock-provider payload path: {name}")
    oci.require(member.size <= MAX_NOTICE_BYTES, f"oversized mock-provider payload file: {name}")
    return archive.extractfile(member).read()


def _apply_updates(payload, removals, updates):
    for name in tuple(payload):
        if any(_is_ancestor(path, name) for path in removals):
            del payload[name]
    for name, data in updates.items():
        if data is None:
            payload.pop(name, None)
        else:
            payload[name] = data


def _apply_layer(payload, directory, layer, diff_id):
    with tempfile.TemporaryFile() as uncompressed:
        _unpack_layer(directory, layer, diff_id, uncompressed)
        with tarfile.open(fileobj=uncompressed, mode="r:") as archive:
            _read_entries(archive, payload)


def _read_entries(archive, payload):
    removals, updates = set(), {}
    for member in archive:
        name = _path(member.name)
        target = _whiteout(PurePosixPath(name))
        if target is not None:
            removals.add(target)
        elif _is_payload(name):
            oci.require(name not in updates, f"duplicate mock-provider payload path: {name}")
            updates[name] = _payload_entry(archive, member, name)
        elif _affects_payload(name):
            oci.require(member.isdir(), f"non-directory mock-provider payload ancestor: {name}")
    _apply_updates(payload, removals, updates)


def verify(root, image_id, platform):
    root = root.resolve()
    proof = proof_path(root)
    layers, companion = proof / "layers", proof / "source-companion"
    for path in (layers, companion):
        oci.require(path.resolve() == path and path.is_dir(), f"missing mock-provider {path.name}")
    oci.require(platform == PLATFORM, "mock-provider proof platform mismatch")
    index = oci.blob(root, ROLE, image_id)
    child = oci.platform_image(root, ROLE, index, platform)
    image = oci.image_manifest(root, ROLE, child)
    config = oci.descriptor(root, ROLE, image["config"], oci.CONFIG)
    oci.require(config["config"]["Entrypoint"] == [ROLE], "unexpected mock-provider entrypoint")
    diff_ids = config["rootfs"]["diff_ids"]
    oci.require(isinstance(diff_ids, list) and len(diff_ids) == len(image["layers"]) > 0,
                "mock-provider layer set does not match its configuration")
    payload = {}
    for layer, diff_id in zip(image["layers"], diff_ids):
        _apply_layer(payload, layers, layer, diff_id)
    manifest = root / MANIFEST
    oci.require(manifest.resolve() == manifest, "unexpected mock-provider legal manifest path")
    notices.verify(payload, manifest.read_bytes(), root, companion)

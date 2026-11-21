"""Verify compact BuildKit metadata for the actual images built by quickstart."""
import base64
import hashlib
import json
import re
from pathlib import Path, PurePosixPath

INDEX = "application/vnd.oci.image.index.v1+json"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
CONFIG = "application/vnd.oci.image.config.v1+json"
IN_TOTO = "application/vnd.in-toto+json"
SLSA = "https://slsa.dev/provenance/v1"
BUILDKIT = "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md"
STORE = Path("artifacts/release-evidence/build-receipts")
SERVICES = {"yabanin": "core", "migrate": "core", "seed": "core",
            "mock-openai": "mock-provider", "dashboard": "dashboard"}
RECIPES = {"core": (".", "Dockerfile"), "dashboard": (".", "web/dashboard/Dockerfile"),
           "mock-provider": ("deploy/mock-provider", "deploy/mock-provider/Dockerfile")}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def only(matches, message):
    items = list(matches)
    require(len(items) == 1, message)
    return items[0]


def blob(root, role, digest, size=None):
    require(isinstance(digest, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", digest),
            "invalid OCI digest")
    path = root.resolve() / STORE / role / digest[7:]
    require(path.resolve() == path and path.is_file(), "missing regular receipt blob")
    actual_size = path.stat().st_size
    require(size is None or actual_size == size, "OCI descriptor size mismatch")
    data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == digest[7:], "OCI descriptor hash mismatch")
    return json.loads(data)


def descriptor(root, role, desc, media_type):
    descriptor_shape(desc)
    require(desc["mediaType"] == media_type, "unexpected OCI descriptor type")
    require(type(desc["size"]) is int and desc["size"] > 0, "invalid OCI descriptor size")
    return blob(root, role, desc["digest"], desc["size"])


def check_inline(desc):
    if "data" not in desc:
        return
    require(isinstance(desc["data"], str), "invalid inline descriptor data")
    raw = base64.b64decode(desc["data"], validate=True)
    require(len(raw) == desc["size"], "inline descriptor size mismatch")
    require("sha256:" + hashlib.sha256(raw).hexdigest() == desc["digest"],
            "inline descriptor digest mismatch")


def descriptor_shape(desc):
    require(isinstance(desc, dict) and isinstance(desc.get("mediaType"), str) and desc["mediaType"],
            "invalid OCI descriptor media type")
    require(isinstance(desc.get("digest"), str) and re.fullmatch(r"sha256:[0-9a-f]{64}", desc["digest"]),
            "invalid OCI descriptor digest")
    require(type(desc.get("size")) is int and desc["size"] >= 0, "invalid OCI descriptor size")
    check_inline(desc)


def image_manifest(root, role, desc):
    obj = descriptor(root, role, desc, MANIFEST)
    require(obj.get("schemaVersion") == 2 and obj.get("mediaType") == MANIFEST,
            "invalid OCI image manifest")
    descriptor_shape(obj.get("config"))
    require(isinstance(obj.get("layers"), list), "invalid OCI layer list")
    for layer in obj["layers"]:
        descriptor_shape(layer)
    return obj


def attestation_config(root, role, desc):
    if desc["mediaType"] == "application/vnd.oci.empty.v1+json":
        require(desc["size"] == 2 and desc["digest"] == "sha256:" + hashlib.sha256(b"{}").hexdigest(),
                "invalid OCI empty configuration")
    else:
        descriptor(root, role, desc, CONFIG)


def platform_name(record):
    return record.get("os", "") + "/" + record.get("architecture", "")


def platform_image(root, role, index, platform):
    require(index["mediaType"] == INDEX and index["schemaVersion"] == 2, "invalid OCI index")
    child = only((d for d in index["manifests"] if platform_name(d.get("platform", {})) == platform),
                 "ambiguous or absent platform")
    image = image_manifest(root, role, child)
    config = descriptor(root, role, image["config"], CONFIG)
    require(platform_name(config) == platform, "image configuration platform mismatch")
    return child


def attests(desc, digest):
    annotations = desc.get("annotations", {})
    return (annotations.get("vnd.docker.reference.type") == "attestation-manifest"
            and annotations.get("vnd.docker.reference.digest") == digest)


def statement(root, role, index, child):
    match = only((d for d in index["manifests"] if attests(d, child["digest"])),
                 "missing or ambiguous platform attestation")
    manifest = image_manifest(root, role, match)
    attestation_config(root, role, manifest["config"])
    descriptor_shape(manifest["subject"])
    require(all(manifest["subject"][k] == child[k] for k in ("digest", "size", "mediaType")),
            "OCI attestation subject mismatch")
    layer = only((d for d in manifest["layers"] if d.get("annotations", {}).get("in-toto.io/predicate-type") == SLSA),
                 "missing or ambiguous SLSA provenance")
    st = descriptor(root, role, layer, IN_TOTO)
    require(st["_type"] == "https://in-toto.io/Statement/v1" and st["predicateType"] == SLSA,
            "invalid in-toto statement type")
    subject = only(st["subject"], "missing or ambiguous in-toto subject")
    require(subject["digest"]["sha256"] == child["digest"][7:], "in-toto subject mismatch")
    return st["predicate"]


def source_path(directory):
    require(isinstance(directory, str) and directory, "invalid build source path")
    path = PurePosixPath(directory)
    require(not path.is_absolute() and ".." not in path.parts, "invalid build source path")
    return path


def check_source(predicate, head, context, recipe):
    build = predicate["buildDefinition"]
    request = build["externalParameters"]
    args = request["request"]["root"]["request"]["args"]
    vcs = predicate["runDetails"]["metadata"]["buildkit_metadata"]["vcs"]
    for fields, prefix in ((args, "vcs:"), (vcs, "")):
        require(fields[prefix + "revision"] == head, "different builder-recorded source revision")
        require(source_path(fields[prefix + "localdir:context"]) == PurePosixPath(context),
                "different build context")
        location = source_path(fields[prefix + "localdir:dockerfile"]) / source_path(request["configSource"]["path"])
        require(location == PurePosixPath(recipe), "different Dockerfile")


def check_image(root, role, image_id, platform, head, pins):
    context, recipe = RECIPES[role]
    index = blob(root, role, image_id)
    child = platform_image(root, role, index, platform)
    predicate = statement(root, role, index, child)
    build = predicate["buildDefinition"]
    require(build["buildType"] == BUILDKIT, "unexpected build type")
    require(build["internalParameters"]["targetPlatform"] == platform, "different build target platform")
    check_source(predicate, head, context, recipe)
    expected = {ref.split("@sha256:")[1] for name, ref in pins if name == recipe}
    observed = {d["digest"]["sha256"] for d in build["resolvedDependencies"] if d["uri"].startswith("pkg:docker/")}
    require(expected and observed == expected, "different pinned base images")


def matches_recipe(root, role, build):
    if isinstance(build, str):
        build = {"context": build}
    require(isinstance(build, dict) and set(build) <= {"context", "dockerfile"}, "unsupported build configuration")
    context = (root / "deploy/quickstart" / build["context"]).resolve()
    recipe = (context / build.get("dockerfile", "Dockerfile")).resolve()
    actual = (str(context.relative_to(root.resolve())), str(recipe.relative_to(root.resolve())))
    require(actual == RECIPES[role], "unexpected Compose context or Dockerfile")


def failures(root, entries, head, services, pins):
    problems = []
    built = {name for name, service in services.items() if service["build"]}
    if built != SERVICES.keys():
        problems.append("distribution: build receipt: unexpected Compose build service set")
    for name in sorted(built & SERVICES.keys()):
        try:
            matches_recipe(root, SERVICES[name], services[name]["build_config"])
        except (ValueError, TypeError, KeyError, OSError, RuntimeError) as error:
            problems.append(f"distribution: {name} build receipt: {error}")
    for row in entries:
        role = row["name"]
        try:
            check_image(root, role, row["image_id"], row["platform"], head, pins)
        except (ValueError, KeyError, AttributeError, TypeError, OSError, RuntimeError) as error:
            problems.append(f"distribution: {role} build receipt: {error}")
    return problems

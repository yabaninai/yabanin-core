#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Adapted from Yabanin's Apache-2.0 delivered-artifact verifier.
# Inspect the bytes that actually ship, not only the source tree.
#
# Stages:
#   npm-pack   — npm pack the SDK project, unpack the tarball and flag
#                secrets / .git / executables / oversized / unexpected
#                file classes against the allowlist.
#   image      — per --image/--profile pair: docker save the image, walk
#                every layer tar for .git dirs, credential-shaped files,
#                node_modules where the profile forbids it, package-manager
#                caches and embedded secret bytes; docker history
#                --no-trunc must not carry --secret / -e KEY=VALUE /
#                --build-arg VALUE style leaks.
#
# Exit codes: 0 = every requested stage ran clean; 1 = finding or stage
# operational error (fail-closed: a tool that IS present but errors is a
# failure, never a skip); 77 = no failure but at least one stage was
# honestly skipped because its tool is absent (reason recorded in the
# report and on stderr — never a silent pass); 2 = usage error.
#
# An optional adjacent scan_delivered_bytes.allow uses "scope kind path" rows
# (exact paths or a trailing /**). No exceptions ship by default. An entry
# matching no live finding is stale and fails the scan.
set -euo pipefail
cd "$(dirname "$0")/../.."

ALLOW_FILE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)/scan_delivered_bytes.allow"
[ -f "$ALLOW_FILE" ] || ALLOW_FILE=""

usage() {
  cat <<'EOF'
usage: scan_delivered_bytes.sh --out DIR
                    [--npm-pack PROJECT_DIR]
                    [--image REF --profile root|dashboard] ...
EOF
}

OUT=""
NPM_DIR=""
# One entry per image, "ref|profile" (refs contain ':' but never '|').
IMAGES=("")
NEXT_IMAGE=""

if ! command -v python3 >/dev/null 2>&1; then
  echo "FAIL: delivered-bytes: python3 is required and was not found" >&2
  exit 1
fi

while [ $# -gt 0 ]; do
  case "$1" in
    --out) OUT="${2:?--out needs a value}"; shift 2 ;;
    --npm-pack) NPM_DIR="${2:?--npm-pack needs a value}"; shift 2 ;;
    --image)
      if [ -n "$NEXT_IMAGE" ]; then usage >&2; exit 2; fi
      NEXT_IMAGE="${2:?--image needs a value}"
      shift 2
      ;;
    --profile)
      if [ -z "$NEXT_IMAGE" ]; then usage >&2; exit 2; fi
      case "${2:?--profile needs a value}" in
        root|dashboard) ;;
        *) echo "FAIL: unknown image profile: $2 (known: root, dashboard)" >&2; exit 2 ;;
      esac
      IMAGES+=("${NEXT_IMAGE}|$2")
      NEXT_IMAGE=""
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) echo "FAIL: unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done
if [ -n "$NEXT_IMAGE" ]; then usage >&2; exit 2; fi
if [ -z "$OUT" ] || { [ -z "$NPM_DIR" ] && [ "${#IMAGES[@]}" -eq 1 ]; }; then usage >&2; exit 2; fi
if [ -n "$NPM_DIR" ] && [ ! -d "$NPM_DIR" ]; then
  echo "FAIL: --npm-pack directory not found: $NPM_DIR" >&2
  exit 2
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/scan-delivered-bytes.XXXXXX")"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$OUT"
REPORT="$OUT/report.txt"
: >"$REPORT"

py_core() {
  # mode report-file allow-file [args...]; the core appends its lines to the
  # report file, echoes them to stdout and exits nonzero on findings.
  local mode=$1 report=$2 allow=$3
  shift 3
  python3 - "$mode" "$report" "$allow" "$@" <<'PY'
import hashlib
import io
import os
import re
import sys
import tarfile

mode, report_path, allow_path = sys.argv[1], sys.argv[2], sys.argv[3]
args = sys.argv[4:]

# Byte-level secret patterns (the same family as scripts/public-export-gate.sh
# and scripts/quality/secret_scan.py). Findings report the rule id only —
# never the matched bytes.
SECRET_PATTERNS = [
    ("openai-key", re.compile(rb"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("aws-access-key", re.compile(rb"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{30,}\b")),
    ("private-key-block", re.compile(rb"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("slack-token", re.compile(rb"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("yabanin-api-key", re.compile(rb"\byb_[A-Za-z0-9]{24,}\b")),
]

CRED_FILE_RE = re.compile(
    r"^(id_rsa|id_dsa|id_ecdsa|id_ed25519|\.npmrc|\.netrc|\.env|\.git-credentials"
    r"|kubeconfig|\.kube/config)$"
    r"|\.(pem|key|p12|pfx)$"
    r"|^(credentials|secrets?|token)(\.(json|ya?ml|txt))?$"
    r"|^service[-_]?account.+\.json$",
    re.IGNORECASE,
)
# Public trust stores ship hundreds of *.pem CA bundles (alpine: etc/ssl/,
# etc/ssl1.1/). They are public material, not credentials; everything named
# like a key OUTSIDE these exact prefixes is still a finding. /etc/ssl/private
# deliberately stays outside the carve-out.
PUBLIC_TRUST_PREFIXES = (
    "etc/ssl/certs/", "etc/ssl/cert.pem", "etc/ssl1.1/",
    "etc/pki/ca-trust/", "usr/share/ca-certificates/", "usr/lib/ssl/certs/",
    "etc/apk/keys/",
)
CRED_DIR_NAMES = {".ssh", ".aws", ".kube", ".docker", ".gnupg"}
CACHE_ROOTS = (
    "var/cache/apt/", "var/lib/apt/lists/", "var/cache/apk/",
    "var/cache/yum/", "var/cache/dnf/", "var/lib/dnf/",
    "root/.npm/", ".npm/",
    "root/.cache/pip/", ".cache/pip/",
    "root/.cache/yarn/", ".cache/yarn/", "usr/local/share/.cache/",
)
PROFILE_ALLOWS_NODE_MODULES = {"root": False, "dashboard": False}
SOURCEMAP_PREFIX = "usr/share/nginx/html/"
NPM_MAX_FILE_BYTES = 2 * 1024 * 1024
SECRET_CHUNK_BYTES = 1024 * 1024
NPM_ALLOWED_SUFFIXES = (".ts", ".js", ".json", ".md")
NPM_ALLOWED_ROOT_NAMES = ("package.json", "package-lock.json", "npm-shrinkwrap.json", "tsconfig.json")
NPM_ALLOWED_TOP_DIRS = ("src", "test")

HIST_SECRET_FLAG = re.compile(r"(^|\s)--secret($|[=\s])")
HIST_ENV_ASSIGN = re.compile(r"(^|\s)(-e|--env)\s+[A-Za-z_][A-Za-z0-9_]*=\S+")
HIST_BUILDARG = re.compile(r"(^|\s)--build-arg\s+\w+=\S+")
HIST_ASSIGN = re.compile(r"(^|[\s;&])([A-Z][A-Z0-9_]{2,})=(\$?)(\S*)")
CRED_NAME_RE = re.compile(
    r"^[A-Z][A-Z0-9_]*(KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*$")


class Findings:
    def __init__(self, allow_path, scopes):
        self.scopes = scopes
        self.allow_path = allow_path
        self.raw = []
        self.info = []
        self.entries = self._load_allow()

    def _load_allow(self):
        entries = []
        if not allow_path or not os.path.isfile(allow_path):
            return entries
        for number, line in enumerate(open(allow_path, encoding="utf-8"), 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parts = stripped.split(None, 2)
            if len(parts) != 3:
                self.raw.append(("parse", "malformed-entry",
                                 f"{allow_path}:{number}", "expected 'scope kind path'"))
            else:
                entries.append({"scope": parts[0], "kind": parts[1],
                                "path": parts[2], "seen": False,
                                "where": f"{allow_path}:{number}"})
        return entries

    def add(self, scope, kind, path, detail=""):
        self.raw.append((scope, kind, path, detail))

    def _matches(self, entry, scope, kind, path):
        if entry["scope"] != scope or entry["kind"] != kind:
            return False
        allowed = entry["path"]
        if allowed.endswith("/**"):
            return path.startswith(allowed[:-2])
        return allowed == path

    def resolve(self):
        lines = [f"INFO\t{line}" for line in self.info]
        failed = False
        for scope, kind, path, detail in self.raw:
            hit = next((e for e in self.entries if self._matches(e, scope, kind, path)), None)
            if hit is not None:
                hit["seen"] = True
                lines.append(f"ALLOWED\t{scope}\t{kind}\t{path}\t{detail}".rstrip("\t"))
                continue
            lines.append(f"FAIL\t{scope}\t{kind}\t{path}\t{detail}".rstrip("\t"))
            failed = True
        for entry in self.entries:
            # Stale-drift is evaluated per scope: an entry belongs to exactly
            # one stage invocation and other invocations must ignore it.
            if entry["scope"] not in self.scopes:
                continue
            if not entry["seen"]:
                lines.append(f"FAIL\t{entry['scope']}\tstale-allow\t{entry['path']}\t"
                             f"{entry['where']} matched no finding (drift)")
                failed = True
        return lines, failed


def secret_hits(data):
    for name, rx in SECRET_PATTERNS:
        for m in rx.finditer(data):
            line = data.count(b"\n", 0, m.start()) + 1
            yield name, line


def stream_secret_hits(stream):
    """Inspect large binary/text payloads too; overlap retains token boundaries."""
    tail = b""
    offset = 0
    lines_before = 0
    seen = set()
    while True:
        chunk = stream.read(SECRET_CHUNK_BYTES)
        if not chunk:
            return
        data = tail + chunk
        start = offset - len(tail)
        for rule, rx in SECRET_PATTERNS:
            for match in rx.finditer(data):
                location = (rule, start + match.start())
                if location not in seen:
                    seen.add(location)
                    yield rule, lines_before + data.count(b"\n", 0, match.start()) + 1
        keep = min(256, len(data))
        lines_before += data[:-keep].count(b"\n")
        tail = data[-keep:]
        offset += len(chunk)


def redact(text):
    """History lines are evidence AND a leak surface: strip secret-shaped
    bytes and any NAME=VALUE assignment with a credential-shaped name (or a
    -e/--env/--build-arg form) before the line reaches the report."""
    scrubbed = text
    for rx, replacement in (
        (re.compile(r"(?i)\b([A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*)=\S+"), r"\1=<redacted>"),
        (re.compile(r"(?i)(--build-arg\s+\w+)=\S+"), r"\1=<redacted>"),
        (re.compile(r"(?i)((?:-e|--env)\s+\w+)=\S+"), r"\1=<redacted>"),
    ):
        scrubbed = rx.sub(replacement, scrubbed)
    redacted = scrubbed.encode("utf-8", "replace")
    for _, rx in SECRET_PATTERNS:
        redacted = rx.sub(b"<redacted>", redacted)
    return redacted.decode("utf-8", "replace")


def scan_npm_tarball(tarball):
    findings = Findings(allow_path, {"npm"})
    digest = hashlib.sha256(open(tarball, "rb").read()).hexdigest()
    findings.info.append(f"npm\ttarball={os.path.basename(tarball)} sha256={digest}")
    files = 0
    with tarfile.open(tarball, "r:*") as tf:
        # Snapshot the header list first: seeking via extractfile() during
        # TarFile iteration replays members (duplicated findings).
        for member in tf.getmembers():
            rel = member.name
            if rel.startswith("package/"):
                rel = rel[len("package/"):]
            if not rel or rel == "package":
                continue
            parts = rel.split("/")
            if ".git" in parts:
                findings.add("npm", "git-dir", rel)
            if member.isdir():
                if len(parts) > 1 and parts[0] not in NPM_ALLOWED_TOP_DIRS:
                    findings.add("npm", "unexpected-class", rel, "directory")
                continue
            if not member.isfile():
                findings.add("npm", "unexpected-class", rel, "non-regular entry")
                continue
            files += 1
            base = parts[-1]
            top = parts[0] if len(parts) > 1 else ""
            allowed_class = (
                top in NPM_ALLOWED_TOP_DIRS
                or base in NPM_ALLOWED_ROOT_NAMES
                or base.startswith(("LICENSE", "LICENCE", "NOTICE", "README"))
                or base.endswith(NPM_ALLOWED_SUFFIXES)
            )
            if not allowed_class:
                findings.add("npm", "unexpected-class", rel, "file class not deliverable")
            if member.mode & 0o111:
                findings.add("npm", "executable", rel, f"mode={oct(member.mode)}")
            if member.size > NPM_MAX_FILE_BYTES:
                findings.add("npm", "oversized", rel, f"{member.size} bytes")
            data = tf.extractfile(member).read()
            for rule, line in secret_hits(data):
                findings.add("npm", "secret-content", f"{rel}:{line}", f"rule={rule}")
    if files == 0:
        findings.add("npm", "empty-artifact", tarball, "no regular files packed")
    findings.info.append(f"npm\tfiles={files} max-file-bytes={NPM_MAX_FILE_BYTES}")
    return findings


def iter_layers(saved_tar):
    """Yield (layer-name, tarfile) for every member of the saved archive that
    is itself a tar (docker-archive layer dirs and OCI blobs alike)."""
    with tarfile.open(saved_tar, "r:*") as outer:
        for member in outer:
            if not member.isfile():
                continue
            blob = outer.extractfile(member)
            if blob is None:
                continue
            data = blob.read()
            try:
                layer = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
            except tarfile.TarError:
                continue
            yield member.name, layer


def scan_image(saved_tar, history_path, profile):
    scope = f"image:{profile}"
    findings = Findings(allow_path, {scope})
    allow_node_modules = PROFILE_ALLOWS_NODE_MODULES.get(profile)
    if allow_node_modules is None:
        findings.add(scope, "unknown-profile", profile, "no scanner profile defined")
        return findings
    layers = 0
    members = 0
    for layer_name, layer in iter_layers(saved_tar):
        layers += 1
        # Snapshot first: extractfile() seeks and would corrupt iteration.
        for member in layer.getmembers():
            path = member.name
            if path.startswith("./"):
                path = path[2:]
            path = path.lstrip("/")
            if not path:
                continue
            members += 1
            parts = path.split("/")
            if ".git" in parts:
                findings.add(scope, "git-dir", f"{layer_name}:{path}")
            if member.isdir():
                if parts[-1] in CRED_DIR_NAMES:
                    findings.add(scope, "credential-dir", f"{layer_name}:{path}")
                continue
            if member.issym():
                # Symlinks do not carry bytes; their names still leak shape.
                if CRED_FILE_RE.match(parts[-1]) and not path.startswith(PUBLIC_TRUST_PREFIXES):
                    findings.add(scope, "credential-file", f"{layer_name}:{path}", "symlink")
                continue
            if not member.isfile() and not member.islnk():
                continue
            if "node_modules" in parts and not allow_node_modules:
                findings.add(scope, "node_modules", f"{layer_name}:{path}")
            if CRED_FILE_RE.match(parts[-1]) and not path.startswith(PUBLIC_TRUST_PREFIXES):
                findings.add(scope, "credential-file", f"{layer_name}:{path}")
            if path.startswith(CACHE_ROOTS):
                findings.add(scope, "build-cache", f"{layer_name}:{path}")
            if path.startswith(SOURCEMAP_PREFIX) and path.endswith(".map"):
                findings.add(scope, "sourcemap", f"{layer_name}:{path}")
            if member.isfile():
                for rule, line in stream_secret_hits(layer.extractfile(member)):
                    findings.add(scope, "secret-content",
                                 f"{layer_name}:{path}:{line}", f"rule={rule}")
    if layers == 0:
        findings.add(scope, "no-layers", saved_tar, "docker save produced no scannable layers")
    findings.info.append(f"{scope}\tlayers={layers} entries={members}")
    with open(history_path, encoding="utf-8", errors="replace") as handle:
        for number, line in enumerate(handle, 1):
            line = line.rstrip("\n")
            if not line:
                continue
            detail = redact(line)[:160]
            if HIST_SECRET_FLAG.search(line):
                findings.add(scope, "history-secret-flag", f"history:{number}", detail)
            if HIST_ENV_ASSIGN.search(line):
                findings.add(scope, "history-env-value", f"history:{number}", detail)
            if HIST_BUILDARG.search(line):
                findings.add(scope, "history-buildarg-value", f"history:{number}", detail)
            for match in HIST_ASSIGN.finditer(line):
                name, dollar, value = match.group(2), match.group(3), match.group(4)
                if CRED_NAME_RE.match(name) and value and not dollar:
                    findings.add(scope, "history-credential-value",
                                 f"history:{number}", f"{name}=… redacted")
                    break
            for rule, _ in secret_hits(line.encode()):
                findings.add(scope, "history-secret-content", f"history:{number}", f"rule={rule}")
    return findings


if mode == "scan-npm":
    tarball = args[0]
    if not os.path.isfile(tarball):
        print(f"FAIL\tnpm\tpack-output\t{tarball}\tnpm pack reported no tarball", file=sys.stderr)
        sys.exit(1)
    result = scan_npm_tarball(tarball)
elif mode == "scan-image":
    saved_tar, history_path, profile = args[0], args[1], args[2]
    result = scan_image(saved_tar, history_path, profile)
else:
    print(f"FAIL\tinternal\tunknown-mode\t{mode}", file=sys.stderr)
    sys.exit(1)

lines, failed = result.resolve()
with open(report_path, "a", encoding="utf-8") as handle:
    for line in lines:
        handle.write(line + "\n")
for line in lines:
    print(line)
sys.exit(1 if failed else 0)
PY
}

fails=0
skips=0

emit() { printf '%s\n' "$1" | tee -a "$REPORT" >&2; }

if [ -n "$NPM_DIR" ]; then
  if ! command -v npm >/dev/null 2>&1; then
    emit "SKIP	npm-pack	npm not found on PATH; tarball bytes not scanned"
    skips=$((skips + 1))
  else
    echo "== delivered-bytes: npm pack $NPM_DIR"
    if ( cd "$NPM_DIR" && npm pack --ignore-scripts --json --pack-destination "$TMP" ) \
        >"$TMP/npm-pack.json" 2>"$OUT/npm-pack.stderr"; then
      tarball="$(python3 - "$TMP/npm-pack.json" "$TMP" <<'PY'
import json, os, sys
try:
    payload = json.load(open(sys.argv[1], encoding="utf-8"))
    name = os.path.basename(payload[0]["filename"])
except Exception as error:  # noqa: BLE001 - any parse failure is a gate failure
    print(f"FAIL: delivered-bytes: cannot parse npm pack output: {error}", file=sys.stderr)
    sys.exit(1)
path = os.path.join(sys.argv[2], name)
if not os.path.isfile(path):
    print(f"FAIL: delivered-bytes: npm pack tarball missing: {path}", file=sys.stderr)
    sys.exit(1)
print(path)
PY
)"
      if ! py_core scan-npm "$REPORT" "$ALLOW_FILE" "$tarball"; then
        fails=1
      fi
    else
      emit "FAIL	npm-pack	npm pack exited nonzero; see npm-pack.stderr"
      fails=1
    fi
  fi
fi

docker_ok=0
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
  docker_ok=1
fi

index=0
for entry in "${IMAGES[@]}"; do
  [ -n "$entry" ] || continue
  index=$((index + 1))
  ref="${entry%%|*}"
  profile="${entry##*|}"
  if [ "$docker_ok" != 1 ]; then
    emit "SKIP	image:$profile ($ref)	docker or its daemon unavailable; layers/history not scanned"
    skips=$((skips + 1))
    continue
  fi
  echo "== delivered-bytes: image $ref (profile $profile)"
  if ! docker history --no-trunc --format '{{.CreatedBy}}' "$ref" \
      >"$TMP/history-$index.txt" 2>"$OUT/history-$profile.stderr"; then
    emit "FAIL	image:$profile	docker history failed for $ref; see history-$profile.stderr"
    fails=1
    continue
  fi
  if ! docker save -o "$TMP/image-$index.tar" "$ref" 2>"$OUT/save-$profile.stderr"; then
    emit "FAIL	image:$profile	docker save failed for $ref; see save-$profile.stderr"
    fails=1
    continue
  fi
  if ! py_core scan-image "$REPORT" "$ALLOW_FILE" "$TMP/image-$index.tar" \
      "$TMP/history-$index.txt" "$profile"; then
    fails=1
  fi
done

if [ "$fails" -eq 1 ]; then
  echo "FAIL: delivered-bytes scan; report=$REPORT" >&2
  exit 1
fi
if [ "$skips" -gt 0 ]; then
  echo "SKIP: delivered-bytes scan incomplete: $skips stage(s) skipped (tool absent); report=$REPORT" >&2
  exit 77
fi
echo "delivered-bytes scan: clean; report=$REPORT"
exit 0

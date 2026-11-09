# Author a guard detector pack

A guard pack is a manifest plus declarative regular-expression detectors loaded
by `pkg/guardhooks`. It does not add Go code or a pipeline step. The public core
supports user-authored packs and signature verification; pack verification is
not a purchase or entitlement check. Distribution of your pack still requires
appropriate rights to its contents.

## Create a synthetic pack

The current loader expects exactly one `detector.json` payload per manifest.
The directory layout is:

```text
PACK_ROOT/
  example.marker/
    manifest.json
    detector.json
```

Use Python 3 to create a local example and compute the digest of the exact
payload bytes. Run this from a shell; the temporary path is retained in
`PACK_ROOT`:

```bash
PACK_ROOT="$(mktemp -d)"
python3 - "$PACK_ROOT" <<'PYTHON'
import hashlib
import json
import sys
from pathlib import Path

pack = Path(sys.argv[1]) / "example.marker"
pack.mkdir()
detector = {"detectors": [{
    "rule_id": "demo-marker",
    "rule_version": "1",
    "category": "secret",
    "pattern": "SYNTHETIC_MARKER_[A-Z]+",
}]}
payload = (json.dumps(detector, indent=2) + "\n").encode()
(pack / "detector.json").write_bytes(payload)
manifest = {
    "schema_version": "guardpacks.v1",
    "pack_id": "example.marker",
    "pack_version": "0.1.0",
    "runtime_api": "guardrails.v1",
    "files": [{"path": "detector.json", "sha256": hashlib.sha256(payload).hexdigest()}],
}
(pack / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(pack)
PYTHON
```

This command only writes example files; it does not activate a guard. The
pattern matches `SYNTHETIC_MARKER_TEST` and should not match `ordinary text`.
It is a demonstration marker, not a useful production secret detector.

The data shapes are `PackManifest` in `pkg/guardhooks/pack.go` and
`DetectorPackFile` / `RegexDetectorSpec` in `pkg/guardhooks/lifecycle.go`.
Each detector has a rule ID, rule version, category, and a pattern
using Go regular-expression syntax. Test realistic positive, negative, and
boundary inputs before relying on a detector's decisions.

## Verify and stage before activation

`LoadDetectorPack` verifies an unsigned pack and compiles its detectors;
`LoadDetectorPackWithVerifier` additionally accepts the configured signature
verifier. `PackLifecycle.Stage` keeps a candidate separate from the active
hook. Successful staging is not activation.

The loader checks schema/runtime versions, identity, file digests, supported
payload shape, detector definitions, and regular-expression compilation. Current
limits include a 1 MiB manifest, a 4 MiB detector file, and 256 detectors per
pack. Path checks constrain reads to the resolved pack root. After changing a
payload, regenerate its digest; a stale digest must fail verification.

An operator configures the local pack root through `YABANIN_GUARD_PACK_DIR`.
`YABANIN_GUARD_ACTIVE_PACKS` supplies startup pack IDs. The guard behavior is
controlled separately by `YABANIN_GUARD_MODE` (`off`, `log`, `redact`, or `deny`).
Copy or mount the pack into the operator-configured paths for the processes
that need to load it; the gateway does not download the example from your
shell's temporary directory. The standard quickstart does not configure these
pack mounts or the lifecycle for you.

In gateway startup wiring, a configured root with no active pack IDs is an
error. An inaccessible root, or a path that is not a directory, instead logs a
warning and retains the built-in hooks. An existing root containing a broken
requested pack fails startup. Inspect logs and effective runtime state; a
healthy gateway alone does not prove that the intended pack loaded.
`YABANIN_GUARD_PACK_MODE=shadow` overrides the pack's startup behavior to log
mode; empty uses the configured guard mode, and other values are rejected.

## Admin lifecycle API

The admin routes require root-admin authorization and the configured lifecycle.
They are not gateway bearer-key endpoints. An unwired lifecycle returns **503**.
Use the admin UI or the deployment's authenticated admin API flow, including
its session and CSRF requirements; do not substitute a gateway API key.

| Route | Purpose |
| --- | --- |
| `GET /api/guard-packs` | Discover packs under the configured local root |
| `GET /api/guard-packs/status` | Inspect durable and runtime state |
| `POST /api/guard-packs/validate` | Validate the requested pack |
| `POST /api/guard-packs/simulate` | Evaluate sample text without activation |
| `POST /api/guard-packs/activate` | Stage and activate a pack through the durable policy store |
| `POST /api/guard-packs/rollback` | Attempt to restore the previous active version |

Validation and activation identify the pack with **`pack_id`**, not `id`:

```json
{"pack_id":"example.marker","version":"0.1.0"}
```

A simulation request additionally supplies `sample`:

```json
{"pack_id":"example.marker","version":"0.1.0","sample":"SYNTHETIC_MARKER_TEST"}
```

These are request bodies, not an unauthenticated activation recipe. The
requested ID/version must match the manifest on disk. See
`services/admin/handlers/guardpacks.go` and `guardpacks_read.go` for the current
response and validation contract.

Activation uses a compare-and-swap operation in the durable policy store before
publishing the local active state. Concurrent changes can return **409**;
inspect current status rather than blindly retrying. A policy-store failure
must not be treated as successful activation. Across processes, inspect runtime
status and logs as well as durable state; a committed version alone does not
prove every replica has loaded its files.

Rollback is conditional: it needs a restorable prior state, pack contents where
required, and a successful durable update. It can fail when the previous pack
is unavailable, when no prior version exists, or when a concurrent activation
wins. Preserve the previous artifacts and test restoration before rollout.
Removing an environment variable is not a general substitute for updating
already-persisted active state.

## Signatures and detection limits

Unsigned local packs are accepted even when verifier keys are configured.
Configuring keys does **not** enforce a signed-only pack policy. A manifest
that declares a signature must pass verification; without a verifier it is
rejected, and an unsupported scheme or algorithm is also rejected.

The supported envelope uses `guardpack-sig.v1` and Ed25519 over the canonical
pack payload. Trusted keys come from `YABANIN_GUARD_PACK_VERIFY_KEYS_DIR` or
`YABANIN_GUARD_PACK_VERIFY_KEYS` (`key-id=base64` entries). Read
`pkg/guardhooks/packsign.go` for key parsing and canonical verification rather
than signing a differently serialized manifest by guesswork.

Checksums alone do not authenticate an author. A valid signature associates
the payload with a trusted key; it does not prove detector effectiveness,
policy suitability, or complete coverage. The current declarative loader
compiles regex data and does not execute arbitrary pack code. It still adds
per-request work and can cause false positives or missed detections. Validate
those effects in log/shadow scenarios before enabling blocking or redaction.

See [extension boundaries](README.md), [policy steps](pipeline-steps.md), and
[offline evaluation](../evaluation.md). The built-in `yb evaluate guards`
workflow is not automatically an evaluation of your newly authored pack;
exercise the pack-specific loader/simulation path as well.

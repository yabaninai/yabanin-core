# Entitlement verification fixtures

Offline-verifiable state corpus for `VerifyPaidModuleEntitlement`
(`pkg/license/module_entitlement.go`) and activation grace behavior
(`pkg/license/license.go`). Executable expectations are in
`pkg/license/entitlement_verify_test.go` and `pkg/license/offline_proof_test.go`.

## Corpus law

- Corpus files are UNSIGNED state definitions (the `PaidModuleEntitlement`
  payload JSON / activation `Claims` JSON). The test issues and signs each
  one at runtime with a RUNTIME-GENERATED Ed25519 keypair: no private key
  material exists in the tree, and the public key is a verify-time
  parameter (the parameterized surfaces — chain plane is keyed by config).
- Absolute dates are pinned to a fixed anchor `2026-11-08T00:00:00Z`.
  State predicates are asserted relative to that anchor. The activation
  grace member additionally derives its window relative to the REAL clock
  (the grace law is a 7-day DURATION, `license.go:35`), so the file
  documents the shape and offsets, not a wall-date promise.
- Adding a state = adding a file + a want-row in
  `entitlement_verify_test.go`. Every file must remain issuable through
  the test-only `fixturePaidModuleEntitlement` helper (except the deliberate version-skew vector,
  which is manually signed precisely because the fixture helper refuses v1).

## Members

| File | Plane | State at anchor | Pins |
| --- | --- | --- | --- |
| `valid.json` | entitlement | maintenance running | verify grants; `UpdatesEntitledAt`=true; `MaintenanceEndedAt`=false; run right both modules; no critical lines ⇒ `CriticalFixEntitledAt` fails closed for any line |
| `grace_activation.json` | activation | 3d past `expires_at`, inside 7d grace | `StateFromClaims`: `Expired`∧`Active`, not `HardExpired`; grace is activation-plane ONLY (entitlement path has no clock) |
| `maintenance_ended.json` | entitlement | 30d past `MaintenanceEnd` | verify STILL passes (no clock input — perpetual run right); `MaintenanceEndedAt`=true; `UpdatesEntitledAt`=false; `HasModule` survives |
| `updates_unentitled_trial.json` | entitlement | maintenance ended, trial active | updates stay unentitled while `TrialActiveAt`=true (trial is observational, never restores rights); trial inactive past `TrialEnd` |
| `critical_only.json` | entitlement | maintenance ended, supported line | Critical-fix exception: `CriticalFixEntitledAt("2026.1")`=true while `UpdatesEntitledAt`=false; ended-support line, flag-off line and unknown line all fail closed |
| `version_skew_v1.json` | entitlement | v1 legacy document (hard `expiry`) | v2 verifier fails closed on `unsupported version` (never half-accepts); test-only fixture helper refuses to produce v1 — the vector is manually signed |

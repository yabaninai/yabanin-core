# Offline license verification: formats and trust boundaries

The repository contains distinct verification mechanisms. They are not
interchangeable and do not themselves define the project's licensing terms.
This page describes the implementation boundaries relevant to deployment; it does not grant or restrict rights.

## Format map

| Mechanism | Input | Trust/configuration | Relevant implementation |
| --- | --- | --- | --- |
| JSON certificate chain | Token JSON plus intermediate certificate JSON | Explicit root public key, optional CRL | `pkg/license/pki.go`, `verify.go`, `cli.go` |
| Activation token | `base64url(payload).base64url(signature)` | Embedded `VendorPublicKey` | `pkg/license/license.go`, `server.go` |

[Customer setup](customer-setup.md) describes the **JSON-chain** path. Do not send an activation token to `yabanin license verify`
or apply its grace period to JSON-chain verification.

## JSON-chain verification

The intended hierarchy is:

```text
Root Ed25519 signing key
  -> intermediate certificate and private signing key
     -> customer token JSON

Verifier inputs:
  trusted root public key + intermediate certificate + customer token
  + optional local CRL of revoked intermediate serials
```

The verifier performs local file reads and Ed25519 checks; it does not need a
phone-home call. Its effective trust boundary includes the binary, the supplied
root key, all installed files, local clock and configuration access.

`VerifyLicenseChain` parses and length-checks the supplied root key, parses the
token, rejects expired tokens, loads the intermediate, checks its expiry and root
signature, checks a configured CRL, then verifies the token signature. The CLI
accepts an explicit `--intermediate-cert`; otherwise the environment variable
`YABANIN_LICENSE_INTERMEDIATE_CERT` is used, followed by the relative default
`deploy/license/intermediate.json`.

The current admin runner invokes this chain at startup when the license-file/root
configuration is present. This is not a continuous CRL refresh or universal
request authorization mechanism. The unified direct service-dispatch path does
not invoke the Cobra license hook for every service, and the gateway runner does
not perform the same JSON-chain startup check. Verify your actual service wiring.

## Wire format and signed fields

The verifier accepts these file formats:

| File | JSON fields | Encoding |
| --- | --- | --- |
| Intermediate certificate | `v`, `s`, `pub`, `root_sig`, `e`, `i` | Byte arrays use JSON base64; times use RFC3339 |
| Customer token | `v`, `c`, `e`, `s`, `i`, `intermediate_id`, `sig` | Signature uses JSON base64; times use RFC3339 |
| CRL | `revoked_serials`, `updated_at` | Plain JSON |

The current intermediate signature covers **version, serial and public-key bytes**.
It does **not** cover the certificate's expiry or issuance time. Although the
verifier checks the supplied expiry against the clock, that value is not
cryptographically bound by the root signature.

The customer-token signature covers **version, customer identifier, token serial,
expiry and intermediate identifier**. It does not cover the token's issuance time.
Verification constructs these payloads in `pkg/license/pki.go`; do not
assume the signature covers the complete serialized JSON object.

Additional verification limits:

- The chain verifier does not compare `intermediate_id` with the loaded
  certificate's serial. The issuer must supply a matching bundle and verify its
  identifiers against the delivery record.
- The customer identifier is a signed claim but is not compared by this verifier
  with an expected local organization, host or installation identity. This is not
  cryptographic prevention of copying a token to another deployment.
- Expiry checking depends on the local clock. There is no JSON-chain grace period.
- A successful result does not authenticate the binary or protect it from
  modification by someone controlling the host.

These are implementation limits to account for, not instructions to bypass
verification. File integrity, authenticated distribution and deployment controls
remain necessary; do not advertise stronger signature coverage or binding.

## Revocation boundary

The CRL lists **intermediate certificate serials**, not individual customer-token
serials. Revoking an intermediate affects tokens verified through that certificate.
A configured unreadable/malformed CRL fails verification. Omitting its path skips
revocation checking entirely.

The CRL has **no signature, authenticated sequence or enforced freshness check**.
`updated_at` is informational to the verifier. Replacing it with an older valid
list can remove knowledge of a revocation. Maintain an authoritative list,
authenticate delivery, retain prior entries and protect the installed file from
unauthorized modification. JSON-chain startup verification does not fetch updates;
reverify/restart the applicable process after installing a new bundle.

## Activation-token boundary

The separate activation format signs a base64url JSON payload containing
`org_id`, `seats`, `features`, `expires_at`, `issued_at` and `nonce`, using the
embedded `VendorPublicKey`. `seats` is legacy metadata, not a core account-count
limit. Its state machinery includes a seven-day expiry grace concept, and the
optional `license.Server` rereads/reverifies its token hourly when instantiated.
Those behaviors do not apply to JSON-chain tokens or establish where that server
is mounted in a particular deployment.

The embedded public key is a build-time trust input. Confirm the key in the
binary you deploy. Embedding a key does not protect against binary replacement
or replace release-signature verification.

## Operational acceptance

For a new JSON-chain bundle, verify the received signed files with the intended
root and explicit certificate path. Test a wrong root, modified signed token
field, missing certificate, expired token and revoked intermediate using disposable
fixtures. Record the binary/source identity and exit statuses without logging private keys.

Then verify the applicable service's startup behavior using its actual mounted
files and environment. Check both the token signature and how the deployed service handles missing,
invalid, and expired tokens. Verify the release signature separately.

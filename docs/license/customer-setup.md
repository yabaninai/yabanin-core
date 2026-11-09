# Installing a JSON-chain license bundle

This page applies when your deployment explicitly uses the **JSON certificate-chain
verification path**. It is separate from activation tokens;
see [PKI architecture](pki-architecture.md). It does not change the terms of the
public core or imply that every core installation requires a token.

## Required files

Obtain these through an authenticated delivery channel:

| Artifact | Purpose |
| --- | --- |
| Customer token JSON | Signed customer/serial/expiry claims, provided in the authenticated bundle |
| Intermediate certificate JSON | Required signing certificate, provided in the authenticated bundle |
| Trusted root public key | Exactly 64 hexadecimal characters; confirm its provenance independently |
| Current CRL, if used | Revoked intermediate serials; protect its authenticity and freshness operationally |

The intermediate certificate is **required**, not optional. A root public key
embedded in a binary is not automatically used by this JSON-chain path: its CLI
and startup verifier take an explicit root public key. Never request or install
the root/intermediate private signing seed.

Use the actual JSON token and certificate files, not a human-readable summary. A two-part
`base64url-payload.base64url-signature` string is the separate activation format and
will not parse as a JSON-chain token.

## 1. Place the files

Choose an operator-managed directory readable by the account running the service.
For a direct process under your current account, an example is:

```bash
set -euo pipefail
umask 077
LICENSE_DIR="$HOME/.config/yabanin/license"
mkdir -p "$LICENSE_DIR"
chmod 700 "$LICENSE_DIR"
# Source files below are the authenticated bundle received from the issuer.
cp acme-corp.json "$LICENSE_DIR/token.json"
cp intermediate.cert "$LICENSE_DIR/intermediate.json"
cp root.pub "$LICENSE_DIR/root.pub"
chmod 600 "$LICENSE_DIR/token.json" "$LICENSE_DIR/intermediate.json" "$LICENSE_DIR/root.pub"
```

For systemd or containers, use a service-owned path and permissions appropriate to
the service UID rather than assuming it can traverse your home directory. Mount
only the distributable files read-only. Public keys/certificates are not signing
secrets, but unauthorized replacement changes trust. Tokens can expose customer
identity and should not be committed to source or pasted into tickets.

If revocation checking is required, install the current CRL as
`$LICENSE_DIR/crl.json` with the same ownership/access protections. Do not configure
a CRL path for a file that has not been delivered and installed.

## 2. Verify before changing the running service

Using a current unified `yabanin` binary:

```bash
ROOT_PUBLIC_KEY=$(cat "$LICENSE_DIR/root.pub")
./yabanin license verify \
  --license-file="$LICENSE_DIR/token.json" \
  --root-pubkey="$ROOT_PUBLIC_KEY" \
  --intermediate-cert="$LICENSE_DIR/intermediate.json"
```

Add `--crl-file="$LICENSE_DIR/crl.json"` when checking revocations. Success is exit
0 and `LICENSE VALID`; retain the exit status and artifact identities, not signing
material. Check the token's `c` customer claim and certificate/token identifiers
against the delivery record yourself. The verifier does not compare the customer
claim with your database organization or machine identity.

The check is offline and evaluates the local clock and installed files. It does
not fetch a newer CRL, prove release authenticity, or establish that the token is
being enforced on every request path.

## 3. Configure the applicable service

For direct admin startup, alongside its normal database/session configuration:

```bash
export YABANIN_LICENSE_FILE="$LICENSE_DIR/token.json"
export YABANIN_LICENSE_ROOT_PUBKEY="$ROOT_PUBLIC_KEY"
export YABANIN_LICENSE_INTERMEDIATE_CERT="$LICENSE_DIR/intermediate.json"
# Set only when the file exists and revocation checking is intended:
# export YABANIN_LICENSE_CRL_FILE="$LICENSE_DIR/crl.json"
./yabanin admin
```

The admin runner checks this JSON chain at startup. If either
`YABANIN_LICENSE_FILE` or `YABANIN_LICENSE_ROOT_PUBKEY` is supplied, both must be
supplied and valid. With neither set, this particular startup check is inactive.
The explicit intermediate path avoids the working-directory-dependent fallback
`deploy/license/intermediate.json`.

For a systemd deployment, put the same literal values into its protected
`EnvironmentFile` or unit configuration, using paths readable by the service user;
shell expressions such as `$(cat ...)` are not expanded in an `Environment=` entry.
Reload the unit if it changed and restart the actual affected service. For a
container deployment, pass the variables and mount the directory read-only at the
container paths referenced by those variables. Host paths are not automatically
available inside the container.

Do not infer gateway enforcement from admin startup success. The current unified
service dispatch does not apply the Cobra license pre-run hook to every service,
and the gateway runner does not perform this same JSON-chain startup verification.
Evaluate the exact deployment path you use; this guide does not promise a universal
service-start or request-time license gate.

## Expiry, renewal and revocation

**The JSON-chain verifier has no seven-day grace period.** It rejects a token after
its expiry and also rejects an expired intermediate. The separate activation-token
state machine has a grace concept; it does not extend this verifier's validity.
Check the full RFC3339 expiry in the received token, including its time zone.

Before renewal, verify the replacement token, matching intermediate and intended
CRL in a staging directory. Keep the trusted root unchanged unless an authenticated
root-rotation process requires a change. Install the reviewed bundle consistently,
then restart/reverify the applicable service. Replacing a file alone is not a
promise of immediate re-evaluation: the JSON-chain admin check runs at startup.

A CRL lists intermediate serials and can invalidate multiple customer tokens.
It is unsigned in the current format, and its `updated_at` field has no enforced
freshness policy. Protect distribution, retain prior revocations and prevent
rollback to an older list. If no CRL is configured, no revocation check occurs.
A configured missing or malformed CRL fails verification.

## Troubleshooting

| Symptom | Investigation |
| --- | --- |
| Token JSON does not parse | Confirm this is the saved JSON token, not activation text or a human-readable summary |
| Cannot load intermediate | Supply the installed `.cert` JSON through the flag/environment variable |
| Signature invalid | Check the authenticated root, certificate and token as one bundle |
| Root key length/hex error | Use the complete 64-character public key without extra whitespace |
| Token/intermediate expired | Check both UTC expiries and system time; request the appropriate replacement |
| CRL error or revoked serial | Verify the current authoritative CRL and obtain a replacement bundle if revoked |
| Admin refuses startup | Inspect its first error and complete license configuration; also check ordinary service prerequisites |
| CLI valid but service disagrees | Compare binary version, effective environment, mount paths, clock and actual files |

For the exact signed-field and deployment limitations, see
[PKI architecture](pki-architecture.md). A successful verification is evidence about
these files under this verifier, not a statement of licensing terms or
complete deployment security.

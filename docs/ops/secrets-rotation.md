# Secrets rotation runbook

Rotate each secret according to what it protects and which processes read
it. Credential encryption, session signing, resolver-cache authentication
and license signing are separate systems; replacing one does not rotate the
others. Record the current deployment configuration and a recovery plan
before changing persistent key material.

This runbook describes the current source contracts. It does not promise
zero downtime: a single replica must stop to reload startup configuration,
and mixed key versions can make otherwise healthy replicas unable to serve
requests. Test a staged rollout against representative encrypted data first.

## Identify the secret and its consumers

| Secret | Configuration or storage | Purpose and format |
|---|---|---|
| Database credential | Service database URI / deployment secret | PostgreSQL authentication; update every service using the role |
| Admin session signing secret | `YABANIN_ADMIN_SESSION_SECRET`, falling back to `YABANIN_SESSION_KEY` | HMAC session signing; use a strong random secret accepted by the admin configuration |
| Resolver-cache HMAC secret | `YABANIN_CACHE_HMAC_SECRET` | Hex-encoded HMAC secret; a fresh 32-byte value represented by 64 hex characters is suitable |
| Legacy column-encryption key | `YABANIN_ENCRYPTION_KEY` | Encrypts `enc:` credential/secret columns; shared by more than organization provider keys |
| Versioned organization-provider keyset | `YABANIN_KMS_KEYSET_FILE` | JSON containing numbered AES keys; `key_hex` is hex-encoded key material |
| Legacy local KMS key | `YABANIN_KMS_LOCAL_KEY` or `_FILE` | AES key, **not an Ed25519 license signer**; the loader treats the value as bytes rather than hex-decoding it |
| License verification trust root | Runtime `YABANIN_LICENSE_ROOT_PUBKEY`, or the relevant build's embedded root | 32-byte Ed25519 public key represented as 64 hex characters |

There is no universal `deploy/secrets/` layout. Use the paths and environment
variables in the deployment you actually run. In particular, a file named
`kms_local_key` does not imply license signing. `pkg/kms/factory.go` accepts
16- or 32-byte legacy local AES keys. File contents are whitespace-trimmed;
a 64-character hexadecimal string is not decoded into a 32-byte AES key by
that loader. Keyset `key_hex`, by contrast, is explicitly hex-decoded.

The local KMS factory refuses a configuration containing both
`YABANIN_KMS_KEYSET_FILE` and `YABANIN_KMS_LOCAL_KEY`/`_FILE`. This is separate
from keeping `YABANIN_ENCRYPTION_KEY` available to read legacy column values.

## Versioned organization-provider credentials

The versioned integration applies to
`org_provider_credentials.api_key_ct`. After a store successfully adopts a
keyset, new values use `ykm1:` followed by a hex-encoded KMS envelope. The
envelope identifies its encryption-key version. Legacy `enc:` values remain
readable only while the corresponding legacy encryptor is available.

Example shape, with placeholders rather than usable keys:

```json
{
  "current": 1,
  "versions": [
    { "version": 1, "key_hex": "<64 hex characters>", "retired": false },
    { "version": 2, "key_hex": "<different 64 hex characters>", "retired": false }
  ]
}
```

Generate each new AES-256 version independently, for example with
`openssl rand -hex 32` in a secure provisioning process. Store the result in
your secret manager, not a command transcript or repository. The keyset
loader also accepts 16-byte AES keys, but do not shorten existing keys during
rotation. Version numbers are positive and permanent: never reuse a version
number for different material.

### Control surface and reload behavior

The shipped keyset lifecycle is file configuration plus Go library methods:
`VersionedKMS.Rotate`, `Retire`, `Reencrypt`, and `SaveKeysetFile`. There is
no documented admin HTTP endpoint that rotates or retires this keyset and no
automatic file-watch reload. Updating the mounted file alone does not update
an existing process's in-memory keyring.

Admin and gateway adopt the credential keyset during startup. A configured
but unusable keyset currently logs a warning and leaves the store in legacy
mode; it does **not** reliably stop the whole service. A running process or
successful health check therefore does not prove adoption. Confirm the
`org credential envelopes: versioned keyset adopted` log on every relevant
instance and test reads/writes. Existing `ykm1:` rows fail to decrypt when no
usable keyset was adopted.

`SaveKeysetFile` validates the record, writes a temporary file, syncs it,
sets restrictive permissions and renames it into place. Directory sync is
best effort. These guarantees apply to that helper, not arbitrary manual
edits or your secret manager. Publish complete validated records atomically
where supported; retain protected recovery copies and verify the mount seen
by restarted containers. A file bind mount can continue referencing an older
inode after a host-side atomic replacement.

### Initial adoption from legacy encryption

1. Inventory all readers and writers of organization provider credentials,
   including every gateway/admin replica and any maintenance jobs. Back up
   the database and the exact existing key material securely.
2. Prepare a valid first keyset and configure its path on all consumers.
   Keep `YABANIN_ENCRYPTION_KEY` unchanged for legacy reads.
3. Pause organization-credential mutations during the transition. Reload
   every reader before allowing an upgraded writer to create `ykm1:` rows;
   a legacy-only reader cannot decrypt them. Check adoption on every instance.
4. Resume mutations only after a controlled create/read/use test succeeds
   through the actual deployed replicas. Confirm that new ciphertext uses
   the versioned envelope without printing ciphertext or plaintext to logs.

This adopts a new envelope format for future writes. It does not immediately
migrate all existing rows or change unrelated encrypted tables.

### Rotate an existing versioned keyset

Use a reader-first rollout. Merely setting a new `current` value and rolling
restarts is unsafe: old snapshots may lack the new key entirely.

1. **Preload:** add a new version while keeping the old version as `current`.
   Distribute this complete keyset to every consumer and reload them. All
   instances still write the old version, but can decrypt both versions.
2. **Check coverage:** confirm every serving reader has loaded the new
   version. Include recovery/maintenance processes that might read the data.
   Do not switch writers while a consumer still lacks the new material.
3. **Switch writers:** change `current` to the new version, keep both versions
   active, and reload writers. During this rollout, old and new write versions
   can coexist because every reader already trusts both.
4. **Verify:** write a disposable test credential, read/use it through each
   serving path, and confirm its envelope names the expected version. Record
   rollout completion before starting the drain.

A program embedding `VersionedKMS` can atomically swap its own in-memory ring
using `Rotate`. That does not distribute the new version to other processes
or persist the change automatically. Library race tests do not prove that a
multi-replica deployment can rotate without interruption.

### Drain old envelopes

A credential update without a new API key attempts to re-seal the existing
value under the current encryption version. The store uses a conditional
rewrite so it does not overwrite a concurrent provider-key rotation.

The existing credential endpoint is:

```text
PUT /api/orgs/{id}/provider-credentials/{credId}
```

It requires the normal admin session, CSRF protection and organization
`keys.manage` permission. A body such as `{"name":"existing-name"}` keeps
the provider API key while exercising the update path. Preserve existing
metadata; omit `api_key` rather than supplying an empty string. The admin UI
can also save an existing credential without replacing its key.

A successful metadata update is **not** proof of successful re-encryption:
the store can log a migration failure and leave the original envelope intact.
Inspect migration warnings and verify remaining rows using a controlled
maintenance process that reports counts, not secret values.

Counting `enc:` versus `ykm1:` distinguishes legacy from versioned envelopes,
but does not distinguish old from current versions within `ykm1:`. Use the
validated envelope parser (`VersionedKMS.EnvelopeVersion`) or equivalent
reviewed maintenance tooling to count each version. The row's provider-key
`key_version` is a different value and must not be used as the encryption
version. Recheck after all old-version writers have stopped; otherwise they
can reintroduce the backlog.

### Retire a version

Retire only after verifying that no required live rows use it and that backup
restoration is covered by an explicit key-retention plan. The current write
version cannot be retired; switch writers first.

Set `retired: true` for the old version, distribute the complete record, and
reload every consumer. A process that adopted the retirement refuses decrypts
for that version with `ErrRetiredKeyVersion`. Old processes still holding the
previous snapshot can continue decrypting until replaced. `Retire` changes
only its local in-memory snapshot unless the caller also persists the state.

Do **not** remove `YABANIN_ENCRYPTION_KEY` merely because organization provider
rows are all `ykm1:`. Model upstream credentials, MCP credentials, lineage
private keys and other `enc:` consumers may still require it. Their migration
and recovery must be assessed separately.

Retirement is an application trust decision, not cryptographic erasure. An
attacker with a copied AES key and matching ciphertext can still decrypt that
copy outside Yabanin. Re-encrypting current database rows does not revoke
ciphertext in stolen data, snapshots or backups.

### Recovery and compromise

For an accidental retirement, restore the exact previous key material and a
reviewed non-retired file record, then reload consumers. The in-memory API has
no un-retire operation. A file edit/restart can restore trust, so retirement
is not irreversible destruction. Restoring a version number with different
bytes will not recover the old ciphertext.

If key material is lost with no recoverable backup, affected provider keys
must be obtained again from their owners or replaced at the provider. A
metadata-only update cannot recover an unreadable secret.

For a suspected compromise, contain access first, introduce fresh encryption
material, drain and retire under a reviewed rollout plan, and rotate/revoke
exposed provider credentials at their issuer. Removing an encryption key
from Yabanin does not invalidate a stolen provider API key. Review logs,
replicas, secret stores and backups within the incident scope. Availability
may require a maintenance window; do not preserve a compromised trust window
solely to avoid a restart.

## Admin session signing

The admin process supports a current secret plus
`YABANIN_ADMIN_SESSION_SECRET_PREVIOUS`. The previous secret is accepted only
during `YABANIN_ADMIN_SESSION_SECRET_GRACE` (default `24h`) measured from that
process's startup. New sessions use the current secret. This mechanism is
specific to admin-session validation; do not assume every token type shares
its grace behavior.

For planned rotation, provision the new current secret and old previous
secret, coordinate the admin replica rollout, and verify both old-session
validation and new-session issuance. Instances still using only the old
secret cannot validate newly signed sessions; drain or otherwise coordinate
those instances. Remove the previous secret after the intended overlap and
reload every instance. Repeated restarts while leaving it configured can
restart the process-local grace window.

For compromise response, do not deliberately retain the compromised secret
as a previous verifier. Coordinate removal and session invalidation across
all replicas and expect users to sign in again. A copied HMAC secret remains
usable for forging signatures wherever a verifier still trusts it.

## Resolver-cache HMAC

`YABANIN_CACHE_HMAC_SECRET` authenticates resolver-cache entries. Rotate all
processes that share this signed cache coherently. Entries signed by the old
secret fail verification under the new one and the resolver falls through to
the authoritative lookup path; allow database capacity for the extra reads.
Mixed secrets can cause repeated cache misses as instances rewrite entries.

This is not automatic eviction of all Redis data or deletion of the response
cache. Do not flush a shared Redis database to rotate the signing secret.
Verify valid API-key resolution, revoked-key rejection and cache-verification
errors after the rollout.

## PostgreSQL credentials

Identify the exact database role and all service connection strings using
it. Prepare a reviewed credential change using PostgreSQL administration
or your secret-management workflow; interactive `psql` `\password` avoids
putting the new password in SQL command arguments. Update every consumer's
secret and recreate/redeploy the affected processes so new connections use
it. A password change does not replace credentials in existing connection
pools, and a healthy existing connection is not a new-login test.

Check fresh connections, migrations, admin operations and gateway requests.
Coordinate the transition or use a maintenance window; changing a password
first can break reconnections from consumers that still have the old value.
Do not rotate database encryption keys as part of an authentication-password
change unless that is a separate planned operation.

## License verification roots

License PKI uses an Ed25519 root to certify an intermediate; the intermediate
signs license tokens. Runtime consumers verify the chain and any configured
revocation list. AES KMS files do not sign these licenses, and there is no
`kms-signer` service in the documented deployment workflow.

Changing an issuer's private key does not retroactively invalidate signatures
already issued. Verifier trust roots, intermediate certificates, expiration
and revocation determine continued acceptance. Plan intermediate or root
rotation with the issuer: stage the appropriate verification material,
reissue certificates/tokens where required, test old/new acceptance and
revocation behavior, then remove obsolete trust. The current runtime
configuration uses one root public key; do not assume an automatic dual-root
overlap exists.

When runtime license checking is configured, `YABANIN_LICENSE_FILE` and
`YABANIN_LICENSE_ROOT_PUBKEY` must both be set. The root value is 64 hex
characters encoding 32 public-key bytes. The optional
`YABANIN_LICENSE_INTERMEDIATE_CERT` and `YABANIN_LICENSE_CRL_FILE` identify
certificate/revocation inputs. Use the CLI's explicit `verify` arguments to
check the intended token, root, intermediate and CRL before deployment.

An embedded activation-token public key is a separate build-time trust input.
Changing it requires rebuilding and verifying the actual binaries. Replacing a
runtime JSON-chain root file does not change a key embedded in a binary.

## Apply configuration to the actual deployment

Use your deployment's real Compose files, environment file, service names or
Kubernetes workload definitions. Inspect the rendered service list and secret
mounts without publishing their values. For Compose, explicitly select the
files with `-f` and `--env-file`; an unqualified command may target another
project. Recreate affected containers when environment configuration changes:
`docker compose restart` alone does not apply new environment values.

After each rotation, record the old/new version identifiers (never key
material), consumers updated, adoption evidence, positive and negative tests,
backup recovery requirements and any remaining overlap. Health checks alone
are insufficient. Keep rollback material according to the incident and
retention plan; do not remove the only copy needed to decrypt retained data.

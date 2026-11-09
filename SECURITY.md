# Security Policy

## Supported versions

The latest release is supported. Older releases are not backported.

## Reporting a vulnerability

Please report security vulnerabilities **privately** using the
"Report a vulnerability" button on this repository's GitHub Security page
(Security advisories). Do NOT open public issues for vulnerabilities —
public reporting exposes the weakness before a fix exists.

We expect to acknowledge receipt within 14 days.

## Known vulnerabilities and scan scope

The source used for the `v0.1.0-preview.1` candidate was scanned on
2026-11-08. The security gate reported the reachable SAML dependency advisory
**GO-2026-6909** in `github.com/crewjam/saml` v0.5.2. The preview was prepared
with an explicitly accepted risk; this is not a passing security gate or a
claim that the product has no known vulnerabilities. SAML is opt-in; leaving
it unconfigured keeps its login routes unmounted.

Module-level findings must be distinguished from reachable product calls.
An earlier review recorded GO-2026-5932 in `golang.org/x/crypto/openpgp` and
GO-2026-6911 in `github.com/mark3labs/mcp-go` as informational findings rather
than additional reachable call paths; this release source updates `x/crypto`
to v0.58.1, which contains the GO-2026-5932 fix, leaving GO-2026-6911 as the
sole informational module-level advisory. Consult the scan for the exact source
and dependency versions you deploy: vulnerability databases and reachability
change over time.

Go scanning does not cover every container package, frontend dependency, or
deployment setting. A dependency update on another branch does not remediate
a published binary; rebuild and rescan the actual release artifacts.

Re-check any time with:

```bash
make analyze-security   # go mod verify + govulncheck ./...
```

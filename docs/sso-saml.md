---
title: "Admin SSO (SAML 2.0)"
description: "SAML 2.0 single sign-on for the Yabanin admin console: SP metadata, IdP-initiated refusal, replay protection, fail-closed user mapping."
sidebar_position: 13
---

# Admin SSO (SAML 2.0)

The admin console also supports single sign-on via any SAML 2.0 identity
provider (Okta, Entra ID, OneLogin, Shibboleth, …). The implementation is the
`github.com/crewjam/saml` service provider. Like the OIDC flow, the
feature is **opt-in**: with no configuration the SAML routes are not mounted
(they answer 404) and the console stays on the password flow, unchanged.

## Enabling

| Env | Required | Meaning |
|---|---|---|
| `YABANIN_SAML_IDP_METADATA_URL` | yes | IdP metadata document URL, e.g. `https://idp.example.com/saml/metadata` |
| `YABANIN_SAML_IDP_METADATA_URL_FILE` | no | Docker/K8s secret file holding the metadata URL (the direct variable wins) |
| `YABANIN_SAML_ENTITY_ID` | no | SP entity ID; defaults to the ACS origin (`https://admin.example.com`) |
| `YABANIN_SAML_ACS_URL` | no | Assertion Consumer Service; defaults to `https://<admin_domain>/auth/saml/acs` (from `YABANIN_ADMIN_DOMAIN`) |
| `YABANIN_SAML_ROLE_ATTR` | no | SAML attribute recorded in the login audit entry as `asserted_role` (informational — it never grants anything) |
| `YABANIN_SAML_SP_KEY_FILE` | paired | PEM signing private-key file; supply together with the certificate file |
| `YABANIN_SAML_SP_CERT_FILE` | paired | PEM signing certificate file; supply together with the private-key file |
| `YABANIN_SAML_METADATA_REFRESH_SECONDS` | no | Metadata refresh interval; default `3600`; zero or negative disables refresh |

The metadata document is fetched at startup. Failure keeps the SAML routes
unmounted and leaves the password flow available. A running server refreshes
IdP metadata hourly by default. Refresh failure retains the previous metadata
and logs a warning; retired IdP certificates remain trusted until a successful
refresh replaces that metadata. Monitor refresh failures during key rotation.

Configure a persistent SP key and certificate for stable metadata across
restarts and replicas. Both files are required together; an invalid pair
prevents SAML initialization. If neither is configured, the server generates
an ephemeral pair, which changes on restart. The SP validates IdP assertions;
the IdP may validate signed AuthnRequests using the SP certificate.

Before enabling SAML, review the dependency advisory described in the
repository's `SECURITY.md`. Protocol checks described here do not negate a
known vulnerability in the SAML dependency.

## Endpoints

| Route | Purpose |
|---|---|
| `GET /auth/saml/metadata` | SP metadata XML for IdP-side import (entity ID + ACS) |
| `GET /auth/saml/login` | Starts the flow: signed AuthnRequest, redirect to the IdP |
| `POST /auth/saml/acs` | Assertion Consumer Service |
| `GET` or `POST /auth/saml/slo` | Clears the local admin session and redirects to login |

These routes are mounted only after successful SAML initialization. The SLO
endpoint clears local session and CSRF cookies; it does not implement a full
SAML logout exchange or terminate the IdP session.

## The flow

1. `GET /auth/saml/login` — builds the AuthnRequest (HTTP-Redirect binding,
   signed HTTP-POST fallback) and seals the request ID in a one-time
   10-minute HttpOnly+Secure cookie scoped to `/auth/saml`.
2. The IdP authenticates the user and posts a SAML Response to the ACS.
3. `POST /auth/saml/acs` — crewjam verifies the **signature against the
   certificates published in the IdP metadata**, the issuer, the **audience
   (SP entity ID)**, the **ACS recipient**, every timestamp
   (NotBefore/NotOnOrAfter/IssueInstant, bounded clock skew) and the
   **InResponseTo** against the flow cookie. On top of that the assertion ID
   is deduplicated: a byte-for-byte **replay of a still-valid response is
   refused**.
4. User mapping — **fail-closed, identical to the OIDC flow**: the NameID
   must be an email address (format `emailAddress` or unspecified) matching
   an **existing active admin user**. SSO never provisions accounts, never
   widens roles; the issued session is byte-for-byte the password-flow
   session (same HMAC cookie, same `IsRoot`, same 24h
   `adminauth.SessionDuration`).
5. A `login` audit entry is written with the IdP entity, the mapped user and
   (when configured) the asserted role attribute.

## Security contract

- **No IdP-initiated login.** `AllowIDPInitiated` is false: an assertion with
  no matching AuthnRequest of ours is refused outright.
- **Replay checks.** crewjam validates InResponseTo. The process-local
  assertion-ID cache rejects repeated IDs while retained. It is not shared
  across replicas and resets on process restart; do not treat it as durable
  cluster-wide replay prevention.
- **XML hardening.** Responses are round-trip validated before parsing; Go's
  `encoding/xml` never resolves external or parameter entities, and the
  metadata ingestion refuses DTD/entity tricks (tested).
- **Unknown emails get the same refusal as disabled accounts** — no user
  enumeration, no signup-by-SSO. The email local part never reaches the logs;
  only the domain is recorded on a mapping refusal.
- **No open redirects.** Success always lands on `/`.
- The asserted role attribute is audit metadata only; authority always comes
  from the database user record (and the guarded-session middleware
  re-validates it per request).

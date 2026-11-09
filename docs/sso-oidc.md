---
title: "Admin SSO (OIDC)"
description: "Single sign-on for the Yabanin admin console: OpenID Connect Authorization Code flow with PKCE, verified email mapping, fail-closed provisioning."
sidebar_position: 12
---

# Admin SSO (OIDC)

The admin console supports single sign-on via any OpenID Connect provider
(Google Workspace, Entra ID, Okta, Dex, …) using the **Authorization Code
flow with PKCE (S256), a state CSRF token and a nonce**. The feature is
**opt-in**: with no configuration the console stays on the password flow,
unchanged.

## Enabling

All four values must be set — anything less keeps SSO off:

| Env / `config.yaml` (`admin:`) | Meaning |
|---|---|
| `YABANIN_ADMIN_OIDC_ISSUER` / `oidc_issuer` | Provider issuer URL, e.g. `https://accounts.google.com` |
| `YABANIN_ADMIN_OIDC_CLIENT_ID` / `oidc_client_id` | OAuth client id |
| `YABANIN_ADMIN_OIDC_CLIENT_SECRET` / `oidc_client_secret` | OAuth client secret |
| `YABANIN_ADMIN_OIDC_REDIRECT_URL` / `oidc_redirect_url` | e.g. `https://admin.example.com/auth/oidc/callback` |

The provider's discovery document is fetched at startup; a failure logs
loudly and keeps the console on the password flow — never a half-working SSO
mount. ID-token signing keys are not frozen at startup: a token carrying an
unknown key id triggers a JWKS refetch, so a provider-side signing-key
rotation takes effect without a console restart. A long-lived process keeps
already-cached keys until such a refetch — a retired key stays trusted by the
running process up to that point, while a freshly started console verifies
against the current key set.

## The flow

1. `GET /auth/oidc/login` — issues a one-time `state`/`nonce`/PKCE triple,
   together with the validated return target, in a 10-minute
   HttpOnly+Secure cookie (SameSite=Lax: the callback arrives as a
   top-level navigation) and redirects to the provider.
2. `GET /auth/oidc/callback` — constant-time state check, code exchange with
   the PKCE verifier, ID token verification (**signature against the
   provider's JWKS, issuer, audience, expiry, nonce**).
3. User mapping — **fail-closed**: the verified email must match an
   **existing active admin user**. SSO never provisions accounts.
4. Group reconciliation — when the ID token carries a `groups` claim, every
   org the user **already belongs to** applies its org-declared
   group→role rules (`sso_group_role_rules`, migration 0012): deny-wins (a
   matching deny rule or conflicting grants give nothing), exact
   byte-equality group matching, grants recorded with provenance. The
   mapping never creates an account or a first membership and never adopts
   a role an admin set by hand. While a rule grants, the declared rule stays
   authoritative for the role it names (an admin's manual demotion is
   re-asserted at the next login); once no rule grants, the mapping
   relinquishes — a manually changed role is left alone, and only the
   mapping's own grant is revoked, and only while the membership still
   holds exactly the granted role. A sync failure never blocks the login;
   the next login re-runs it. An org without declared rules is untouched.
5. Session issuance — the same HMAC cookie the password flow issues (same
   `IsRoot`), then a redirect to the validated return target.

The one-time cookie is cleared on every callback outcome — its secrets are
single-use by construction.

## Security contract

- **`email_verified` is required.** A provider asserting an email without
  verifying it does not log anyone in.
- **No auto-provisioning.** Unknown emails get the same refusal as disabled
  accounts — no user enumeration, no signup-by-SSO.
- **Group mapping never widens the account.** The org-level rules can set or
  revoke org-membership roles only for memberships that already exist; the
  session itself keeps mirroring the DB user (`IsRoot`), and a mapping-sync
  failure never blocks the login.
- **Nonce binds the ID token to this login.** A token minted for another
  session cannot be replayed.
- **No open redirects.** The optional `next` return target is validated to a
  same-origin relative path at login and re-validated from the flow cookie
  at the callback: no scheme, no protocol-relative `//` or `\`, no control
  characters, at most 2048 bytes — anything else, including a tampered
  cookie value, collapses to `/`. The login redirect itself always targets
  the configured issuer.
- The local part of emails never reaches the logs; only the domain is
  recorded on a mapping refusal.

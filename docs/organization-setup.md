---
title: Organization setup
description: First requests, provider keys, member invitations, credits, and organization limits.
---

# Organization setup

The admin console groups credentials, members, request history, and cost
controls by organization. Select the intended organization before changing
its settings. Platform root users can create organizations; organization
members act within the permissions of their assigned role.

## First request

The welcome flow checks three signals from the selected organization's APIs:

1. A provider credential exists in **Organization settings → Provider keys**.
2. An active gateway API key exists in **Keys**.
3. Request statistics include at least one successful request.

The provider-credential signal checks existence, not connection health. Use
the [BYOK connection test](byok.md) and an actual inference request to verify
the setup. Copy the gateway key when it is created; later lists show only its
metadata. Client configuration examples are available for
[OpenCode](clients/opencode.md), [Claude Code](clients/claude-code.md),
[Codex](clients/codex.md), [Continue](clients/continue.md), and [Cline](clients/cline.md).

Skipping or completing the flow persists an **organization-wide** flag, not
a per-browser preference. `GET /api/me/onboarding?org_id=<id>` reads it;
`POST` to the same URL accepts exactly one true flag, `completed` or
`skipped`. These endpoints require an admin session and membership in the
target organization (reader or above; root bypasses the role gate).

## Bootstrap administrator and request visibility

Platform-root access to administrative endpoints does not automatically create
organization membership. Request-history list visibility separately checks the
organization role. A newly seeded root can therefore see an empty Request
explorer even when requests made with the organization's gateway key were logged.

For the local walkthrough, add the seeded administrator as a `reader` of the
seeded organization using the [quickstart's dashboard steps](quickstart.md#view-the-requests-you-just-made).
That grants metadata visibility; original request/response content has separate
permissions and retention rules. Do not treat an empty filtered list as proof
that no request exists in persistent storage.

## Invite members

Open the organization's **Members** page and create an invitation with the
recipient's email and role. The available roles are `org-admin`, `operator`,
`reader`, `security_auditor`, and `partner`. Managing invitations requires
`members.manage`.

Creation returns a one-time invitation link. Share that link with the
recipient; the API does not send invitation email. It expires after 72 hours.
Resending rotates the token and starts a new validity window, invalidating
the previous link. Revoking removes the pending invitation.

At `/invite/<token>`, a new recipient creates credentials; an existing user
must authenticate with the invited account's password. The database stores
only the token's SHA-256 hash. Missing or revoked tokens return 404; expired
or already accepted invitations return 410.

| Method | Admin endpoint |
| --- | --- |
| GET | `/api/organizations/{id}/members/invites` |
| POST | `/api/organizations/{id}/members/invite` |
| POST | `/api/organizations/{id}/members/invites/{inviteID}/resend` |
| POST | `/api/organizations/{id}/members/invites/{inviteID}/revoke` |

## Organization roles and access

An organization role determines which actions a member can take in that
organization. The role names below are assigned per organization. A permission
not listed for a role is not granted.

| Permission | org-admin | operator | security_auditor | reader | partner |
| --- | --- | --- | --- | --- | --- |
| `analytics.read` | yes | yes | yes | yes | no |
| `requests.read` | yes | yes | yes | yes | no |
| `requests.read_payloads` | yes | no | yes | no | no |
| `lineage.read` | yes | yes | yes | yes | no |
| `lineage.verify` | yes | yes | yes | no | no |
| `audit.read` | yes | no | yes | no | no |
| `keys.manage` | yes | yes | no | no | no |
| `agent_keys.manage` | yes | yes | no | no | no |
| `budgets.manage` | yes | yes | no | no | no |
| `members.manage` | yes | no | no | no | no |
| `routing.manage` | yes | yes | no | no | no |
| `policies.manage` | yes | no | no | no | no |
| `org.update` | yes | no | no | no | no |

The table describes organization-scoped permissions. `org-admin` has all of
these permissions. `operator` can work with keys, budgets, and routing, but
cannot manage members, organization settings, or policies. `security_auditor`
can read request payloads and has the `audit.read` permission. `reader` has
read access to analytics, requests, and lineage. `partner` has no
organization-scoped permissions in the current role matrix. A separate
platform-level security-auditor role and platform-root access are not granted
by choosing an organization role.

The console uses your permissions to hide or disable protected organization
actions you cannot take. That is a convenience, not an authorization
boundary: the server checks protected organization actions too. For example,
a member without `members.manage` cannot create an invitation by calling the
invitation endpoint directly; the request is denied and no invitation is
created. Some foreign organization resources are reported as unavailable, so
the response may not reveal whether a resource in another organization exists.

If an action is unavailable or a request is denied, first check that the
console is set to the organization you intend to manage. If you need an action
that your role does not grant, ask that organization's `org-admin` to update
your membership. For a resource that belongs to another organization, switch
to that organization only if you are a member; otherwise contact its
administrator. Do not treat a hidden button or a copied resource ID as a way
to bypass the role check.

## Credits and organization caps

The **Credits** page exposes the selected organization's balance and ledger.
Reads require `budgets.manage`; top-ups and the cross-organization low-balance
report remain root-only. [Operator setup](getting-started-reseller.md)
describes these endpoints and the prepaid flow.

Organization creation through the admin API and the `yabanin seed` path can
apply a one-time beta starter grant. `BETA_STARTER_CREDITS_CENTS` defaults to
5000 ($50); zero or a negative value disables it. The ledger marker
`beta-starter-grant` prevents a repeated grant. This is deployment credit,
not a promise of free upstream provider usage. Seed fixtures may carry
additional demo credits.

The **Budgets** page also manages organization-wide RPM, TPM, and monthly
budget caps through `GET` / `PUT /api/orgs/{id}/caps`. Read and write access
require `budgets.manage` (or root). Monthly amounts are in cents. Defaults
are 60 RPM, 200,000 TPM, and **5,000,000 cents ($50,000) per month** in the
current `DefaultOrgCapsMonthlyBudgetCents` constant. Some source comments
still say $50; the constant and API response determine behavior. This cap
is separate from the default $50 starter credit grant. A PUT requires a mutation
`reason`; null or omitted cap fields reset their overrides to defaults.

Set `YABANIN_ORG_CAPS=enforce` to enforce caps, or `shadow` to count
would-be denials. Unset or unrecognized values disable this layer; `1` is
not an enable value. Configure Redis and the database-backed caps source:
startup without Redis disables caps with a warning.

Once the enforcer is wired, rate or token cap exhaustion returns 429,
monthly budget exhaustion returns 402, and dependency failures return 503
in enforce mode. Caps are cached for five seconds and month-to-date spend
for three seconds; this is not a zero-overrun reservation mechanism.
Organization caps are additional controls alongside API-key limits, team
budgets, and credits.

## Feedback and operations

The root-only **Feedback** page lists submitted classifier feedback, filters
by organization and rating, and exports the filtered data as CSV. Available
ratings are `thumbs_up`, `thumbs_down`, and `regenerate`. See
[Analytics](analytics.md) for request and cost reporting and the
[public deployment runbook](runbooks/public-stand-deploy.md) for alerts and status checks.

---
title: Operator-managed evaluation stand
description: Access boundaries and verification for an operator-managed Yabanin evaluation instance.
---

# Operator-managed evaluation stand

An evaluation stand is an instance maintained by its operator. Its existence does
not establish current availability, a service-level commitment, or permission to
use real customer data. Obtain its URL, credentials, permitted models and data
policy from that operator. The local quickstart's credentials do not apply.

## Client access

A deployment may mount the gateway below a prefix. For example, if the operator
provides `https://stand.example.com/gw`, an OpenAI-compatible client uses
`https://stand.example.com/gw/v1`. The edge must remove `/gw` before forwarding
to the gateway. This is an example topology; use the URL actually provided.

| Surface | Example path | Verification |
| --- | --- | --- |
| Gateway health | `/gw/healthz` | Healthy response from the gateway |
| Model listing | `/gw/v1/models` | Authenticated response using an organization key |
| Chat | `/gw/v1/chat/completions` | Successful response from a listed, permitted model |
| Admin session/API | `/auth/...`, `/api/...` | Browser login and authorized organization access |
| Dashboard | Operator-provided URL | Separately served React application |
| Documentation | Optional `/docs/...` | Static documentation deployment |

A response from `mock-model` verifies gateway plumbing, not a paid provider
connection or model quality. For your own upstream, see [BYOK](../byok.md) and
[organization setup](../organization-setup.md). Client configuration and supported
protocol limits are in the [compatibility matrix](../compatibility.md).

## Operator responsibilities

The public export does not ship the maintainer's SSH redeployment scripts,
shared-host Caddy configuration, or website synchronization automation. Do not
assume those tools exist in a clean public checkout. To operate your own instance:

1. Complete the [quickstart](../quickstart.md) on an isolated machine.
2. Choose a deployment topology and prepare an explicit, versioned configuration
   using the [deployment checklist](../runbooks/public-stand-deploy.md).
3. Configure [DNS and TLS](dns-setup.md), access controls, provider routes and
   credentials. Keep test and production credentials separate.
4. Establish backups, restore acceptance, monitoring, and actual alert delivery.
5. Record the deployed source/image digest, configuration version and migration
   status. Run health, authenticated inference and browser acceptance after each
   change.

## Updates and rollback

Preserve the previous immutable image, configuration, database backup and required
encryption keys before updating. Image rollback alone does not reverse schema
changes, overwritten configuration, or external state. Review migration
compatibility first and rehearse rollback against a disposable restore.

The website and dashboard are separate build artifacts. Publish each to its own
owned destination, with its expected base path and edge routes. A synchronization
command that deletes destination files can erase manually installed dashboard
assets when both share a directory. Inventory the destination before deployment
and retain the previous assets until acceptance succeeds.

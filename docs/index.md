---
title: Documentation
slug: /
sidebar_position: 0.5
description: Start Yabanin locally, connect clients, and operate a self-hosted AI gateway.
---

# Documentation

Yabanin routes model requests, applies organization policies, and records
usage and request details. This documentation describes the Developer
Preview. Begin with the **[quickstart](quickstart.md)** for a local mock request
and an optional dashboard; no provider account is needed.

| Task | Read next |
| --- | --- |
| Understand what runs where | [Introduction](intro.md) · [Architecture](architecture.md) |
| Analyze an existing request log offline | [Spend audit](audit.md) |
| Connect a client or SDK | [Compatibility](compatibility.md) · [SDK guide](clients/sdk-versions.md) |
| Set up users, keys, and models | [Organization setup](organization-setup.md) · [BYOK](byok.md) · [Providers](providers.md) |
| Control requests and spending | [Policies](pipeline.md) · [Agent governance](agent-governance.md) · [Analytics](analytics.md) |
| Evaluate changes with local fixtures | [Evaluation](evaluation.md) |
| Inspect recorded model and region information | [Lineage](lineage.md) · [Residency policies](residency-packs.md) |
| Build or contribute | [Development](DEVELOPMENT.md) · [Extensions](extensions/README.md) |
| Deploy and operate | [Deployment options](deployment-options.md) · [Production runbook](runbooks/production.md) |

Costs may be estimates, and simulated savings require workload validation.
Signed lineage verifies recorded claims; it does not independently establish
where a provider processed a request. Each feature guide states its scope and
limitations. Test the configuration you deploy.

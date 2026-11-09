---
title: Introduction
sidebar_position: 1
description: Understand Yabanin's gateway, control plane, offline tools, and preview limits.
---

# Introduction

Yabanin is a self-hosted AI gateway. Applications send model requests to one
endpoint; the gateway resolves a model, checks organization policies and
budgets, and forwards allowed requests to the configured provider. Its admin
API and dashboard manage the control plane and expose usage records.

Start with the **[quickstart](quickstart.md)** to send a request to a local mock
provider and check asynchronous request logging. For an existing request log,
the [offline spend audit](audit.md) works without any gateway or database.

## What you can evaluate

| Area | Capabilities and relevant limits |
| --- | --- |
| Client protocols | OpenAI-compatible and Anthropic-compatible routes, including streaming where supported. The [compatibility matrix](compatibility.md) lists supported clients and the checks performed for each. |
| Routing and resilience | Model registry, rules, retries, fallback, and circuit breakers. Availability depends on configured providers and failure handling; see [providers](providers.md). |
| Organization controls | Gateway keys, roles, labels, credits, budgets, and provider credentials; start with [organization setup](organization-setup.md). |
| Policies and agents | Request policies, guard detectors, agent credentials and tool controls; see [policy pipeline](pipeline.md) and [agent governance](agent-governance.md). |
| Cost analysis | Usage-based cost estimates and cache/routing simulations. Results depend on price coverage, workload, and acceptable output quality; see [analytics](analytics.md) and [audit](audit.md). |
| Caching | Exact and optional semantic caching. Semantic reuse needs an embedder and quality validation for your workload; see [cache](cache.md). |
| Request records | Optional signed lineage records model and region-related claims. A signature verifies the recorded claim's integrity, not physical processing location; see [lineage](lineage.md). |
| SDKs | Small Go, Node, and Python clients with different endpoint coverage. Source installation and limitations are in the [SDK guide](clients/sdk-versions.md). |

This is a **Developer Preview**. Read the release's security notes and test
the integrations you plan to use before sending production traffic.

## Components and deployment boundaries

```text
Application -> Gateway -> Configured provider
                  |
                  +-> PostgreSQL (configuration and records)
                  +-> Redis (cache and events) -> Loggerd -> PostgreSQL

Browser -> Dashboard -> Admin API
```

The unified `yabanin` binary can run `gateway`, `admin`, or `loggerd` separately.
`yabanin dev` combines those services in one process; PostgreSQL and Redis
still run separately. `migrate` applies embedded database migrations, `seed`
creates bootstrap records, and `mcp` is a separate optional partner bridge.
The `yb` binary provides operator commands, offline audit, and evaluation.

The quickstart exposes gateway port **8082** and admin API port **8086** on
localhost. The optional React dashboard uses **5173** through Vite. Other
Compose or Kubernetes deployments may map different ports. An API response at
8086 is not the web interface.

Self-hosting the gateway alone does not keep inference local. Review the
complete path: external providers, local model endpoints, logs, caches,
backups, and telemetry. Residency presets and signed records support controls
and investigation; they are not legal or compliance certifications.

The [architecture guide](architecture.md) expands the request flow,
persistence, optional integrations, and component boundaries.

## Next steps

- [Run the local quickstart](quickstart.md), then [connect a client](compatibility.md).
- [Configure provider credentials](byok.md) and [model routing](providers.md).
- [Build or contribute](DEVELOPMENT.md).
- [Plan a deployment](deployment-options.md) and read the [production runbook](runbooks/production.md).

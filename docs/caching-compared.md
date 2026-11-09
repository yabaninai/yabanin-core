---
title: Response caching and provider prompt caching
description: Different reuse mechanisms, their costs, and how to evaluate them.
---

# Response caching and provider prompt caching

A response cache reuses an earlier answer. Provider prompt caching can reuse
processing of eligible input while the provider still generates a new answer.
The mechanisms have different correctness, freshness, and billing implications.

| Question | Provider prompt caching | Yabanin response caching |
|---|---|---|
| What is reused? | Provider-specific input processing | A stored response |
| What matches? | Provider-specific eligibility and prefix rules | An exact normalized key, or an enabled embedding-similarity lookup |
| Is a new answer generated? | Yes | No on a response-cache hit |
| Where is scope defined? | Provider, model, account, and API rules | Organization, cache key/tier, model version, and configured policy |
| What remains to pay? | Provider's current input/output/cache charges | Gateway, storage, embedding, and operational costs; no new inference call for a served hit |
| What needs validation? | Eligibility, reported usage, current pricing | Answer equivalence, freshness, isolation, hit rate, and infrastructure cost |

## Choosing a mechanism

Repeated system instructions with changing user questions may benefit from
provider prompt caching. Repeated requests for an answer that remains valid
may benefit from exact response caching. Semantic reuse also requires evidence
that nearby embedding vectors mean the same acceptable answer for your use case.
See [Cache precision](cache-precision.md) for the limitations of the historical
measurements and a validation procedure.

Do not enable cross-model reuse merely because models share a tier: confirm
that their behavior, capabilities, and the expected answer contract are
interchangeable. Review cache-key normalization and model-version invalidation
before changing routes.

## Accounting and coexistence

Both mechanisms can operate in one deployment: response-cache misses can
reach a provider that applies its own prompt cache. Where supplied and supported
by the adapter, provider usage includes cache-read and cache-creation tokens.
Compare those observations with provider invoices; estimated or counterfactual
savings are not invoiced savings.

Provider eligibility, retention, and prices vary and change. Consult the
specific provider's documentation and contract before budgeting. This page
makes no fixed discount or TTL promise. The [offline audit](audit.md) can
estimate exact-repeat opportunities and highlight repeated prefixes; it does
not prove provider cache eligibility or semantic answer quality.

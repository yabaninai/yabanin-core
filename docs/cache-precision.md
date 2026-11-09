---
title: Cache precision
description: How precisely the semantic cache decides two prompts are the same question — measured, not asserted.
---

# Cache precision

Semantic caching uses embedding similarity as a heuristic for reusing an
answer. Similar wording does not establish that two requests are equivalent:
negation, names, dates, authorization context, and freshness can change the
correct response. An exact cache match also does not establish answer quality.

The semantic layer requires a configured embedding service and pgvector.
The default similarity threshold is 0.95; a higher threshold does not by
itself establish an acceptable false-hit rate. The mock quickstart is not a
semantic-quality benchmark.

## Historical measurements

The tables below preserve previously recorded synthetic measurements. The
original pair corpus and benchmark harness are **not included in the public
source export**, so these results cannot be independently reproduced from
this checkout. They were not rerun for this documentation revision and are
not a release acceptance result or a production recommendation.

Positive pairs were labeled as acceptable answer reuse; negative pairs were
near-misses. Precision is the fraction of predicted hits labeled positive;
recall is the fraction of positive pairs retrieved. Each language sample
contains only 91 pairs (60 positive and 31 negative).

| Model | Dataset | Threshold | Precision | Recall | F1 |
|---|---|---|---|---|---|
| bge-small-en-v1.5 | pairs_en (N=91: 60 same / 31 different) | 0.95 | 0.0000 | 0.0000 | 0.0000 |
| multilingual-e5-small | pairs_ja (N=91: 60 same / 31 different) | 0.95 | 0.2857 | 0.0667 | 0.1081 |

Full threshold sweep (same runs):

**bge-small-en-v1.5 / pairs_en:**

| Threshold | Precision | Recall | F1 | FP | FN |
|---|---|---|---|---|---|
| 0.85 | 0.4643 | 0.2167 | 0.2955 | 15 | 47 |
| 0.90 | 0.0833 | 0.0167 | 0.0278 | 11 | 59 |
| 0.92 | 0.0000 | 0.0000 | 0.0000 | 9 | 60 |
| 0.95 | 0.0000 | 0.0000 | 0.0000 | 3 | 60 |
| 0.97 | 0.0000 | 0.0000 | 0.0000 | 1 | 60 |
| 0.98 | 0.0000 | 0.0000 | 0.0000 | 1 | 60 |

Best F1: **0.2955 at threshold 0.85**. Similarity distribution:
same-questions p10=0.7549 p50=0.8282 p90=0.8816; different-questions
p50=0.8449 p90=0.9437 p99=0.9874.

**multilingual-e5-small / pairs_ja:**

| Threshold | Precision | Recall | F1 | FP | FN |
|---|---|---|---|---|---|
| 0.85 | 0.6988 | 0.9667 | 0.8112 | 25 | 2 |
| 0.90 | 0.6346 | 0.5500 | 0.5893 | 19 | 27 |
| 0.92 | 0.5588 | 0.3167 | 0.4043 | 15 | 41 |
| 0.95 | 0.2857 | 0.0667 | 0.1081 | 10 | 56 |
| 0.97 | 0.0000 | 0.0000 | 0.0000 | 6 | 60 |
| 0.98 | 0.0000 | 0.0000 | 0.0000 | 3 | 60 |

Best F1: **0.8112 at threshold 0.85**. Similarity distribution:
same-questions p10=0.8683 p50=0.9114 p90=0.9440; different-questions
p50=0.9164 p90=0.9794 p99=0.9986.

## Interpretation

At threshold 0.95, the recorded English run retrieved no positive pairs and
three false positives. The Japanese run retrieved four positive pairs and
ten false positives. These observations do not support a general claim of
high-precision answer reuse.

The historical E5 run omitted input prefixes. Its results are not a bound
on correctly configured E5 performance; adding prefixes can change both true
and false hits. Neither sample establishes how your production traffic will
behave. A threshold selected on these samples must not be generalized to
another language, model, embedding configuration, or workload.

## Validate before enabling semantic reuse

1. Build a representative labeled corpus with acceptable-reuse and near-miss
   pairs. Include adversarial differences in entities, dates, negation, user
   permissions, and requested output formats. Keep evaluation inputs separate
   from threshold-selection inputs.
2. Fix the embedding model revision, dimensions, preprocessing, and prefixes.
   Record these with the dataset version and environment.
3. Measure true positives, false positives, false negatives, precision, and
   recall across thresholds. Inspect false hits individually; a single harmful
   answer can matter more than the overall hit rate.
4. Choose a threshold using the acceptable error rate for the application,
   then evaluate it on the held-out set. Measure latency and infrastructure cost.
5. Roll out with an explicit rollback and cache invalidation plan. Use
   [cache experiments](cache-architecture.md#ab-experiment-flow) to compare
   accounting outcomes, and a separate response-quality review to assess
   correctness. Cost metrics alone do not measure answer quality.

Use `exact` or `off` when semantic reuse is unsuitable. See
[cache configuration](cache.md) and [privacy modes](cache-architecture.md#privacy-model).
The offline [audit CLI](audit.md) currently supports exact reuse estimates;
it does not validate semantic precision.

# Compare requested and served models

A model comparison can be misleading when automatic routing changes the requested
model. If a runner prices every response using the requested model while the
gateway serves a different one, both the quality comparison and cost estimate can
be attributed to the wrong model.

## Make a controlled comparison

1. Choose explicit routes for the models being compared. Disable automatic route
   changes for the experiment, or record every route change as part of the result.
2. Capture the requested model, gateway routing decision, response model and usage
   for each attempt. Check that each completed response belongs to the intended arm.
3. Apply prices for the model actually served and the relevant price date. Keep
   missing prices as unknown instead of assigning zero cost.
4. Include failures and retries in the accounting. Distinguish transport failures
   from completed model responses when reporting latency and quality.
5. Use separate evaluation inputs for development and final comparison; publish
   the method and limitations with the result.

The provider's response `model` field is a claim about the served model. It is not
an independent attestation of model weights or the physical inference location.
[Lineage](../lineage.md) can preserve signed routing claims, with the same limit.

## Interpret costs and results

Token charges cover only part of operating cost. Local hardware, electricity,
administration and subscription allocation remain relevant even when a route has
no per-token fee. A mock-provider test can verify routing and accounting behavior;
it cannot establish model quality, customer savings or a reconciled provider bill.

Use the [evaluation guide](../evaluation.md) for local fixtures and the
[performance guide](../gateway-performance.md) for latency measurements.

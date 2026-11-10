# Security inbox scoring contract

The pure functions in `pkg/inbox/scoring.go` compute severity and grouping
confidence from security events. This contract describes those functions;
the incident projection currently uses provisional severity and confidence
values rather than invoking `ScoreEvents`.

## Severity

The closed severity vocabulary is `low|medium|high`, in increasing order.
The escalation law is **escalation = max** over readable finding verdicts.
Event volume cannot raise severity. An empty event list returns `ErrNoEvents`;
a fold without any readable verdict returns `ErrNoVerdict` rather than inventing
`low`.

The current event format carries verdicts in whitespace-separated
`severity=<word>` summary tokens. `EventVerdict` returns no verdict when that
token is absent. Empty, truncated or unsupported values produce
`ErrUnreadableVerdict`, even if another token is valid. Multiple valid tokens
use their maximum severity so an extra low-severity token cannot lower a
finding. `CoreAdapter` output is checked directly by the contract tests.

## Confidence

Confidence describes grouping quality, not attack probability or detector
accuracy. For `n` input events:

```text
confidence = 0.6 * completeness + 0.3 * corroboration + 0.1 * dedup certainty
completeness = events with a readable verdict and at least one evidence reference / n
corroboration = (n - 1) / (n + 3)
dedup certainty = distinct nonempty event IDs / n
```

Events without verdicts still contribute to the denominators. Evidence
references are counted for presence; this function does not verify their
contents. Confidence and severity have independence: changing verdict rank
without changing its readability does not change confidence, and adding events
with the same verdict cannot change severity. Input order and wall-clock time
do not enter the formula.

Numerical anchors retained by the contract tests:

- One complete event: `0.7`.
- Two distinct complete events: `0.76`.
- Nine distinct complete events: `0.9`.
- Two complete events with the same event ID: `0.71`.

[Implementation](https://github.com/yabaninai/yabanin-core/blob/main/pkg/inbox/scoring.go) ·
[Behavior tests](https://github.com/yabaninai/yabanin-core/blob/main/pkg/inbox/scoring_test.go) ·
[Adapter and contract tests](https://github.com/yabaninai/yabanin-core/blob/main/pkg/inbox/scoring_contract_test.go)

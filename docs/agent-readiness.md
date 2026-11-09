# Before you expand an agent workflow

Use these questions when planning an agent deployment. Record the responsible
person, the current configuration, and the result of each check. Mark anything
you have not checked yet as unknown.

| Question | What to record |
| --- | --- |
| Which data may leave your chosen environment? | Data classes, approved destinations and decision owner |
| Which tool, SDK and telemetry paths bypass the gateway? | A reviewed connection map |
| How do you revoke one agent's access? | A tested revocation procedure and observed propagation |
| Which actions require approval, and who enforces it? | Approval boundary and negative test |
| Are failed attempts, fallbacks and subscriptions included in costs? | Coverage and explicit exclusions |
| What counts as an accepted task? | Independent acceptance criteria and verifier version |
| Can the agent modify its own checks? | Protected verifier and workspace boundary |
| How do you recover or roll back a model-route change? | An exercised runbook |

Record each item as established, partial, unknown or not applicable.
Test the behavior and review the configuration in the environment you will use.

# Continuous integration

Workflow definitions are in `.github/workflows/`. Repository administrators
configure which workflows run, their permissions, and any required checks.

- [Public CI configuration](public-ci-proposal.md)
- [Release workflow](public-release-proposal.md)
- [Branch protection](branch-protection-proposal.md)

Run pull-request jobs with read-only permissions and without signing or
deployment credentials. Populate caches only from public sources. Keep
release credentials in a restricted maintainer environment.

See [Contributing](../CONTRIBUTING.md) for local checks and
[Security](../SECURITY.md) for vulnerability reporting.

# Contributing to Yabanin Core

Pull requests are welcome. Keep changes focused and use conventional commit
messages such as `fix:`, `feat:`, `docs:`, and `test:`. Write documentation and
explanatory code comments in English.

## Check your changes

Follow [Development](docs/DEVELOPMENT.md) for prerequisites, source builds,
focused tests, and documentation checks. Run `make lint` and the relevant tests
for code changes. Run the [quickstart](docs/quickstart.md) when changing the
installation flow. Include the commands and results in your pull request,
including any checks you could not run.

Discuss new dependencies with a maintainer before adding them. Authentication,
authorization, dependency, and security changes require maintainer review.
Report vulnerabilities through [SECURITY.md](SECURITY.md), not a public issue.

## Contribution rights and attribution

Sign off every commit under the [Developer Certificate of Origin](DCO):

```text
Signed-off-by: Your Name <your-email@example.com>
```

Use `git commit -s` to add the trailer. It records your confirmation that you
have the right to submit the contribution; it is separate from a cryptographic
Git signature. Use your real name and email address.

Disclose any employer, contractor, or third-party restrictions. If an employer
owns the contribution, provide its written permission. Preserve copyright and
license notices for copied material and identify its origin. Maintainers cannot
accept contributions whose rights remain unresolved.

Accepted contributions are distributed under Apache-2.0. No separate CLA is
required. Maintainers preserve the original author and sign-off when importing
or exporting accepted work. A contributor may withdraw a pull request before
it is accepted.

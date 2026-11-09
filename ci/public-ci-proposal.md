# Public CI configuration

Configure the workflows in `.github/workflows/` for the repository's available
runners and services. The development guide lists the commands supported by
the public source tree.

For pull requests, check formatting, compile the affected code, run its tests,
and build changed documentation or frontend assets. Run Docker-dependent
checks on a runner with an isolated Docker daemon.

Use read-only permissions for untrusted pull requests. Do not expose signing
keys, registry credentials, or deployment secrets to those jobs. Public build
caches must contain only public source and dependencies.

Record failed or unavailable checks in the job results. A missing tool or
external service requires a runner configuration fix before that check can pass.

# Branch protection

For routine development, configure protection on the default branch:

- Require a pull request and review before merging.
- Require the CI checks that are actually configured for this repository.
- Require resolved review conversations.
- Restrict force pushes and branch deletion.
- Grant release and repository administration permissions only to maintainers
  who need them.

Keep published release tags stable. Publish changed release artifacts under a
new version, or clearly document a replacement and its new hashes.

Apply these settings in the repository administration interface. Merely adding
this document to the repository does not configure branch protection.

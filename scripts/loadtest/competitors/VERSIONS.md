# Frozen competitor benchmark inputs

These image references are the repository's recorded benchmark pins. Version
labels identify the intended upstream release for each configuration; this
file does not assert that either is the latest release or report a performance
result. Runtime identity is selected by the digest, not by a mutable tag.

| Component | Recorded version label | Image reference |
|---|---|---|
| Bifrost | v2.4.0 | `maximhq/bifrost@sha256:a1c90607dcfd13c1fb2f9476ceb3bb24407a50ade7fdf3e61a59fb42b09e5c57` |
| LiteLLM Proxy | 1.108.0 | `ghcr.io/berriai/litellm@sha256:c560d317136880ea92d62334d4367ab10955b1af189dd3ea24f6551290b1d6c1` |

The references appear in the corresponding `docker-compose.yml` files and in
`validate-configs.sh`. Its static mode checks agreement with this document; it
does not fetch registry metadata or authenticate the relationship between a
version label, a tag and a digest.

## Updating a pin

1. Inspect the intended upstream release and resolve its immutable image
   digest. Record the registry response, source revision when available and
   selected platform manifest with the benchmark evidence.
2. Review the exact image contents and configuration contract, including
   authentication, upstream URL handling, worker settings and response
   transformations. Update the applicable configuration and Compose file.
3. Update this table and the expected digest in `validate-configs.sh` together.
4. Run static validation and then live validation as described in
   [README.md](README.md). Retain commands, environment, selected architecture,
   output and error counts; validation does not establish a performance ranking.

These third-party containers are optional test inputs and are not copied into
Yabanin's runtime image. Review the license files and notices of the exact
upstream source and image before redistributing them. A version label, absence
of an enterprise key or successful configuration validation does not establish
that all image contents have one license. The repository's own dependency
checks are not a complete license audit of these external images.

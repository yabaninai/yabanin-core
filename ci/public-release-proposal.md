# Release workflow

Release from a clean, tagged source tree. Record the source commit,
`SOURCE_DATE_EPOCH`, toolchain versions, and container base digests.

1. Build binaries and the container from the tagged source.
2. Generate software inventories and include the required third-party notices
   and corresponding source archives.
3. Run the checks selected for the release and document any known issues.
4. Sign the completed artifact checksums and container digest with the release
   key in a maintainer-controlled environment.
5. Upload the release files and verify the downloaded bytes and signatures.

`make release-artifacts` builds the five server binaries. The complete release
also needs the container image, source archives, notices, and verification
instructions. Store signing credentials outside the repository and public CI
caches. Repository workflow settings determine whether publication jobs run;
this document does not enable them.

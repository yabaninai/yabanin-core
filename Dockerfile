# Go multi-stage Dockerfile for yabanin services

# The tag component documents the toolchain; the digest is the actual pin.
# golang:1.27.3-alpine carries the standard-library security fixes from
# Go 1.27.3 (GO-2026-6809 / CVE-2026-111943: distrust of compromised
# intermediate certificates in crypto/x509, reachable via the loggerd S3
# export path; the root go.mod declares go 1.27.3, so the builder must be
# 1.27.3 or newer).
ARG GO_VERSION=1.27.3
FROM golang:${GO_VERSION}-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS builder

# Release rebuilds override this with a frozen mirror containing the original
# signed indices and every resolved APK, retained with a checksum manifest.
# Version pins alone do not freeze transitive dependencies or repository indices.
# Disable implicit repositories so a missing snapshot package cannot fall back
# to the live mirror. Keep /etc/apk/repositories unchanged in the image.
ARG APK_MIRROR=https://dl-cdn.alpinelinux.org/alpine

# Exact-version package pins: the apk repository index is a mutable input, so
# bare package names would let OS package bytes float between builds. Versions
# below were resolved inside this pinned builder image (alpine 3.24.3, base
# already ships ca-certificates at the same version). If the mirror drops a
# pinned version the build fails loudly instead of drifting.
RUN apk add --no-cache \
        --repositories-file /dev/null \
        --repository "${APK_MIRROR}/v3.24/main" \
        --repository "${APK_MIRROR}/v3.24/community" \
        ca-certificates=20261020-r0 \
        git=2.54.0-r0

WORKDIR /app

# Copy go mod files and download dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build all binaries
COPY . .

# Build the unified binary with the same recipe as
# scripts/release/release-artifacts.sh (CGO off, GOOS pinned, trimpath, no VCS
# stamping, env-normalized, stripped): one public source and one recipe give a
# byte-identical subject in the release set and inside this image. The runtime
# stage selects the service via the yabanin subcommand (compose `command:`),
# so there is no SERVICE build arg.
RUN CGO_ENABLED=0 GOOS=linux GOFLAGS= GOWORK=off go build \
        -trimpath -buildvcs=false \
        -ldflags "-s -w" \
        -o /bin/yabanin \
        ./cmd/yabanin

# Wall-clock normalization rationale (same pattern as Dockerfile.hardened;
# BUILD-20261102 A/B divergence fix, artifacts/internal-delivery-program/BUILD-20261102/
# repro-ab-20261102.md §2.2): go build stamps the binary with the builder-stage
# wall-clock mtime, and the final stage records it verbatim in the layer tar
# header, so two builds of the same commit seconds apart diverge in OCI layer
# digests. Normalizing the payload's mtime to SOURCE_DATE_EPOCH before it
# leaves this stage makes the final layers a pure function of (source tree,
# epoch). busybox touch -d @N parses the seconds-since-epoch form exactly.
ARG SOURCE_DATE_EPOCH
RUN case "${SOURCE_DATE_EPOCH:-}" in \
        ''|*[!0-9]*) \
            echo "FAIL: SOURCE_DATE_EPOCH must be an integer unix timestamp (got: '${SOURCE_DATE_EPOCH:-}')" >&2; \
            exit 1 ;; \
        esac
# The payload ships as a tar installed by the final stage: a plain `COPY`
# into a subdirectory bumps the parent directory's mtime to the COPY wall
# clock (observed: /app dir mtime 1793832992 vs 1793832995 across A/B builds)
# and BuildKit does not clamp that bump, while writes into `/` are not part
# of any layer diff. Pack /app/yabanin into /payload.tar, pin its mtime, and
# let the final stage untar + normalize inside a single RUN. The legal payload
# retains project, linked Go module/toolchain and versioned OS notice bytes.
# It does not replace the release source companion or human license review.
RUN mkdir -p /payload/app \
        && cp /bin/yabanin /payload/app/yabanin \
        && go run ./scripts/release/image-notices \
            -binary /bin/yabanin -source /app \
            -output /payload/usr/share/licenses/yabanin -epoch "${SOURCE_DATE_EPOCH}" \
        && find /payload -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} + \
        && tar -C /payload -cf /payload.tar app usr \
        && touch -d "@${SOURCE_DATE_EPOCH}" /payload.tar

# Final stage: supported Alpine 3.24 runtime; the digest is the actual pin.
FROM alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

# ARG values are stage-scoped; use the same frozen mirror in the runtime stage.
ARG APK_MIRROR=https://dl-cdn.alpinelinux.org/alpine

# Fail-loud epoch convention (same as Dockerfile.hardened and
# scripts/release/release-artifacts.sh): a missing or non-integer epoch must
# fail the build instead of silently leaving wall-clock bytes in the OCI
# layers. Always build with `--build-arg SOURCE_DATE_EPOCH=<integer>` (commit
# time per plans/internal-delivery-program-2026-10-31/REPRODUCIBLE-BUILDS.md §2).
ARG SOURCE_DATE_EPOCH
RUN case "${SOURCE_DATE_EPOCH:-}" in \
        ''|*[!0-9]*) \
            echo "FAIL: SOURCE_DATE_EPOCH must be an integer unix timestamp (got: '${SOURCE_DATE_EPOCH:-}')" >&2; \
            exit 1 ;; \
        esac

# Exact-version package pins (same rationale as the builder stage); libcurl is
# pinned alongside curl so the shared-library dependency cannot float within
# the index. Versions come from the retained signed Alpine 3.24 index.
# Keep an explicit security floor for musl, zlib and OpenSSL rather than
# assuming that a newer base digest upgrades every package. Alpine 3.24.4
# still carries zlib 1.3.2-r1; the pin below upgrades it to 1.4-r0.
# Alpine's v3.24 main security database maps CVE-2026-107891 to musl
# 1.2.6-r3, CVE-2026-85091 and CVE-2026-4738 to zlib 1.3.2-r1/1.4-r0, and
# CVE-2026-45447 to OpenSSL 3.5.7-r0. OpenSSL's 3.5.9 release notes
# additionally confirm the CVE-2026-84782 fix. These exact pins fail if
# unavailable; they are not a claim that future advisory coverage is clean.
# Sources: https://secdb.alpinelinux.org/v3.24/main.json
# https://openssl-library.org/news/openssl-3.5-notes/
# APK 3 writes wall-clock timestamps inside /var/log/apk.log. Disable only
# this build transaction's log-file write; BuildKit retains stdout/stderr and
# the package database is unchanged. Mtime normalization cannot fix log text.
# apk writes the package database and hundreds of directory entries with the
# wall-clock mtime of the apk invocation, so normalize the whole
# rootfs mtime in the same RUN — a later RUN could not repair this layer's
# digest retroactively. touch -h pins the SYMLINK's own mtime (the package
# trigger creates ~250 /etc/ssl/certs/*.0 links with wall-clock mtimes);
# default touch would follow the link and leave the leak in place.
# /proc /sys /dev are runtime mounts and /etc/hosts /etc/resolv.conf are
# read-only BuildKit bind mounts, not layer content.
RUN apk add --no-cache --logfile=no \
        --repositories-file /dev/null \
        --repository "${APK_MIRROR}/v3.24/main" \
        --repository "${APK_MIRROR}/v3.24/community" \
        ca-certificates=20261020-r0 \
        curl=8.23.0-r0 \
        libcurl=8.23.0-r0 \
        musl=1.2.6-r3 \
        zlib=1.4-r0 \
        libcrypto3=3.5.9-r0 \
        libssl3=3.5.9-r0 \
    && find / \( -path /proc -o -path /sys -o -path /dev \
        -o -path /etc/hosts -o -path /etc/resolv.conf \) -prune -o \
        -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

RUN addgroup -S yabanin && adduser -S yabanin -G yabanin \
    && find /etc /home \( -path /etc/hosts -o -path /etc/resolv.conf \) -prune -o \
        -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} +

WORKDIR /app

COPY --from=builder /payload.tar /payload.tar

# Install the payload (tar preserves the builder-normalized mtimes), remove
# the transport tar, fix ownership, and re-pin /app's mtime (untar bumped it
# to the RUN wall clock) — all within this one RUN so the layer digest is a
# pure function of (source tree, epoch).
RUN tar -C / -xf /payload.tar \
    && rm /payload.tar \
    && chown -R yabanin:yabanin /app \
    && find /app /usr/share/licenses/yabanin -exec touch -h -d "@${SOURCE_DATE_EPOCH}" {} + \
    && touch -d "@${SOURCE_DATE_EPOCH}" /usr /usr/share /usr/share/licenses

USER yabanin

ARG HEALTH_PORT=8082
EXPOSE ${HEALTH_PORT}

# Default to the unified binary (which dispatches to subcommands)
ENTRYPOINT ["/app/yabanin"]
CMD ["gateway"]

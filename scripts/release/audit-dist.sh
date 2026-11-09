#!/usr/bin/env bash
# Cross-compiles cmd/yb for the release platforms into dist/ with static
# linking (CGO_ENABLED=0), trimmed paths, and version/commit stamped via
# -ldflags, then emits a SHA256SUMS file so a downloader can verify a binary.
# dist/ is gitignored; the binaries are an artifact, not source.
# Override AUDIT_DIST_PLATFORMS to change the platform list.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

PLATFORMS="${AUDIT_DIST_PLATFORMS:-darwin/arm64 darwin/amd64 linux/amd64 linux/arm64}"

mkdir -p dist
VERSION=$(git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
for plat in $PLATFORMS; do
    GOOS=${plat%/*}; GOARCH=${plat#*/}
    out="dist/yb-$VERSION-$GOOS-$GOARCH"
    echo "building $out (CGO_ENABLED=0)"
    CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build \
        -trimpath \
        -ldflags "-s -w -X github.com/reireirei/yabanin/pkg/trcli.version=$VERSION -X github.com/reireirei/yabanin/pkg/trcli.commit=$COMMIT" \
        -o "$out" ./cmd/yb || exit 1
done
echo "computing SHA256SUMS"
cd dist && shasum -a 256 yb-* > SHA256SUMS && cat SHA256SUMS

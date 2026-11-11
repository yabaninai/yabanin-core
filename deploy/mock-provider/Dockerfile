FROM golang:1.27.4-alpine@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS builder
WORKDIR /app
COPY go.mod go.sum ./
# BuildKit cache mounts keep the module + build caches across rebuilds, so a
# mock source change no longer recompiles the whole Go standard library from
# an empty GOCACHE (the pre-fix cost of every `COPY . .` cache bust).
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download 2>/dev/null || true
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -o mock-provider .

# alpine:3.21 digest-pinned 2026-10-25 via `docker buildx imagetools inspect`
FROM alpine:3.21@sha256:bc21487101ae47172509130ee1092cc273a831968d64b617776d1f69c81e42ab
RUN apk --no-cache add wget ca-certificates
COPY --from=builder /app/mock-provider /usr/local/bin/
EXPOSE 8081
ENTRYPOINT ["mock-provider"]

# NEXT-16: run as non-root
USER nobody

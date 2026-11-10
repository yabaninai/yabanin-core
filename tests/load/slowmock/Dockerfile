FROM golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS builder
WORKDIR /app
COPY go.mod ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o slowmock .

# alpine:3.21 digest-pinned 2026-10-25 via `docker buildx imagetools inspect`
# (same pin as deploy/mock-provider — no new base images introduced)
FROM alpine:3.21@sha256:bc21487101ae47172509130ee1092cc273a831968d64b617776d1f69c81e42ab
RUN apk --no-cache add wget ca-certificates
COPY --from=builder /app/slowmock /usr/local/bin/
EXPOSE 8081
ENTRYPOINT ["slowmock"]

# run as non-root (NEXT-16 pattern)
USER nobody

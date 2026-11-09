FROM golang:1.27.3-alpine@sha256:d530cf60723abf1ffae0cd16bb546b379ec0550d2f3815e5b16ed69dbc00fba4 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o mock-provider .

# alpine:3.21 digest-pinned 2026-10-25 via `docker buildx imagetools inspect`
FROM alpine:3.21@sha256:ee16d92f96db08d9d2d07da48555a27f3a69d8f0759021dbc601195ed0d2b5bd
RUN apk --no-cache add wget ca-certificates
COPY --from=builder /app/mock-provider /usr/local/bin/
EXPOSE 8081
ENTRYPOINT ["mock-provider"]

# NEXT-16: run as non-root
USER nobody

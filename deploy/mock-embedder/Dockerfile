FROM golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o mock-embedder .

# alpine:3.21 digest-pinned 2026-10-25 via `docker buildx imagetools inspect`
FROM alpine:3.21@sha256:bc21487101ae47172509130ee1092cc273a831968d64b617776d1f69c81e42ab
RUN apk --no-cache add wget ca-certificates
COPY --from=builder /app/mock-embedder /usr/local/bin/
EXPOSE 6006
ENTRYPOINT ["mock-embedder"]

# NEXT-16: run as non-root
USER nobody

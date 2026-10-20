# Build Stage
FROM golang:1.27-alpine AS builder

WORKDIR /src
COPY go.mod ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o threat-engine ./cmd

# Minimal Final Image
FROM alpine:3.21

RUN apk add --no-cache ipset iptables ca-certificates tzdata

COPY --from=builder /src/threat-engine /usr/local/bin/threat-engine

ENTRYPOINT ["/usr/local/bin/threat-engine"]
# Build Stage
FROM golang:1.27-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/

RUN go mod download

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o threat-engine ./cmd

# Minimal Final Image
FROM alpine:3.21

RUN apk add --no-cache ipset iptables ca-certificates tzdata

COPY --from=builder /src/threat-engine /usr/local/bin/threat-engine

# The `enforce` alias. `docker exec threat-engine enforce off` reads better
# than repeating the binary name. The binary detects that it was invoked
# under this name and acts as the enforcement CLI, so the symlink never
# starts a second daemon.
RUN ln -s /usr/local/bin/threat-engine /usr/local/bin/enforce

ENTRYPOINT ["/usr/local/bin/threat-engine"]
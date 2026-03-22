# ============================================================
# Stage 1 – Build
# ============================================================
FROM golang:1.24-alpine AS builder

# Install git (needed for private modules, if any) and ca-certs
RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /src

# Cache dependency downloads separately from source
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire repo
COPY . .

# Build the server binary (static, no CGO)
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/server \
    ./server

# ============================================================
# Stage 2 – Runtime
# ============================================================
FROM scratch

# Bring in timezone data and root CA certs from builder
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy the compiled binary
COPY --from=builder /out/server /server

# Default config/key paths expected inside the container.
# Mount real config & keys at runtime via volumes (see docker-compose.yml).
WORKDIR /app

EXPOSE 8080

ENTRYPOINT ["/server"]
# Consumers can override the config path:  docker run ... -config /app/config.yaml
CMD ["-config", "/app/config.yaml"]


# Build stage for Go application
FROM golang:1.25-alpine AS builder

# Install build dependencies
RUN apk --no-cache add git

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o telescope .

# Multi-stage build for CA certificates
FROM alpine:3.19 AS certs
RUN apk --no-cache add ca-certificates tzdata

# Use scratch for minimal image
FROM scratch

# Add metadata
LABEL maintainer="robert-jan.boezeman@enexis.nl"
LABEL description="Telescope - Cilium Network Policy Violation Monitor"
LABEL version="1.0.0"

# Copy CA certificates from alpine stage
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Copy timezone data for time operations
COPY --from=certs /usr/share/zoneinfo /usr/share/zoneinfo

# Copy the compiled static binary from builder stage
COPY --from=builder /app/telescope /telescope

# Default environment variables for configuration
ENV HUBBLE_ENDPOINT="hubble-relay.kube-system.svc.cluster.local:80"
ENV NAMESPACE=""
ENV SINCE="1h"
ENV TLS_ENABLED="false"
ENV TLS_SKIP_VERIFY="false"
ENV VERBOSE="false"

# Expose no ports (this is a client application)

# Use the binary as entrypoint with configurable arguments
ENTRYPOINT ["/telescope"]

# Default CMD will be overridden by environment variables in Kubernetes
CMD []
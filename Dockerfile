# Multi-stage Dockerfile for the Vaultwarden exporter

# =============================================================================
# Stage 1: Builder
# =============================================================================
# Base images pinned by digest, updated by Dependabot
FROM --platform=$BUILDPLATFORM golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS builder

# Target platform, set automatically by Docker Buildx
ARG TARGETOS
ARG TARGETARCH
ARG TARGETVARIANT

WORKDIR /build

# Download modules first for better layer caching
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

# Build metadata
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

# Static binary: every driver is pure Go (pgx, go-sql-driver/mysql, modernc
# sqlite), so CGO stays disabled
RUN GOARM="${TARGETVARIANT#v}" CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
    -ldflags="-s -w \
      -X 'main.version=${VERSION}' \
      -X 'main.commit=${COMMIT}' \
      -X 'main.buildDate=${BUILD_DATE}'" \
    -o vaultwarden-exporter \
    ./cmd/vaultwarden-exporter

# =============================================================================
# Stage 2: Runtime image (distroless, non-root)
# =============================================================================
FROM gcr.io/distroless/static:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329

ARG VERSION=dev
ARG COMMIT=unknown

LABEL org.opencontainers.image.title="Vaultwarden Exporter" \
      org.opencontainers.image.description="Prometheus metrics and audit event stream for Vaultwarden" \
      org.opencontainers.image.vendor="Maxime Wewer" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.source="https://github.com/MaximeWewer/vaultwarden-exporter" \
      org.opencontainers.image.documentation="https://github.com/MaximeWewer/vaultwarden-exporter/blob/main/README.md"

COPY --from=builder /build/vaultwarden-exporter /vaultwarden-exporter

USER nonroot:nonroot

EXPOSE 9776

# Distroless has no shell: the binary checks its own /healthz endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/vaultwarden-exporter", "--healthcheck"]

ENTRYPOINT ["/vaultwarden-exporter"]

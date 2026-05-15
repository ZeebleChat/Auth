# Builder stage
FROM rust:1.93-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy manifests
COPY Cargo.toml ./
COPY Cargo.lock ./

# Copy source code
COPY src ./src
COPY migrations ./migrations

# Build release binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Create keys directory
RUN mkdir -p /keys

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/target/release/zeeble-auth /usr/local/bin/zeeble-auth

EXPOSE 8001

VOLUME /keys

HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=3 \
    CMD wget -qO- http://localhost:8001/health || exit 1

CMD ["zeeble-auth"]

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

# Expose auth server port
EXPOSE 3001

# Declare volume
VOLUME /keys

# Run the auth server
CMD ["zeeble-auth"]

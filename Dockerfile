# ---------------------------------------------------
# Stage 1: Build the Rust Binary
# ---------------------------------------------------
FROM rust:slim-bullseye AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev clang && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/aegisdns
COPY . .

# Build the release binaries
RUN cargo build --release

# ---------------------------------------------------
# Stage 2: Minimal Runtime Environment
# ---------------------------------------------------
FROM debian:bullseye-slim

# Install runtime dependency: unbound
RUN apt-get update && \
    apt-get install -y unbound ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Prevent system unbound from running automatically (AegisDNS manages it)
RUN update-rc.d -f unbound remove || true

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /usr/src/aegisdns/target/release/aegisdnsd /usr/local/bin/aegisdnsd


# Copy Web Dashboard UI
RUN mkdir -p /usr/share/aegisdns/ui
COPY ui /usr/share/aegisdns/ui

# Create runtime directories
RUN mkdir -p /run/aegisdns /var/lib/aegisdns

# Expose required ports
# 53 (UDP/TCP): DNS Server
# 5380 (TCP): Web Dashboard
# 80 (TCP): Block Page
EXPOSE 53/udp 53/tcp 5380/tcp 80/tcp

# Run AegisDNS Daemon
CMD ["aegisdnsd"]

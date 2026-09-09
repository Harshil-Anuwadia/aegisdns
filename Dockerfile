FROM node:22-bookworm-slim AS dashboard
WORKDIR /ui
COPY ui/package.json ui/package-lock.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build

FROM rust:slim-bookworm AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev clang && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/src/aegisdns
COPY . .
ENV CARGO_REGISTRIES_CRATES_IO_PROTOCOL=sparse
RUN cargo build --release --locked --bin aegisdnsd

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y unbound unbound-anchor ca-certificates openssl util-linux tzdata && \
    rm -rf /var/lib/apt/lists/* && \
    groupadd -g 10001 aegis && useradd -u 10001 -g aegis -M -s /usr/sbin/nologin aegis
WORKDIR /app
COPY --from=builder /usr/src/aegisdns/target/release/aegisdnsd /usr/local/bin/aegisdnsd
COPY --from=dashboard /ui/dist /usr/share/aegisdns/ui
COPY docker-entrypoint.sh /usr/local/bin/aegis-entrypoint
RUN chmod 755 /usr/local/bin/aegis-entrypoint && mkdir -p /run/aegisdns /var/lib/aegisdns
EXPOSE 53/udp 53/tcp 5380/tcp 5381/tcp
ENTRYPOINT ["/usr/local/bin/aegis-entrypoint"]

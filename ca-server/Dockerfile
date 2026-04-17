# Copyright 2026 INNO LOTUS PTY LTD
# SPDX-License-Identifier: Apache-2.0

# ── Build ─────────────────────────────────────────────────────────────────────
FROM rust:1.87-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock* ./
COPY src/ src/
COPY db/  db/

RUN cargo build --release

# ── Runtime ───────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd --gid 1001 nipca \
 && useradd  --uid 1001 --gid 1001 --no-create-home nipca \
 && mkdir -p /data && chown nipca:nipca /data

COPY --from=builder /build/target/release/nip-ca-server /usr/local/bin/nip-ca-server

USER nipca

EXPOSE 17440

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD sh -c 'printf "GET /health HTTP/1.0\r\nHost: localhost\r\n\r\n" | nc -w2 localhost 17440 | grep -q "ok"'

CMD ["nip-ca-server"]

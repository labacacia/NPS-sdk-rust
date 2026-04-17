English | [中文版](./ca-server.cn.md)

# NIP CA Server — Rust / Axum

A lightweight Certificate Authority server implementing the NIP (Neural Identity Protocol) certificate lifecycle. Built with Rust stable, Axum 0.8, rusqlite, and Docker.

---

## Overview

The NIP CA Server issues, renews, revokes, and verifies NPS agent/node identities. It exposes a REST API over HTTP, stores state in a SQLite database, and ships a Docker Compose file for zero-config deployment.

**Technology stack**

| Component | Library |
|-----------|---------|
| HTTP framework | Axum 0.8 |
| Database | rusqlite 0.32 (bundled SQLite) |
| Crypto | ed25519-dalek 2, aes-gcm 0.10, pbkdf2 0.12 |
| Async runtime | Tokio 1 |
| Logging | tracing + tracing-subscriber |

---

## Quick Start

### Docker (Recommended)

```bash
cd ca-server/
docker compose up -d
```

The server listens on port **8080** by default. The CA key and database are persisted in a Docker volume.

### Cargo

```bash
cd ca-server/
cargo run --release
```

Set environment variables to override defaults:

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | HTTP listen port |
| `DB_PATH` | `./ca.db` | SQLite database file path |
| `CA_KEY_PASS` | _(required)_ | Passphrase for CA private key encryption |

---

## REST API

Base path: `/v1`

### Agent Registration

**POST** `/v1/agents/register`

Register a new agent identity. Generates an Ed25519 key pair, issues an identity certificate, and returns the NID.

```json
Request body:
{
  "label": "my-agent",
  "metadata": {}
}

Response 200:
{
  "nid": "nps-agent-abc123",
  "certificate": "<base64>",
  "private_key_encrypted": "<base64>"
}
```

### Node Registration

**POST** `/v1/nodes/register`

Register a new node identity (same flow as agent registration, sets entity type to `node`).

```json
Request body:
{
  "label": "my-node",
  "metadata": {}
}
```

### Renew Certificate

**POST** `/v1/agents/:nid/renew`

Renew the certificate for the given NID. The previous certificate is invalidated and a new one is issued with a refreshed validity period.

```
POST /v1/agents/nps-agent-abc123/renew
```

### Revoke Certificate

**POST** `/v1/agents/:nid/revoke`

Revoke the certificate for the given NID. The entry is marked revoked in the database and will appear in the CRL.

```
POST /v1/agents/nps-agent-abc123/revoke
```

### Verify Certificate

**GET** `/v1/agents/:nid/verify`

Check whether the NID has a currently active, non-revoked certificate.

```
GET /v1/agents/nps-agent-abc123/verify
```

```json
Response 200:
{
  "nid": "nps-agent-abc123",
  "status": "active",
  "expires_at": "2027-04-17T00:00:00Z"
}
```

### Get CA Certificate

**GET** `/v1/ca/cert`

Retrieve the CA's public certificate (Ed25519 public key, base64-encoded).

```json
Response 200:
{
  "ca_cert": "<base64>",
  "algorithm": "Ed25519"
}
```

### Certificate Revocation List

**GET** `/v1/crl`

Retrieve the current Certificate Revocation List. Returns a list of revoked NIDs and their revocation timestamps.

```json
Response 200:
{
  "revoked": [
    { "nid": "nps-agent-xyz", "revoked_at": "2026-04-01T12:00:00Z" }
  ]
}
```

### Well-Known Discovery

**GET** `/.well-known/nps-ca`

NPS-standard well-known endpoint for CA discovery. Returns CA metadata including the public cert endpoint and CRL URL.

```json
Response 200:
{
  "ca_cert_url": "/v1/ca/cert",
  "crl_url":     "/v1/crl",
  "algorithm":   "Ed25519"
}
```

### Health Check

**GET** `/health`

Liveness probe. Returns `{"status": "ok"}` when the server is running.

---

## Building

```bash
cd ca-server/

# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test
```

---

## Docker Compose

The `ca-server/docker-compose.yml` mounts a local `./data/` directory for database and key persistence:

```yaml
services:
  nip-ca:
    build: .
    ports:
      - "8080:8080"
    environment:
      - CA_KEY_PASS=${CA_KEY_PASS}
    volumes:
      - ./data:/data
```

Set `CA_KEY_PASS` in your environment before running `docker compose up -d`.

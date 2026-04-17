English | [中文版](./sdk-usage.cn.md)

# NPS Rust SDK — Usage Guide

Copyright 2026 INNO LOTUS PTY LTD — Licensed under Apache 2.0

---

## Overview

The NPS Rust SDK (`nps-sdk`) provides a complete, production-ready implementation of the Neural Protocol Suite for Rust applications. The SDK is organized as a Cargo workspace with protocol-level crates that can be used individually or through the umbrella `nps-sdk` crate.

- **Crate group**: `nps-sdk` and sub-crates on crates.io
- **Rust**: stable (1.70+)
- **Async runtime**: Tokio
- **Default port**: 17433

---

## Workspace Crates

| Crate | Description |
|-------|-------------|
| `nps-core` | Frame header, codec (Tier-1 JSON / Tier-2 MsgPack), frame registry, anchor cache, error types |
| `nps-ncp` | AnchorFrame, DiffFrame, StreamFrame, CapsFrame, ErrorFrame |
| `nps-nwp` | QueryFrame, ActionFrame, AsyncActionResponse, NwpClient (reqwest) |
| `nps-nip` | IdentFrame, TrustFrame, RevokeFrame, NipIdentity (Ed25519 + AES-256-GCM key encryption) |
| `nps-ndp` | AnnounceFrame, ResolveFrame, GraphFrame, InMemoryNdpRegistry, NdpAnnounceValidator |
| `nps-nop` | TaskFrame, DelegateFrame, SyncFrame, AlignStreamFrame, BackoffStrategy, NopClient |
| `nps-sdk` | Re-export umbrella crate (all protocols via feature flags) |

---

## Installation

### Using the Umbrella Crate (Recommended)

```toml
[dependencies]
nps-sdk = "1.0.0-alpha.1"
tokio   = { version = "1", features = ["full"] }
```

By default all protocol features (`nwp`, `nip`, `ndp`, `nop`) are enabled. To select specific protocols:

```toml
[dependencies]
nps-sdk = { version = "1.0.0-alpha.1", default-features = false, features = ["nwp", "nip"] }
```

### Using Individual Crates

```toml
[dependencies]
nps-core = "1.0.0-alpha.1"
nps-ncp  = "1.0.0-alpha.1"
nps-nwp  = "1.0.0-alpha.1"
nps-nip  = "1.0.0-alpha.1"
nps-ndp  = "1.0.0-alpha.1"
nps-nop  = "1.0.0-alpha.1"
tokio    = { version = "1", features = ["full"] }
```

---

## Quick Start

### Encode and Send a Query Frame (NWP)

```rust
use nps_sdk::nwp::{QueryFrame, NwpClient};
use nps_sdk::core::Codec;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Build a query frame
    let frame = QueryFrame {
        query_id: "q-001".to_string(),
        anchor_id: "anchor-abc".to_string(),
        payload: serde_json::json!({ "filter": "active" }),
        metadata: Default::default(),
    };

    // Encode to MsgPack (Tier-2)
    let bytes = Codec::encode_msgpack(&frame)?;

    // Send to a Memory Node on default port
    let client = NwpClient::new("http://localhost:17433");
    let response = client.query(&frame).await?;

    println!("Response: {:?}", response);
    Ok(())
}
```

### Generate an Ed25519 Identity (NIP)

```rust
use nps_sdk::nip::NipIdentity;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Generate a new identity (key pair)
    let identity = NipIdentity::generate()?;
    println!("NID: {}", identity.nid());

    // Export encrypted private key (AES-256-GCM, PBKDF2 key derivation)
    let encrypted = identity.export_encrypted_key("my-passphrase")?;

    // Reload from encrypted blob
    let restored = NipIdentity::from_encrypted_key(&encrypted, "my-passphrase")?;
    assert_eq!(identity.nid(), restored.nid());

    Ok(())
}
```

### Register with a Discovery Node (NDP)

```rust
use nps_sdk::ndp::{AnnounceFrame, InMemoryNdpRegistry};

fn main() -> anyhow::Result<()> {
    let mut registry = InMemoryNdpRegistry::new();

    let announce = AnnounceFrame {
        nid:      "agent-001".to_string(),
        endpoint: "http://localhost:17433".to_string(),
        ttl:      3600,
        metadata: Default::default(),
    };

    registry.announce(announce)?;

    let resolved = registry.resolve("agent-001")?;
    println!("Endpoint: {}", resolved.endpoint);

    Ok(())
}
```

### Submit an Orchestration Task (NOP)

```rust
use nps_sdk::nop::{TaskFrame, NopClient, BackoffStrategy};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client = NopClient::builder()
        .endpoint("http://localhost:17433")
        .backoff(BackoffStrategy::exponential(100, 2.0, 30_000))
        .build();

    let task = TaskFrame {
        task_id:   "task-xyz".to_string(),
        dag_nodes: vec!["step-1".to_string(), "step-2".to_string()],
        payload:   serde_json::json!({ "input": "hello" }),
        metadata:  Default::default(),
    };

    let result = client.submit_task(&task).await?;
    println!("Task status: {:?}", result.status);

    Ok(())
}
```

---

## API Reference

### `nps-core`

- `Codec` — `encode_json()`, `decode_json()`, `encode_msgpack()`, `decode_msgpack()`
- `FrameRegistry` — frame type lookup by opcode
- `AnchorCache` — TTL-based anchor schema cache (default TTL: 3600 s)
- `NpsError` — unified error enum for all protocol layers

### `nps-ncp`

- `AnchorFrame` — schema declaration (opcode `0x01`)
- `DiffFrame` — incremental schema update (opcode `0x02`)
- `StreamFrame` — streaming data chunk (opcode `0x03`)
- `CapsFrame` — capability negotiation (opcode `0x04`)
- `ErrorFrame` — unified error carrier (opcode `0xFE`)

### `nps-nwp`

- `QueryFrame` — read request (opcode `0x10`)
- `ActionFrame` — write/mutate request (opcode `0x11`)
- `AsyncActionResponse` — async task acknowledgement
- `NwpClient` — HTTP-mode client (reqwest); connects to port 17433 by default

### `nps-nip`

- `NipIdentity` — Ed25519 key pair with AES-256-GCM encrypted storage
- `IdentFrame` — identity assertion (opcode `0x20`)
- `TrustFrame` — signed trust delegation (opcode `0x21`)
- `RevokeFrame` — certificate revocation (opcode `0x22`)

### `nps-ndp`

- `AnnounceFrame` — node announcement (opcode `0x30`)
- `ResolveFrame` — resolution request (opcode `0x31`)
- `GraphFrame` — topology graph snapshot (opcode `0x32`)
- `InMemoryNdpRegistry` — in-process registry for tests and embedded use
- `NdpAnnounceValidator` — validates announce fields and TTL

### `nps-nop`

- `TaskFrame` — orchestration task definition (opcode `0x40`)
- `DelegateFrame` — delegation to sub-agent, max chain depth 3 (opcode `0x41`)
- `SyncFrame` — DAG synchronisation (opcode `0x42`)
- `AlignStreamFrame` — stream alignment with task context and NID binding (opcode `0x43`)
- `BackoffStrategy` — exponential / linear backoff for retries (respects HTTP 429)
- `NopClient` — HTTP-mode orchestration client

---

## Testing

```bash
# Run all tests in the workspace
cargo test --workspace

# Run tests for a specific crate
cargo test -p nps-nip

# Run tests with output
cargo test --workspace -- --nocapture
```

The workspace ships with 88 tests covering frame encoding/decoding, identity lifecycle, discovery registry, and orchestration logic.

---

## Feature Flags (`nps-sdk`)

| Feature | Enables |
|---------|---------|
| `nwp` (default) | `nps-nwp` |
| `nip` (default) | `nps-nip` |
| `ndp` (default) | `nps-ndp` + `nps-nip` |
| `nop` (default) | `nps-nop` |

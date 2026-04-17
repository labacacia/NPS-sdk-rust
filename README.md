# NPS Rust SDK

[![Crates.io](https://img.shields.io/crates/v/nps-sdk)](https://crates.io/crates/nps-sdk)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](./LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange)](https://www.rust-lang.org/)

Async Rust SDK for the **Neural Protocol Suite (NPS)** — a complete internet protocol stack purpose-built for AI Agents and models.

Workspace: `nps-core`, `nps-ncp`, `nps-nwp`, `nps-nip`, `nps-ndp`, `nps-nop`, `nps-sdk` (façade).

---

## NPS Repositories

| Repo | Role | Language |
|------|------|----------|
| [NPS-Release](https://github.com/labacacia/NPS-Release) | Protocol specifications (authoritative) | Markdown / YAML |
| [NPS-sdk-dotnet](https://github.com/labacacia/NPS-sdk-dotnet) | Reference implementation | C# / .NET 10 |
| [NPS-sdk-py](https://github.com/labacacia/NPS-sdk-py) | Async Python SDK | Python 3.11+ |
| [NPS-sdk-ts](https://github.com/labacacia/NPS-sdk-ts) | Node/browser SDK | TypeScript |
| [NPS-sdk-java](https://github.com/labacacia/NPS-sdk-java) | JVM SDK | Java 21+ |
| **[NPS-sdk-rust](https://github.com/labacacia/NPS-sdk-rust)** (this repo) | Async SDK | Rust stable |
| [NPS-sdk-go](https://github.com/labacacia/NPS-sdk-go) | Go SDK | Go 1.23+ |

---

## Status

**v1.0.0-alpha.1 — Phase 1 release**

Covers all five NPS protocols: NCP + NWP + NIP + NDP + NOP. 88 tests passing.

## Requirements

- Rust 1.75+ (stable)
- Core dependencies: `serde`, `rmp-serde`, `sha2`, `ed25519-dalek`, `aes-gcm`, `tokio`, `reqwest`

## Installation

```toml
[dependencies]
nps-sdk = "1.0.0-alpha.1"              # full-façade crate (re-exports everything)
# or pick only what you need:
nps-core = "1.0.0-alpha.1"
nps-ncp  = "1.0.0-alpha.1"
nps-nwp  = "1.0.0-alpha.1"
nps-nip  = "1.0.0-alpha.1"
nps-ndp  = "1.0.0-alpha.1"
nps-nop  = "1.0.0-alpha.1"
```

## Crates

| Crate | Description | Reference |
|-------|-------------|-----------|
| `nps-core` | Frame header, codec (Tier-1 JSON / Tier-2 MsgPack), frame registry, anchor cache, errors | [`doc/nps-rust.core.md`](./doc/nps-rust.core.md) |
| `nps-ncp`  | NCP frame types (`AnchorFrame`, `DiffFrame`, `StreamFrame`, `CapsFrame`, `ErrorFrame`) | [`doc/nps-rust.ncp.md`](./doc/nps-rust.ncp.md) |
| `nps-nwp`  | `QueryFrame`, `ActionFrame`; async `NwpClient` over `reqwest` | [`doc/nps-rust.nwp.md`](./doc/nps-rust.nwp.md) |
| `nps-nip`  | `NipIdentity` (Ed25519), encrypted key store (AES-256-GCM + PBKDF2), Ident/Trust/Revoke frames | [`doc/nps-rust.nip.md`](./doc/nps-rust.nip.md) |
| `nps-ndp`  | Announce/Resolve/Graph frames, in-memory registry, signature validator | [`doc/nps-rust.ndp.md`](./doc/nps-rust.ndp.md) |
| `nps-nop`  | Task/Delegate/Sync/AlignStream frames, DAG models, async orchestrator client | [`doc/nps-rust.nop.md`](./doc/nps-rust.nop.md) |
| `nps-sdk`  | Meta-crate: re-exports the six protocol crates under `nps_sdk::{core, ncp, nwp, nip, ndp, nop}` | — |

Full API reference (per-crate class and method docs) lives under [`doc/`](./doc/) — start with [`doc/overview.md`](./doc/overview.md). For a narrative walkthrough see [`doc/sdk-usage.md`](./doc/sdk-usage.md) / [`doc/sdk-usage.cn.md`](./doc/sdk-usage.cn.md).

## Quick Start

### Encode / decode frames

```rust
use nps_core::{FrameCodec, Registry};
use nps_ncp::{AnchorFrame, FrameSchema, SchemaField};

let registry = Registry::default();
let codec    = FrameCodec::new(&registry);

let schema = FrameSchema {
    fields: vec![
        SchemaField { name: "id".into(),    r#type: "uint64".into(),  ..Default::default() },
        SchemaField { name: "price".into(), r#type: "decimal".into(), semantic: Some("commerce.price.usd".into()), ..Default::default() },
    ],
};
let frame = AnchorFrame::new(&schema, 3600);

let wire  = codec.encode(&frame)?;            // Tier-2 MsgPack by default
let back: AnchorFrame = codec.decode(&wire)?;
```

### NWP client

```rust
use nps_nwp::{NwpClient, QueryFrame};

let client = NwpClient::new("http://node.example.com:17433");
let caps   = client.query(QueryFrame { anchor_ref: Some("sha256:…".into()), limit: 50, ..Default::default() }).await?;
```

### NIP identity

```rust
use nps_nip::Identity;

let id = Identity::generate();
id.save("node.key", "my-passphrase")?;     // AES-256-GCM + PBKDF2

let loaded = Identity::load("node.key", "my-passphrase")?;
let sig    = loaded.sign(&payload)?;
let ok     = loaded.verify(&payload, &sig)?;
```

### NOP orchestration

```rust
use nps_nop::{NopClient, TaskFrame, TaskDag};

let client = NopClient::new("http://orchestrator.example.com:17433");
let task_id = client.submit(TaskFrame { task_id: "job-1".into(), dag }).await?;
let status  = client.wait(&task_id, std::time::Duration::from_secs(30)).await?;
```

## Encoding Tiers

| Tier | Value | Description |
|------|-------|-------------|
| Tier-1 JSON    | `0x00` | UTF-8 JSON, development / interop |
| Tier-2 MsgPack | `0x01` | MsgPack binary, ~60% smaller, production default |

## NIP CA Server

A standalone NIP Certificate Authority server is bundled under [`nip-ca-server/`](./nip-ca-server/) — Axum, SQLite-backed, Docker-ready.

## Build & Test

```bash
cargo build --workspace
cargo test  --workspace      # 88 tests
```

## License

Apache 2.0 — see [LICENSE](./LICENSE) and [NOTICE](./NOTICE).

Copyright 2026 INNO LOTUS PTY LTD

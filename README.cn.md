[English Version](./README.md) | 中文版

# NPS Rust SDK

[![Crates.io](https://img.shields.io/crates/v/nps-sdk)](https://crates.io/crates/nps-sdk)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](./LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange)](https://www.rust-lang.org/)

**Neural Protocol Suite (NPS)** 的异步 Rust SDK —— 专为 AI Agent 与神经模型设计的完整互联网协议栈。

Workspace：`nps-core`、`nps-ncp`、`nps-nwp`、`nps-nip`、`nps-ndp`、`nps-nop`、`nps-sdk`（facade）。

---

## NPS 仓库导航

| 仓库 | 职责 | 语言 |
|------|------|------|
| [NPS-Release](https://github.com/labacacia/NPS-Release) | 协议规范（权威来源） | Markdown / YAML |
| [NPS-sdk-dotnet](https://github.com/labacacia/NPS-sdk-dotnet) | 参考实现 | C# / .NET 10 |
| [NPS-sdk-py](https://github.com/labacacia/NPS-sdk-py) | 异步 Python SDK | Python 3.11+ |
| [NPS-sdk-ts](https://github.com/labacacia/NPS-sdk-ts) | Node/浏览器 SDK | TypeScript |
| [NPS-sdk-java](https://github.com/labacacia/NPS-sdk-java) | JVM SDK | Java 21+ |
| **[NPS-sdk-rust](https://github.com/labacacia/NPS-sdk-rust)**（本仓库） | 异步 SDK | Rust stable |
| [NPS-sdk-go](https://github.com/labacacia/NPS-sdk-go) | Go SDK | Go 1.23+ |

---

## 状态

**v1.0.0-alpha.1 — Phase 1 发布**

覆盖 NPS 全部五个协议：NCP + NWP + NIP + NDP + NOP，88 个测试全部通过。

## 运行要求

- Rust 1.75+（stable）
- 核心依赖：`serde`、`rmp-serde`、`sha2`、`ed25519-dalek`、`aes-gcm`、`tokio`、`reqwest`

## 安装

```toml
[dependencies]
nps-sdk = "1.0.0-alpha.1"              # 全量 facade crate（重新导出所有内容）
# 或按需挑选：
nps-core = "1.0.0-alpha.1"
nps-ncp  = "1.0.0-alpha.1"
nps-nwp  = "1.0.0-alpha.1"
nps-nip  = "1.0.0-alpha.1"
nps-ndp  = "1.0.0-alpha.1"
nps-nop  = "1.0.0-alpha.1"
```

## Crates

| Crate | 说明 | 参考文档 |
|-------|------|----------|
| `nps-core` | 帧头、编解码（Tier-1 JSON / Tier-2 MsgPack）、帧注册表、AnchorFrame 缓存、错误 | [`doc/nps-rust.core.cn.md`](./doc/nps-rust.core.cn.md) |
| `nps-ncp`  | NCP 帧类型（`AnchorFrame`、`DiffFrame`、`StreamFrame`、`CapsFrame`、`ErrorFrame`） | [`doc/nps-rust.ncp.cn.md`](./doc/nps-rust.ncp.cn.md) |
| `nps-nwp`  | `QueryFrame`、`ActionFrame`；基于 `reqwest` 的异步 `NwpClient` | [`doc/nps-rust.nwp.cn.md`](./doc/nps-rust.nwp.cn.md) |
| `nps-nip`  | `NipIdentity`（Ed25519）、加密密钥存储（AES-256-GCM + PBKDF2）、Ident/Trust/Revoke 帧 | [`doc/nps-rust.nip.cn.md`](./doc/nps-rust.nip.cn.md) |
| `nps-ndp`  | Announce/Resolve/Graph 帧、内存注册表、签名验证器 | [`doc/nps-rust.ndp.cn.md`](./doc/nps-rust.ndp.cn.md) |
| `nps-nop`  | Task/Delegate/Sync/AlignStream 帧、DAG 模型、异步编排客户端 | [`doc/nps-rust.nop.cn.md`](./doc/nps-rust.nop.cn.md) |
| `nps-sdk`  | 元 crate：将六个协议 crate 以 `nps_sdk::{core, ncp, nwp, nip, ndp, nop}` 形式重新导出 | — |

完整 API 参考（按 crate 分的类与方法文档）见 [`doc/`](./doc/) —— 从 [`doc/overview.cn.md`](./doc/overview.cn.md) 入门。叙事性教程参见 [`doc/sdk-usage.cn.md`](./doc/sdk-usage.cn.md) / [`doc/sdk-usage.md`](./doc/sdk-usage.md)。

## 快速开始

### 编解码帧

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

let wire  = codec.encode(&frame)?;            // 默认 Tier-2 MsgPack
let back: AnchorFrame = codec.decode(&wire)?;
```

### NWP 客户端

```rust
use nps_nwp::{NwpClient, QueryFrame};

let client = NwpClient::new("http://node.example.com:17433");
let caps   = client.query(QueryFrame { anchor_ref: Some("sha256:…".into()), limit: 50, ..Default::default() }).await?;
```

### NIP 身份

```rust
use nps_nip::Identity;

let id = Identity::generate();
id.save("node.key", "my-passphrase")?;     // AES-256-GCM + PBKDF2

let loaded = Identity::load("node.key", "my-passphrase")?;
let sig    = loaded.sign(&payload)?;
let ok     = loaded.verify(&payload, &sig)?;
```

### NOP 编排

```rust
use nps_nop::{NopClient, TaskFrame, TaskDag};

let client = NopClient::new("http://orchestrator.example.com:17433");
let task_id = client.submit(TaskFrame { task_id: "job-1".into(), dag }).await?;
let status  = client.wait(&task_id, std::time::Duration::from_secs(30)).await?;
```

## 编码分层

| Tier | 值 | 说明 |
|------|----|------|
| Tier-1 JSON    | `0x00` | UTF-8 JSON，开发 / 互操作 |
| Tier-2 MsgPack | `0x01` | MsgPack 二进制，约小 60%，生产默认 |

## NIP CA Server

`nip-ca-server/` 目录提供一个独立 NIP 证书颁发机构服务 —— 基于 Axum，SQLite 存储，开箱即用的 Docker 部署。详见 [`doc/ca-server.cn.md`](./doc/ca-server.cn.md)。

## 构建与测试

```bash
cargo build --workspace
cargo test  --workspace      # 88 个测试
```

## 许可证

Apache 2.0 —— 详见 [LICENSE](./LICENSE) 与 [NOTICE](./NOTICE)。

Copyright 2026 INNO LOTUS PTY LTD

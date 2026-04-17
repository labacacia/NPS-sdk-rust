[English Version](./sdk-usage.md) | 中文版

# NPS Rust SDK — 使用指南

Copyright 2026 INNO LOTUS PTY LTD — 基于 Apache 2.0 授权

---

## 概述

NPS Rust SDK（`nps-sdk`）为 Rust 应用提供完整的 Neural Protocol Suite 生产级实现。SDK 采用 Cargo workspace 组织，包含协议级独立 crate，可单独使用也可通过统一的 `nps-sdk` 伞形 crate 引入。

- **Crate 组**: `nps-sdk` 及子 crate，发布于 crates.io
- **Rust**: stable（1.70+）
- **异步运行时**: Tokio
- **默认端口**: 17433

---

## Workspace Crate 列表

| Crate | 描述 |
|-------|------|
| `nps-core` | 帧头、编解码器（Tier-1 JSON / Tier-2 MsgPack）、帧注册表、Anchor 缓存、错误类型 |
| `nps-ncp` | AnchorFrame、DiffFrame、StreamFrame、CapsFrame、ErrorFrame |
| `nps-nwp` | QueryFrame、ActionFrame、AsyncActionResponse、NwpClient（reqwest） |
| `nps-nip` | IdentFrame、TrustFrame、RevokeFrame、NipIdentity（Ed25519 + AES-256-GCM 密钥加密） |
| `nps-ndp` | AnnounceFrame、ResolveFrame、GraphFrame、InMemoryNdpRegistry、NdpAnnounceValidator |
| `nps-nop` | TaskFrame、DelegateFrame、SyncFrame、AlignStreamFrame、BackoffStrategy、NopClient |
| `nps-sdk` | 伞形 crate（通过 feature flag 按需启用各协议） |

---

## 安装

### 使用伞形 Crate（推荐）

```toml
[dependencies]
nps-sdk = "1.0.0-alpha.1"
tokio   = { version = "1", features = ["full"] }
```

默认情况下，所有协议 feature（`nwp`、`nip`、`ndp`、`nop`）均已启用。如需按需选择：

```toml
[dependencies]
nps-sdk = { version = "1.0.0-alpha.1", default-features = false, features = ["nwp", "nip"] }
```

### 使用独立 Crate

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

## 快速开始

### 编码并发送查询帧（NWP）

```rust
use nps_sdk::nwp::{QueryFrame, NwpClient};
use nps_sdk::core::Codec;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 构建查询帧
    let frame = QueryFrame {
        query_id:  "q-001".to_string(),
        anchor_id: "anchor-abc".to_string(),
        payload:   serde_json::json!({ "filter": "active" }),
        metadata:  Default::default(),
    };

    // 编码为 MsgPack（Tier-2，~60% 体积压缩）
    let bytes = Codec::encode_msgpack(&frame)?;

    // 向默认端口的 Memory Node 发送请求
    let client = NwpClient::new("http://localhost:17433");
    let response = client.query(&frame).await?;

    println!("响应: {:?}", response);
    Ok(())
}
```

### 生成 Ed25519 身份（NIP）

```rust
use nps_sdk::nip::NipIdentity;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // 生成新身份（密钥对）
    let identity = NipIdentity::generate()?;
    println!("NID: {}", identity.nid());

    // 导出加密私钥（AES-256-GCM，PBKDF2 密钥派生）
    let encrypted = identity.export_encrypted_key("my-passphrase")?;

    // 从加密 blob 还原身份
    let restored = NipIdentity::from_encrypted_key(&encrypted, "my-passphrase")?;
    assert_eq!(identity.nid(), restored.nid());

    Ok(())
}
```

### 向发现节点注册（NDP）

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
    println!("端点: {}", resolved.endpoint);

    Ok(())
}
```

### 提交编排任务（NOP）

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
    println!("任务状态: {:?}", result.status);

    Ok(())
}
```

---

## API 参考

### `nps-core`

- `Codec` — `encode_json()`、`decode_json()`、`encode_msgpack()`、`decode_msgpack()`
- `FrameRegistry` — 通过操作码查找帧类型
- `AnchorCache` — 带 TTL 的 Anchor Schema 缓存（默认 TTL：3600 秒）
- `NpsError` — 统一错误枚举，覆盖所有协议层

### `nps-ncp`

- `AnchorFrame` — Schema 声明帧（操作码 `0x01`）
- `DiffFrame` — 增量 Schema 更新（操作码 `0x02`）
- `StreamFrame` — 流式数据块（操作码 `0x03`）
- `CapsFrame` — 能力协商（操作码 `0x04`）
- `ErrorFrame` — 统一错误载体（操作码 `0xFE`）

### `nps-nwp`

- `QueryFrame` — 读请求（操作码 `0x10`）
- `ActionFrame` — 写/变更请求（操作码 `0x11`）
- `AsyncActionResponse` — 异步任务确认
- `NwpClient` — HTTP 模式客户端（reqwest），默认连接端口 17433

### `nps-nip`

- `NipIdentity` — Ed25519 密钥对，支持 AES-256-GCM 加密存储
- `IdentFrame` — 身份断言（操作码 `0x20`）
- `TrustFrame` — 签名信任委托（操作码 `0x21`）
- `RevokeFrame` — 证书吊销（操作码 `0x22`）

### `nps-ndp`

- `AnnounceFrame` — 节点公告（操作码 `0x30`）
- `ResolveFrame` — 解析请求（操作码 `0x31`）
- `GraphFrame` — 拓扑图快照（操作码 `0x32`）
- `InMemoryNdpRegistry` — 内存注册表，适合测试和嵌入式使用
- `NdpAnnounceValidator` — 验证公告字段及 TTL

### `nps-nop`

- `TaskFrame` — 编排任务定义（操作码 `0x40`）
- `DelegateFrame` — 委托给子 Agent，最大委托链深度 3（操作码 `0x41`）
- `SyncFrame` — DAG 同步（操作码 `0x42`）
- `AlignStreamFrame` — 携带任务上下文和 NID 绑定的流对齐（操作码 `0x43`）
- `BackoffStrategy` — 指数/线性退避重试（遵守 HTTP 429）
- `NopClient` — HTTP 模式编排客户端

---

## 测试

```bash
# 运行 workspace 中的所有测试
cargo test --workspace

# 运行特定 crate 的测试
cargo test -p nps-nip

# 带输出运行测试
cargo test --workspace -- --nocapture
```

workspace 共包含 88 个测试，覆盖帧编解码、身份生命周期、发现注册表和编排逻辑。

---

## Feature Flag（`nps-sdk`）

| Feature | 启用内容 |
|---------|---------|
| `nwp`（默认） | `nps-nwp` |
| `nip`（默认） | `nps-nip` |
| `ndp`（默认） | `nps-ndp` + `nps-nip` |
| `nop`（默认） | `nps-nop` |

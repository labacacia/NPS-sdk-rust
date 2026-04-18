[English Version](./ca-server.md) | 中文版

# NIP CA Server — Rust / Axum

一个轻量级证书颁发机构服务，实现 NIP（Neural Identity Protocol）证书生命周期。基于 Rust stable、Axum 0.8、rusqlite 与 Docker 构建。

---

## 总览

NIP CA Server 为 NPS Agent / Node 身份提供签发、续期、吊销和验证能力。它通过 HTTP 暴露 REST API，状态存储在 SQLite 数据库中，并附带 Docker Compose 文件用于零配置部署。

**技术栈**

| 组件 | 库 |
|------|------|
| HTTP 框架 | Axum 0.8 |
| 数据库 | rusqlite 0.32（内置 SQLite） |
| 加密 | ed25519-dalek 2、aes-gcm 0.10、pbkdf2 0.12 |
| 异步运行时 | Tokio 1 |
| 日志 | tracing + tracing-subscriber |

---

## 快速开始

### Docker（推荐）

```bash
cd ca-server/
docker compose up -d
```

服务默认监听端口 **8080**。CA 私钥和数据库持久化在 Docker volume 中。

### Cargo

```bash
cd ca-server/
cargo run --release
```

通过环境变量覆盖默认值：

| 变量 | 默认 | 说明 |
|------|------|------|
| `PORT` | `8080` | HTTP 监听端口 |
| `DB_PATH` | `./ca.db` | SQLite 数据库文件路径 |
| `CA_KEY_PASS` | _（必填）_ | CA 私钥加密口令 |

---

## REST API

基础路径：`/v1`

### Agent 注册

**POST** `/v1/agents/register`

注册一个新的 Agent 身份。生成 Ed25519 密钥对，签发身份证书，并返回 NID。

```json
请求体：
{
  "label": "my-agent",
  "metadata": {}
}

响应 200：
{
  "nid": "nps-agent-abc123",
  "certificate": "<base64>",
  "private_key_encrypted": "<base64>"
}
```

### Node 注册

**POST** `/v1/nodes/register`

注册一个新的 Node 身份（与 Agent 注册同一流程，将实体类型设为 `node`）。

```json
请求体：
{
  "label": "my-node",
  "metadata": {}
}
```

### 续期证书

**POST** `/v1/agents/:nid/renew`

为指定 NID 续期证书。原证书失效，新证书以刷新后的有效期签发。

```
POST /v1/agents/nps-agent-abc123/renew
```

### 吊销证书

**POST** `/v1/agents/:nid/revoke`

吊销指定 NID 的证书。数据库中该条目会被标记为吊销，并将出现在 CRL 中。

```
POST /v1/agents/nps-agent-abc123/revoke
```

### 验证证书

**GET** `/v1/agents/:nid/verify`

检查 NID 当前是否拥有一个有效且未被吊销的证书。

```
GET /v1/agents/nps-agent-abc123/verify
```

```json
响应 200：
{
  "nid": "nps-agent-abc123",
  "status": "active",
  "expires_at": "2027-04-17T00:00:00Z"
}
```

### 获取 CA 证书

**GET** `/v1/ca/cert`

获取 CA 的公开证书（Ed25519 公钥，Base64 编码）。

```json
响应 200：
{
  "ca_cert": "<base64>",
  "algorithm": "Ed25519"
}
```

### 证书吊销列表

**GET** `/v1/crl`

获取当前证书吊销列表。返回已吊销的 NID 及其吊销时间戳。

```json
响应 200：
{
  "revoked": [
    { "nid": "nps-agent-xyz", "revoked_at": "2026-04-01T12:00:00Z" }
  ]
}
```

### Well-Known 发现

**GET** `/.well-known/nps-ca`

NPS 标准的 CA 发现 well-known 端点。返回 CA 元数据，包括公开证书端点与 CRL URL。

```json
响应 200：
{
  "ca_cert_url": "/v1/ca/cert",
  "crl_url":     "/v1/crl",
  "algorithm":   "Ed25519"
}
```

### 健康检查

**GET** `/health`

存活探针。服务运行时返回 `{"status": "ok"}`。

---

## 构建

```bash
cd ca-server/

# Debug 构建
cargo build

# Release 构建
cargo build --release

# 运行测试
cargo test
```

---

## Docker Compose

`ca-server/docker-compose.yml` 挂载本地 `./data/` 目录用于数据库与密钥持久化：

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

运行 `docker compose up -d` 前请在环境中设置 `CA_KEY_PASS`。

[English Version](./CHANGELOG.md) | 中文版

# 变更日志 —— Rust SDK (`nps-rs`)

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

在 NPS 达到 v1.0 稳定版之前，套件内所有仓库同步使用同一个预发布版本号。

---

## [1.0.0-alpha.4] —— 2026-04-30

### 新增

- **NPS-RFC-0001 Phase 2 —— NCP 连接前导（Rust helper 跟进）。**
  `nps-ncp/src/preamble.rs` 暴露 `write_preamble()` /
  `read_preamble()`，往返字面量 `b"NPS/1.0\n"` 哨兵；
  `nps-ncp/tests/preamble_tests.rs` 覆盖。让 Rust SDK 与 .NET /
  Python / TypeScript / Go / Java 在 alpha.4 的 preamble helper 持平。
- **NPS-RFC-0002 Phase A/B —— X.509 NID 证书 + ACME `agent-01`
  （Rust 端口）。** 新增 `nps-nip/` 子模块：
  - `src/x509/` —— X.509 NID 证书 builder + verifier（基于 `rcgen`
    + `x509-parser`）。
  - `src/acme/` —— ACME `agent-01` 客户端 + 服务端参考实现（挑战
    签发、key authorization、按 NPS-RFC-0002 Phase B 的 JWS 签名
    wire 包络）。
  - `src/assurance_level.rs` —— Agent 身份保证等级
    （`anonymous` / `attested` / `verified`），承接 NPS-RFC-0003。
  - `src/cert_format.rs` —— IdentFrame 的 `cert_format` 判别器
    （`v1` Ed25519 vs. `x509`）。
  - `src/error_codes.rs` —— NIP 错误码命名空间。
  - `src/verifier.rs` —— dual-trust IdentFrame 验证器
    （v1 + X.509）。
- 新增测试：`preamble_tests.rs`、`nip_x509_tests.rs`、
  `nip_acme_agent01_tests.rs`。总数：109 tests 全绿（alpha.3 时 88）。

### 变更

- workspace 内全部 crate 经 `version.workspace = true` 升至
  `1.0.0-alpha.4`：`nps-core`、`nps-ncp`、`nps-nwp`、`nps-nip`、
  `nps-ndp`、`nps-nop`、`nps-sdk`。
- `nps-nip/src/frames.rs` —— `IdentFrame` 在原有 v1 Ed25519 字段
  旁新增可选 `cert_format` 判别器 + `x509_chain` 字段。alpha.3
  写出的 v1 IdentFrame 仍可被 alpha.4 验签。

### 套件级 alpha.4 要点

- **NPS-RFC-0002 X.509 + ACME** —— 完整跨 SDK 端口波（.NET / Java /
  Python / TypeScript / Go / Rust）。
- **NPS-CR-0002 —— Anchor Node topology 查询** —— `topology.snapshot`
  / `topology.stream`（.NET 参考 + L2 conformance）。Rust 消费侧
  helper 后续版本跟进。
- **`nps-registry` SQLite 实仓** + **`nps-ledger` Phase 2**
  （RFC 9162 Merkle + STH + inclusion proof）已在 daemon 仓库交付。

---

## [1.0.0-alpha.3] —— 2026-04-25

### Changed

- 版本升级至 `1.0.0-alpha.3`，与 NPS `v1.0.0-alpha.3` 套件同步。本次 Rust SDK 无功能变更。
- 88 tests 仍全绿。

### 套件级 alpha.3 要点（各语言 helper 在 alpha.4 跟进）

- **NPS-RFC-0001 —— NCP 连接前导**（Accepted）。原生模式连接现以字面量 `b"NPS/1.0\n"`（8 字节）开头。.NET SDK 已落地参考实现；Rust helper 在 alpha.4 跟进。
- **NPS-RFC-0003 —— Agent 身份保证等级**（Accepted）。NIP IdentFrame 与 NWM 新增三态 `assurance_level`（`anonymous`/`attested`/`verified`）。.NET 参考类型已落地；Rust 同步在 alpha.4。
- **NPS-RFC-0004 —— NID 声誉日志（CT 风格）**（Accepted）。append-only Merkle 日志条目结构发布；.NET 参考签名器已落地（并以 `nps-ledger` daemon Phase 1 形态发布）。Rust helper 在 alpha.4 跟进。
- **NPS-CR-0001 —— Anchor / Bridge 节点拆分。** 旧的 "Gateway Node" 角色更名为 **Anchor Node**；"NPS↔外部协议翻译" 单独成为 **Bridge Node** 类型。AnnounceFrame 新增 `node_kind` / `cluster_anchor` / `bridge_protocols`。源代码层面变更落在 `spec/` + .NET 参考实现。
- **6 个 NPS 常驻 daemon。** NPS-Dev 新建 `daemons/` 目录，定义 `npsd` / `nps-runner` / `nps-gateway` / `nps-registry` / `nps-cloud-ca` / `nps-ledger`；其中 `npsd` 提供 L1 功能性参考实现，其余为 Phase 1 骨架。

### 涵盖模块

- nps-core / nps-ncp / nps-nwp / nps-nip / nps-ndp / nps-nop / nps-sdk

---

## [1.0.0-alpha.2] —— 2026-04-19

### Changed

- 版本升级至 `1.0.0-alpha.2`，与套件同步。除版本对齐外无功能变更。
- 88 tests 全绿。

### 涵盖模块

- nps-core / nps-ncp / nps-nwp / nps-nip / nps-ndp / nps-nop / nps-sdk

---

## [1.0.0-alpha.1] —— 2026-04-10

作为 NPS 套件 `v1.0.0-alpha.1` 的一部分首次公开 alpha。

[1.0.0-alpha.4]: https://gitee.com/labacacia/NPS-sdk-rust/releases/tag/v1.0.0-alpha.4
[1.0.0-alpha.3]: https://github.com/LabAcacia/NPS-Dev/releases/tag/v1.0.0-alpha.3
[1.0.0-alpha.2]: https://github.com/LabAcacia/NPS-Dev/releases/tag/v1.0.0-alpha.2
[1.0.0-alpha.1]: https://github.com/LabAcacia/NPS-Dev/releases/tag/v1.0.0-alpha.1

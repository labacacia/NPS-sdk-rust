[English Version](./CHANGELOG.md) | 中文版

# 变更日志 —— Rust SDK (`nps-rs`)

格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

在 NPS 达到 v1.0 稳定版之前，套件内所有仓库同步使用同一个预发布版本号。

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

[1.0.0-alpha.3]: https://github.com/LabAcacia/NPS-Dev/releases/tag/v1.0.0-alpha.3
[1.0.0-alpha.2]: https://github.com/LabAcacia/NPS-Dev/releases/tag/v1.0.0-alpha.2
[1.0.0-alpha.1]: https://github.com/LabAcacia/NPS-Dev/releases/tag/v1.0.0-alpha.1

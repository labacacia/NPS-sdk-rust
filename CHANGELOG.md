English | [中文版](./CHANGELOG.cn.md)

# Changelog — Rust SDK (`nps-rs`)

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Until NPS reaches v1.0 stable, every repository in the suite is synchronized to the same pre-release version tag.

---

## [1.0.0-alpha.14] — 2026-06-26

### Added
- `nps_nip::ca_client::NipCaClient`: typed remote NIP CA client for discovery, CRL, agent/node registration, X.509 registration, renewal, revocation, and verification.
- `nps_nwp::NwpNativeNodeServer`: native-mode NWP serving helper for dispatching QueryFrame/ActionFrame over an already established NCP stream.
- `nps-conformance` crate plus `nps-sdk` re-export: TC-N1/TC-N2 conformance catalog, manifest builder, and validator for CI/self-certification flows.

---

## [1.0.0-alpha.11] — 2026-05-28

### Added

#### nps-nop
- `DagNode` struct (serde-derived) with `compensate_action` and `compensate_params_mapping` fields for saga compensation.
- `compensation_policy` module with wire constants: `none`, `on_failure`, `always`.
- `aggregate_strategy` module with wire constants: `merge`, `weighted_first_k`, `merge_all`.
- `TaskState::Compensating` and `TaskState::Compensated` variants; `Compensated` is now a terminal state.
- `TaskFrame::compensation_policy` — optional per-task compensation policy override.
- `DelegateFrame::target_cluster_anchor` — optional cross-cluster routing hint.
- `AlignStreamFrame::ack_seq` and `nak_seq` — selective-ack fields for stream flow control.

#### nps-ndp
- `security_profile` module with wire constants: `local-dev`, `org-private`, `public-federated`.
- `InMemoryNdpRegistry::security_profile` field (default `"local-dev"`).
- `AnnounceFrame` extended: `node_roles`, `cluster_anchor`, `spawn_spec_ref`, `bridge_protocols`, `activation_mode`, `activation_endpoint`.
- `GraphNode` struct (serde-derived) with `nid`, `cluster_anchor`, `node_roles` — replaces the previous opaque `Value` representation.
- `GraphEdge` struct (serde-derived) with `from_nid`, `to_nid`, `latency_ms`, `protocol`.
- `GraphFrame` updated to §5 format: `graph_id`, typed `nodes`/`edges` collections, `ttl`, `metadata`.

#### nps-nip
- `IdentReputationPolicyHint` struct (serde-derived) with `log_sources` and `consent` fields.
- `IdentFrame::reputation_policy` — optional embedded reputation policy hint.
- `IdentFrame::ocsp_staple` — optional OCSP staple (base64-encoded DER).

#### nps-nwp
- `SubscribeFrame` struct (serde-derived) with `subscription_id`, `filter`, `heartbeat_interval_ms`, `max_events`, `cursor`.

---

## [1.0.0-alpha.2] — 2026-04-19

### Changed

- Version bump to `1.0.0-alpha.2` for suite-wide synchronization. No functional changes beyond version alignment.
- 88 tests green.

### Covered modules

- nps-core / nps-ncp / nps-nwp / nps-nip / nps-ndp / nps-nop / nps-sdk

---

## [1.0.0-alpha.1] — 2026-04-10

First public alpha as part of the NPS suite `v1.0.0-alpha.1` release.

[1.0.0-alpha.11]: https://github.com/LabAcacia/nps/releases/tag/v1.0.0-alpha.11
[1.0.0-alpha.2]: https://github.com/LabAcacia/nps/releases/tag/v1.0.0-alpha.2
[1.0.0-alpha.1]: https://github.com/LabAcacia/nps/releases/tag/v1.0.0-alpha.1

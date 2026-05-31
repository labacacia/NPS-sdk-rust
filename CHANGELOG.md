English | [中文版](./CHANGELOG.cn.md)

# Changelog — Rust SDK (`nps-rs`)

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Until NPS reaches v1.0 stable, every repository in the suite is synchronized to the same pre-release version tag.

---

## [1.0.0-alpha.11] — 2026-05-31

### Added

- **NWP — `SubscribeFrame` CR-0006** (Breaking rewrite): Wire format updated — `subscription_id` (required), `filter` (`Option<Map<String,Value>>`), `heartbeat_interval_ms` (`Option<u32>`), `max_events` (`Option<u32>`), `cursor` (`Option<String>`). **Wire breaking change vs alpha.8–10.**
- **NOP — AlignStream ack/NAK**: `AlignStreamFrame` gains `ack_seq` and `nak_seq` (`Option<u64>`) for NOP v0.6 sliding-window acknowledgement.
- **NOP — Saga compensation**: `TaskFrame.compensation_policy`; `DelegateFrame.target_cluster_anchor`; `AggregateStrategy` constants `WEIGHTED_FIRST_K` / `MERGE_ALL`.
- **NDP — `GraphFrame` §5** (Breaking rewrite): `GraphNode`, `GraphEdge` structs; `GraphFrame` with `graph_id`, `nodes`, `edges`, `ttl`, `metadata`. Max 256 nodes / 1024 edges.
- **NIP — `IdentFrame.ocsp_staple`**: `Option<String>` base64url DER OCSP response field; `IdentReputationPolicyHint` struct.

### Tracking the suite

This release tracks NPS suite `v1.0.0-alpha.11`. NCP v0.7 / NWP v0.13 / NIP v0.9 / NDP v0.8 / NOP v0.6.

---

## [1.0.0-alpha.10] — 2026-05-28

### Added

- **NOP — Saga compensation**: `DagNode` struct with `compensate_action` / `compensate_params_mapping`; `TaskState::Compensating` / `Compensated`; `compensation_policy` module.
- **NDP — `SecurityProfile`**: `LOCAL_DEV` / `ORG_PRIVATE` / `PUBLIC_FEDERATED` constants.
- **NIP — `IdentReputationPolicyHint`**: Reputation policy hint struct.

### Tracking the suite

This release tracks NPS suite `v1.0.0-alpha.10`.

---

## [1.0.0-alpha.9] — 2026-05-28

### Added

- **NWP — `SubscribeFrame` (0x12)**: Initial `SubscribeFrame` struct (pre-CR-0006 format — replaced in alpha.11).
- **NWP — `ReputationPolicy` / `RepOutcome`**: RFC-0005 reputation types.

### Tracking the suite

This release tracks NPS suite `v1.0.0-alpha.9`.

---

## [1.0.0-alpha.8] — 2026-05-28

### Tracking the suite

This release tracks NPS suite `v1.0.0-alpha.8`.

Suite highlights: RFC-0005 `ReputationPolicyEvaluator` in .NET SDK; cgn_limit
pre-execution enforcement; RFC-0002 and RFC-0005 promoted to Accepted.

---

## [1.0.0-alpha.7] — 2026-05-17

### Added

- **`nps-nip` — `reputation` module (NPS-RFC-0004 Phase 2)**: Full async HTTP client for the reputation-log operator API (`reqwest`). `submit_entry`, `query_entries`, `get_sth`, `get_proof`, `get_gossip_sth`. `verify_inclusion` performs RFC 9162 §2.1.3.2 Merkle audit-path verification locally using `sha2`. `sign_entry` / `verify_entry` with `ed25519-dalek`. Wire types: `ReputationLogEntry`, `SignedTreeHead`, `InclusionProof`. Manual serde for `IncidentType` (kebab-case wire, forward-compat unknown → `Other`) and `Severity` (ordered 5-level enum, strict). `ReputationLogError` via `thiserror`. `nps-nip` adds `thiserror` as a dependency. 31 regression tests.

- **`nps-nwp` — `AnchorNodeClient` (NPS-CR-0002)**: Async `reqwest`-based client for Anchor Node topology queries. `get_snapshot` and `subscribe` (async `Stream` of `TopologyEvent`). Typed event enum: `MemberJoined`, `MemberLeft`, `MemberUpdated`, `AnchorState`, `ResyncRequired`. `AnchorTopologyError` for protocol errors. `with_path_prefix`, `with_client` builder methods. 25 regression tests using `tiny_http`.

### Tracking the suite

This release tracks NPS suite `v1.0.0-alpha.7`.

---

## [1.0.0-alpha.6] — 2026-05-14

### Changed

- **`nps-nip` — IANA PEN 65715 (Breaking, CR-0004)**: All OID constants in `nps_nip::x509::oids` now use the assigned arc `1.3.6.1.4.1.65715` (replacing provisional `1.3.6.1.4.1.99999`). Certificates issued under the provisional arc must be revoked and re-issued.

- **Version bump to `1.0.0-alpha.6`** — synchronized with NPS suite alpha.6 release.

---

## [1.0.0-alpha.5] — 2026-05-01

### Added

- **`nps_nwp::error_codes` module** — new module with all 30 NWP wire error code constants (auth, query, action, task, subscribe, infrastructure, manifest, topology, reserved-type). Missing from previous releases. Re-exported via `nps_nwp::error_codes::*`.
- **`nps_ndp::dns_txt` — DNS TXT fallback resolution** — new async `InMemoryNdpRegistry::resolve_via_dns(target, lookup)` falls back to `_nps-node.{host}` TXT lookup (NPS-4 §5) when no in-memory entry matches. `DnsTxtLookup` trait (object-safe via `Pin<Box<dyn Future>>`); `parse_nps_txt_record` + `extract_host_from_target` in `nps_ndp::dns_txt`. Tests: 109 → 119.

### Changed

- **Version bump to `1.0.0-alpha.5`** — all workspace crates (`nps-core`, `nps-ncp`, `nps-nwp`, `nps-nip`, `nps-ndp`, `nps-nop`, `nps-sdk`) synchronized with NPS suite alpha.5 release.

### Fixed

- **`nps_nip::assurance_level::AssuranceLevel::from_wire("")` now returns `ANONYMOUS`** — `from_wire` previously had no empty-string guard. Fix adds `if wire.is_empty() { return Ok(ANONYMOUS); }` (NPS-RFC-0003 §5.1.1 backward compat).
- **`nps_nip::error_codes::REPUTATION_GOSSIP_FORK` / `REPUTATION_GOSSIP_SIG_INVALID`** — two new NIP reputation gossip error codes added (RFC-0004 Phase 3).

---

## [1.0.0-alpha.4] — 2026-04-30

### Added

- **NPS-RFC-0001 Phase 2 — NCP connection preamble (Rust helper
  parity).** `nps-ncp/src/preamble.rs` exposes `write_preamble()` and
  `read_preamble()` round-tripping the literal `b"NPS/1.0\n"`
  sentinel; matched by `nps-ncp/tests/preamble_tests.rs`. Brings Rust
  in line with the .NET / Python / TypeScript / Go / Java preamble
  helpers shipped at alpha.4.
- **NPS-RFC-0002 Phase A/B — X.509 NID certificates + ACME `agent-01`
  (Rust port).** New surface under `nps-nip/`:
  - `src/x509/` — X.509 NID certificate builder + verifier
    (built on `rcgen` + `x509-parser`).
  - `src/acme/` — ACME `agent-01` client + server reference
    (challenge issuance, key authorisation, JWS-signed wire envelope
    per NPS-RFC-0002 Phase B).
  - `src/assurance_level.rs` — agent identity assurance levels
    (`anonymous` / `attested` / `verified`) per NPS-RFC-0003.
  - `src/cert_format.rs` — IdentFrame `cert_format` discriminator
    (`v1` Ed25519 vs. `x509`).
  - `src/error_codes.rs` — NIP error code namespace.
  - `src/verifier.rs` — dual-trust IdentFrame verifier
    (v1 + X.509).
- New tests: `preamble_tests.rs`, `nip_x509_tests.rs`,
  `nip_acme_agent01_tests.rs`. Total: 109 tests green
  (was 88 at alpha.3).

### Changed

- All workspace crates bumped to `1.0.0-alpha.4` via
  `version.workspace = true`:
  `nps-core`, `nps-ncp`, `nps-nwp`, `nps-nip`, `nps-ndp`, `nps-nop`,
  `nps-sdk`.
- `nps-nip/src/frames.rs` — `IdentFrame` extended with optional
  `cert_format` discriminator + `x509_chain` field alongside the
  existing v1 Ed25519 fields. v1 IdentFrames written by alpha.3
  consumers continue to verify unchanged.

### Suite-wide highlights at alpha.4

- **NPS-RFC-0002 X.509 + ACME** — full cross-SDK port wave (.NET /
  Java / Python / TypeScript / Go / Rust). Servers can now issue
  dual-trust IdentFrames (v1 Ed25519 + X.509 leaf cert chained to a
  self-signed root) and self-onboard NIDs over ACME's `agent-01`
  challenge type.
- **NPS-CR-0002 — Anchor Node topology queries** — `topology.snapshot`
  / `topology.stream` query types (.NET reference + L2 conformance
  suite). Rust consumer-side helpers planned for a later release.
- **`nps-registry` SQLite-backed real registry** + **`nps-ledger`
  Phase 2** (RFC 9162 Merkle + STH + inclusion proofs) shipped in the
  daemon repos.

---

## [1.0.0-alpha.3] — 2026-04-25

### Changed

- Version bump to `1.0.0-alpha.3` for suite-wide synchronization with the NPS `v1.0.0-alpha.3` release. No functional changes in the Rust SDK at this milestone.
- 88 tests still green.

### Suite-wide highlights at alpha.3 (per-language helpers planned for alpha.4)

- **NPS-RFC-0001 — NCP connection preamble** (Accepted). Native-mode connections now begin with the literal `b"NPS/1.0\n"` (8 bytes). Reference helper landed in the .NET SDK; Rust helper deferred to alpha.4.
- **NPS-RFC-0003 — Agent identity assurance levels** (Accepted). NIP IdentFrame and NWM gain a tri-state `assurance_level` (`anonymous`/`attested`/`verified`). Reference types landed in .NET; Rust parity deferred to alpha.4.
- **NPS-RFC-0004 — NID reputation log (CT-style)** (Accepted). Append-only Merkle log entry shape published; reference signer landed in .NET (and shipped as the `nps-ledger` daemon Phase 1). Rust helpers deferred to alpha.4.
- **NPS-CR-0001 — Anchor / Bridge node split.** The legacy "Gateway Node" role is renamed to **Anchor Node**; the "translate NPS↔external protocol" role is now its own **Bridge Node** type. AnnounceFrame gained `node_kind` / `cluster_anchor` / `bridge_protocols`. Source-of-truth changes are in `spec/` + the .NET reference implementation.
- **6 NPS resident daemons.** New `daemons/` tree in NPS-Dev defines `npsd` / `nps-runner` / `nps-gateway` / `nps-registry` / `nps-cloud-ca` / `nps-ledger`; `npsd` ships an L1-functional reference and the rest ship as Phase 1 skeletons.

### Covered modules

- nps-core / nps-ncp / nps-nwp / nps-nip / nps-ndp / nps-nop / nps-sdk

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

[1.0.0-alpha.7]: https://github.com/labacacia/NPS-sdk-rust/releases/tag/v1.0.0-alpha.7
[1.0.0-alpha.2]: https://github.com/LabAcacia/nps/releases/tag/v1.0.0-alpha.2
[1.0.0-alpha.1]: https://github.com/LabAcacia/nps/releases/tag/v1.0.0-alpha.1

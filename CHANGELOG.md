English | [中文版](./CHANGELOG.cn.md)

# Changelog — Rust SDK (`nps-rs`)

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Until NPS reaches v1.0 stable, every repository in the suite is synchronized to the same pre-release version tag.

---

## [1.0.0-alpha.5] — 2026-05-01

### Added

- **`nps_nwp::error_codes` module** — new module with all 30 NWP wire error code constants (auth, query, action, task, subscribe, infrastructure, manifest, topology, reserved-type). Missing from previous releases. Re-exported via `nps_nwp::error_codes::*`.
- **`nps_ndp::dns_txt` — DNS TXT fallback resolution** — new async `InMemoryNdpRegistry::resolve_via_dns(target, lookup)` falls back to `_nps-node.{host}` TXT lookup (NPS-4 §5) when no in-memory entry matches. `DnsTxtLookup` trait (object-safe via `Pin<Box<dyn Future>>`); `parse_nps_txt_record` + `extract_host_from_target` in `nps_ndp::dns_txt`. Tests: 109 → 119.

### Changed

- **Version bump to `1.0.0-alpha.5`** — all workspace crates (`nps-core`, `nps-ncp`, `nps-nwp`, `nps-nip`, `nps-ndp`, `nps-nop`, `nps-sdk`) synchronized with NPS suite alpha.5 release.

### Fixed

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

[1.0.0-alpha.5]: https://github.com/labacacia/NPS-sdk-rust/releases/tag/v1.0.0-alpha.5
[1.0.0-alpha.4]: https://github.com/labacacia/NPS-sdk-rust/releases/tag/v1.0.0-alpha.4
[1.0.0-alpha.3]: https://github.com/LabAcacia/NPS-Dev/releases/tag/v1.0.0-alpha.3
[1.0.0-alpha.2]: https://github.com/LabAcacia/NPS-Dev/releases/tag/v1.0.0-alpha.2
[1.0.0-alpha.1]: https://github.com/LabAcacia/NPS-Dev/releases/tag/v1.0.0-alpha.1

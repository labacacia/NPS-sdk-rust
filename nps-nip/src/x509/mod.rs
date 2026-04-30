// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NPS X.509 NID certificate primitives per NPS-RFC-0002 §4.
//!
//! Built on rcgen (cert build, via ring under the hood) and x509-parser
//! (cert parse + chain verify). Ed25519 signing throughout.

pub mod oids;
pub mod builder;
pub mod verifier;

pub use builder::{issue_leaf, issue_root, IssueLeafOptions, IssueRootOptions, LeafRole};
pub use verifier::{verify, VerifyOptions, VerifyResult};

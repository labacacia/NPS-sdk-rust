// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Helpers for NDP cross-registry federation forwarding (NPS-4 §7.6).

use nps_core::error::{NpsError, NpsResult};

use crate::error_codes::FEDERATION_LOOP;

pub const FORWARDED_BY_HEADER: &str = "ndp-forwarded-by";
pub const MAX_FEDERATION_HOPS: usize = 3;

pub fn parse_forwarded_by(header: Option<&str>) -> Vec<String> {
    header
        .unwrap_or("")
        .split(',')
        .filter_map(|part| {
            let hop = part.trim();
            (!hop.is_empty()).then(|| hop.to_string())
        })
        .collect()
}

pub fn append_forwarded_by(own_nid: &str, header: Option<&str>) -> NpsResult<Option<String>> {
    let hops = parse_forwarded_by(header);
    if hops.iter().any(|hop| hop == own_nid) {
        return Err(NpsError::Frame(format!(
            "{FEDERATION_LOOP}: own NID already appears in ndp-forwarded-by"
        )));
    }
    if hops.len() >= MAX_FEDERATION_HOPS {
        return Ok(None);
    }

    let mut next = hops;
    next.push(own_nid.to_string());
    Ok(Some(next.join(", ")))
}

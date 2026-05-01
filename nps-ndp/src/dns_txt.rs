// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! DNS TXT record lookup and parsing for NDP node discovery (NPS-4 §5).
//!
//! TXT record format:
//! ```text
//! _nps-node.api.example.com.  IN TXT  "v=nps1 type=memory port=17434 nid=urn:nps:node:api.example.com:products fp=sha256:a3f9..."
//! ```
//! Required keys: `v` (must be `nps1`), `nid`.
//! Optional keys: `port` (default 17433), `type`, `fp`.

use std::future::Future;
use std::pin::Pin;

use crate::registry::ResolveResult;

/// Default TTL (seconds) applied to DNS-resolved entries when no explicit TTL is present.
pub const DNS_TXT_DEFAULT_TTL: u32 = 300;

/// Injectable trait for DNS TXT record lookup.
///
/// Implementors return a list of raw TXT string values for a given hostname.
/// Using a trait allows unit tests to inject a mock without requiring a live DNS
/// resolver or the optional `hickory-resolver` crate.
pub trait DnsTxtLookup: Send + Sync {
    fn lookup_txt<'a>(
        &'a self,
        hostname: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>>;
}

/// Extract the hostname from a `nwp://hostname/path` target URL.
///
/// Returns `None` if the URL does not start with `nwp://` or has no path separator.
pub fn extract_host_from_target(target: &str) -> Option<&str> {
    let rest = target.strip_prefix("nwp://")?;
    let slash = rest.find('/')?;
    Some(&rest[..slash])
}

/// Parse a single NPS TXT record string into a [`ResolveResult`].
///
/// The `host` parameter is the hostname used as the `host` field of the result
/// (typically the node's hostname extracted from the target URL).
///
/// Returns `None` if the record is invalid (missing `v=nps1`, missing `nid`, or
/// `v` value is not `nps1`).
pub fn parse_nps_txt_record(txt: &str, host: &str) -> Option<ResolveResult> {
    let mut version: Option<&str> = None;
    let mut nid: Option<&str> = None;
    let mut port: u64 = 17433;

    for token in txt.split_whitespace() {
        if let Some((key, value)) = token.split_once('=') {
            match key {
                "v"    => version = Some(value),
                "nid"  => nid     = Some(value),
                "port" => {
                    if let Ok(p) = value.parse::<u64>() {
                        port = p;
                    }
                }
                // `type` and `fp` are parsed but not stored in ResolveResult
                // to avoid breaking changes to the struct.
                _ => {}
            }
        }
    }

    // Both v=nps1 and nid are required.
    if version? != "nps1" {
        return None;
    }
    nid?; // ensures nid was present; value itself is not used in ResolveResult

    Some(ResolveResult {
        host:     host.to_string(),
        port,
        protocol: "https".to_string(),
    })
}

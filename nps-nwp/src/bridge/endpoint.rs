// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Validates outbound Bridge endpoints before dereferencing them (SSRF guard).

use serde_json::Value;

use super::error::{bridge_error_codes, BridgeDispatchError};
use super::target::target_get_json;
use super::types::BridgeTarget;
use crate::action_server::is_private_host;

/// Minimal absolute-URL breakdown used for endpoint validation.
#[derive(Debug, Clone)]
pub struct ParsedEndpoint {
    /// Full endpoint URL (as supplied).
    pub url: String,
    /// Lower-cased scheme, `http` or `https`.
    pub scheme: String,
    /// Host component (no port, brackets stripped for IPv6).
    pub host: String,
    /// Effective port (default 80/443 when unspecified).
    pub port: u16,
    /// Absolute path, defaulting to `/`.
    pub path: String,
}

/// Parse and validate an HTTP(S) Bridge endpoint. By default both `http://` and
/// `https://` are accepted, while private and loopback hosts are rejected as an
/// SSRF guard.
pub fn parse_http_endpoint(target: &BridgeTarget) -> Result<ParsedEndpoint, BridgeDispatchError> {
    let uri = parse_absolute_http(&target.endpoint).ok_or_else(|| {
        BridgeDispatchError::new(
            bridge_error_codes::ENDPOINT_INVALID,
            "bridge_target.endpoint must be an absolute http:// or https:// URI.",
        )
    })?;

    let allow_http = get_bool(target, "allow_http", true);
    if !allow_http && uri.scheme == "http" {
        return Err(BridgeDispatchError::new(
            bridge_error_codes::ENDPOINT_INVALID,
            "bridge_target.endpoint MUST use https:// unless bridge_target.allow_http is true.",
        ));
    }

    let allowed_prefixes = get_string_list(target, "allowed_prefixes");
    if !allowed_prefixes.is_empty()
        && !allowed_prefixes
            .iter()
            .any(|prefix| matches_allowed_prefix(&uri, prefix))
    {
        return Err(BridgeDispatchError::new(
            bridge_error_codes::ENDPOINT_INVALID,
            format!(
                "bridge_target.endpoint '{}' is not in bridge_target.allowed_prefixes.",
                target.endpoint
            ),
        ));
    }

    let reject_private = get_bool(target, "reject_private", true);
    if reject_private && is_private_host(&uri.host) {
        return Err(BridgeDispatchError::new(
            bridge_error_codes::ENDPOINT_INVALID,
            format!(
                "bridge_target.endpoint host '{}' is private or loopback (SSRF guard).",
                uri.host
            ),
        ));
    }

    Ok(uri)
}

/// Parse an absolute http/https URL into scheme/host/port/path. Returns `None`
/// for non-absolute inputs or non-http(s) schemes.
pub(crate) fn parse_absolute_http(raw: &str) -> Option<ParsedEndpoint> {
    let (scheme, rest) = raw.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    if rest.is_empty() {
        return None;
    }

    // Split authority from path/query/fragment.
    let authority_end = rest
        .find(['/', '?', '#'])
        .unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let mut path = &rest[authority_end..];
    // Strip query/fragment for the path component.
    if let Some(idx) = path.find(['?', '#']) {
        path = &path[..idx];
    }

    if authority.is_empty() {
        return None;
    }

    // Strip userinfo.
    let host_port = authority.rsplit_once('@').map(|(_, h)| h).unwrap_or(authority);

    let (host, port_str) = if host_port.starts_with('[') {
        // IPv6 literal: [::1]:8080
        let close = host_port.find(']')?;
        let host = &host_port[1..close];
        let after = &host_port[close + 1..];
        let port = after.strip_prefix(':');
        (host, port)
    } else if let Some((h, p)) = host_port.rsplit_once(':') {
        // Only treat trailing ':' as a port when the remainder is numeric.
        if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() {
            (h, Some(p))
        } else {
            (host_port, None)
        }
    } else {
        (host_port, None)
    };

    if host.is_empty() {
        return None;
    }

    let port = match port_str {
        Some(p) => p.parse::<u16>().ok()?,
        None => {
            if scheme == "https" {
                443
            } else {
                80
            }
        }
    };

    let path = if path.is_empty() { "/" } else { path };

    Some(ParsedEndpoint {
        url: raw.to_string(),
        scheme,
        host: host.to_ascii_lowercase(),
        port,
        path: path.to_string(),
    })
}

fn get_bool(target: &BridgeTarget, name: &str, default_value: bool) -> bool {
    match target_get_json(target, name) {
        Some(Value::Bool(b)) => b,
        Some(Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
            "true" => true,
            "false" => false,
            _ => default_value,
        },
        _ => default_value,
    }
}

fn get_string_list(target: &BridgeTarget, name: &str) -> Vec<String> {
    match target_get_json(target, name) {
        Some(Value::String(s)) if !s.trim().is_empty() => vec![s],
        Some(Value::Array(items)) => items
            .into_iter()
            .filter_map(|item| match item {
                Value::String(s) if !s.trim().is_empty() => Some(s),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn matches_allowed_prefix(endpoint: &ParsedEndpoint, raw_prefix: &str) -> bool {
    let Some(prefix) = parse_absolute_http(raw_prefix) else {
        return false;
    };

    if !endpoint.scheme.eq_ignore_ascii_case(&prefix.scheme)
        || !endpoint.host.eq_ignore_ascii_case(&prefix.host)
        || endpoint.port != prefix.port
    {
        return false;
    }

    let prefix_path = &prefix.path;
    if prefix_path == "/" {
        return true;
    }

    let endpoint_path = &endpoint.path;
    if !endpoint_path
        .to_ascii_lowercase()
        .starts_with(&prefix_path.to_ascii_lowercase())
    {
        return false;
    }

    endpoint_path.len() == prefix_path.len()
        || prefix_path.ends_with('/')
        || endpoint_path.as_bytes().get(prefix_path.len()) == Some(&b'/')
}

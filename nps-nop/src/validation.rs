// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! DAG validation (Kahn topological sort / cycle / uniqueness / limits) and
//! callback URL validation (https + SSRF guard). Faithful port of the .NET
//! `DagValidator` and `NopCallbackValidator`.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::constants;
use crate::error_codes;
use crate::orch_models::TaskDag;

// ── DAG validation ──────────────────────────────────────────────────────────

/// Result of DAG validation.
#[derive(Debug, Clone)]
pub struct DagValidationResult {
    pub is_valid: bool,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    /// Topologically sorted node IDs (populated only when valid).
    pub topological_order: Option<Vec<String>>,
}

impl DagValidationResult {
    fn success(order: Vec<String>) -> Self {
        DagValidationResult {
            is_valid: true,
            error_code: None,
            error_message: None,
            topological_order: Some(order),
        }
    }

    fn failure(error_code: &str, message: impl Into<String>) -> Self {
        DagValidationResult {
            is_valid: false,
            error_code: Some(error_code.to_string()),
            error_message: Some(message.into()),
            topological_order: None,
        }
    }
}

/// Validates the given DAG and returns a topological ordering on success.
pub fn validate_dag(dag: &TaskDag) -> DagValidationResult {
    if dag.nodes.is_empty() {
        return DagValidationResult::failure(
            error_codes::TASK_DAG_INVALID,
            "DAG must contain at least one node.",
        );
    }

    if dag.nodes.len() > constants::MAX_DAG_NODES {
        return DagValidationResult::failure(
            error_codes::TASK_DAG_TOO_LARGE,
            format!(
                "DAG contains {} nodes, exceeding the maximum of {}.",
                dag.nodes.len(),
                constants::MAX_DAG_NODES
            ),
        );
    }

    let mut node_ids: HashSet<String> = HashSet::with_capacity(dag.nodes.len());
    for node in &dag.nodes {
        if !node_ids.insert(node.id.clone()) {
            return DagValidationResult::failure(
                error_codes::TASK_DAG_INVALID,
                format!("Duplicate node ID: '{}'.", node.id),
            );
        }
    }

    let mut adjacency: HashMap<String, Vec<String>> = HashMap::with_capacity(node_ids.len());
    let mut in_degree: HashMap<String, i32> = HashMap::with_capacity(node_ids.len());
    for id in &node_ids {
        adjacency.insert(id.clone(), Vec::new());
        in_degree.insert(id.clone(), 0);
    }

    for edge in &dag.edges {
        if !node_ids.contains(&edge.from) {
            return DagValidationResult::failure(
                error_codes::TASK_DAG_INVALID,
                format!("Edge references unknown source node: '{}'.", edge.from),
            );
        }
        if !node_ids.contains(&edge.to) {
            return DagValidationResult::failure(
                error_codes::TASK_DAG_INVALID,
                format!("Edge references unknown target node: '{}'.", edge.to),
            );
        }
        adjacency.get_mut(&edge.from).unwrap().push(edge.to.clone());
        *in_degree.get_mut(&edge.to).unwrap() += 1;
    }

    // Validate input_from references
    for node in &dag.nodes {
        if let Some(input_from) = &node.input_from {
            for upstream in input_from {
                if !node_ids.contains(upstream) {
                    return DagValidationResult::failure(
                        error_codes::TASK_DAG_INVALID,
                        format!(
                            "Node '{}' references unknown upstream node '{}' in input_from.",
                            node.id, upstream
                        ),
                    );
                }
            }
        }
    }

    // At least one start node (no incoming edges)
    let has_start = in_degree.values().any(|&d| d == 0);
    if !has_start {
        return DagValidationResult::failure(
            error_codes::TASK_DAG_INVALID,
            "DAG must have at least one start node (no incoming edges).",
        );
    }

    // At least one end node (no outgoing edges)
    let has_end = adjacency.values().any(|list| list.is_empty());
    if !has_end {
        return DagValidationResult::failure(
            error_codes::TASK_DAG_INVALID,
            "DAG must have at least one end node (no outgoing edges).",
        );
    }

    // Condition expression lengths
    for node in &dag.nodes {
        if let Some(cond) = &node.condition {
            if cond.chars().count() > constants::MAX_CONDITION_LENGTH {
                return DagValidationResult::failure(
                    error_codes::CONDITION_EVAL_ERROR,
                    format!(
                        "Node '{}' condition expression exceeds {} characters.",
                        node.id,
                        constants::MAX_CONDITION_LENGTH
                    ),
                );
            }
        }
    }

    // Kahn's algorithm for topological sort + cycle detection
    let mut remaining = in_degree.clone();
    let mut queue: VecDeque<String> = VecDeque::new();
    // Deterministic ordering: iterate over declared node order.
    for node in &dag.nodes {
        if remaining[&node.id] == 0 {
            queue.push_back(node.id.clone());
        }
    }

    let mut sorted: Vec<String> = Vec::with_capacity(node_ids.len());
    while let Some(current) = queue.pop_front() {
        sorted.push(current.clone());
        if let Some(neighbors) = adjacency.get(&current) {
            for neighbor in neighbors {
                let d = remaining.get_mut(neighbor).unwrap();
                *d -= 1;
                if *d == 0 {
                    queue.push_back(neighbor.clone());
                }
            }
        }
    }

    if sorted.len() != node_ids.len() {
        return DagValidationResult::failure(error_codes::TASK_DAG_CYCLE, "DAG contains a cycle.");
    }

    DagValidationResult::success(sorted)
}

// ── Callback URL validation ─────────────────────────────────────────────────

/// Validates `callback_url` (NPS-5 §8.4). Returns `None` when valid; otherwise a
/// human-readable error string.
pub fn validate_callback_url(callback_url: &str) -> Option<String> {
    if callback_url.trim().is_empty() {
        return Some("callback_url must not be empty.".to_string());
    }

    let (scheme, rest) = match callback_url.split_once("://") {
        Some((s, r)) => (s.to_ascii_lowercase(), r),
        None => {
            return Some(format!(
                "callback_url '{callback_url}' is not a valid absolute URI."
            ))
        }
    };

    if scheme != "https" {
        return Some(format!(
            "callback_url MUST use the https:// scheme (got '{scheme}://')."
        ));
    }

    let host = extract_host(rest);
    if host.is_empty() {
        return Some(format!(
            "callback_url '{callback_url}' is not a valid absolute URI."
        ));
    }

    if is_private_host(&host) {
        return Some(format!(
            "callback_url host '{host}' resolves to a private or loopback address (SSRF guard)."
        ));
    }

    None
}

/// Extracts the host portion (authority host) from the part after `://`.
fn extract_host(rest: &str) -> String {
    // Strip path/query/fragment.
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    // Strip userinfo.
    let authority = authority.rsplit('@').next().unwrap_or(authority);

    // IPv6 literal: [::1]:443
    if let Some(stripped) = authority.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            return authority[..end + 2].to_string(); // keep brackets
        }
        return authority.to_string();
    }

    // host:port
    match authority.split_once(':') {
        Some((h, _)) => h.to_string(),
        None => authority.to_string(),
    }
}

/// Returns `true` when `host` is a well-known private / loopback / link-local
/// address or hostname without performing DNS resolution.
pub fn is_private_host(host: &str) -> bool {
    if host.is_empty() {
        return true;
    }

    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }

    // Strip IPv6 URI brackets: [::1]
    let stripped = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = stripped.parse::<IpAddr>() {
        return is_private_ip(ip);
    }

    false
}

fn is_private_ip(ip: IpAddr) -> bool {
    let ip = match ip {
        // Normalise IPv4-mapped IPv6 (::ffff:10.0.0.1) to IPv4.
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        other => other,
    };

    match ip {
        IpAddr::V4(v4) => is_private_ipv4(v4),
        IpAddr::V6(v6) => is_private_ipv6(v6),
    }
}

fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    let b = ip.octets();
    b[0] == 127                                    // 127.0.0.0/8 loopback
        || b[0] == 10                              // 10.0.0.0/8
        || b[0] == 0                               // 0.0.0.0/8
        || (b[0] == 172 && (16..=31).contains(&b[1])) // 172.16.0.0/12
        || (b[0] == 192 && b[1] == 168)            // 192.168.0.0/16
        || (b[0] == 169 && b[1] == 254) // 169.254.0.0/16 link-local
}

fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() {
        return true; // ::1
    }
    let seg = ip.segments();
    // fe80::/10 link-local
    let link_local = (seg[0] & 0xffc0) == 0xfe80;
    // fec0::/10 site-local (deprecated but guard anyway)
    let site_local = (seg[0] & 0xffc0) == 0xfec0;
    // fc00::/7 unique local (guard for completeness)
    let unique_local = (seg[0] & 0xfe00) == 0xfc00;
    link_local || site_local || unique_local
}

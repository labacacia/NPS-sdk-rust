// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use nps_conformance::alpha19::*;
use serde_json::{Map, Value};
use std::{collections::HashSet, path::PathBuf};

fn repo_file(relative: &str) -> PathBuf {
    let mut current = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = current.join(relative);
        if candidate.is_file() {
            return candidate;
        }
        if !current.pop() {
            panic!("missing {relative}")
        }
    }
}

#[test]
fn executes_all_shared_vectors() {
    let suites = [
        ("ncp", "runtime_hardening_vectors.json"),
        ("nwp", "alpha19_hardening_vectors.json"),
        ("nip", "renewal_revocation_vectors.json"),
        ("ndp", "recovery_fence_vectors.json"),
        ("nop", "replay_retention_vectors.json"),
    ];
    let mut seen = HashSet::new();
    for (protocol, name) in suites {
        let root: Value = serde_json::from_str(
            &std::fs::read_to_string(repo_file(&format!("spec/conformance/{protocol}/{name}")))
                .unwrap(),
        )
        .unwrap();
        for v in root["vectors"].as_array().unwrap() {
            let id = v["id"].as_str().unwrap();
            assert!(seen.insert(id.to_owned()));
            let input = v["input"].as_object().unwrap();
            let actual = if id.starts_with("ncp.") {
                ncp(input)
            } else if id.contains(".metadata.") {
                nwp_metadata(input)
            } else if id.contains(".subscription.") {
                nwp_subscription(input)
            } else if id.contains(".renewal.") {
                nip_renewal(input)
            } else if id.contains(".revocation.") {
                nip_revocation(input)
            } else if id.contains(".advisory.") {
                nip_advisory(input)
            } else if id.starts_with("ndp.") {
                ndp(input)
            } else {
                nop(input)
            };
            assert_eq!(Value::Object(actual), v["expected"], "{id}");
        }
    }
    assert_eq!(seen.len(), 47);
}

#[test]
fn boundary_branches_are_not_fixture_constants() {
    let input: Map<String, Value> =
        serde_json::from_value(serde_json::json!({"client_ping_ms":0,"server_ping_ms":2500}))
            .unwrap();
    assert_eq!(ncp(&input)["effective_interval_ms"], 2500);
}

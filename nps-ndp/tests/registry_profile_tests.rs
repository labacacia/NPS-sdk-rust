// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use nps_ndp::{
    canonical_announce_json, verify_announce_signature, AnnounceFrame, NdpAnnounceValidator,
    NdpRegistryProfile,
};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::PathBuf;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

fn repo_file(relative: &str) -> PathBuf {
    let mut current = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let candidate = current.join(relative);
        if candidate.is_file() {
            return candidate;
        }
        assert!(
            current.pop(),
            "unable to locate repository file: {relative}"
        );
    }
}

fn vectors(relative: &str) -> Vec<Value> {
    let document: Value =
        serde_json::from_str(&std::fs::read_to_string(repo_file(relative)).unwrap()).unwrap();
    document["vectors"].as_array().unwrap().clone()
}

fn timestamp(value: &str) -> i64 {
    OffsetDateTime::parse(value, &Rfc3339)
        .unwrap()
        .unix_timestamp()
}

#[test]
fn shared_canonicalization_vectors_pass() {
    let cases = vectors("spec/conformance/ndp/announce_canonicalization_vectors.json");
    assert_eq!(cases.len(), 3);
    for vector in cases {
        let input = &vector["input"];
        assert_eq!(
            canonical_announce_json(&input["frame"]).unwrap(),
            vector["expected"]["canonical_json"].as_str().unwrap(),
            "{}",
            vector["id"]
        );
        assert_eq!(
            verify_announce_signature(
                &input["frame"],
                input["public_key"].as_str().unwrap(),
                input["signature"].as_str().unwrap(),
            ),
            vector["expected"]["signature_valid"].as_bool().unwrap(),
            "{}",
            vector["id"]
        );
        let mut wire = input["frame"].as_object().unwrap().clone();
        wire.insert("signature".into(), input["signature"].clone());
        let model = AnnounceFrame::from_dict(&wire).unwrap();
        let mut validator = NdpAnnounceValidator::new();
        validator.register_public_key(model.nid.clone(), input["public_key"].as_str().unwrap());
        assert_eq!(
            validator.validate(&model).is_valid,
            vector["expected"]["signature_valid"].as_bool().unwrap(),
            "{}",
            vector["id"]
        );
    }
}

#[test]
fn shared_registry_consistency_vectors_pass() {
    let cases = vectors("spec/conformance/ndp/registry_consistency_vectors.json");
    assert_eq!(cases.len(), 16);
    for vector in cases {
        let input = &vector["input"];
        let expected = &vector["expected"];
        let now = timestamp(input["now"].as_str().unwrap());
        let mut registry = NdpRegistryProfile::new(input["profile"].as_str().unwrap());
        let outcomes: Vec<_> = input["announces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|announce| {
                let received_at = announce
                    .get("received_at")
                    .and_then(Value::as_str)
                    .map(timestamp)
                    .unwrap_or(now);
                registry.apply_announce(
                    &announce["frame"],
                    announce["signature_valid"].as_bool().unwrap(),
                    received_at,
                )
            })
            .collect();

        let decisions: Vec<_> = outcomes
            .iter()
            .map(|outcome| outcome.decision.as_str())
            .collect();
        let expected_decisions: Vec<_> = expected["decisions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        assert_eq!(decisions, expected_decisions, "{}", vector["id"]);

        let errors: Vec<_> = outcomes.iter().map(|outcome| outcome.error_code).collect();
        let expected_errors: Vec<_> = expected["errors"]
            .as_array()
            .unwrap()
            .iter()
            .map(Value::as_str)
            .collect();
        assert_eq!(errors, expected_errors, "{}", vector["id"]);

        let expected_nids: Vec<_> = expected["live_nids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap().to_string())
            .collect();
        assert_eq!(registry.live_nids(now), expected_nids, "{}", vector["id"]);

        let expected_sequences: BTreeMap<String, u64> = expected["highest_sequences"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(nid, value)| (nid.clone(), value.as_u64().unwrap()))
            .collect();
        assert_eq!(
            registry.highest_sequences(),
            expected_sequences,
            "{}",
            vector["id"]
        );

        if let Some(cluster) = input.get("cluster_query").and_then(Value::as_str) {
            let selected = registry.resolve_cluster(cluster, now);
            assert_eq!(
                selected.nid.as_deref(),
                expected.get("selected_nid").and_then(Value::as_str)
            );
            assert_eq!(
                selected.epoch,
                expected.get("selected_epoch").and_then(Value::as_u64)
            );
            assert_eq!(
                selected.error_code,
                expected.get("cluster_error").and_then(Value::as_str)
            );
        }

        if let Some(queries) = input.get("bridge_queries").and_then(Value::as_array) {
            let actual: Vec<Vec<String>> = queries
                .iter()
                .map(|query| {
                    registry.discover_bridges(
                        query["direction"].as_str().unwrap(),
                        query["protocol"].as_str().unwrap(),
                        now,
                    )
                })
                .collect();
            let expected_results: Vec<Vec<String>> = expected["bridge_results"]
                .as_array()
                .unwrap()
                .iter()
                .map(|result| {
                    result
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|value| value.as_str().unwrap().to_string())
                        .collect()
                })
                .collect();
            assert_eq!(actual, expected_results);
        }

        if expected.get("resolve_error").is_some() {
            assert!(registry.has_stale_entry(now));
        }
    }
}

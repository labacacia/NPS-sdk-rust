// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use nps_nwp::{
    evaluate_bridge_lifecycle, evaluate_portable_node, BridgeLifecycleRequest,
    NwpPortableNodeRequest,
};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{Map, Value};

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

#[derive(Deserialize)]
struct Fixture<T> {
    vectors: Vec<Vector<T>>,
}

#[derive(Deserialize)]
struct Vector<T> {
    id: String,
    input: T,
    expected: Map<String, Value>,
}

fn fixture<T: DeserializeOwned>(name: &str) -> Fixture<T> {
    let path = repo_file(&format!("spec/conformance/nwp/{name}"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn assert_expected(id: &str, actual: Value, expected: &Map<String, Value>) {
    let actual = actual.as_object().unwrap();
    for (key, value) in expected {
        if key == "response" {
            continue;
        }
        assert_eq!(actual.get(key), Some(value), "{id} {key}");
    }
}

#[test]
fn portable_node_server_vectors() {
    for vector in fixture::<NwpPortableNodeRequest>("portable_node_server_vectors.json").vectors {
        assert_expected(
            &vector.id,
            serde_json::to_value(evaluate_portable_node(&vector.input)).unwrap(),
            &vector.expected,
        );
    }
}

#[test]
fn bridge_lifecycle_vectors() {
    for vector in fixture::<BridgeLifecycleRequest>("bridge_lifecycle_vectors.json").vectors {
        assert_expected(
            &vector.id,
            serde_json::to_value(evaluate_bridge_lifecycle(&vector.input)).unwrap(),
            &vector.expected,
        );
    }
}

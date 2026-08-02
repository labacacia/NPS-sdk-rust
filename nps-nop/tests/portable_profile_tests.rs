// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use nps_nop::{evaluate_orchestration, evaluate_runtime};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

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

#[test]
fn shared_orchestrator_transcripts_pass() {
    let fixture = load("orchestrator_transcripts.json");
    let vectors = fixture["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 10);
    for vector in vectors {
        assert_eq!(
            evaluate_orchestration(&vector["input"]),
            vector["expected"],
            "{}",
            vector["id"]
        );
    }
}

#[test]
fn shared_runtime_security_vectors_pass() {
    let fixture = load("runtime_security_vectors.json");
    let vectors = fixture["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 22);
    for vector in vectors {
        assert_eq!(
            evaluate_runtime(vector["category"].as_str().unwrap(), &vector["input"]),
            vector["expected"],
            "{}",
            vector["id"]
        );
    }
}

fn load(name: &str) -> Value {
    let path = repo_file(&format!("spec/conformance/nop/{name}"));
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

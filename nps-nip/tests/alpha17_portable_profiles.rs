// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::PathBuf;

use nps_nip::ca::ca_canonical_json;
use nps_nip::{
    NipCaClient, NipCaCrl, NipRevocationMode, NipRevocationOutcome, NipRevocationPolicy,
    NipRevocationSource,
};
use serde_json::Value;

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

fn fixture(name: &str) -> Value {
    let path = repo_file(&format!("spec/conformance/nip/{name}"));
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn mode(token: &str) -> NipRevocationMode {
    match token {
        "if_configured" => NipRevocationMode::IfConfigured,
        "required" => NipRevocationMode::Required,
        other => panic!("unknown mode {other}"),
    }
}

fn source(token: &str) -> NipRevocationSource {
    match token {
        "local_crl" => NipRevocationSource::LocalCrl,
        "callback" => NipRevocationSource::Callback,
        "ca_store" => NipRevocationSource::CaStore,
        "ocsp" => NipRevocationSource::Ocsp,
        other => panic!("unknown source {other}"),
    }
}

fn outcome(token: &str) -> NipRevocationOutcome {
    match token {
        "good" => NipRevocationOutcome::Good,
        "revoked" => NipRevocationOutcome::Revoked,
        "unavailable" => NipRevocationOutcome::Unavailable,
        other => panic!("unknown outcome {other}"),
    }
}

fn source_token(value: NipRevocationSource) -> &'static str {
    match value {
        NipRevocationSource::LocalCrl => "local_crl",
        NipRevocationSource::Callback => "callback",
        NipRevocationSource::CaStore => "ca_store",
        NipRevocationSource::Ocsp => "ocsp",
    }
}

#[test]
fn portable_revocation_policy_vectors() {
    let fixture = fixture("revocation_policy_vectors.json");
    for vector in fixture["vectors"].as_array().unwrap() {
        let id = vector["id"].as_str().unwrap();
        let input = &vector["input"];
        let expected = &vector["expected"];
        let mut policy = NipRevocationPolicy::new(
            mode(input["revocation_mode"].as_str().unwrap()),
            input["ocsp_fail_open"].as_bool().unwrap(),
        );
        let mut result = None;
        for item in input["sources"].as_array().unwrap() {
            result = policy.observe(
                source(item["source"].as_str().unwrap()),
                outcome(item["outcome"].as_str().unwrap()),
            );
            if result.is_some() {
                break;
            }
        }
        let result = result.unwrap_or_else(|| policy.complete());
        assert_eq!(result.valid, expected["valid"].as_bool().unwrap(), "{id}");
        assert_eq!(
            result.step_failed,
            expected
                .get("failed_step")
                .and_then(Value::as_u64)
                .unwrap_or(0) as u8,
            "{id}"
        );
        assert_eq!(
            result.error_code,
            expected.get("error").and_then(Value::as_str),
            "{id}"
        );
        let consulted: Vec<&str> = policy
            .consulted_sources()
            .iter()
            .copied()
            .map(source_token)
            .collect();
        let expected_consulted: Vec<&str> = expected["consulted_sources"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| item.as_str().unwrap())
            .collect();
        assert_eq!(consulted, expected_consulted, "{id}");
    }
}

#[test]
fn portable_signed_crl_vectors() {
    let fixture = fixture("signed_crl_vectors.json");
    for vector in fixture["vectors"].as_array().unwrap() {
        let id = vector["id"].as_str().unwrap();
        let input = &vector["input"];
        let mut crl_value = input["body"].clone();
        crl_value["signature"] = input["signature"].clone();
        let crl: NipCaCrl = serde_json::from_value(crl_value).unwrap();
        assert_eq!(
            NipCaClient::verify_crl_signature(&crl, input["public_key"].as_str().unwrap(),),
            vector["expected"]["signature_valid"].as_bool().unwrap(),
            "{id}"
        );
        if let Some(expected) = vector["expected"]["canonical_for_signing"].as_str() {
            assert_eq!(ca_canonical_json(&input["body"]), expected, "{id}");
        }
    }
}

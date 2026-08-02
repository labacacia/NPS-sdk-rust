// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use nps_core::frames::{EncodingTier, FrameHeader, FrameType};
use nps_ncp::{
    evaluate_hello_header, evaluate_preamble, negotiate_handshake, HelloFrame, NcpHandshakeAction,
    NcpHandshakeProfile,
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

fn fixture() -> Value {
    let path = repo_file("spec/conformance/ncp/native_server_handshake_vectors.json");
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(|item| item.as_str().unwrap().to_string())
                .collect()
        })
        .unwrap_or_default()
}

fn server_profile(server: &Value) -> NcpHandshakeProfile {
    let defaults = NcpHandshakeProfile::default();
    NcpHandshakeProfile {
        min_version: server
            .get("min_version")
            .and_then(Value::as_str)
            .unwrap_or(&defaults.min_version)
            .into(),
        nps_version: server
            .get("nps_version")
            .and_then(Value::as_str)
            .unwrap_or(&defaults.nps_version)
            .into(),
        supported_encodings: server
            .get("supported_encodings")
            .map_or(defaults.supported_encodings, |value| strings(Some(value))),
        supported_protocols: server
            .get("supported_protocols")
            .map_or(defaults.supported_protocols, |value| strings(Some(value))),
        max_frame_payload: server
            .get("max_frame_payload")
            .and_then(Value::as_u64)
            .unwrap_or(defaults.max_frame_payload),
        ext_support: server
            .get("ext_support")
            .and_then(Value::as_bool)
            .unwrap_or(defaults.ext_support),
        max_concurrent_streams: server
            .get("max_concurrent_streams")
            .and_then(Value::as_u64)
            .unwrap_or(defaults.max_concurrent_streams),
    }
}

fn hello_frame(hello: &Value) -> HelloFrame {
    let mut frame = HelloFrame::new(
        hello["nps_version"].as_str().unwrap(),
        strings(hello.get("supported_encodings")),
        strings(hello.get("supported_protocols")),
    );
    frame.min_version = hello
        .get("min_version")
        .and_then(Value::as_str)
        .map(str::to_string);
    frame.max_frame_payload = hello["max_frame_payload"].as_u64().unwrap();
    frame.ext_support = hello["ext_support"].as_bool().unwrap();
    frame.max_concurrent_streams = hello["max_concurrent_streams"].as_u64().unwrap();
    frame
}

fn action_token(action: NcpHandshakeAction) -> &'static str {
    match action {
        NcpHandshakeAction::Continue => "continue",
        NcpHandshakeAction::Accept => "accept",
        NcpHandshakeAction::SilentClose => "silent_close",
        NcpHandshakeAction::ErrorClose => "error_close",
    }
}

#[test]
fn portable_native_server_handshake_vectors() {
    let fixture = fixture();
    for vector in fixture["vectors"].as_array().unwrap() {
        let id = vector["id"].as_str().unwrap();
        let input = &vector["input"];
        let server = &input["server"];
        let transport = &input["transport"];
        let expected = &vector["expected"];

        let preamble = hex::decode(transport["preamble_hex"].as_str().unwrap()).unwrap();
        let preamble_decision = evaluate_preamble(
            &preamble,
            Duration::from_millis(transport["preamble_elapsed_ms"].as_u64().unwrap()),
            Duration::from_millis(server["preamble_timeout_ms"].as_u64().unwrap()),
        );
        if preamble_decision.action == NcpHandshakeAction::SilentClose {
            assert_eq!(
                action_token(preamble_decision.action),
                expected["action"].as_str().unwrap(),
                "{id}"
            );
            assert_eq!(
                preamble_decision.diagnostic_error,
                expected.get("diagnostic_error").and_then(Value::as_str),
                "{id}"
            );
            continue;
        }

        let frame_type = u8::from_str_radix(
            transport["first_frame_type"]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
            16,
        )
        .unwrap();
        let tier = match transport["first_frame_tier"].as_str().unwrap() {
            "json" => EncodingTier::Json,
            "msgpack" => EncodingTier::MsgPack,
            other => panic!("{id}: unsupported fixture tier {other}"),
        };
        let mut header = FrameHeader::new(
            FrameType::from_u8(frame_type).unwrap(),
            tier,
            true,
            transport["hello_payload_length"].as_u64().unwrap(),
        );
        if transport["first_frame_encrypted"].as_bool().unwrap() {
            header.flags |= 0x08;
        }
        if transport["first_frame_extended"].as_bool().unwrap() {
            header.flags |= 0x80;
            header.is_extended = true;
        }
        let header_decision = evaluate_hello_header(
            &header,
            Duration::from_millis(transport["hello_elapsed_ms"].as_u64().unwrap()),
            Duration::from_millis(server["hello_timeout_ms"].as_u64().unwrap()),
            server["max_hello_payload"].as_u64().unwrap(),
        );
        if header_decision.action == NcpHandshakeAction::SilentClose {
            assert_eq!(
                action_token(header_decision.action),
                expected["action"].as_str().unwrap(),
                "{id}"
            );
            continue;
        }

        let decision = negotiate_handshake(&server_profile(server), &hello_frame(&input["hello"]));
        assert_eq!(
            action_token(decision.action),
            expected["action"].as_str().unwrap(),
            "{id}"
        );
        assert_eq!(
            decision.status,
            expected.get("status").and_then(Value::as_str),
            "{id}"
        );
        assert_eq!(
            decision.error,
            expected.get("error").and_then(Value::as_str),
            "{id}"
        );
        if decision.action == NcpHandshakeAction::Accept {
            assert_eq!(
                decision.session_version.as_deref(),
                expected["session_version"].as_str(),
                "{id}"
            );
            assert_eq!(
                decision.negotiated_encoding.as_deref(),
                expected["negotiated_encoding"].as_str(),
                "{id}"
            );
            assert_eq!(
                decision.enabled_encodings.as_deref().unwrap(),
                strings(expected.get("enabled_encodings")),
                "{id}"
            );
            assert_eq!(
                decision.supported_protocols.as_deref().unwrap(),
                strings(expected.get("supported_protocols")),
                "{id}"
            );
            assert_eq!(
                decision.max_frame_payload,
                expected["max_frame_payload"].as_u64(),
                "{id}"
            );
            assert_eq!(
                decision.ext_support,
                expected["ext_support"].as_bool(),
                "{id}"
            );
            assert_eq!(
                decision.max_concurrent_streams,
                expected["max_concurrent_streams"].as_u64(),
                "{id}"
            );
        }
    }
}

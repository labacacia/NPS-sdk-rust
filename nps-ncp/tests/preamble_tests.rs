// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0
//
// Parity tests for NPS-RFC-0001 NCP native-mode connection preamble.

use nps_ncp::preamble;

const SPEC_BYTES: &[u8] = &[0x4E, 0x50, 0x53, 0x2F, 0x31, 0x2E, 0x30, 0x0A];

#[test]
fn bytes_are_exactly_the_spec_constant() {
    assert_eq!(preamble::LENGTH, 8);
    assert_eq!(preamble::LITERAL, "NPS/1.0\n");
    assert_eq!(preamble::BYTES, SPEC_BYTES);
}

#[test]
fn matches_returns_true_for_exact_preamble() {
    assert!(preamble::matches(preamble::BYTES));
}

#[test]
fn matches_returns_true_when_preamble_is_at_start_of_longer_buffer() {
    let mut combined = [0u8; 16];
    combined[..8].copy_from_slice(preamble::BYTES);
    combined[8] = 0x06;
    assert!(preamble::matches(&combined));
}

#[test]
fn matches_returns_false_on_short_reads() {
    for n in [0, 1, 7] {
        assert!(!preamble::matches(&preamble::BYTES[..n]));
    }
}

#[test]
fn validate_accepts_exact_preamble() {
    preamble::validate(preamble::BYTES).expect("expected ok");
}

#[test]
fn validate_rejects_short_read() {
    let err = preamble::validate(&[0, 0, 0]).expect_err("expected error");
    let msg = format!("{err}");
    assert!(msg.contains("short read"), "msg: {msg}");
    assert!(msg.contains("3/8"), "msg: {msg}");
}

#[test]
fn validate_rejects_garbage() {
    let err = preamble::validate(b"GET / HTT").expect_err("expected error");
    let msg = format!("{err}");
    assert!(!msg.contains("future"), "msg: {msg}");
    assert!(msg.contains("not speaking NPS"), "msg: {msg}");
}

#[test]
fn validate_flags_future_major_distinctly() {
    let err = preamble::validate(b"NPS/2.0\n").expect_err("expected error");
    let msg = format!("{err}");
    assert!(msg.contains("future-major"), "msg: {msg}");
}

#[test]
fn write_emits_exactly_the_constant_bytes() {
    let mut buf: Vec<u8> = Vec::new();
    preamble::write(&mut buf).unwrap();
    assert_eq!(buf, SPEC_BYTES);
}

#[test]
fn status_and_error_code_constants_match_spec() {
    assert_eq!(preamble::ERROR_CODE,  "NCP-PREAMBLE-INVALID");
    assert_eq!(preamble::STATUS_CODE, "NPS-PROTO-PREAMBLE-INVALID");
}

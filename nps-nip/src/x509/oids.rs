// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! OID constants for NPS X.509 certificates per NPS-RFC-0002 §4.
//!
//! The 1.3.6.1.4.1.99999 arc is provisional pending IANA Private Enterprise
//! Number assignment (RFC-0002 §10 OQ-2). All implementations MUST update
//! these constants when the official PEN is granted.

// EKU OIDs (NPS-RFC-0002 §4.1).
pub const EKU_AGENT_IDENTITY_OID:        &[u64] = &[1, 3, 6, 1, 4, 1, 99999, 1, 1];
pub const EKU_NODE_IDENTITY_OID:         &[u64] = &[1, 3, 6, 1, 4, 1, 99999, 1, 2];
pub const EKU_CA_INTERMEDIATE_AGENT_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 99999, 1, 3];

// Custom extensions.
pub const NID_ASSURANCE_LEVEL_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 99999, 2, 1];

// Standard X.509 OID for ExtendedKeyUsage extension (id-ce-extKeyUsage).
pub const EXTENSION_EXTENDED_KEY_USAGE_OID: &[u64] = &[2, 5, 29, 37];

/// Compare an x509-parser Oid (which iterates u64 components) to a `&[u64]` slice.
pub fn oid_equals(parsed: &x509_parser::oid_registry::Oid, expected: &[u64]) -> bool {
    let Some(it) = parsed.iter() else { return false; };
    let parsed_components: Vec<u64> = it.collect();
    parsed_components.as_slice() == expected
}

/// Encode an OID component sequence into DER OID content bytes (no tag/length).
pub fn encode_oid_content(oid: &[u64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(oid.len() * 2);
    if oid.len() < 2 {
        return out;
    }
    out.push((oid[0] * 40 + oid[1]) as u8);
    for &n in &oid[2..] {
        if n < 128 {
            out.push(n as u8);
        } else {
            // Multi-byte base-128 encoding, MSB-first with high bit set on all but last.
            let mut bytes = Vec::new();
            let mut v = n;
            bytes.push((v & 0x7F) as u8);
            v >>= 7;
            while v > 0 {
                bytes.push(((v & 0x7F) | 0x80) as u8);
                v >>= 7;
            }
            bytes.reverse();
            out.extend(bytes);
        }
    }
    out
}

/// Build the DER encoding of `SEQUENCE OF OBJECT IDENTIFIER { eku }` —
/// the value field for the ExtendedKeyUsage extension.
pub fn build_eku_extension_value(eku_oid: &[u64]) -> Vec<u8> {
    let oid_content = encode_oid_content(eku_oid);
    let mut oid_tlv = Vec::with_capacity(2 + oid_content.len());
    oid_tlv.push(0x06); // OBJECT IDENTIFIER tag
    oid_tlv.push(oid_content.len() as u8);
    oid_tlv.extend(oid_content);

    let mut seq = Vec::with_capacity(2 + oid_tlv.len());
    seq.push(0x30); // SEQUENCE
    seq.push(oid_tlv.len() as u8);
    seq.extend(oid_tlv);
    seq
}

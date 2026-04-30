// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Issues NPS X.509 NID certificates per NPS-RFC-0002 §4.1.

use ed25519_dalek::SigningKey;
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, CustomExtension, DistinguishedName, DnType,
    IsCa, KeyPair, KeyUsagePurpose, SanType, SerialNumber, SubjectPublicKeyInfo,
};
use std::time::SystemTime;
use time::OffsetDateTime;

use crate::assurance_level::AssuranceLevel;

use super::oids::{
    build_eku_extension_value, EKU_AGENT_IDENTITY_OID, EKU_NODE_IDENTITY_OID,
    EXTENSION_EXTENDED_KEY_USAGE_OID, NID_ASSURANCE_LEVEL_OID,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeafRole {
    Agent,
    Node,
}

pub struct IssueLeafOptions<'a> {
    pub subject_nid:     &'a str,
    pub subject_pub_raw: &'a [u8; 32],
    pub ca_signing_key:  &'a SigningKey,
    pub ca_root_cert:    &'a Certificate,
    pub role:            LeafRole,
    pub assurance_level: AssuranceLevel,
    pub not_before:      SystemTime,
    pub not_after:       SystemTime,
    pub serial_number:   &'a [u8],
}

pub struct IssueRootOptions<'a> {
    pub ca_nid:         &'a str,
    pub ca_signing_key: &'a SigningKey,
    pub not_before:     SystemTime,
    pub not_after:      SystemTime,
    pub serial_number:  &'a [u8],
}

/// Convert an ed25519-dalek SigningKey to an rcgen KeyPair via PKCS#8 DER
/// (RFC 8410 fixed prefix + 32-byte seed).
pub fn dalek_to_rcgen_keypair(sk: &SigningKey) -> Result<KeyPair, rcgen::Error> {
    let mut pkcs8 = Vec::with_capacity(48);
    pkcs8.extend_from_slice(&[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ]);
    pkcs8.extend_from_slice(sk.as_bytes());
    KeyPair::try_from(pkcs8.as_slice())
}

/// Convert a 32-byte Ed25519 raw public key to a rcgen SubjectPublicKeyInfo
/// via SPKI DER (RFC 8410 fixed prefix + 32-byte raw key).
fn raw_pub_to_spki(pub_raw: &[u8; 32]) -> Result<SubjectPublicKeyInfo, rcgen::Error> {
    let mut spki = Vec::with_capacity(44);
    spki.extend_from_slice(&[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
        0x70, 0x03, 0x21, 0x00,
    ]);
    spki.extend_from_slice(pub_raw);
    SubjectPublicKeyInfo::from_der(&spki)
}

fn system_to_offset(t: SystemTime) -> OffsetDateTime {
    let duration = t.duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default();
    OffsetDateTime::from_unix_timestamp(duration.as_secs() as i64).unwrap_or(OffsetDateTime::UNIX_EPOCH)
}

/// Issue a self-signed CA root certificate (testing / private CA use).
pub fn issue_root(opts: IssueRootOptions<'_>) -> Result<Certificate, String> {
    let ca_keypair = dalek_to_rcgen_keypair(opts.ca_signing_key)
        .map_err(|e| format!("dalek→rcgen keypair: {e}"))?;

    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| format!("rcgen params: {e}"))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, opts.ca_nid.to_string());
    params.distinguished_name = dn;
    params.serial_number = Some(SerialNumber::from_slice(opts.serial_number));
    params.not_before = system_to_offset(opts.not_before);
    params.not_after  = system_to_offset(opts.not_after);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    params.self_signed(&ca_keypair)
        .map_err(|e| format!("rcgen self_signed: {e}"))
}

/// Issue a leaf NPS NID certificate (RFC-0002 §4.1).
pub fn issue_leaf(opts: IssueLeafOptions<'_>) -> Result<Certificate, String> {
    let ca_keypair = dalek_to_rcgen_keypair(opts.ca_signing_key)
        .map_err(|e| format!("dalek→rcgen keypair: {e}"))?;
    let subject_spki = raw_pub_to_spki(opts.subject_pub_raw)
        .map_err(|e| format!("subject SPKI build: {e}"))?;

    let mut params = CertificateParams::new(vec![opts.subject_nid.to_string()])
        .map_err(|e| format!("rcgen params: {e}"))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, opts.subject_nid.to_string());
    params.distinguished_name = dn;

    // Replace the auto-derived DNS SAN (from CertificateParams::new) with our URI SAN.
    params.subject_alt_names = vec![SanType::URI(
        opts.subject_nid.try_into()
            .map_err(|e: rcgen::Error| format!("SAN URI: {e}"))?,
    )];

    params.serial_number = Some(SerialNumber::from_slice(opts.serial_number));
    params.not_before    = system_to_offset(opts.not_before);
    params.not_after     = system_to_offset(opts.not_after);
    params.is_ca         = IsCa::NoCa;
    params.key_usages    = vec![KeyUsagePurpose::DigitalSignature];

    // Critical EKU containing the NPS agent-identity / node-identity OID.
    let eku_oid: &[u64] = if opts.role == LeafRole::Node {
        EKU_NODE_IDENTITY_OID
    } else {
        EKU_AGENT_IDENTITY_OID
    };
    let mut eku_ext = CustomExtension::from_oid_content(
        EXTENSION_EXTENDED_KEY_USAGE_OID,
        build_eku_extension_value(eku_oid),
    );
    eku_ext.set_criticality(true);
    params.custom_extensions.push(eku_ext);

    // ASN.1 ENUMERATED encoding of assurance level: tag=0x0A, len=0x01, value=<rank>.
    let assurance_der = vec![0x0A, 0x01, opts.assurance_level.rank];
    let assurance_ext = CustomExtension::from_oid_content(
        NID_ASSURANCE_LEVEL_OID,
        assurance_der,
    );
    params.custom_extensions.push(assurance_ext);

    params.signed_by(&subject_spki, opts.ca_root_cert, &ca_keypair)
        .map_err(|e| format!("rcgen signed_by: {e}"))
}

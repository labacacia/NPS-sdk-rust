// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! NIP v0.12 §7.5 — Phase-3 enforcement.
//!
//! Stateless and pure: no I/O, no network. The clock is injectable through the
//! optional `now` argument (defaults to UTC now) so the checks are
//! deterministic under test.
//!
//! Port of `src/NPS.NIP/Verification/NipPhase3Enforcer.cs`. Like the reference,
//! [`enforce`] implements three of the four normative rows —
//! **node_roles → capabilities → OCSP staple, in that fixed order**. The fourth
//! (assurance) lives in [`crate::x509::verifier`]'s chain validation and runs
//! *unconditionally*, regardless of the flag; with `phase3_enforcement = true`
//! all four are hard failures.
//!
//! Everything here is DER-parsed with a small self-contained TLV reader — no
//! new dependency, and no signature verification: Phase-3's job on the staple is
//! freshness only.

use base64::Engine;
use time::OffsetDateTime;

use crate::error_codes;
use crate::frames::IdentFrame;
use crate::verifier::NipIdentVerifyResult;
use crate::x509::oids::{encode_oid_content, ID_NPS_CAPABILITIES_OID, ID_NPS_NODE_ROLES_OID};

/// Phase-3 failures always report step 3 of verification.
const STEP: u8 = 3;

fn ok() -> NipIdentVerifyResult {
    NipIdentVerifyResult {
        valid: true,
        step_failed: 0,
        error_code: None,
        message: None,
    }
}

fn fail(code: &'static str, msg: impl Into<String>) -> NipIdentVerifyResult {
    NipIdentVerifyResult {
        valid: false,
        step_failed: STEP,
        error_code: Some(code),
        message: Some(msg.into()),
    }
}

/// Run the Phase-3 checks against `leaf_der` (the DER of `cert_chain[0]`).
///
/// `now` defaults to `OffsetDateTime::now_utc()`.
///
/// Evaluation order is fixed: node_roles → capabilities → OCSP staple.
pub fn enforce(
    frame: &IdentFrame,
    leaf_der: &[u8],
    now: Option<OffsetDateTime>,
) -> NipIdentVerifyResult {
    let now = now.unwrap_or_else(OffsetDateTime::now_utc);

    // ── 1. node_roles ⊆ id-nps-node-roles ────────────────────────────────────
    if let Some(attested) = read_utf8_sequence_extension(leaf_der, ID_NPS_NODE_ROLES_OID) {
        let excess = excess(frame.node_roles.as_deref().unwrap_or(&[]), &attested);
        if !excess.is_empty() {
            return fail(
                error_codes::CERT_NODE_ROLES_MISMATCH,
                format!(
                    "IdentFrame.node_roles claims role(s) not attested by id-nps-node-roles: {}.",
                    excess.join(", ")
                ),
            );
        }
    }
    // Extension absent ⇒ the check does not apply at all.

    // ── 2. capabilities ⊆ id-nps-capabilities ────────────────────────────────
    if let Some(attested) = read_utf8_sequence_extension(leaf_der, ID_NPS_CAPABILITIES_OID) {
        let excess = excess(&frame.capabilities, &attested);
        if !excess.is_empty() {
            return fail(
                error_codes::CERT_CAPABILITIES_EXCEEDED,
                format!(
                    "IdentFrame.capabilities claims capabilit(ies) not attested by \
                     id-nps-capabilities: {}.",
                    excess.join(", ")
                ),
            );
        }
    }

    // ── 3. OCSP staple — the one UNCONDITIONAL check; fails closed ───────────
    let staple = frame.ocsp_staple.as_deref().unwrap_or("");
    if staple.is_empty() {
        return fail(
            error_codes::OCSP_STAPLE_EXPIRED,
            "Phase-3 enforcement requires ocsp_staple on v2-x509 IdentFrames; none was supplied.",
        );
    }
    let der = match base64url_decode(staple) {
        Some(d) => d,
        None => {
            return fail(
                error_codes::OCSP_STAPLE_EXPIRED,
                "ocsp_staple is not valid base64url.",
            )
        }
    };
    let next_update = match try_get_ocsp_next_update(&der) {
        Some(t) => t,
        None => {
            return fail(
                error_codes::OCSP_STAPLE_EXPIRED,
                "ocsp_staple could not be parsed as a DER OCSPResponse with a nextUpdate.",
            )
        }
    };
    // `<=`, not `<`: nextUpdate exactly at `now` has elapsed.
    if next_update <= now {
        return fail(
            error_codes::OCSP_STAPLE_EXPIRED,
            format!("ocsp_staple nextUpdate {next_update} has elapsed."),
        );
    }

    ok()
}

/// `claimed \ attested`, preserving claim order. Comparison is ordinal /
/// exact-byte — no case folding, no normalisation, no trimming. Under-claiming
/// is allowed (subset check); duplicates are irrelevant.
fn excess(claimed: &[String], attested: &[String]) -> Vec<String> {
    claimed
        .iter()
        .filter(|c| !attested.iter().any(|a| a == *c))
        .cloned()
        .collect()
}

/// Read a `SEQUENCE OF UTF8String` certificate extension. **Tri-state, and the
/// tri-state IS the rule:**
///
/// | Extension state | Return | Behaviour |
/// |---|---|---|
/// | absent from the cert | `None` | the check is skipped entirely |
/// | present, valid | `Some(list)` (may be empty) | subset check runs against it |
/// | present, malformed ASN.1 | `Some(vec![])` | strictest reading — any claim then fails |
///
/// Collapsing "absent" onto "present but empty" would turn a fail-closed case
/// into a skip.
pub fn read_utf8_sequence_extension(leaf_der: &[u8], oid: &[u64]) -> Option<Vec<String>> {
    let raw = find_extension_value(leaf_der, oid)?;
    Some(parse_utf8_sequence(raw).unwrap_or_default())
}

fn parse_utf8_sequence(value: &[u8]) -> Option<Vec<String>> {
    let mut outer = Der::new(value);
    let (tag, content) = outer.read()?;
    if tag != 0x30 {
        return None;
    }
    let mut inner = Der::new(content);
    let mut out = Vec::new();
    while !inner.at_end() {
        let (t, c) = inner.read()?;
        if t != 0x0C {
            return None; // not a UTF8String — malformed for our purposes
        }
        out.push(String::from_utf8(c.to_vec()).ok()?);
    }
    Some(out)
}

/// Minimal RFC 6960 DER walk returning the first SingleResponse's `nextUpdate`.
///
/// Returns `None` (⇒ fail closed) when `responseBytes` is absent, `responses` is
/// empty, `nextUpdate` is absent, or any content is malformed. Signature
/// verification is deliberately NOT performed — Phase-3 checks freshness only.
///
/// ```text
/// OCSPResponse      ::= SEQUENCE { responseStatus ENUMERATED,
///                                  responseBytes [0] EXPLICIT ResponseBytes OPTIONAL }
/// ResponseBytes     ::= SEQUENCE { responseType OID, response OCTET STRING }
/// BasicOCSPResponse ::= SEQUENCE { tbsResponseData ResponseData, ... }
/// ResponseData      ::= SEQUENCE { version [0] EXPLICIT OPTIONAL,
///                                  responderID CHOICE [1]/[2],
///                                  producedAt GeneralizedTime,
///                                  responses SEQUENCE OF SingleResponse }
/// SingleResponse    ::= SEQUENCE { certID SEQUENCE, certStatus CHOICE,
///                                  thisUpdate GeneralizedTime,
///                                  nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL, ... }
/// ```
pub fn try_get_ocsp_next_update(der: &[u8]) -> Option<OffsetDateTime> {
    // OCSPResponse
    let (tag, body) = Der::new(der).read()?;
    if tag != 0x30 {
        return None;
    }
    let mut resp = Der::new(body);
    let (status_tag, _) = resp.read()?; // responseStatus ENUMERATED
    if status_tag != 0x0A {
        return None;
    }
    let (rb_tag, rb) = resp.read()?; // [0] EXPLICIT ResponseBytes
    if rb_tag != 0xA0 {
        return None; // responseBytes absent
    }

    // ResponseBytes
    let (t, rb_seq) = Der::new(rb).read()?;
    if t != 0x30 {
        return None;
    }
    let mut rbs = Der::new(rb_seq);
    let (oid_tag, _oid) = rbs.read()?; // responseType (id-pkix-ocsp-basic)
    if oid_tag != 0x06 {
        return None;
    }
    let (os_tag, basic_der) = rbs.read()?; // response OCTET STRING
    if os_tag != 0x04 {
        return None;
    }

    // BasicOCSPResponse → tbsResponseData
    let (t, basic) = Der::new(basic_der).read()?;
    if t != 0x30 {
        return None;
    }
    let mut basic = Der::new(basic);
    let (t, tbs) = basic.read()?;
    if t != 0x30 {
        return None;
    }

    // ResponseData
    let mut rd = Der::new(tbs);
    let mut cur = rd.read()?;
    if cur.0 == 0xA0 {
        cur = rd.read()?; // skip version [0]
    }
    if cur.0 & 0xC0 == 0x80 {
        cur = rd.read()?; // skip responderID [1]/[2]
    }
    if cur.0 == 0x18 || cur.0 == 0x17 {
        cur = rd.read()?; // skip producedAt
    }
    if cur.0 != 0x30 {
        return None; // responses SEQUENCE OF SingleResponse
    }

    // First SingleResponse only.
    let mut responses = Der::new(cur.1);
    let (t, single) = responses.read()?;
    if t != 0x30 {
        return None; // responses empty ⇒ read() already returned None
    }
    let mut sr = Der::new(single);
    let (t, _cert_id) = sr.read()?; // certID SEQUENCE
    if t != 0x30 {
        return None;
    }
    let (t, _status) = sr.read()?; // certStatus CHOICE (context-specific)
    if t & 0xC0 != 0x80 {
        return None;
    }
    let (t, _this_update) = sr.read()?; // thisUpdate GeneralizedTime
    if t != 0x18 && t != 0x17 {
        return None;
    }
    // nextUpdate [0] EXPLICIT GeneralizedTime OPTIONAL
    let (t, next) = sr.read()?;
    if t != 0xA0 {
        return None; // nextUpdate absent
    }
    let (t, gt) = Der::new(next).read()?;
    if t != 0x18 {
        return None;
    }
    parse_generalized_time(gt)
}

// ── DER helpers ──────────────────────────────────────────────────────────────

/// A cursor over concatenated DER TLVs.
struct Der<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Der<'a> {
    fn new(b: &'a [u8]) -> Self {
        Der { b, pos: 0 }
    }

    fn at_end(&self) -> bool {
        self.pos >= self.b.len()
    }

    /// Read one TLV, returning `(tag, content)`. `None` at end of input or on a
    /// malformed length.
    fn read(&mut self) -> Option<(u8, &'a [u8])> {
        if self.pos + 2 > self.b.len() {
            return None;
        }
        let tag = self.b[self.pos];
        let (len, hdr) = read_len(&self.b[self.pos + 1..])?;
        let start = self.pos + 1 + hdr;
        let end = start.checked_add(len)?;
        if end > self.b.len() {
            return None;
        }
        self.pos = end;
        Some((tag, &self.b[start..end]))
    }
}

/// Read a DER length prefix → `(content_length, header_length)`.
fn read_len(b: &[u8]) -> Option<(usize, usize)> {
    let first = *b.first()?;
    if first & 0x80 == 0 {
        return Some((first as usize, 1));
    }
    let n = (first & 0x7F) as usize;
    if n == 0 || n > 4 || b.len() < 1 + n {
        return None;
    }
    let mut len = 0usize;
    for i in 0..n {
        len = (len << 8) | b[1 + i] as usize;
    }
    Some((len, 1 + n))
}

/// Locate the first extension whose OID matches and return its raw value bytes.
fn find_extension_value<'a>(cert_der: &'a [u8], oid: &[u64]) -> Option<&'a [u8]> {
    let wanted = encode_oid_content(oid);

    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    let (t, cert) = Der::new(cert_der).read()?;
    if t != 0x30 {
        return None;
    }
    let (t, tbs) = Der::new(cert).read()?;
    if t != 0x30 {
        return None;
    }
    // Walk tbsCertificate for the [3] EXPLICIT extensions block.
    let mut c = Der::new(tbs);
    let exts = loop {
        let (t, v) = c.read()?;
        if t == 0xA3 {
            break v;
        }
    };
    let (t, ext_seq) = Der::new(exts).read()?;
    if t != 0x30 {
        return None;
    }
    let mut it = Der::new(ext_seq);
    while let Some((t, ext)) = it.read() {
        if t != 0x30 {
            continue;
        }
        let mut e = Der::new(ext);
        let (ot, ov) = match e.read() {
            Some(x) => x,
            None => continue,
        };
        if ot != 0x06 || ov != wanted.as_slice() {
            continue;
        }
        // Optional BOOLEAN critical, then the OCTET STRING value.
        let mut next = e.read();
        if let Some((0x01, _)) = next {
            next = e.read();
        }
        if let Some((0x04, value)) = next {
            return Some(value);
        }
        return None;
    }
    None
}

/// Decode base64url (padded or not); also tolerates a standard-alphabet value.
fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(s))
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s))
        .ok()
}

/// Parse an ASN.1 GeneralizedTime (`YYYYMMDDHHMMSS[.fff]Z`).
fn parse_generalized_time(b: &[u8]) -> Option<OffsetDateTime> {
    let s = std::str::from_utf8(b).ok()?;
    let s = s.strip_suffix('Z')?;
    // Drop any fractional-seconds part; second resolution is enough here.
    let s = s.split('.').next()?;
    if s.len() != 14 {
        return None;
    }
    let num = |a: usize, b: usize| s[a..b].parse::<i64>().ok();
    let year = num(0, 4)? as i32;
    let month = time::Month::try_from(num(4, 6)? as u8).ok()?;
    let day = num(6, 8)? as u8;
    let hour = num(8, 10)? as u8;
    let min = num(10, 12)? as u8;
    let sec = num(12, 14)? as u8;
    let date = time::Date::from_calendar_date(year, month, day).ok()?;
    let t = time::Time::from_hms(hour, min, sec).ok()?;
    Some(date.with_time(t).assume_utc())
}

// ── Test-support DER builders ────────────────────────────────────────────────

/// Build the DER value of a `SEQUENCE OF UTF8String` — the encoding of the
/// `id-nps-node-roles` / `id-nps-capabilities` extension values.
pub fn build_utf8_sequence_extension_value(values: &[&str]) -> Vec<u8> {
    let mut inner = Vec::new();
    for v in values {
        inner.push(0x0C);
        inner.extend(encode_len(v.len()));
        inner.extend_from_slice(v.as_bytes());
    }
    let mut out = vec![0x30];
    out.extend(encode_len(inner.len()));
    out.extend(inner);
    out
}

fn encode_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else if n < 0x100 {
        vec![0x81, n as u8]
    } else {
        vec![0x82, (n >> 8) as u8, (n & 0xFF) as u8]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut v = vec![tag];
        v.extend(encode_len(content.len()));
        v.extend_from_slice(content);
        v
    }

    fn gen_time(t: OffsetDateTime) -> Vec<u8> {
        let s = format!(
            "{:04}{:02}{:02}{:02}{:02}{:02}Z",
            t.year(),
            t.month() as u8,
            t.day(),
            t.hour(),
            t.minute(),
            t.second()
        );
        tlv(0x18, s.as_bytes())
    }

    /// Hand-build a minimal RFC 6960 OCSPResponse carrying `next_update`.
    fn ocsp_response(next_update: Option<OffsetDateTime>, this_update: OffsetDateTime) -> Vec<u8> {
        let mut single = Vec::new();
        single.extend(tlv(0x30, &[])); // certID SEQUENCE (empty is fine here)
        single.extend(tlv(0x80, &[])); // certStatus [0] good
        single.extend(gen_time(this_update));
        if let Some(n) = next_update {
            single.extend(tlv(0xA0, &gen_time(n))); // [0] EXPLICIT
        }
        let responses = tlv(0x30, &tlv(0x30, &single));

        let mut rd = Vec::new();
        rd.extend(tlv(0xA1, &[])); // responderID [1]
        rd.extend(gen_time(this_update)); // producedAt
        rd.extend(responses);
        let tbs = tlv(0x30, &rd);
        let basic = tlv(0x30, &tbs);

        let mut rb = Vec::new();
        // id-pkix-ocsp-basic 1.3.6.1.5.5.7.48.1.1
        rb.extend(tlv(
            0x06,
            &encode_oid_content(&[1, 3, 6, 1, 5, 5, 7, 48, 1, 1]),
        ));
        rb.extend(tlv(0x04, &basic));
        let response_bytes = tlv(0x30, &rb);

        let mut outer = Vec::new();
        outer.extend(tlv(0x0A, &[0x00])); // responseStatus successful
        outer.extend(tlv(0xA0, &response_bytes));
        tlv(0x30, &outer)
    }

    const NOW: OffsetDateTime = datetime!(2026-07-05 12:00:00 UTC);

    // ── the OCSP DER walk ────────────────────────────────────────────────────

    #[test]
    fn ocsp_next_update_is_recovered() {
        let der = ocsp_response(Some(datetime!(2026-07-05 18:00:00 UTC)), NOW);
        assert_eq!(
            try_get_ocsp_next_update(&der),
            Some(datetime!(2026-07-05 18:00:00 UTC))
        );
    }

    #[test]
    fn ocsp_without_next_update_returns_none() {
        let der = ocsp_response(None, NOW);
        assert_eq!(try_get_ocsp_next_update(&der), None);
    }

    #[test]
    fn ocsp_garbage_returns_none() {
        assert_eq!(try_get_ocsp_next_update(b"not-an-ocsp"), None);
        assert_eq!(try_get_ocsp_next_update(&[]), None);
        assert_eq!(try_get_ocsp_next_update(&[0x30, 0x80]), None);
    }

    #[test]
    fn ocsp_without_response_bytes_returns_none() {
        let der = tlv(0x30, &tlv(0x0A, &[0x06])); // status only, no [0] block
        assert_eq!(try_get_ocsp_next_update(&der), None);
    }

    // ── the SEQUENCE OF UTF8String parser ────────────────────────────────────

    #[test]
    fn utf8_sequence_round_trips() {
        let v = build_utf8_sequence_extension_value(&["memory", "anchor"]);
        assert_eq!(
            parse_utf8_sequence(&v),
            Some(vec!["memory".to_string(), "anchor".to_string()])
        );
    }

    #[test]
    fn empty_utf8_sequence_parses_to_an_empty_list() {
        let v = build_utf8_sequence_extension_value(&[]);
        assert_eq!(parse_utf8_sequence(&v), Some(vec![]));
    }

    #[test]
    fn malformed_utf8_sequence_parses_to_none_and_reads_as_empty() {
        assert_eq!(parse_utf8_sequence(b"\x30\x03\x02\x01\x05"), None);
    }

    // ── subset semantics ─────────────────────────────────────────────────────

    #[test]
    fn excess_is_ordinal_and_order_preserving() {
        let claimed = vec!["a".to_string(), "B".to_string(), "c".to_string()];
        let attested = vec!["a".to_string(), "b".to_string()];
        assert_eq!(excess(&claimed, &attested), vec!["B", "c"]);
        // exact-byte: "B" is NOT matched by "b".
        assert!(excess(&["a".to_string()], &attested).is_empty());
    }
}

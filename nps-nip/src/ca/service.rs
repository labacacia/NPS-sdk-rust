// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! Core CA business logic: issue, renew, revoke, verify NID certificates
//! (NPS-3 §6–8) plus orchestrator groups + sessions (NPS-CR-0003) and the
//! RA enrollment gate (NPS-CR-0005). Mirror of the .NET `NipCaService`.
//!
//! All signing uses the CA's Ed25519 key via [`super::signer`]; canonical form
//! and wire field names match the .NET reference byte-for-byte.

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::{json, Map, Value};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use crate::error_codes;
use crate::frames::{IdentFrame, RevokeFrame};

use super::error::{EnrollmentOutcome, NipCaError, NipRaPending};
use super::options::NipCaOptions;
use super::ra::{EnrollmentPolicy, EnrollmentRequest};
use super::signer;
use super::store::{NipCaStore, NipCertRecord, StoreError, ROLE_GROUP, ROLE_SESSION};

/// Verification outcome of [`NipCaService::verify`].
#[derive(Debug, Clone)]
pub struct NipVerifyResult {
    pub valid: bool,
    pub error_code: Option<&'static str>,
    pub message: Option<String>,
    pub record: Option<NipCertRecord>,
}

impl NipVerifyResult {
    fn ok(record: NipCertRecord) -> Self {
        Self {
            valid: true,
            error_code: None,
            message: None,
            record: Some(record),
        }
    }
    fn fail(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            valid: false,
            error_code: Some(code),
            message: Some(message.into()),
            record: None,
        }
    }
}

/// Parameters for [`NipCaService::issue_session`].
#[derive(Default)]
pub struct IssueSessionParams {
    pub validity: Option<Duration>,
    pub purpose: Option<String>,
    pub capabilities: Option<Vec<String>>,
    pub scope_json: Option<String>,
    pub metadata_json: Option<String>,
}

/// Core NIP CA service. Generic over the [`NipCaStore`] backend.
pub struct NipCaService<S: NipCaStore> {
    opts: NipCaOptions,
    store: S,
    signing_key: SigningKey,
}

impl<S: NipCaStore> NipCaService<S> {
    pub fn new(opts: NipCaOptions, store: S, signing_key: SigningKey) -> Self {
        Self {
            opts,
            store,
            signing_key,
        }
    }

    pub fn options(&self) -> &NipCaOptions {
        &self.opts
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    // ── Register (Agent / Node) ───────────────────────────────────────────────

    /// Register a new Agent or Node, issue an IdentFrame, and persist the record.
    pub fn register(
        &self,
        entity_type: &str,
        identifier: &str,
        pub_key: &str,
        capabilities: &[String],
        scope_json: &str,
        metadata_json: Option<&str>,
    ) -> Result<IdentFrame, NipCaError> {
        let nid = self.build_nid(entity_type, identifier);
        if self.store.get_by_nid(&nid).is_some() {
            return Err(NipCaError::new(
                format!("NID already exists: {nid}"),
                error_codes::CA_NID_ALREADY_EXISTS,
            ));
        }
        self.check_capabilities(capabilities)?;

        let valid_days = if entity_type == "node" {
            self.opts.node_cert_validity_days
        } else {
            self.opts.agent_cert_validity_days
        };
        let now = OffsetDateTime::now_utc();
        let expires_at = now + Duration::days(valid_days);
        let serial = self.store.next_serial();

        let frame = self.issue_frame(
            &nid,
            pub_key,
            capabilities,
            scope_json,
            now,
            expires_at,
            &serial,
            metadata_json,
            None,
            None,
        )?;

        self.persist(NipCertRecord {
            nid: nid.clone(),
            entity_type: entity_type.to_string(),
            serial,
            pub_key: pub_key.to_string(),
            capabilities: capabilities.to_vec(),
            scope_json: scope_json.to_string(),
            issued_by: self.opts.ca_nid.clone(),
            issued_at: now,
            expires_at,
            revoked_at: None,
            revoke_reason: None,
            metadata_json: metadata_json.map(str::to_string),
            nid_role: None,
            parent_nid: None,
            lineage_json: None,
        })?;

        Ok(frame)
    }

    // ── Register with RA gate (NPS-CR-0005) ───────────────────────────────────

    /// RA-gated registration: run the active [`EnrollmentPolicy`] before
    /// delegating to [`Self::register`].
    ///
    /// A `Pending` outcome is surfaced as `Err(RegisterWithRaError::Pending(..))`.
    #[allow(clippy::too_many_arguments)]
    pub fn register_with_ra(
        &self,
        entity_type: &str,
        identifier: &str,
        pub_key: &str,
        capabilities: &[String],
        scope_json: &str,
        metadata_json: Option<&str>,
        enrollment_token: Option<&str>,
        policy: &dyn EnrollmentPolicy,
    ) -> Result<IdentFrame, RegisterWithRaError> {
        let req = EnrollmentRequest {
            entity_type,
            identifier,
            pub_key,
            capabilities,
            scope_json,
            metadata_json,
            enrollment_token,
        };
        match policy.check(&req) {
            EnrollmentOutcome::Admit => {}
            EnrollmentOutcome::Deny(e) => return Err(RegisterWithRaError::Ca(e)),
            EnrollmentOutcome::Pending(p) => return Err(RegisterWithRaError::Pending(p)),
        }
        self.register(
            entity_type,
            identifier,
            pub_key,
            capabilities,
            scope_json,
            metadata_json,
        )
        .map_err(RegisterWithRaError::Ca)
    }

    // ── Register X.509 (NPS-RFC-0002 prototype) ───────────────────────────────

    /// Register an Agent/Node and issue an IdentFrame carrying both the v1
    /// CA-signed JSON proof and a DER X.509 chain (leaf + root) per
    /// NPS-RFC-0002 §4.1.
    #[allow(clippy::too_many_arguments)]
    pub fn register_x509(
        &self,
        entity_type: &str,
        identifier: &str,
        pub_key: &str,
        capabilities: &[String],
        scope_json: &str,
        assurance_level: Option<crate::assurance_level::AssuranceLevel>,
        metadata_json: Option<&str>,
    ) -> Result<IdentFrame, NipCaError> {
        use crate::x509::{issue_leaf, issue_root, IssueLeafOptions, IssueRootOptions, LeafRole};
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
        use base64::Engine as _;

        let nid = self.build_nid(entity_type, identifier);
        if self.store.get_by_nid(&nid).is_some() {
            return Err(NipCaError::new(
                format!("NID already exists: {nid}"),
                error_codes::CA_NID_ALREADY_EXISTS,
            ));
        }
        self.check_capabilities(capabilities)?;

        let valid_days = if entity_type == "node" {
            self.opts.node_cert_validity_days
        } else {
            self.opts.agent_cert_validity_days
        };
        let now = OffsetDateTime::now_utc();
        let expires_at = now + Duration::days(valid_days);
        let serial = self.store.next_serial();

        let level = assurance_level.unwrap_or(crate::assurance_level::ANONYMOUS);
        let v1 = self.issue_frame(
            &nid,
            pub_key,
            capabilities,
            scope_json,
            now,
            expires_at,
            &serial,
            metadata_json,
            Some(level),
            None,
        )?;

        // Layer X.509 on top.
        let subject_raw = extract_ed25519_raw(pub_key)?;
        let leaf_serial = parse_serial_bytes(&serial);
        let role = if entity_type == "node" {
            LeafRole::Node
        } else {
            LeafRole::Agent
        };

        let now_sys: std::time::SystemTime = now.into();
        let exp_sys: std::time::SystemTime = expires_at.into();

        let root = issue_root(IssueRootOptions {
            ca_nid: &self.opts.ca_nid,
            ca_signing_key: &self.signing_key,
            not_before: now_sys,
            not_after: (now + Duration::days(3650)).into(),
            serial_number: &[0x01],
        })
        .map_err(|e| NipCaError::new(e, error_codes::CERT_FORMAT_INVALID))?;

        let leaf = issue_leaf(IssueLeafOptions {
            subject_nid: &nid,
            subject_pub_raw: &subject_raw,
            ca_signing_key: &self.signing_key,
            ca_root_cert: &root,
            role,
            assurance_level: level,
            not_before: now_sys,
            not_after: exp_sys,
            serial_number: &leaf_serial,
            attested_node_roles: None,
            attested_capabilities: Some(&capabilities),
        })
        .map_err(|e| NipCaError::new(e, error_codes::CERT_FORMAT_INVALID))?;

        let chain = vec![B64URL.encode(leaf.der()), B64URL.encode(root.der())];

        self.persist(NipCertRecord {
            nid: nid.clone(),
            entity_type: entity_type.to_string(),
            serial,
            pub_key: pub_key.to_string(),
            capabilities: capabilities.to_vec(),
            scope_json: scope_json.to_string(),
            issued_by: self.opts.ca_nid.clone(),
            issued_at: now,
            expires_at,
            revoked_at: None,
            revoke_reason: None,
            metadata_json: metadata_json.map(str::to_string),
            nid_role: None,
            parent_nid: None,
            lineage_json: None,
        })?;

        let mut frame = v1;
        frame.cert_format = Some(crate::cert_format::V2_X509.to_string());
        frame.cert_chain = Some(chain);
        Ok(frame)
    }

    // ── Register Group (NPS-CR-0003) ──────────────────────────────────────────

    /// Register an orchestrator group NID with `lineage.role = "group"`.
    #[allow(clippy::too_many_arguments)]
    pub fn register_group(
        &self,
        identifier: Option<&str>,
        pub_key: &str,
        capabilities: &[String],
        scope_json: &str,
        owner_user_id: Option<&str>,
        owner_key_id: Option<&str>,
        metadata_json: Option<&str>,
    ) -> Result<IdentFrame, NipCaError> {
        let identifier: String = match identifier {
            None => format!("group-{}", super::ra::new_uuid_hex()),
            Some("") => format!("group-{}", super::ra::new_uuid_hex()),
            Some(id) if !id.starts_with("group-") => {
                return Err(NipCaError::new(
                    format!(
                        "Group identifier MUST start with reserved prefix 'group-' (got '{id}'). NPS-3 §3.1."
                    ),
                    error_codes::CA_NID_ALREADY_EXISTS,
                ));
            }
            Some(id) => id.to_string(),
        };

        let nid = self.build_nid("agent", &identifier);
        if self.store.get_by_nid(&nid).is_some() {
            return Err(NipCaError::new(
                format!("NID already exists: {nid}"),
                error_codes::CA_NID_ALREADY_EXISTS,
            ));
        }
        self.check_capabilities(capabilities)?;

        let now = OffsetDateTime::now_utc();
        let expires_at = now + Duration::days(self.opts.group_cert_validity_days);
        let serial = self.store.next_serial();

        let lineage = build_lineage_group(owner_user_id, owner_key_id);
        let lineage_json = serde_json::to_string(&lineage).unwrap();

        let frame = self.issue_frame(
            &nid,
            pub_key,
            capabilities,
            scope_json,
            now,
            expires_at,
            &serial,
            metadata_json,
            None,
            Some(&lineage),
        )?;

        self.persist(NipCertRecord {
            nid: nid.clone(),
            entity_type: "agent".to_string(),
            serial,
            pub_key: pub_key.to_string(),
            capabilities: capabilities.to_vec(),
            scope_json: scope_json.to_string(),
            issued_by: self.opts.ca_nid.clone(),
            issued_at: now,
            expires_at,
            revoked_at: None,
            revoke_reason: None,
            metadata_json: metadata_json.map(str::to_string),
            nid_role: Some(ROLE_GROUP.to_string()),
            parent_nid: None,
            lineage_json: Some(lineage_json),
        })?;

        Ok(frame)
    }

    // ── Issue Session (NPS-CR-0003) ───────────────────────────────────────────

    /// Issue a short-lived session NID under `group_nid`. Clamps validity,
    /// enforces capability subset, and stamps session lineage.
    pub fn issue_session(
        &self,
        group_nid: &str,
        session_pub_key: &str,
        params: IssueSessionParams,
    ) -> Result<IdentFrame, NipCaError> {
        let group = self.store.get_by_nid(group_nid).ok_or_else(|| {
            NipCaError::new(
                format!("Group NID not found: {group_nid}."),
                error_codes::CA_PARENT_NOT_FOUND,
            )
        })?;

        if group.nid_role.as_deref() != Some(ROLE_GROUP) {
            return Err(NipCaError::new(
                format!(
                    "NID '{group_nid}' is not registered as a group (role='{}').",
                    group.nid_role.as_deref().unwrap_or("<null>")
                ),
                error_codes::CA_PARENT_NOT_GROUP,
            ));
        }
        if let Some(rev) = group.revoked_at {
            return Err(NipCaError::new(
                format!(
                    "Group {group_nid} was revoked at {}; cannot issue new sessions.",
                    fmt_ts(rev)
                ),
                error_codes::CA_GROUP_REVOKED,
            ));
        }
        if OffsetDateTime::now_utc() > group.expires_at {
            return Err(NipCaError::new(
                format!(
                    "Group {group_nid} expired at {}; cannot issue new sessions.",
                    fmt_ts(group.expires_at)
                ),
                error_codes::CERT_EXPIRED,
            ));
        }

        // Validity window.
        let v = params
            .validity
            .unwrap_or(self.opts.session_default_validity);
        if v < self.opts.session_min_validity || v > self.opts.session_max_validity {
            return Err(NipCaError::new(
                format!(
                    "Session validity must be in [{}, {}]; got {}.",
                    self.opts.session_min_validity, self.opts.session_max_validity, v
                ),
                error_codes::CA_SESSION_VALIDITY_INVALID,
            ));
        }

        // Subset checks (no scope expansion past the group).
        let session_caps = params
            .capabilities
            .clone()
            .unwrap_or_else(|| group.capabilities.clone());
        if params.capabilities.is_some() {
            let expansion: Vec<&String> = session_caps
                .iter()
                .filter(|c| !group.capabilities.contains(c))
                .collect();
            if !expansion.is_empty() {
                let list = expansion
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(NipCaError::new(
                    format!("Session capabilities not in parent group: {list}."),
                    error_codes::CA_SCOPE_EXPANSION_DENIED,
                ));
            }
        }
        let session_scope = params
            .scope_json
            .clone()
            .unwrap_or_else(|| group.scope_json.clone());

        // Build session NID.
        let unix_seconds = OffsetDateTime::now_utc().unix_timestamp();
        let rand_hex = random_hex(8);
        let session_id = format!("session-{unix_seconds}-{rand_hex}");
        let session_nid = self.build_nid("agent", &session_id);

        let now = OffsetDateTime::now_utc();
        let expires_at = now + v;
        let serial = self.store.next_serial();

        // Lineage.
        let lineage = build_lineage_session(
            group_nid,
            &session_id,
            params.purpose.as_deref(),
            extract_lineage_str(group.lineage_json.as_deref(), "owner_user_id").as_deref(),
            extract_lineage_str(group.lineage_json.as_deref(), "owner_key_id").as_deref(),
        );
        let lineage_json = serde_json::to_string(&lineage).unwrap();

        let frame = self.issue_frame(
            &session_nid,
            session_pub_key,
            &session_caps,
            &session_scope,
            now,
            expires_at,
            &serial,
            params.metadata_json.as_deref(),
            None,
            Some(&lineage),
        )?;

        self.persist(NipCertRecord {
            nid: session_nid.clone(),
            entity_type: "agent".to_string(),
            serial,
            pub_key: session_pub_key.to_string(),
            capabilities: session_caps,
            scope_json: session_scope,
            issued_by: self.opts.ca_nid.clone(),
            issued_at: now,
            expires_at,
            revoked_at: None,
            revoke_reason: None,
            metadata_json: params.metadata_json.clone(),
            nid_role: Some(ROLE_SESSION.to_string()),
            parent_nid: Some(group_nid.to_string()),
            lineage_json: Some(lineage_json),
        })?;

        Ok(frame)
    }

    /// List every session NID issued under `group_nid` (live + revoked).
    pub fn list_sessions(&self, group_nid: &str) -> Vec<NipCertRecord> {
        self.store.get_by_parent_nid(group_nid)
    }

    /// Return the persisted record for `nid`, or `None` (for pre-flight checks).
    pub fn get_cert(&self, nid: &str) -> Option<NipCertRecord> {
        self.store.get_by_nid(nid)
    }

    // ── Renew ─────────────────────────────────────────────────────────────────

    /// Renew a certificate — only within the renewal window before expiry.
    pub fn renew(&self, nid: &str) -> Result<IdentFrame, NipCaError> {
        let record = self.store.get_by_nid(nid).ok_or_else(|| {
            NipCaError::new(
                format!("NID not found: {nid}"),
                error_codes::CA_NID_NOT_FOUND,
            )
        })?;
        if record.revoked_at.is_some() {
            return Err(NipCaError::new(
                format!("NID is revoked: {nid}"),
                error_codes::CERT_REVOKED,
            ));
        }

        let now = OffsetDateTime::now_utc();
        let renew_window_start = record.expires_at - Duration::days(self.opts.renewal_window_days);
        if now < renew_window_start {
            return Err(NipCaError::new(
                format!(
                    "Renewal window opens {}. Too early to renew.",
                    fmt_ts(renew_window_start)
                ),
                error_codes::CA_RENEWAL_TOO_EARLY,
            ));
        }

        let valid_days = if record.entity_type == "node" {
            self.opts.node_cert_validity_days
        } else {
            self.opts.agent_cert_validity_days
        };
        let expires_at = now + Duration::days(valid_days);
        let serial = self.store.next_serial();

        let frame = self.issue_frame(
            nid,
            &record.pub_key,
            &record.capabilities,
            &record.scope_json,
            now,
            expires_at,
            &serial,
            record.metadata_json.as_deref(),
            None,
            None,
        )?;

        self.persist(NipCertRecord {
            nid: nid.to_string(),
            entity_type: record.entity_type.clone(),
            serial,
            pub_key: record.pub_key.clone(),
            capabilities: record.capabilities.clone(),
            scope_json: record.scope_json.clone(),
            issued_by: self.opts.ca_nid.clone(),
            issued_at: now,
            expires_at,
            revoked_at: None,
            revoke_reason: None,
            metadata_json: record.metadata_json.clone(),
            nid_role: None,
            parent_nid: None,
            lineage_json: None,
        })?;

        Ok(frame)
    }

    // ── Revoke ────────────────────────────────────────────────────────────────

    /// Revoke a certificate immediately (and cascade to live sessions when the
    /// target is a group). Returns the signed RevokeFrame for the target.
    pub fn revoke(&self, nid: &str, reason: &str) -> Result<RevokeFrame, NipCaError> {
        let record = self.store.get_by_nid(nid).ok_or_else(|| {
            NipCaError::new(
                format!("NID not found: {nid}"),
                error_codes::CA_NID_NOT_FOUND,
            )
        })?;

        let now = OffsetDateTime::now_utc();
        if !self.store.revoke(nid, reason, now) {
            return Err(NipCaError::new(
                format!("Failed to revoke {nid}."),
                error_codes::CA_NID_NOT_FOUND,
            ));
        }

        // Cascade revoke live sessions if this is a group.
        if record.nid_role.as_deref() == Some(ROLE_GROUP) {
            for child in self.store.get_by_parent_nid(nid) {
                if child.revoked_at.is_some() {
                    continue;
                }
                self.store.revoke(&child.nid, "parent_revoked", now);
            }
        }

        // Build the RevokeFrame (signature excludes `frame` per canonical form).
        let revoked_at = fmt_ts(now);
        let mut payload = Map::new();
        payload.insert("frame".into(), json!("0x22"));
        payload.insert("target_nid".into(), json!(nid));
        payload.insert("serial".into(), json!(record.serial));
        payload.insert("reason".into(), json!(reason));
        payload.insert("revoked_at".into(), json!(revoked_at));
        payload.insert("signer_nid".into(), json!(self.opts.ca_nid));
        let signature = signer::sign(&self.signing_key, &Value::Object(payload));

        Ok(RevokeFrame {
            target_nid: nid.to_string(),
            serial: Some(record.serial),
            reason: reason.to_string(),
            revoked_at,
            parent_nid: None,
            signer_nid: self.opts.ca_nid.clone(),
            signature,
        })
    }

    // ── Verify (OCSP) ─────────────────────────────────────────────────────────

    /// Verify a NID: existence, expiry, revocation, and — for sessions — the
    /// parent-group chain (NPS-3 §7 step 3a).
    pub fn verify(&self, nid: &str) -> NipVerifyResult {
        let record = match self.store.get_by_nid(nid) {
            Some(r) => r,
            None => return NipVerifyResult::fail(error_codes::CA_NID_NOT_FOUND, "NID not found."),
        };

        if let Some(rev) = record.revoked_at {
            return NipVerifyResult::fail(
                error_codes::CERT_REVOKED,
                format!(
                    "Revoked at {}: {}",
                    fmt_ts(rev),
                    record.revoke_reason.as_deref().unwrap_or("")
                ),
            );
        }
        if OffsetDateTime::now_utc() > record.expires_at {
            return NipVerifyResult::fail(
                error_codes::CERT_EXPIRED,
                format!("Expired at {}.", fmt_ts(record.expires_at)),
            );
        }

        // Chain check — NPS-3 §7 step 3a.
        if let Some(parent_nid) = record.parent_nid.clone() {
            if !parent_nid.is_empty() {
                match self.store.get_by_nid(&parent_nid) {
                    None => {
                        return NipVerifyResult::fail(
                            error_codes::CERT_PARENT_REVOKED,
                            format!("Parent NID {parent_nid} not found."),
                        )
                    }
                    Some(parent) => {
                        if let Some(rev) = parent.revoked_at {
                            return NipVerifyResult::fail(
                                error_codes::CERT_PARENT_REVOKED,
                                format!(
                                    "Parent {parent_nid} revoked at {}: {}",
                                    fmt_ts(rev),
                                    parent.revoke_reason.as_deref().unwrap_or("")
                                ),
                            );
                        }
                        if OffsetDateTime::now_utc() > parent.expires_at {
                            return NipVerifyResult::fail(
                                error_codes::CERT_PARENT_REVOKED,
                                format!(
                                    "Parent {parent_nid} expired at {}.",
                                    fmt_ts(parent.expires_at)
                                ),
                            );
                        }
                    }
                }
            }
        }

        NipVerifyResult::ok(record)
    }

    // ── CRL / list / sign / public key ────────────────────────────────────────

    /// Current Certificate Revocation List (NPS-3 §8).
    pub fn get_crl(&self) -> Vec<NipCertRecord> {
        self.store.get_revoked()
    }

    /// All certificate records from the backing store.
    pub fn list_certificates(&self) -> Vec<NipCertRecord> {
        self.store.list()
    }

    /// Sign an arbitrary CA-owned JSON artifact with the CA key.
    pub fn sign_artifact(&self, artifact: &Value) -> String {
        signer::sign(&self.signing_key, artifact)
    }

    /// CA public key in `ed25519:{base64url}` form.
    pub fn get_ca_public_key(&self) -> String {
        signer::encode_verifying_key(&self.verifying_key())
    }

    // ── NID builder ───────────────────────────────────────────────────────────

    /// Build a NID from the CA issuer domain and an entity-specific identifier.
    /// `urn:nps:org:ca.example.com` → `urn:nps:{entity}:ca.example.com:{id}`.
    pub fn build_nid(&self, entity_type: &str, identifier: &str) -> String {
        let parts: Vec<&str> = self.opts.ca_nid.split(':').collect();
        let domain = if parts.len() >= 4 {
            parts[3]
        } else {
            self.opts.ca_nid.as_str()
        };
        format!("urn:nps:{entity_type}:{domain}:{identifier}")
    }

    // ── Private ───────────────────────────────────────────────────────────────

    fn check_capabilities(&self, capabilities: &[String]) -> Result<(), NipCaError> {
        if let Some(allowed) = &self.opts.allowed_capabilities {
            let disallowed: Vec<&String> = capabilities
                .iter()
                .filter(|c| !allowed.contains(*c))
                .collect();
            if !disallowed.is_empty() {
                let list = disallowed
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                return Err(NipCaError::new(
                    format!("Capabilities not permitted by this CA: {list}"),
                    error_codes::CERT_CAPABILITY_MISSING,
                ));
            }
        }
        Ok(())
    }

    fn persist(&self, record: NipCertRecord) -> Result<(), NipCaError> {
        self.store.save(record).map_err(|e| match e {
            StoreError::NidExists(n) => NipCaError::new(
                format!("NID already exists: {n}"),
                error_codes::CA_NID_ALREADY_EXISTS,
            ),
            StoreError::SerialExists(s) => NipCaError::new(
                format!("Serial already exists: {s}"),
                error_codes::CA_SERIAL_DUPLICATE,
            ),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn issue_frame(
        &self,
        nid: &str,
        pub_key: &str,
        capabilities: &[String],
        scope_json: &str,
        issued_at: OffsetDateTime,
        expires_at: OffsetDateTime,
        serial: &str,
        metadata_json: Option<&str>,
        assurance_level: Option<crate::assurance_level::AssuranceLevel>,
        lineage: Option<&Value>,
    ) -> Result<IdentFrame, NipCaError> {
        let scope: Value = serde_json::from_str(scope_json).map_err(|e| {
            NipCaError::new(
                format!("invalid scope_json: {e}"),
                error_codes::CA_NID_ALREADY_EXISTS,
            )
        })?;
        let issued_at_str = fmt_ts(issued_at);
        let expires_at_str = fmt_ts(expires_at);

        // Canonical signed payload — alphabetical order enforced by the signer.
        // assurance_level / lineage included only when present (bit-compat with
        // pre-RFC-0003 / pre-CR-0003 verifiers).
        let mut payload = Map::new();
        payload.insert("capabilities".into(), json!(capabilities));
        payload.insert("expires_at".into(), json!(expires_at_str));
        payload.insert("frame".into(), json!("0x20"));
        payload.insert("issued_at".into(), json!(issued_at_str));
        payload.insert("issued_by".into(), json!(self.opts.ca_nid));
        payload.insert("nid".into(), json!(nid));
        payload.insert("pub_key".into(), json!(pub_key));
        payload.insert("scope".into(), scope.clone());
        payload.insert("serial".into(), json!(serial));
        if let Some(level) = assurance_level {
            payload.insert("assurance_level".into(), json!(level.wire));
        }
        if let Some(l) = lineage {
            payload.insert("lineage".into(), l.clone());
        }
        let signature = signer::sign(&self.signing_key, &Value::Object(payload));

        let meta = metadata_json.and_then(|m| serde_json::from_str::<Map<String, Value>>(m).ok());

        let mut frame = IdentFrame::new(nid.to_string(), pub_key.to_string());
        frame.capabilities = capabilities.to_vec();
        frame.scope = Some(scope);
        frame.issued_by = Some(self.opts.ca_nid.clone());
        frame.issued_at = Some(issued_at_str);
        frame.expires_at = Some(expires_at_str);
        frame.serial = Some(serial.to_string());
        frame.signature = Some(signature);
        frame.meta = meta;
        frame.assurance_level = assurance_level;
        Ok(frame)
    }
}

/// Error surfaced by [`NipCaService::register_with_ra`].
#[derive(Debug, Clone)]
pub enum RegisterWithRaError {
    /// Enrollment denied or issuance failed.
    Ca(NipCaError),
    /// Tier-3: queued — return 202 with the pending id.
    Pending(NipRaPending),
}

impl std::fmt::Display for RegisterWithRaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegisterWithRaError::Ca(e) => write!(f, "{e}"),
            RegisterWithRaError::Pending(p) => write!(f, "{p}"),
        }
    }
}

impl std::error::Error for RegisterWithRaError {}

// ── Free helpers ────────────────────────────────────────────────────────────

/// Format an `OffsetDateTime` in the .NET round-trip ("O") ISO 8601 UTC form.
pub(crate) fn fmt_ts(dt: OffsetDateTime) -> String {
    dt.to_offset(time::UtcOffset::UTC)
        .format(&Rfc3339)
        .unwrap_or_default()
}

fn build_lineage_group(owner_user_id: Option<&str>, owner_key_id: Option<&str>) -> Value {
    let mut m = Map::new();
    m.insert("role".into(), json!("group"));
    if let Some(v) = owner_user_id {
        m.insert("owner_user_id".into(), json!(v));
    }
    if let Some(v) = owner_key_id {
        m.insert("owner_key_id".into(), json!(v));
    }
    Value::Object(m)
}

fn build_lineage_session(
    group_nid: &str,
    session_id: &str,
    purpose: Option<&str>,
    owner_user_id: Option<&str>,
    owner_key_id: Option<&str>,
) -> Value {
    let mut m = Map::new();
    m.insert("role".into(), json!("session"));
    m.insert("parent_nid".into(), json!(group_nid));
    m.insert("group_nid".into(), json!(group_nid));
    m.insert("session_id".into(), json!(session_id));
    if let Some(v) = purpose {
        m.insert("purpose".into(), json!(v));
    }
    if let Some(v) = owner_user_id {
        m.insert("owner_user_id".into(), json!(v));
    }
    if let Some(v) = owner_key_id {
        m.insert("owner_key_id".into(), json!(v));
    }
    Value::Object(m)
}

fn extract_lineage_str(lineage_json: Option<&str>, field: &str) -> Option<String> {
    let s = lineage_json?;
    let v: Value = serde_json::from_str(s).ok()?;
    v.get(field).and_then(Value::as_str).map(str::to_string)
}

fn random_hex(byte_len: usize) -> String {
    let mut buf = vec![0u8; byte_len];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut buf);
    hex::encode(buf)
}

fn extract_ed25519_raw(encoded: &str) -> Result<[u8; 32], NipCaError> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
    use base64::Engine as _;
    let b64 = encoded.strip_prefix("ed25519:").ok_or_else(|| {
        NipCaError::new(
            format!("X.509 issuance requires an ed25519:* pubkey; got '{encoded}'."),
            error_codes::CERT_FORMAT_INVALID,
        )
    })?;
    let raw = B64URL.decode(b64.as_bytes()).map_err(|_| {
        NipCaError::new(
            "ed25519 pubkey is not valid base64url.",
            error_codes::CERT_FORMAT_INVALID,
        )
    })?;
    raw.try_into().map_err(|v: Vec<u8>| {
        NipCaError::new(
            format!("Ed25519 pubkey must be 32 bytes; got {}.", v.len()),
            error_codes::CERT_FORMAT_INVALID,
        )
    })
}

fn parse_serial_bytes(serial: &str) -> Vec<u8> {
    let hex_str = serial
        .strip_prefix("0x")
        .or_else(|| serial.strip_prefix("0X"))
        .unwrap_or(serial);
    let hex_str = if hex_str.len() & 1 != 0 {
        format!("0{hex_str}")
    } else {
        hex_str.to_string()
    };
    let mut bytes = hex::decode(&hex_str).unwrap_or_else(|_| vec![0x01]);
    if bytes.is_empty() {
        bytes = vec![0x01];
    }
    if bytes[0] & 0x80 != 0 {
        let mut padded = Vec::with_capacity(bytes.len() + 1);
        padded.push(0x00);
        padded.extend_from_slice(&bytes);
        return padded;
    }
    bytes
}

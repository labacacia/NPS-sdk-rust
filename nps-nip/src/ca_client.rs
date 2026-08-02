// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Clone, Serialize)]
pub struct NipCaRegisterRequest {
    pub identifier: String,
    pub pub_key: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub capabilities: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_json: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_json: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NipCaRegisterX509Request {
    pub identifier: String,
    pub pub_key: String,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub capabilities: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope_json: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata_json: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assurance_level: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NipCaIdentFrame {
    #[serde(default)]
    pub frame: Option<String>,
    pub nid: String,
    pub pub_key: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub scope: Option<Value>,
    #[serde(default)]
    pub issued_by: Option<String>,
    #[serde(default)]
    pub issued_at: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub serial: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub cert_format: Option<String>,
    #[serde(default)]
    pub cert_chain: Vec<String>,
    #[serde(default)]
    pub ocsp_staple: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NipCaCrlEntry {
    pub nid: String,
    pub serial: String,
    #[serde(default)]
    pub revoked_at: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NipCaCrl {
    pub issued_by: String,
    pub issued_at: String,
    pub entries: Vec<NipCaCrlEntry>,
    pub signature: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NipCaCertificateRecord {
    pub nid: String,
    pub entity_type: String,
    pub serial: String,
    pub pub_key: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub scope: Value,
    pub issued_by: String,
    pub issued_at: String,
    pub expires_at: String,
    #[serde(default)]
    pub revoked_at: Option<String>,
    #[serde(default)]
    pub revoke_reason: Option<String>,
    #[serde(default)]
    pub nid_role: Option<String>,
    #[serde(default)]
    pub parent_nid: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NipCaCertificateList {
    #[serde(default)]
    pub entries: Vec<NipCaCertificateRecord>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NipCaRevokeFrame {
    #[serde(default)]
    pub frame: Option<String>,
    #[serde(default)]
    pub target_nid: Option<String>,
    #[serde(default)]
    pub nid: Option<String>,
    #[serde(default)]
    pub serial: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub revoked_at: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NipCaDiscoveryDocument {
    pub nps_ca: String,
    pub issuer: String,
    pub public_key: String,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub algorithms: Vec<String>,
    #[serde(default)]
    pub endpoints: serde_json::Map<String, Value>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub max_cert_validity_days: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NipCaVerifyResponse {
    pub valid: bool,
    #[serde(default)]
    pub nid: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub serial: Option<String>,
    #[serde(default)]
    pub error_code: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct NipCaClientError {
    pub error_code: String,
    pub message: String,
    pub status_code: Option<StatusCode>,
}

#[derive(Debug, Clone)]
pub struct NipCaClient {
    base_url: String,
    prefix: String,
    http: reqwest::Client,
}

impl NipCaClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self::with_client(base_url, "", reqwest::Client::new())
    }

    pub fn with_client(
        base_url: impl Into<String>,
        route_prefix: impl Into<String>,
        http: reqwest::Client,
    ) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            prefix: route_prefix.into().trim_end_matches('/').to_string(),
            http,
        }
    }

    pub async fn get_discovery(&self) -> Result<NipCaDiscoveryDocument, NipCaClientError> {
        self.get_json("/.well-known/nps-ca").await
    }

    pub async fn get_crl(&self) -> Result<NipCaCrl, NipCaClientError> {
        self.get_json(&format!("{}/v1/crl", self.prefix)).await
    }

    pub async fn get_certificates(
        &self,
        bearer_token: Option<&str>,
    ) -> Result<NipCaCertificateList, NipCaClientError> {
        self.send_json::<(), NipCaCertificateList>(
            "GET",
            &format!("{}/v1/certificates", self.prefix),
            None,
            bearer_token,
        )
        .await
    }

    /// Verify a signed CRL using the CA's `ed25519:{base64url}` public key.
    pub fn verify_crl_signature(crl: &NipCaCrl, ca_public_key: &str) -> bool {
        let Some(key) = crate::ca::signer::decode_public_key(ca_public_key) else {
            return false;
        };
        let body = serde_json::json!({
            "issued_by": crl.issued_by,
            "issued_at": crl.issued_at,
            "entries": crl.entries,
        });
        crate::ca::signer::verify(&key, &body, &crl.signature)
    }

    pub async fn register_agent(
        &self,
        request: &NipCaRegisterRequest,
        bearer_token: Option<&str>,
    ) -> Result<NipCaIdentFrame, NipCaClientError> {
        self.send_json(
            "POST",
            &format!("{}/v1/agents/register", self.prefix),
            Some(request),
            bearer_token,
        )
        .await
    }

    pub async fn register_node(
        &self,
        request: &NipCaRegisterRequest,
        bearer_token: Option<&str>,
    ) -> Result<NipCaIdentFrame, NipCaClientError> {
        self.send_json(
            "POST",
            &format!("{}/v1/nodes/register", self.prefix),
            Some(request),
            bearer_token,
        )
        .await
    }

    pub async fn register_agent_x509(
        &self,
        request: &NipCaRegisterX509Request,
        bearer_token: Option<&str>,
    ) -> Result<NipCaIdentFrame, NipCaClientError> {
        self.send_json(
            "POST",
            &format!("{}/v1/agents/register-x509", self.prefix),
            Some(request),
            bearer_token,
        )
        .await
    }

    pub async fn register_node_x509(
        &self,
        request: &NipCaRegisterX509Request,
        bearer_token: Option<&str>,
    ) -> Result<NipCaIdentFrame, NipCaClientError> {
        self.send_json(
            "POST",
            &format!("{}/v1/nodes/register-x509", self.prefix),
            Some(request),
            bearer_token,
        )
        .await
    }

    pub async fn renew_agent(
        &self,
        nid: &str,
        bearer_token: Option<&str>,
    ) -> Result<NipCaIdentFrame, NipCaClientError> {
        self.send_json::<(), NipCaIdentFrame>(
            "POST",
            &format!("{}/v1/agents/{}/renew", self.prefix, escape(nid)),
            None,
            bearer_token,
        )
        .await
    }

    pub async fn renew_node(
        &self,
        nid: &str,
        bearer_token: Option<&str>,
    ) -> Result<NipCaIdentFrame, NipCaClientError> {
        self.send_json::<(), NipCaIdentFrame>(
            "POST",
            &format!("{}/v1/nodes/{}/renew", self.prefix, escape(nid)),
            None,
            bearer_token,
        )
        .await
    }

    pub async fn revoke_agent(
        &self,
        nid: &str,
        reason: Option<&str>,
        bearer_token: Option<&str>,
    ) -> Result<NipCaRevokeFrame, NipCaClientError> {
        let body = serde_json::json!({ "reason": reason.unwrap_or("cessation_of_operation") });
        self.send_json(
            "POST",
            &format!("{}/v1/agents/{}/revoke", self.prefix, escape(nid)),
            Some(&body),
            bearer_token,
        )
        .await
    }

    pub async fn revoke_node(
        &self,
        nid: &str,
        reason: Option<&str>,
        bearer_token: Option<&str>,
    ) -> Result<NipCaRevokeFrame, NipCaClientError> {
        let body = serde_json::json!({ "reason": reason.unwrap_or("cessation_of_operation") });
        self.send_json(
            "POST",
            &format!("{}/v1/nodes/{}/revoke", self.prefix, escape(nid)),
            Some(&body),
            bearer_token,
        )
        .await
    }

    pub async fn verify_agent(&self, nid: &str) -> Result<NipCaVerifyResponse, NipCaClientError> {
        self.get_json(&format!("{}/v1/agents/{}/verify", self.prefix, escape(nid)))
            .await
    }

    pub async fn verify_node(&self, nid: &str) -> Result<NipCaVerifyResponse, NipCaClientError> {
        self.get_json(&format!("{}/v1/nodes/{}/verify", self.prefix, escape(nid)))
            .await
    }

    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
    ) -> Result<T, NipCaClientError> {
        let response = self
            .http
            .get(format!("{}{}", self.base_url, path))
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(io_error)?;
        read_response(response).await
    }

    async fn send_json<B: Serialize + ?Sized, T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        body: Option<&B>,
        bearer_token: Option<&str>,
    ) -> Result<T, NipCaClientError> {
        let method =
            reqwest::Method::from_bytes(method.as_bytes()).map_err(|e| NipCaClientError {
                error_code: "NIP-CA-CLIENT-ERROR".into(),
                message: e.to_string(),
                status_code: None,
            })?;
        let mut request = self
            .http
            .request(method, format!("{}{}", self.base_url, path))
            .header("Accept", "application/json");
        if let Some(token) = bearer_token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request.send().await.map_err(io_error)?;
        read_response(response).await
    }
}

async fn read_response<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, NipCaClientError> {
    let status = response.status();
    let text = response.text().await.map_err(io_error)?;
    if status.is_success() {
        return serde_json::from_str(&text).map_err(|e| NipCaClientError {
            error_code: "NIP-CA-DECODE-ERROR".into(),
            message: e.to_string(),
            status_code: Some(status),
        });
    }
    let body: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    let error_code = body
        .get("error_code")
        .or_else(|| body.get("error"))
        .and_then(Value::as_str)
        .unwrap_or("NIP-CA-HTTP-ERROR")
        .to_string();
    let message = body
        .get("message")
        .and_then(Value::as_str)
        .map(str::to_string)
        .unwrap_or_else(|| format!("NIP CA returned HTTP {}.", status.as_u16()));
    Err(NipCaClientError {
        error_code,
        message,
        status_code: Some(status),
    })
}

fn io_error(error: reqwest::Error) -> NipCaClientError {
    NipCaClientError {
        error_code: "NIP-CA-HTTP-ERROR".into(),
        message: error.to_string(),
        status_code: error.status(),
    }
}

fn escape(value: &str) -> String {
    let mut out = String::new();
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

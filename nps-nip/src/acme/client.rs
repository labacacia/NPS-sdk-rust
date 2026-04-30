// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

//! ACME client implementing the `agent-01` challenge per NPS-RFC-0002 §4.4.
//!
//! Flow: newNonce → newAccount → newOrder → fetch authz → sign challenge token
//! → finalize with CSR → fetch leaf cert.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

use crate::x509::builder::dalek_to_rcgen_keypair;

use super::jws::{self, Envelope, ProtectedHeader};
use super::messages::*;
use super::wire;

pub struct AcmeClient {
    pub directory_url: String,
    pub signing_key:   SigningKey,
    pub verifying_key: VerifyingKey,
    http:              reqwest::Client,
    directory:         Option<Directory>,
    account_url:       Option<String>,
    last_nonce:        Option<String>,
}

impl AcmeClient {
    pub fn new(directory_url: String, sk: SigningKey) -> Self {
        let verifying_key = sk.verifying_key();
        Self {
            directory_url, signing_key: sk, verifying_key,
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build().expect("reqwest client"),
            directory:   None,
            account_url: None,
            last_nonce:  None,
        }
    }

    /// Drive the full agent-01 flow for `nid`. Returns the issued PEM cert chain.
    pub async fn issue_agent_cert(&mut self, nid: &str) -> Result<String, String> {
        self.ensure_directory().await?;
        if self.account_url.is_none() {
            self.new_account().await?;
        }
        let order = self.new_order(nid).await?;
        let authz = self.fetch_authz(&order.authorizations[0]).await?;
        self.respond_agent_01(&authz).await?;
        let finalized = self.finalize_order(&order, nid).await?;
        let cert_url = finalized.certificate
            .ok_or_else(|| "finalized order has no certificate URL".to_string())?;
        self.download_pem(&cert_url).await
    }

    // ── Stages ───────────────────────────────────────────────────────────

    async fn ensure_directory(&mut self) -> Result<(), String> {
        if self.directory.is_some() { return Ok(()); }
        let resp = self.http.get(&self.directory_url).send().await
            .map_err(|e| format!("get directory: {e}"))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("get directory: HTTP {status}"));
        }
        let dir: Directory = resp.json().await.map_err(|e| format!("decode directory: {e}"))?;
        self.directory = Some(dir);
        self.refresh_nonce().await
    }

    async fn refresh_nonce(&mut self) -> Result<(), String> {
        let url = self.directory.as_ref().unwrap().new_nonce.clone();
        let resp = self.http.head(&url).send().await
            .map_err(|e| format!("HEAD newNonce: {e}"))?;
        let nonce = resp.headers().get("Replay-Nonce")
            .and_then(|v| v.to_str().ok()).map(String::from)
            .ok_or("server omitted Replay-Nonce")?;
        self.last_nonce = Some(nonce);
        Ok(())
    }

    async fn new_account(&mut self) -> Result<(), String> {
        let jwk = jws::jwk_from_public_key(self.verifying_key.as_bytes());
        let nonce = self.consume_last_nonce()?;
        let url = self.directory.as_ref().unwrap().new_account.clone();
        let env = jws::sign(
            &ProtectedHeader { alg: jws::ALG_EDDSA.into(), nonce, url: url.clone(), jwk: Some(jwk), kid: None },
            Some(&NewAccountPayload { terms_of_service_agreed: Some(true), ..Default::default() }),
            &self.signing_key,
        )?;
        let resp = self.post_jose(&url, &env).await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("newAccount: HTTP {status}"));
        }
        let account_url = resp.headers().get("Location")
            .and_then(|v| v.to_str().ok()).map(String::from)
            .ok_or("server omitted account Location header")?;
        self.capture_nonce(&resp);
        self.account_url = Some(account_url);
        // Drain body so connection is reusable.
        let _ = resp.text().await;
        Ok(())
    }

    async fn new_order(&mut self, nid: &str) -> Result<Order, String> {
        let nonce = self.consume_last_nonce()?;
        let url = self.directory.as_ref().unwrap().new_order.clone();
        let kid = self.account_url.clone();
        let env = jws::sign(
            &ProtectedHeader { alg: jws::ALG_EDDSA.into(), nonce, url: url.clone(), jwk: None, kid },
            Some(&NewOrderPayload {
                identifiers: vec![Identifier { type_: wire::IDENTIFIER_TYPE_NID.into(), value: nid.into() }],
                not_before: None, not_after: None,
            }),
            &self.signing_key,
        )?;
        let resp = self.post_jose(&url, &env).await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("newOrder: HTTP {status}"));
        }
        self.capture_nonce(&resp);
        let order: Order = resp.json().await.map_err(|e| format!("decode order: {e}"))?;
        Ok(order)
    }

    async fn fetch_authz(&mut self, url: &str) -> Result<Authorization, String> {
        let nonce = self.consume_last_nonce()?;
        let kid = self.account_url.clone();
        // POST-as-GET (RFC 8555 §6.3) — payload is None.
        let env = jws::sign::<NewAccountPayload>(
            &ProtectedHeader { alg: jws::ALG_EDDSA.into(), nonce, url: url.into(), jwk: None, kid },
            None, &self.signing_key,
        )?;
        let resp = self.post_jose(url, &env).await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("fetch authz: HTTP {status}"));
        }
        self.capture_nonce(&resp);
        resp.json().await.map_err(|e| format!("decode authz: {e}"))
    }

    async fn respond_agent_01(&mut self, authz: &Authorization) -> Result<(), String> {
        let challenge = authz.challenges.iter()
            .find(|c| c.type_ == wire::CHALLENGE_AGENT_01)
            .ok_or("authz has no agent-01 challenge")?;
        let agent_sig = self.signing_key.sign(challenge.token.as_bytes());
        let nonce = self.consume_last_nonce()?;
        let kid = self.account_url.clone();
        let env = jws::sign(
            &ProtectedHeader { alg: jws::ALG_EDDSA.into(), nonce, url: challenge.url.clone(), jwk: None, kid },
            Some(&ChallengeRespondPayload { agent_signature: jws::b64u_encode(&agent_sig.to_bytes()) }),
            &self.signing_key,
        )?;
        let resp = self.post_jose(&challenge.url, &env).await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("challenge: HTTP {status}"));
        }
        self.capture_nonce(&resp);
        let _ = resp.text().await;
        Ok(())
    }

    async fn finalize_order(&mut self, order: &Order, nid: &str) -> Result<Order, String> {
        let csr_der = self.build_csr(nid)?;
        let nonce = self.consume_last_nonce()?;
        let kid = self.account_url.clone();
        let env = jws::sign(
            &ProtectedHeader { alg: jws::ALG_EDDSA.into(), nonce, url: order.finalize.clone(), jwk: None, kid },
            Some(&FinalizePayload { csr: jws::b64u_encode(&csr_der) }),
            &self.signing_key,
        )?;
        let resp = self.post_jose(&order.finalize, &env).await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("finalize: HTTP {status}"));
        }
        self.capture_nonce(&resp);
        resp.json().await.map_err(|e| format!("decode finalized order: {e}"))
    }

    async fn download_pem(&mut self, cert_url: &str) -> Result<String, String> {
        let nonce = self.consume_last_nonce()?;
        let kid = self.account_url.clone();
        let env = jws::sign::<NewAccountPayload>(
            &ProtectedHeader { alg: jws::ALG_EDDSA.into(), nonce, url: cert_url.into(), jwk: None, kid },
            None, &self.signing_key,
        )?;
        let resp = self.post_jose(cert_url, &env).await?;
        let status = resp.status();
        if !status.is_success() {
            return Err(format!("download cert: HTTP {status}"));
        }
        self.capture_nonce(&resp);
        resp.text().await.map_err(|e| format!("read PEM: {e}"))
    }

    fn build_csr(&self, nid: &str) -> Result<Vec<u8>, String> {
        let key_pair = dalek_to_rcgen_keypair(&self.signing_key)
            .map_err(|e| format!("dalek→rcgen: {e}"))?;
        let mut params = CertificateParams::new(vec![nid.to_string()])
            .map_err(|e| format!("CSR params: {e}"))?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, nid.to_string());
        params.distinguished_name = dn;
        params.subject_alt_names = vec![SanType::URI(
            nid.try_into().map_err(|e: rcgen::Error| format!("SAN URI: {e}"))?,
        )];
        let csr = params.serialize_request(&key_pair)
            .map_err(|e| format!("serialize_request: {e}"))?;
        let _ = key_pair; // ensure lifetime
        let _ = KeyPair::generate; // keep KeyPair import alive
        Ok(csr.der().to_vec())
    }

    async fn post_jose(&self, url: &str, env: &Envelope) -> Result<reqwest::Response, String> {
        let body = serde_json::to_vec(env).map_err(|e| format!("marshal envelope: {e}"))?;
        self.http.post(url)
            .header("Content-Type", wire::CONTENT_TYPE_JOSE_JSON)
            .body(body)
            .send().await.map_err(|e| format!("POST {url}: {e}"))
    }

    fn capture_nonce(&mut self, resp: &reqwest::Response) {
        if let Some(n) = resp.headers().get("Replay-Nonce")
            .and_then(|v| v.to_str().ok()).map(String::from)
        {
            self.last_nonce = Some(n);
        }
    }

    fn consume_last_nonce(&self) -> Result<String, String> {
        self.last_nonce.clone().ok_or("no nonce available".into())
    }
}

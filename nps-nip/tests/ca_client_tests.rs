// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

use nps_nip::{NipCaClient, NipCaClientError, NipCaRegisterRequest};
use std::str::FromStr;
use tiny_http::{Header, Response, Server};

fn bind_server() -> (Server, String) {
    let server = Server::http("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    let url = format!("http://127.0.0.1:{}", port);
    (server, url)
}

#[tokio::test]
async fn register_agent_sends_typed_request_with_bearer() {
    let (server, url) = bind_server();
    let guard = std::thread::spawn(move || {
        let req = server.recv().unwrap();
        assert_eq!(req.url(), "/nip/v1/agents/register");
        let auth = req
            .headers()
            .iter()
            .find(|h| h.field.equiv("Authorization"))
            .unwrap();
        assert_eq!(auth.value.as_str(), "Bearer secret");
        let body = r#"{"frame":"0x20","nid":"urn:nps:agent:example.test:a","pub_key":"ed25519:a","capabilities":["nwp:query"],"scope":{},"issued_by":"urn:nps:org:example.test","issued_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-02T00:00:00Z","serial":"0x1","signature":"ed25519:sig"}"#;
        let resp = Response::from_string(body)
            .with_status_code(201)
            .with_header(Header::from_str("Content-Type: application/json").unwrap())
            .with_header(Header::from_str(&format!("Content-Length: {}", body.len())).unwrap());
        req.respond(resp).unwrap();
    });

    let client = NipCaClient::with_client(&url, "/nip", reqwest::Client::new());
    let frame = client
        .register_agent(
            &NipCaRegisterRequest {
                identifier: "a".into(),
                pub_key: "ed25519:a".into(),
                capabilities: vec!["nwp:query".into()],
                scope_json: Some("{}".into()),
                metadata_json: None,
            },
            Some("secret"),
        )
        .await
        .unwrap();

    assert_eq!(frame.nid, "urn:nps:agent:example.test:a");
    guard.join().unwrap();
}

#[tokio::test]
async fn error_response_throws_typed_exception() {
    let (server, url) = bind_server();
    let guard = std::thread::spawn(move || {
        let req = server.recv().unwrap();
        assert!(req.url().contains("/renew"));
        let body = r#"{"error_code":"NIP-CA-UNAUTHORIZED","message":"nope"}"#;
        let resp = Response::from_string(body)
            .with_status_code(401)
            .with_header(Header::from_str("Content-Type: application/json").unwrap())
            .with_header(Header::from_str(&format!("Content-Length: {}", body.len())).unwrap());
        req.respond(resp).unwrap();
    });

    let client = NipCaClient::with_client(&url, "", reqwest::Client::new());
    let err = client
        .renew_agent("urn:nps:agent:example.test:a", None)
        .await
        .expect_err("renew should fail");

    assert_eq!(err.error_code, "NIP-CA-UNAUTHORIZED");
    assert_eq!(err.status_code.unwrap().as_u16(), 401);
    let _: NipCaClientError = err;
    guard.join().unwrap();
}

#[tokio::test]
async fn certificate_inventory_get_sends_bearer() {
    let (server, url) = bind_server();
    let guard = std::thread::spawn(move || {
        let req = server.recv().unwrap();
        assert_eq!(req.method().as_str(), "GET");
        assert_eq!(req.url(), "/nip/v1/certificates");
        let auth = req
            .headers()
            .iter()
            .find(|header| header.field.equiv("Authorization"))
            .unwrap();
        assert_eq!(auth.value.as_str(), "Bearer secret");
        let body = r#"{"entries":[{"nid":"urn:nps:agent:example.test:a","entity_type":"agent","serial":"0x1","pub_key":"ed25519:a","capabilities":[],"scope":{},"issued_by":"urn:nps:org:example.test","issued_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-02T00:00:00Z"}]}"#;
        req.respond(
            Response::from_string(body)
                .with_header(Header::from_str("Content-Type: application/json").unwrap()),
        )
        .unwrap();
    });

    let client = NipCaClient::with_client(&url, "/nip", reqwest::Client::new());
    let list = client.get_certificates(Some("secret")).await.unwrap();
    assert_eq!(list.entries.len(), 1);
    assert_eq!(list.entries[0].serial, "0x1");
    guard.join().unwrap();
}

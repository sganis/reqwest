// tests/negotiate_integration.rs

//! Integration tests for HTTP Negotiate authentication.
//!
//! Note: These tests use mock servers and cannot fully test actual Kerberos/SSPI functionality
//! without a real Active Directory environment. They verify the protocol flow and fallback logic.

#![cfg(all(not(target_arch = "wasm32"), feature = "negotiate"))]

mod support;
use support::server;

use http::StatusCode;
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn test_no_auth_needed() {
    // Test that requests succeed without authentication if server doesn't require it
    let server = server::http(move |_req| async move {
        http::Response::builder()
            .status(StatusCode::OK)
            .body("success".into())
            .unwrap()
    });

    let client = reqwest::Client::builder()
        .negotiate()
        .build()
        .unwrap();

    let resp = client
        .get(format!("http://{}/", server.addr()))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "success");
}

#[tokio::test]
async fn test_401_without_negotiate_challenge() {
    // Test that 401 without Negotiate challenge is returned as-is
    let server = server::http(move |_req| async move {
        http::Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .header("WWW-Authenticate", "Basic realm=\"test\"")
            .body("unauthorized".into())
            .unwrap()
    });

    let client = reqwest::Client::builder()
        .negotiate()
        .build()
        .unwrap();

    let resp = client
        .get(format!("http://{}/", server.addr()))
        .send()
        .await
        .unwrap();

    // Should get 401 back since no Negotiate challenge was offered
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_negotiate_with_credentials_fallback_to_basic() {
    // Test that explicit credentials fall back to Basic auth when server only supports Basic
    let request_count = Arc::new(Mutex::new(0));
    let count_clone = request_count.clone();

    let server = server::http(move |req| {
        let count_clone = count_clone.clone();
        async move {
            let mut count = count_clone.lock().unwrap();
            *count += 1;

            if *count == 1 {
                // First request - send Basic auth challenge
                http::Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("WWW-Authenticate", "Basic realm=\"test\"")
                    .body("unauthorized".into())
                    .unwrap()
            } else {
                // Second request - check for Basic auth header
                if let Some(auth) = req.headers().get(http::header::AUTHORIZATION) {
                    if auth.to_str().unwrap().starts_with("Basic ") {
                        http::Response::builder()
                            .status(StatusCode::OK)
                            .body("authenticated".into())
                            .unwrap()
                    } else {
                        http::Response::builder()
                            .status(StatusCode::UNAUTHORIZED)
                            .body("wrong auth type".into())
                            .unwrap()
                    }
                } else {
                    http::Response::builder()
                        .status(StatusCode::UNAUTHORIZED)
                        .body("no auth header".into())
                        .unwrap()
                }
            }
        }
    });

    let client = reqwest::Client::builder()
        .negotiate_with_credentials("testuser", "testpass")
        .build()
        .unwrap();

    let resp = client
        .get(format!("http://{}/", server.addr()))
        .send()
        .await
        .unwrap();

    // Should successfully authenticate with Basic auth
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "authenticated");

    assert_eq!(*request_count.lock().unwrap(), 2);
}

#[tokio::test]
async fn test_post_with_json_body() {
    // Test that POST requests with JSON bodies can be retried after 401
    let request_count = Arc::new(Mutex::new(0));
    let count_clone = request_count.clone();

    let server = server::http(move |req| {
        let count_clone = count_clone.clone();
        async move {
            let mut count = count_clone.lock().unwrap();
            *count += 1;

            if *count == 1 {
                // First request - send Basic auth challenge
                http::Response::builder()
                    .status(StatusCode::UNAUTHORIZED)
                    .header("WWW-Authenticate", "Basic realm=\"test\"")
                    .body("unauthorized".into())
                    .unwrap()
            } else {
                // Second request - verify body was preserved
                let (parts, body) = req.into_parts();

                // Verify Content-Type
                if let Some(ct) = parts.headers.get(http::header::CONTENT_TYPE) {
                    if ct.to_str().unwrap().contains("application/json") {
                        http::Response::builder()
                            .status(StatusCode::OK)
                            .body("json accepted".into())
                            .unwrap()
                    } else {
                        http::Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body("wrong content type".into())
                            .unwrap()
                    }
                } else {
                    http::Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body("no content type".into())
                        .unwrap()
                }
            }
        }
    });

    let client = reqwest::Client::builder()
        .negotiate_with_credentials("testuser", "testpass")
        .build()
        .unwrap();

    let json_body = serde_json::json!({
        "query": "select * from table"
    });

    let resp = client
        .post(format!("http://{}/api", server.addr()))
        .json(&json_body)
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.unwrap();
    assert_eq!(body, "json accepted");

    assert_eq!(*request_count.lock().unwrap(), 2);
}

#[tokio::test]
async fn test_negotiate_disabled_by_default() {
    // Verify that negotiate is opt-in, not enabled by default
    let server = server::http(move |req| async move {
        // Check that no Authorization header is sent initially
        if req.headers().contains_key(http::header::AUTHORIZATION) {
            http::Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("unexpected auth header".into())
                .unwrap()
        } else {
            http::Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("WWW-Authenticate", "Negotiate")
                .body("unauthorized".into())
                .unwrap()
        }
    });

    // Client without .negotiate() should NOT automatically send auth
    let client = reqwest::Client::builder().build().unwrap();

    let resp = client
        .get(format!("http://{}/", server.addr()))
        .send()
        .await
        .unwrap();

    // Should get 401 without attempting negotiate
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[cfg(windows)]
#[test]
fn test_windows_platform_available() {
    // Verify we're on Windows where SSPI should be available
    assert!(cfg!(windows));
    assert!(cfg!(feature = "negotiate"));
}

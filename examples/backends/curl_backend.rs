// examples/backends/curl_backend.rs

//! curl backend implementation using libcurl's built-in negotiate support.
//!
//! This uses the mature and battle-tested libcurl SSPI implementation on Windows.

use super::{AuthConfig, HttpBackend, Method, RequestConfig, Response};
use curl::easy::{Auth, Easy, List};
use std::collections::HashMap;

pub struct CurlBackend;

impl CurlBackend {
    pub fn new() -> Self {
        Self
    }
}

impl HttpBackend for CurlBackend {
    fn name(&self) -> &'static str {
        "curl (libcurl)"
    }

    fn execute(&self, config: &RequestConfig) -> Result<Response, Box<dyn std::error::Error>> {
        let mut easy = Easy::new();

        // Set URL
        easy.url(&config.url)?;

        // Set method
        match config.method {
            Method::Get => {}
            Method::Post => {
                easy.post(true)?;
            }
            Method::Put => {
                easy.put(true)?;
            }
            Method::Delete => {
                easy.custom_request("DELETE")?;
            }
            Method::Head => {
                easy.nobody(true)?;
            }
        }

        // Set authentication
        match &config.auth {
            AuthConfig::None => {}
            AuthConfig::Negotiate => {
                let mut auth = Auth::new();
                auth.gssnegotiate(true);
                easy.http_auth(&auth)?;
                // Empty credentials means use current Windows user
                easy.username(":")?;
                easy.password("")?;
            }
            AuthConfig::NegotiateWithCredentials { username, password } => {
                let mut auth = Auth::new();
                auth.gssnegotiate(true);
                easy.http_auth(&auth)?;
                easy.username(username)?;
                easy.password(password)?;
            }
            AuthConfig::Basic { username, password } => {
                easy.username(username)?;
                easy.password(password)?;
            }
        }

        // Set headers
        if !config.headers.is_empty() {
            let mut headers = List::new();
            for (name, value) in &config.headers {
                headers.append(&format!("{}: {}", name, value))?;
            }
            easy.http_headers(headers)?;
        }

        // Set body
        if let Some(ref body) = config.body {
            let body_bytes = body.as_bytes();
            easy.post_field_size(body_bytes.len() as u64)?;
            easy.post_fields_copy(body_bytes)?;
        }

        // Set options
        if config.verbose {
            easy.verbose(true)?;
        }

        if config.insecure {
            easy.ssl_verify_peer(false)?;
            easy.ssl_verify_host(false)?;
        }

        // Capture response
        let mut response_body = Vec::new();
        let mut response_headers = HashMap::new();
        let mut status_line = String::new();

        {
            let mut transfer = easy.transfer();

            // Capture headers
            transfer.header_function(|header| {
                if let Ok(header_str) = std::str::from_utf8(header) {
                    let header_str = header_str.trim();
                    if header_str.starts_with("HTTP/") {
                        status_line = header_str.to_string();
                    } else if let Some(colon_pos) = header_str.find(':') {
                        let name = header_str[..colon_pos].trim().to_string();
                        let value = header_str[colon_pos + 1..].trim().to_string();
                        response_headers.insert(name, value);
                    }
                }
                true
            })?;

            // Capture body
            transfer.write_function(|data| {
                response_body.extend_from_slice(data);
                Ok(data.len())
            })?;

            transfer.perform()?;
        }

        // Get status code
        let status = easy.response_code()? as u16;

        // Parse status text from status line
        let status_text = status_line
            .split_whitespace()
            .nth(2)
            .unwrap_or("")
            .to_string();

        Ok(Response {
            status,
            status_text,
            headers: response_headers,
            body: response_body,
        })
    }
}

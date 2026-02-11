// examples/backends/reqwest_backend.rs

//! reqwest backend implementation using our custom negotiate support.
//!
//! This uses the reqwest library with our newly implemented negotiate feature.

use super::{AuthConfig, HttpBackend, Method, RequestConfig, Response};
use std::collections::HashMap;

pub struct ReqwestBackend {
    runtime: tokio::runtime::Runtime,
}

impl ReqwestBackend {
    pub fn new() -> Self {
        let runtime = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
        Self { runtime }
    }
}

impl HttpBackend for ReqwestBackend {
    fn name(&self) -> &'static str {
        "reqwest (custom negotiate)"
    }

    fn execute(&self, config: &RequestConfig) -> Result<Response, Box<dyn std::error::Error>> {
        self.runtime.block_on(async {
            // Build client with authentication
            let mut client_builder = reqwest::Client::builder();

            match &config.auth {
                AuthConfig::None => {}
                AuthConfig::Negotiate => {
                    client_builder = client_builder.negotiate();
                }
                AuthConfig::NegotiateWithCredentials { username, password } => {
                    client_builder =
                        client_builder.negotiate_with_credentials(username, password);
                }
                AuthConfig::Basic { username, password } => {
                    // For basic auth, we'll add it as a header in the request
                    // (reqwest doesn't have a built-in .basic_auth on ClientBuilder)
                }
            }

            if config.insecure {
                client_builder = client_builder.tls_danger_accept_invalid_certs(true);
            }

            let client = client_builder.build()?;

            // Build request
            let mut request_builder = match config.method {
                Method::Get => client.get(&config.url),
                Method::Post => client.post(&config.url),
                Method::Put => client.put(&config.url),
                Method::Delete => client.delete(&config.url),
                Method::Head => client.head(&config.url),
            };

            // Add headers
            for (name, value) in &config.headers {
                request_builder = request_builder.header(name, value);
            }

            // Add body
            if let Some(ref body) = config.body {
                request_builder = request_builder.body(body.clone());
            }

            // Add basic auth if configured
            if let AuthConfig::Basic { username, password } = &config.auth {
                request_builder = request_builder.basic_auth(username, Some(password));
            }

            // Execute request
            let response = request_builder.send().await?;

            // Extract response data
            let status = response.status().as_u16();
            let status_text = response
                .status()
                .canonical_reason()
                .unwrap_or("")
                .to_string();

            let mut headers = HashMap::new();
            for (name, value) in response.headers() {
                if let Ok(value_str) = value.to_str() {
                    headers.insert(name.to_string(), value_str.to_string());
                }
            }

            let body = response.bytes().await?.to_vec();

            Ok(Response {
                status,
                status_text,
                headers,
                body,
            })
        })
    }
}

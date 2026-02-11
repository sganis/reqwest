// examples/backends/mod.rs

//! HTTP client backend abstraction for testing negotiate authentication.
//!
//! This module provides a common interface that can be implemented by:
//! - curl backend (using libcurl's mature SSPI/GSS-Negotiate support)
//! - reqwest backend (using our custom negotiate implementation)

#[cfg(feature = "curl")]
pub mod curl_backend;

#[cfg(feature = "reqwest")]
pub mod reqwest_backend;

use std::collections::HashMap;

/// HTTP method
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
    Head,
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Method::Get => write!(f, "GET"),
            Method::Post => write!(f, "POST"),
            Method::Put => write!(f, "PUT"),
            Method::Delete => write!(f, "DELETE"),
            Method::Head => write!(f, "HEAD"),
        }
    }
}

/// Authentication configuration
#[derive(Debug, Clone)]
pub enum AuthConfig {
    /// No authentication
    None,
    /// Negotiate (Kerberos/SPNEGO) with current user
    Negotiate,
    /// Negotiate with explicit credentials (fallback to Basic)
    NegotiateWithCredentials { username: String, password: String },
    /// Basic authentication
    Basic { username: String, password: String },
}

/// Request configuration
#[derive(Debug, Clone)]
pub struct RequestConfig {
    pub url: String,
    pub method: Method,
    pub auth: AuthConfig,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub verbose: bool,
    pub insecure: bool,
}

impl RequestConfig {
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            url: url.into(),
            method: Method::Get,
            auth: AuthConfig::None,
            headers: HashMap::new(),
            body: None,
            verbose: false,
            insecure: false,
        }
    }

    pub fn method(mut self, method: Method) -> Self {
        self.method = method;
        self
    }

    pub fn negotiate(mut self) -> Self {
        self.auth = AuthConfig::Negotiate;
        self
    }

    pub fn negotiate_with_credentials(mut self, username: String, password: String) -> Self {
        self.auth = AuthConfig::NegotiateWithCredentials { username, password };
        self
    }

    pub fn basic_auth(mut self, username: String, password: String) -> Self {
        self.auth = AuthConfig::Basic { username, password };
        self
    }

    pub fn header(mut self, name: String, value: String) -> Self {
        self.headers.insert(name, value);
        self
    }

    pub fn body(mut self, body: String) -> Self {
        self.body = Some(body);
        self
    }

    pub fn verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    pub fn insecure(mut self, insecure: bool) -> Self {
        self.insecure = insecure;
        self
    }
}

/// HTTP response
#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub status_text: String,
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn body_string(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }

    pub fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }
}

/// HTTP client backend trait
pub trait HttpBackend {
    /// Name of the backend (for display purposes)
    fn name(&self) -> &'static str;

    /// Execute an HTTP request
    fn execute(&self, config: &RequestConfig) -> Result<Response, Box<dyn std::error::Error>>;
}

/// Get the active backend based on compile-time features
pub fn get_backend() -> Box<dyn HttpBackend> {
    #[cfg(feature = "curl")]
    {
        Box::new(curl_backend::CurlBackend::new())
    }

    #[cfg(all(feature = "reqwest", not(feature = "curl")))]
    {
        Box::new(reqwest_backend::ReqwestBackend::new())
    }

    #[cfg(all(not(feature = "curl"), not(feature = "reqwest")))]
    {
        compile_error!("Either curl or reqwest feature must be enabled");
        unreachable!()
    }
}

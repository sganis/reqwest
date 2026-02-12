// src/auth/mod.rs

//! Authentication module for HTTP Negotiate (Kerberos/SPNEGO/NTLM) support.
//!
//! This module provides Windows SSPI-based authentication with automatic fallback
//! to Basic authentication when explicit credentials are provided.

#![allow(unused)]

#[cfg(all(windows, feature = "negotiate"))]
pub(crate) mod sspi;

#[cfg(feature = "negotiate")]
mod negotiate;

#[cfg(feature = "negotiate")]
pub(crate) use negotiate::execute_with_negotiate;

use std::task::{Context, Poll};
use tower::{Layer, Service};
use crate::{Request, Response, Error};

/// Credentials for Negotiate authentication.
///
/// Supports either using the current Windows user's credentials
/// or explicit username/password for fallback scenarios.
#[cfg(feature = "negotiate")]
#[derive(Clone, Debug)]
pub(crate) enum Credentials {
    /// Use the currently logged-in Windows user's credentials.
    /// This will attempt Kerberos/SPNEGO authentication using SSPI.
    CurrentUser,

    /// Use explicit credentials with fallback support.
    /// Tries Kerberos/NTLM first, falls back to Basic auth if SSPI unavailable.
    Explicit {
        username: String,
        password: String,
    },
}

/// Configuration for Negotiate authentication.
#[cfg(feature = "negotiate")]
#[derive(Clone, Debug)]
pub(crate) struct NegotiateConfig {
    pub(crate) credentials: Credentials,
}

impl NegotiateConfig {
    pub(crate) fn current_user() -> Self {
        Self {
            credentials: Credentials::CurrentUser,
        }
    }

    pub(crate) fn with_credentials(username: String, password: String) -> Self {
        Self {
            credentials: Credentials::Explicit { username, password },
        }
    }
}

// Negotiate authentication is integrated directly in the Client execute flow
// rather than as Tower middleware to avoid circular dependencies

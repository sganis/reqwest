// src/auth/negotiate.rs

//! HTTP Negotiate protocol implementation with fallback support.
//!
//! Implements the HTTP "Negotiate" authentication scheme (RFC 4559) with automatic
//! fallback to NTLM and Basic authentication when Kerberos/SSPI is unavailable.

use super::Credentials;
use crate::{Client, Request, Response, Result};
use http::{HeaderMap, HeaderValue};
use base64::Engine as _;

#[cfg(windows)]
use super::sspi::SspiContext;

const MAX_ROUNDTRIPS: usize = 5;

/// Derive the Service Principal Name (SPN) from a URL.
///
/// For HTTP authentication, the SPN format is "HTTP/<hostname>".
///
/// # Examples
/// ```ignore
/// assert_eq!(derive_spn("http://example.com/path"), Ok("HTTP/example.com"));
/// assert_eq!(derive_spn("https://server.corp.com:8080/"), Ok("HTTP/server.corp.com"));
/// ```
pub(crate) fn derive_spn(url: &url::Url) -> Result<String> {
    let host = url
        .host_str()
        .ok_or_else(|| crate::error::negotiate("URL has no host for SPN"))?;

    Ok(format!("HTTP/{}", host))
}

/// Parse WWW-Authenticate header to extract authentication challenges.
///
/// Returns a tuple of (negotiate_token, ntlm_token, has_basic) where:
/// - negotiate_token: Some(None) if bare "Negotiate", Some(Some(token)) if "Negotiate <token>"
/// - ntlm_token: Some(None) if bare "NTLM", Some(Some(token)) if "NTLM <token>"
/// - has_basic: true if "Basic" challenge present
fn parse_www_authenticate(
    headers: &HeaderMap,
) -> (Option<Option<Vec<u8>>>, Option<Option<Vec<u8>>>, bool) {
    let mut negotiate_token = None;
    let mut ntlm_token = None;
    let mut has_basic = false;

    for value in headers.get_all(http::header::WWW_AUTHENTICATE) {
        if let Ok(value_str) = value.to_str() {
            let trimmed = value_str.trim();

            if trimmed.eq_ignore_ascii_case("negotiate") {
                negotiate_token = Some(None);
            } else if trimmed.to_lowercase().starts_with("negotiate ") {
                // Extract base64 token
                let token_str = &trimmed[10..].trim();
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(token_str) {
                    negotiate_token = Some(Some(decoded));
                }
            } else if trimmed.eq_ignore_ascii_case("ntlm") {
                ntlm_token = Some(None);
            } else if trimmed.to_lowercase().starts_with("ntlm ") {
                let token_str = &trimmed[5..].trim();
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(token_str) {
                    ntlm_token = Some(Some(decoded));
                }
            } else if trimmed.to_lowercase().starts_with("basic") {
                has_basic = true;
            }
        }
    }

    (negotiate_token, ntlm_token, has_basic)
}

/// Execute a request with HTTP Negotiate authentication and fallback support.
///
/// This function implements the full authentication flow:
/// 1. Send initial request without authentication
/// 2. If 401, attempt Negotiate (Kerberos/NTLM via SSPI)
/// 3. If SSPI unavailable and credentials provided, fallback to NTLM then Basic
///
/// # Arguments
/// * `request` - The request to execute with authentication
/// * `creds` - Credentials (current user or explicit username/password)
/// * `execute_fn` - Function to execute HTTP requests (avoids recursion)
///
/// # Returns
/// The final response after authentication, or an error if authentication fails
pub(crate) async fn execute_with_negotiate<F, Fut>(
    request: Request,
    creds: &Credentials,
    mut execute_fn: F,
) -> Result<Response>
where
    F: FnMut(Request) -> Fut,
    Fut: std::future::Future<Output = Result<Response>>,
{
    // Clone the request for potential retry
    // Note: This will fail if the body is not clonable (e.g., streaming body)
    let original_request = request.try_clone().ok_or_else(|| {
        crate::error::negotiate("Request body is not replayable for Negotiate authentication")
    })?;

    // Send initial request without authentication
    let response = execute_fn(request).await?;

    // If not 401, no authentication needed
    if response.status() != http::StatusCode::UNAUTHORIZED {
        return Ok(response);
    }

    // Parse authentication challenges
    let (negotiate_challenge, ntlm_challenge, has_basic) =
        parse_www_authenticate(response.headers());

    // Derive SPN from URL
    let spn = derive_spn(original_request.url())?;

    // Try authentication methods in priority order

    // 1. Try Negotiate (Kerberos/NTLM via SSPI)
    #[cfg(windows)]
    if negotiate_challenge.is_some() {
        match try_negotiate_auth(&original_request, &spn, creds, &mut execute_fn).await {
            Ok(response) => return Ok(response),
            Err(e) => {
                log::debug!("Negotiate authentication failed: {:?}", e);
                // Continue to fallback
            }
        }
    }

    // 2. Try NTLM directly (if server supports it)
    #[cfg(windows)]
    if ntlm_challenge.is_some() {
        match try_ntlm_auth(&original_request, &spn, creds, &mut execute_fn).await {
            Ok(response) => return Ok(response),
            Err(e) => {
                log::debug!("NTLM authentication failed: {:?}", e);
                // Continue to fallback
            }
        }
    }

    // 3. Fallback to Basic authentication (only if explicit credentials provided)
    if has_basic {
        if let Credentials::Explicit { username, password } = creds {
            return try_basic_auth(&original_request, username, password, &mut execute_fn).await;
        }
    }

    // No authentication method succeeded
    Err(crate::error::negotiate(
        "All authentication methods failed or no supported method available",
    ))
}

/// Try Negotiate authentication using Windows SSPI.
#[cfg(windows)]
async fn try_negotiate_auth<F, Fut>(
    original_request: &Request,
    spn: &str,
    creds: &Credentials,
    execute_fn: &mut F,
) -> Result<Response>
where
    F: FnMut(Request) -> Fut,
    Fut: std::future::Future<Output = Result<Response>>,
{
    let mut ctx = SspiContext::new("Negotiate");

    // Acquire credentials
    ctx.acquire_credentials(creds)
        .map_err(|code| crate::error::negotiate(format!("SSPI AcquireCredentials failed: 0x{:08X}", code)))?;

    let mut input_token = None;
    let mut round = 0;

    loop {
        if round >= MAX_ROUNDTRIPS {
            return Err(crate::error::negotiate("Too many authentication round-trips"));
        }

        // Generate token
        let (output_token, is_complete) = ctx
            .initialize_context(spn, input_token.as_deref())
            .map_err(|code| crate::error::negotiate(format!("SSPI InitializeContext failed: 0x{:08X}", code)))?;

        // Encode token as base64
        let token_base64 = base64::engine::general_purpose::STANDARD.encode(&output_token);

        // Clone request and add Authorization header
        let mut auth_request = original_request
            .try_clone()
            .ok_or_else(|| crate::error::negotiate("Request not clonable"))?;

        auth_request
            .headers_mut()
            .insert(
                http::header::AUTHORIZATION,
                HeaderValue::from_str(&format!("Negotiate {}", token_base64))
                    .map_err(|_| crate::error::negotiate("Invalid authorization header"))?,
            );

        // Send authenticated request
        let response = execute_fn(auth_request).await?;

        // Check response status
        match response.status() {
            http::StatusCode::UNAUTHORIZED => {
                // Server sent another challenge, continue negotiation
                let (negotiate_token, _, _) = parse_www_authenticate(response.headers());

                if let Some(Some(server_token)) = negotiate_token {
                    input_token = Some(server_token);
                    round += 1;
                    continue;
                } else {
                    return Err(crate::error::negotiate(
                        "Server returned 401 without new challenge token",
                    ));
                }
            }
            status if status.is_success() => {
                // Authentication succeeded
                // Optionally validate mutual authentication token
                if let Some(Some(server_token)) = parse_www_authenticate(response.headers()).0 {
                    // Server sent final token for mutual auth validation
                    log::debug!("Mutual authentication token received from server");
                }
                return Ok(response);
            }
            _ => {
                // Other status code, return response
                return Ok(response);
            }
        }
    }
}

/// Try NTLM authentication using Windows SSPI.
#[cfg(windows)]
async fn try_ntlm_auth<F, Fut>(
    original_request: &Request,
    spn: &str,
    creds: &Credentials,
    execute_fn: &mut F,
) -> Result<Response>
where
    F: FnMut(Request) -> Fut,
    Fut: std::future::Future<Output = Result<Response>>,
{
    let mut ctx = SspiContext::new("NTLM");

    // Acquire credentials
    ctx.acquire_credentials(creds)
        .map_err(|code| crate::error::negotiate(format!("SSPI AcquireCredentials failed: 0x{:08X}", code)))?;

    let mut input_token = None;
    let mut round = 0;

    loop {
        if round >= MAX_ROUNDTRIPS {
            return Err(crate::error::negotiate("Too many authentication round-trips"));
        }

        // Generate token
        let (output_token, is_complete) = ctx
            .initialize_context(spn, input_token.as_deref())
            .map_err(|code| crate::error::negotiate(format!("SSPI InitializeContext failed: 0x{:08X}", code)))?;

        // Encode token as base64
        let token_base64 = base64::engine::general_purpose::STANDARD.encode(&output_token);

        // Clone request and add Authorization header
        let mut auth_request = original_request
            .try_clone()
            .ok_or_else(|| crate::error::negotiate("Request not clonable"))?;

        auth_request
            .headers_mut()
            .insert(
                http::header::AUTHORIZATION,
                HeaderValue::from_str(&format!("NTLM {}", token_base64))
                    .map_err(|_| crate::error::negotiate("Invalid authorization header"))?,
            );

        // Send authenticated request
        let response = execute_fn(auth_request).await?;

        // Check response status
        match response.status() {
            http::StatusCode::UNAUTHORIZED => {
                // Server sent another challenge
                let (_, ntlm_token, _) = parse_www_authenticate(response.headers());

                if let Some(Some(server_token)) = ntlm_token {
                    input_token = Some(server_token);
                    round += 1;
                    continue;
                } else {
                    return Err(crate::error::negotiate(
                        "Server returned 401 without new challenge token",
                    ));
                }
            }
            status if status.is_success() => {
                return Ok(response);
            }
            _ => {
                return Ok(response);
            }
        }
    }
}

/// Try Basic authentication (fallback method).
async fn try_basic_auth<F, Fut>(
    original_request: &Request,
    username: &str,
    password: &str,
    execute_fn: &mut F,
) -> Result<Response>
where
    F: FnMut(Request) -> Fut,
    Fut: std::future::Future<Output = Result<Response>>,
{
    // Encode credentials as base64
    let credentials = format!("{}:{}", username, password);
    let encoded = base64::engine::general_purpose::STANDARD.encode(credentials.as_bytes());

    // Clone request and add Authorization header
    let mut auth_request = original_request
        .try_clone()
        .ok_or_else(|| crate::error::negotiate("Request not clonable"))?;

    auth_request
        .headers_mut()
        .insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", encoded))
                .map_err(|_| crate::error::negotiate("Invalid authorization header"))?,
        );

    // Send authenticated request
    execute_fn(auth_request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_spn() {
        let url = url::Url::parse("http://example.com/path").unwrap();
        assert_eq!(derive_spn(&url).unwrap(), "HTTP/example.com");

        let url = url::Url::parse("https://server.corp.com:8080/api").unwrap();
        assert_eq!(derive_spn(&url).unwrap(), "HTTP/server.corp.com");
    }

    #[test]
    fn test_parse_www_authenticate_negotiate() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Negotiate"),
        );

        let (negotiate, _, _) = parse_www_authenticate(&headers);
        assert_eq!(negotiate, Some(None));
    }

    #[test]
    fn test_parse_www_authenticate_with_token() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Negotiate YIIFzgYGKwYBBQUCoIIFwjCCBb4="),
        );

        let (negotiate, _, _) = parse_www_authenticate(&headers);
        assert!(negotiate.is_some());
        assert!(negotiate.unwrap().is_some());
    }

    #[test]
    fn test_parse_www_authenticate_basic() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"test\""),
        );

        let (_, _, has_basic) = parse_www_authenticate(&headers);
        assert!(has_basic);
    }

    #[test]
    fn test_parse_www_authenticate_multiple() {
        let mut headers = HeaderMap::new();
        headers.insert(
            http::header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Negotiate"),
        );
        headers.append(
            http::header::WWW_AUTHENTICATE,
            HeaderValue::from_static("NTLM"),
        );
        headers.append(
            http::header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"test\""),
        );

        let (negotiate, ntlm, has_basic) = parse_www_authenticate(&headers);
        assert_eq!(negotiate, Some(None));
        assert_eq!(ntlm, Some(None));
        assert!(has_basic);
    }
}

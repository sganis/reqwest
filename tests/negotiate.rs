// tests/negotiate.rs

//! Unit tests for Negotiate authentication module.

#![cfg(all(not(target_arch = "wasm32"), feature = "negotiate"))]

// Note: Most negotiate tests are in src/auth/negotiate.rs as inline tests
// These are additional integration-style unit tests

#[test]
fn test_negotiate_feature_enabled() {
    // Simple test to verify the negotiate feature is compiled in
    assert!(cfg!(feature = "negotiate"));
}

#[cfg(windows)]
#[test]
fn test_windows_negotiate_available() {
    // Verify we're on Windows where SSPI is available
    assert!(cfg!(windows));
}

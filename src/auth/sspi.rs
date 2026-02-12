// src/auth/sspi.rs

//! Windows SSPI (Security Support Provider Interface) wrapper for Kerberos/NTLM authentication.
//!
//! Uses the `windows` crate to call SSPI functions:
//! - `AcquireCredentialsHandleW` to obtain a credential handle
//! - `InitializeSecurityContextW` to generate SPNEGO/NTLM tokens
//! - `FreeCredentialsHandle` / `DeleteSecurityContext` for cleanup

use std::ffi::c_void;
use std::ptr;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{SEC_E_OK, SEC_I_CONTINUE_NEEDED};
use windows::Win32::Security::Authentication::Identity::{
    AcquireCredentialsHandleW, DeleteSecurityContext, FreeCredentialsHandle,
    InitializeSecurityContextW, SecBuffer, SecBufferDesc, ISC_REQ_FLAGS, SECBUFFER_TOKEN,
    SECBUFFER_VERSION, SECPKG_CRED_OUTBOUND, SECURITY_NATIVE_DREP,
};
use windows::Win32::Security::Credentials::SecHandle;

use super::Credentials;

/// Maximum token size for Negotiate/Kerberos. 48 KB is generous enough
/// for even large Kerberos tickets with PAC data.
const MAX_TOKEN_SIZE: u32 = 48000;

/// ISC_REQ_MUTUAL_AUTH | ISC_REQ_DELEGATE
const CONTEXT_FLAGS: ISC_REQ_FLAGS = ISC_REQ_FLAGS(0x3);

/// Encode a Rust string as a null-terminated UTF-16 wide string.
fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// SSPI context for Kerberos/NTLM authentication.
///
/// Wraps credential and context handles with proper lifetime management.
/// Handles are freed automatically on drop.
pub(crate) struct SspiContext {
    package: String,
    cred_handle: SecHandle,
    ctx_handle: SecHandle,
    has_cred: bool,
    has_ctx: bool,
}

impl SspiContext {
    /// Create a new SSPI context for the specified security package.
    ///
    /// Common packages: `"Negotiate"` (Kerberos/NTLM), `"NTLM"`.
    pub(crate) fn new(package: &str) -> Self {
        Self {
            package: package.to_string(),
            cred_handle: SecHandle {
                dwLower: 0,
                dwUpper: 0,
            },
            ctx_handle: SecHandle {
                dwLower: 0,
                dwUpper: 0,
            },
            has_cred: false,
            has_ctx: false,
        }
    }

    /// Acquire credentials handle from SSPI.
    ///
    /// For `CurrentUser` or empty explicit credentials, passes NULL as pAuthData
    /// which tells SSPI to use the current Windows logon session (SSO).
    ///
    /// For explicit credentials with a non-empty username, builds a
    /// `SEC_WINNT_AUTH_IDENTITY_W` structure with the provided username/password.
    pub(crate) fn acquire_credentials(&mut self, creds: &Credentials) -> Result<(), i32> {
        let package_wide = to_wide(&self.package);
        let mut lifetime: i64 = 0;

        // Determine if we should use explicit credentials or default (SSO)
        let use_explicit = matches!(
            creds,
            Credentials::Explicit { username, .. } if !username.is_empty()
        );

        unsafe {
            let result = if use_explicit {
                if let Credentials::Explicit { username, password } = creds {
                    self.acquire_with_explicit(username, password, &package_wide, &mut lifetime)
                } else {
                    unreachable!()
                }
            } else {
                // CurrentUser or empty explicit creds: use default credentials (SSO)
                AcquireCredentialsHandleW(
                    PCWSTR(ptr::null()),
                    PCWSTR(package_wide.as_ptr()),
                    SECPKG_CRED_OUTBOUND,
                    None,
                    None, // NULL pAuthData = use current logon session
                    None,
                    None,
                    &mut self.cred_handle,
                    Some(&mut lifetime),
                )
            };

            match result {
                Ok(()) => {
                    self.has_cred = true;
                    Ok(())
                }
                Err(e) => Err(e.code().0),
            }
        }
    }

    /// Acquire credentials with explicit username/password via SEC_WINNT_AUTH_IDENTITY_W.
    ///
    /// Handles `user@DOMAIN` and `DOMAIN\user` formats by splitting into
    /// separate user and domain components.
    unsafe fn acquire_with_explicit(
        &mut self,
        username: &str,
        password: &str,
        package_wide: &[u16],
        lifetime: &mut i64,
    ) -> windows::core::Result<()> {
        // Parse domain from username (user@DOMAIN or DOMAIN\user)
        let (user_part, domain_part) = if let Some(pos) = username.find('@') {
            (&username[..pos], &username[pos + 1..])
        } else if let Some(pos) = username.find('\\') {
            (&username[pos + 1..], &username[..pos])
        } else {
            (username, "")
        };

        let mut user_wide = to_wide(user_part);
        let mut domain_wide = to_wide(domain_part);
        let mut pass_wide = to_wide(password);

        // SEC_WINNT_AUTH_IDENTITY_W layout (manual struct to avoid Win32_System_Rpc dependency):
        //   User: *mut u16         (offset 0)
        //   UserLength: u32        (offset 8)
        //   Domain: *mut u16       (offset 16)
        //   DomainLength: u32      (offset 24)
        //   Password: *mut u16     (offset 32)
        //   PasswordLength: u32    (offset 40)
        //   Flags: u32             (offset 48) = SEC_WINNT_AUTH_IDENTITY_UNICODE = 0x2
        #[repr(C)]
        struct AuthIdentity {
            user: *mut u16,
            user_length: u32,
            domain: *mut u16,
            domain_length: u32,
            password: *mut u16,
            password_length: u32,
            flags: u32,
        }

        let mut identity = AuthIdentity {
            user: user_wide.as_mut_ptr(),
            user_length: user_part.encode_utf16().count() as u32,
            domain: domain_wide.as_mut_ptr(),
            domain_length: domain_part.encode_utf16().count() as u32,
            password: pass_wide.as_mut_ptr(),
            password_length: password.encode_utf16().count() as u32,
            flags: 0x2, // SEC_WINNT_AUTH_IDENTITY_UNICODE
        };

        let result = AcquireCredentialsHandleW(
            PCWSTR(ptr::null()),
            PCWSTR(package_wide.as_ptr()),
            SECPKG_CRED_OUTBOUND,
            None,
            Some(&mut identity as *mut AuthIdentity as *const c_void),
            None,
            None,
            &mut self.cred_handle,
            Some(lifetime),
        );

        // Zero out password memory before it's freed
        for b in pass_wide.iter_mut() {
            ptr::write_volatile(b, 0);
        }

        result
    }

    /// Initialize security context and generate an authentication token.
    ///
    /// # Arguments
    /// * `spn` - Service Principal Name (e.g., `"HTTP/proxy.example.com"`)
    /// * `input_token` - Server challenge token from previous round (None for first call)
    ///
    /// # Returns
    /// * `Ok((token, is_complete))` - The output token bytes and whether auth is complete
    /// * `Err(hresult)` - SSPI error code
    pub(crate) fn initialize_context(
        &mut self,
        spn: &str,
        input_token: Option<&[u8]>,
    ) -> Result<(Vec<u8>, bool), i32> {
        let spn_wide = to_wide(spn);

        // Input buffer (server challenge token, if any)
        let mut in_buffer = SecBuffer {
            cbBuffer: 0,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: ptr::null_mut(),
        };
        let mut in_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut in_buffer,
        };

        if let Some(token) = input_token {
            in_buffer.cbBuffer = token.len() as u32;
            in_buffer.pvBuffer = token.as_ptr() as *mut c_void;
        }

        // Output buffer (pre-allocated)
        let mut out_buf = vec![0u8; MAX_TOKEN_SIZE as usize];
        let mut out_buffer = SecBuffer {
            cbBuffer: MAX_TOKEN_SIZE,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: out_buf.as_mut_ptr() as *mut c_void,
        };
        let mut out_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut out_buffer,
        };

        let mut attrs: u32 = 0;
        let mut expiry: i64 = 0;

        unsafe {
            let status = InitializeSecurityContextW(
                Some(&self.cred_handle),
                if self.has_ctx {
                    Some(&self.ctx_handle)
                } else {
                    None
                },
                Some(spn_wide.as_ptr()),
                CONTEXT_FLAGS,
                0,
                SECURITY_NATIVE_DREP,
                if input_token.is_some() {
                    Some(&in_desc)
                } else {
                    None
                },
                0,
                Some(&mut self.ctx_handle),
                Some(&mut out_desc),
                &mut attrs,
                Some(&mut expiry),
            );

            if status == SEC_E_OK || status == SEC_I_CONTINUE_NEEDED {
                self.has_ctx = true;
                let is_complete = status == SEC_E_OK;

                let token = if out_buffer.cbBuffer > 0 {
                    out_buf[..out_buffer.cbBuffer as usize].to_vec()
                } else {
                    Vec::new()
                };

                Ok((token, is_complete))
            } else {
                Err(status.0)
            }
        }
    }
}

impl Drop for SspiContext {
    fn drop(&mut self) {
        unsafe {
            if self.has_ctx {
                let _ = DeleteSecurityContext(&self.ctx_handle);
            }
            if self.has_cred {
                let _ = FreeCredentialsHandle(&self.cred_handle);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sspi_context_creation() {
        let ctx = SspiContext::new("Negotiate");
        assert_eq!(ctx.package, "Negotiate");
        assert!(!ctx.has_cred);
        assert!(!ctx.has_ctx);
    }

    #[test]
    fn test_sspi_context_creation_ntlm() {
        let ctx = SspiContext::new("NTLM");
        assert_eq!(ctx.package, "NTLM");
    }

    #[test]
    fn test_to_wide() {
        let wide = to_wide("Negotiate");
        assert_eq!(wide.last(), Some(&0)); // null-terminated
        assert_eq!(wide.len(), 10); // 9 chars + null
    }

    #[test]
    fn test_acquire_credentials_current_user() {
        let mut ctx = SspiContext::new("Negotiate");
        let result = ctx.acquire_credentials(&Credentials::CurrentUser);
        // Should succeed on a Windows machine with SSPI available
        assert!(result.is_ok(), "acquire_credentials failed: {:?}", result);
        assert!(ctx.has_cred);
    }

    #[test]
    fn test_acquire_credentials_empty_explicit() {
        // Empty username/password should behave like CurrentUser (SSO)
        let mut ctx = SspiContext::new("Negotiate");
        let result = ctx.acquire_credentials(&Credentials::Explicit {
            username: String::new(),
            password: String::new(),
        });
        assert!(result.is_ok(), "acquire_credentials failed: {:?}", result);
        assert!(ctx.has_cred);
    }

    #[test]
    fn test_initialize_context_first_token() {
        let mut ctx = SspiContext::new("Negotiate");
        ctx.acquire_credentials(&Credentials::CurrentUser)
            .expect("acquire_credentials failed");

        // Generate initial token for a dummy SPN
        // This may fail if no Kerberos ticket is available for the SPN,
        // but it should not crash.
        let result = ctx.initialize_context("HTTP/localhost", None);
        // On a domain-joined machine this succeeds; on others it may fail
        // with a specific SSPI error, but should not panic.
        match result {
            Ok((token, _complete)) => {
                assert!(!token.is_empty(), "token should not be empty");
            }
            Err(code) => {
                // Acceptable failure (e.g., no KDC reachable)
                log::debug!("InitializeSecurityContext returned 0x{:08X}", code);
            }
        }
    }
}

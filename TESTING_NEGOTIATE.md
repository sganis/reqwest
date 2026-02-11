# Testing Negotiate Authentication: curl vs reqwest Backends

This document explains how to test HTTP Negotiate (Kerberos/SPNEGO) authentication using both the curl and reqwest backends.

## Overview

The `test_negotiate` example provides a unified CLI that can use either:
- **curl backend**: Uses libcurl's mature, battle-tested SSPI/GSS-Negotiate implementation (via the `curl` Rust crate)
- **reqwest backend**: Uses our custom negotiate implementation (the newly added feature)

This allows side-by-side comparison of both implementations to verify compatibility and behavior.

## Building and Running

### Test with curl Backend (libcurl SSPI)

```bash
# Build and run with curl backend
cargo run --example test_negotiate --no-default-features --features backend-curl -- \
    https://your-ad-server.corp.com/api --negotiate

# Short form
cargo run --example test_negotiate -F backend-curl -- \
    https://your-ad-server.corp.com/api --negotiate
```

### Test with reqwest Backend (Custom Implementation)

```bash
# Build and run with reqwest backend
cargo run --example test_negotiate --no-default-features --features backend-reqwest -- \
    https://your-ad-server.corp.com/api --negotiate

# Short form
cargo run --example test_negotiate -F backend-reqwest -- \
    https://your-ad-server.corp.com/api --negotiate
```

## Usage Examples

### Basic GET with Current User (Kerberos)

```bash
# curl backend
cargo run --example test_negotiate -F backend-curl -- \
    https://ad-server.corp.com/api --negotiate

# reqwest backend
cargo run --example test_negotiate -F backend-reqwest -- \
    https://ad-server.corp.com/api --negotiate
```

### POST with JSON Body

```bash
# curl backend
cargo run --example test_negotiate -F backend-curl -- \
    https://ad-server.corp.com/api --negotiate \
    --post --json '{"query":"select * from table"}'

# reqwest backend
cargo run --example test_negotiate -F backend-reqwest -- \
    https://ad-server.corp.com/api --negotiate \
    --post --json '{"query":"select * from table"}'
```

### With Fallback Credentials

```bash
# curl backend - tries Kerberos, falls back to Basic if needed
cargo run --example test_negotiate -F backend-curl -- \
    https://ad-server.corp.com/api --negotiate \
    -u user@DOMAIN.COM:password

# reqwest backend - tries Kerberos, falls back to Basic if needed
cargo run --example test_negotiate -F backend-reqwest -- \
    https://ad-server.corp.com/api --negotiate \
    -u user@DOMAIN.COM:password
```

### Custom Headers

```bash
cargo run --example test_negotiate -F backend-curl -- \
    https://ad-server.corp.com/api --negotiate \
    -H "Accept: application/json" \
    -H "X-Custom-Header: value"
```

### Verbose Mode

```bash
# Show detailed request/response information
cargo run --example test_negotiate -F backend-curl -- \
    https://ad-server.corp.com/api --negotiate -v
```

### Skip SSL Verification (for testing)

```bash
cargo run --example test_negotiate -F backend-curl -- \
    https://ad-server.corp.com/api --negotiate -k
```

## Command Line Options

```
Usage: test_negotiate <url> [OPTIONS]

Options:
  --negotiate              Enable Negotiate (Kerberos/SPNEGO) authentication
  -u, --user <user:pass>  Username and password (enables fallback to Basic)
  --post                   Use POST method
  --put                    Use PUT method
  --delete                 Use DELETE method
  --head                   Use HEAD method
  -H, --header <name:value>  Add custom header
  --json <data>            Send JSON data (sets Content-Type)
  --data <data>            Send request body
  -v, --verbose            Verbose output
  -k, --insecure          Skip SSL verification
  -h, --help              Show help
```

## Comparison Script

Create a shell script to test both backends side-by-side:

```bash
#!/bin/bash
# compare_backends.sh

URL="$1"
shift

echo "=== Testing curl backend ==="
cargo run -q --example test_negotiate -F backend-curl -- "$URL" "$@"

echo ""
echo "=== Testing reqwest backend ==="
cargo run -q --example test_negotiate -F backend-reqwest -- "$URL" "$@"
```

Usage:
```bash
chmod +x compare_backends.sh
./compare_backends.sh https://ad-server.corp.com/api --negotiate
```

## Expected Results

Both backends should produce:
1. Same HTTP status codes
2. Similar response headers (order may differ)
3. Identical response bodies
4. Successful authentication when credentials are valid

### Differences to Expect

| Aspect | curl backend | reqwest backend |
|--------|-------------|-----------------|
| Implementation | libcurl SSPI (C library) | Pure Rust (currently stubbed) |
| Maturity | Battle-tested, production-ready | New implementation, needs SSPI completion |
| Windows Support | Full SSPI support | Stubbed (needs completion) |
| Performance | Synchronous (blocking) | Async with tokio runtime |
| Dependencies | Native libcurl library | Pure Rust dependencies |

## Troubleshooting

### curl backend

**Issue**: `curl` crate fails to build

**Solution**: Ensure you have libcurl development files installed. On Windows, the curl-sys crate should handle this automatically via vcpkg.

### reqwest backend

**Issue**: Authentication fails with "SSPI not implemented" error

**Solution**: The SSPI wrapper (`src/auth/sspi.rs`) is currently stubbed due to missing Windows crate types. To complete it:

1. Upgrade `windows` crate to a version that exports `CredHandle`, `CtxtHandle`, and `SEC_WINNT_AUTH_IDENTITY_W`
2. Or implement manual FFI bindings using `windows-sys` or `extern` declarations
3. Or use a dedicated SSPI crate like `sspi-rs` if available

### Both backends

**Issue**: 401 Unauthorized with negotiate enabled

**Possible causes**:
- Not on a domain-joined Windows machine
- No valid Kerberos tickets available
- Server doesn't support Negotiate authentication
- SPN (Service Principal Name) mismatch

**Debug steps**:
1. Run with `-v` for verbose output
2. Check `klist` output to verify Kerberos tickets
3. Try with explicit credentials using `-u user:pass`
4. Verify the server actually returns `WWW-Authenticate: Negotiate` header

## Architecture

### Module Structure

```
examples/
├── test_negotiate.rs          # Main CLI binary
└── backends/
    ├── mod.rs                 # Common trait and types
    ├── curl_backend.rs        # curl implementation
    └── reqwest_backend.rs     # reqwest implementation
```

### Backend Trait

```rust
pub trait HttpBackend {
    fn name(&self) -> &'static str;
    fn execute(&self, config: &RequestConfig) -> Result<Response, Box<dyn std::error::Error>>;
}
```

Both backends implement this trait, allowing them to be swapped at compile-time via feature flags.

## Contributing

To add support for additional backends:

1. Create a new module in `examples/backends/`
2. Implement the `HttpBackend` trait
3. Add a feature flag in `Cargo.toml`
4. Update `get_backend()` in `mod.rs` to support the new feature

## Related Files

- `src/auth/` - reqwest negotiate implementation
- `examples/negotiate_ad.rs` - Original reqwest-only example
- `CLAUDE.md` - Project-specific instructions
- `kerberos-01.md`, `kerberos-02.md` - Implementation plans

// examples/test_negotiate.rs

//! Test CLI for comparing curl vs reqwest negotiate authentication implementations.
//!
//! # Usage
//!
//! Test with curl backend (libcurl's SSPI):
//! ```bash
//! cargo run --example test_negotiate --no-default-features --features backend-curl -- \
//!     https://ad-server.corp.com/api --negotiate
//! ```
//!
//! Test with reqwest backend (custom implementation):
//! ```bash
//! cargo run --example test_negotiate --no-default-features --features backend-reqwest -- \
//!     https://ad-server.corp.com/api --negotiate
//! ```
//!
//! With credentials:
//! ```bash
//! cargo run --example test_negotiate -F backend-curl -- \
//!     https://ad-server.corp.com/api --negotiate -u user:pass
//! ```
//!
//! POST with JSON:
//! ```bash
//! cargo run --example test_negotiate -F backend-reqwest -- \
//!     https://ad-server.corp.com/api --negotiate --post --json '{"query":"test"}'
//! ```

mod backends;

use backends::{get_backend, Method, RequestConfig};
use std::env;

fn print_usage() {
    eprintln!("Usage: test_negotiate <url> [OPTIONS]");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --negotiate          Enable Negotiate (Kerberos/SPNEGO) authentication");
    eprintln!("  -u, --user <user:pass>  Username and password (enables fallback to Basic)");
    eprintln!("  --post               Use POST method");
    eprintln!("  --put                Use PUT method");
    eprintln!("  --delete             Use DELETE method");
    eprintln!("  --head               Use HEAD method");
    eprintln!("  -H, --header <name:value>  Add custom header");
    eprintln!("  --json <data>        Send JSON data (sets Content-Type)");
    eprintln!("  --data <data>        Send request body");
    eprintln!("  -v, --verbose        Verbose output");
    eprintln!("  -k, --insecure       Skip SSL verification");
    eprintln!("  -h, --help           Show this help");
    eprintln!();
    eprintln!("Examples:");
    eprintln!();
    eprintln!("  # GET with current user (Kerberos):");
    eprintln!("  test_negotiate https://ad-server.corp.com/api --negotiate");
    eprintln!();
    eprintln!("  # POST with JSON and credentials:");
    eprintln!("  test_negotiate https://ad-server.corp.com/api --negotiate \\");
    eprintln!("    -u user@DOMAIN.COM:password --post --json '{{\"query\":\"test\"}}'");
    eprintln!();
    eprintln!("  # Compare backends:");
    eprintln!("  cargo run --example test_negotiate -F backend-curl -- <url> --negotiate");
    eprintln!("  cargo run --example test_negotiate -F backend-reqwest -- <url> --negotiate");
}

fn parse_user_pass(s: &str) -> (String, String) {
    if let Some(colon_pos) = s.find(':') {
        let user = s[..colon_pos].to_string();
        let pass = s[colon_pos + 1..].to_string();
        (user, pass)
    } else {
        (s.to_string(), String::new())
    }
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() || args.contains(&"-h".to_string()) || args.contains(&"--help".to_string())
    {
        print_usage();
        std::process::exit(if args.is_empty() { 1 } else { 0 });
    }

    let url = &args[0];

    // Parse arguments
    let mut config = RequestConfig::new(url);
    let mut i = 1;

    while i < args.len() {
        match args[i].as_str() {
            "--negotiate" => {
                config = config.negotiate();
            }
            "-u" | "--user" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: {} requires an argument", args[i]);
                    std::process::exit(1);
                }
                let (user, pass) = parse_user_pass(&args[i + 1]);
                config = config.negotiate_with_credentials(user, pass);
                i += 1;
            }
            "--post" => {
                config = config.method(Method::Post);
            }
            "--put" => {
                config = config.method(Method::Put);
            }
            "--delete" => {
                config = config.method(Method::Delete);
            }
            "--head" => {
                config = config.method(Method::Head);
            }
            "-H" | "--header" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: {} requires an argument", args[i]);
                    std::process::exit(1);
                }
                if let Some(colon_pos) = args[i + 1].find(':') {
                    let name = args[i + 1][..colon_pos].trim().to_string();
                    let value = args[i + 1][colon_pos + 1..].trim().to_string();
                    config = config.header(name, value);
                } else {
                    eprintln!("Error: Header must be in format 'Name: Value'");
                    std::process::exit(1);
                }
                i += 1;
            }
            "--json" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --json requires an argument");
                    std::process::exit(1);
                }
                config = config.header("Content-Type".to_string(), "application/json".to_string());
                config = config.body(args[i + 1].clone());
                if config.method == Method::Get {
                    config = config.method(Method::Post);
                }
                i += 1;
            }
            "--data" => {
                if i + 1 >= args.len() {
                    eprintln!("Error: --data requires an argument");
                    std::process::exit(1);
                }
                config = config.body(args[i + 1].clone());
                if config.method == Method::Get {
                    config = config.method(Method::Post);
                }
                i += 1;
            }
            "-v" | "--verbose" => {
                config = config.verbose(true);
            }
            "-k" | "--insecure" => {
                config = config.insecure(true);
            }
            _ => {
                eprintln!("Error: Unknown option '{}'", args[i]);
                print_usage();
                std::process::exit(1);
            }
        }
        i += 1;
    }

    // Get backend and display info
    let backend = get_backend();
    println!("=== HTTP Negotiate Authentication Test ===");
    println!("Backend: {}", backend.name());
    println!("URL: {}", url);
    println!("Method: {}", config.method);
    println!("Auth: {:?}", config.auth);
    println!();

    // Execute request
    println!("Sending request...");
    match backend.execute(&config) {
        Ok(response) => {
            println!();
            println!("=== Response ===");
            println!("Status: {} {}", response.status, response.status_text);

            if response.is_success() {
                println!("✓ Success");
            } else {
                println!("✗ Error");
            }

            println!();
            println!("Headers:");
            for (name, value) in &response.headers {
                println!("  {}: {}", name, value);
            }

            println!();
            let body_str = response.body_string();
            if body_str.len() <= 1000 {
                println!("Body ({} bytes):", body_str.len());
                println!("{}", body_str);
            } else {
                println!("Body ({} bytes, truncated):", body_str.len());
                println!("{}...", &body_str[..1000]);
            }
        }
        Err(e) => {
            eprintln!();
            eprintln!("✗ Request failed: {}", e);
            std::process::exit(1);
        }
    }
}

// examples/negotiate_ad.rs

//! Example of using HTTP Negotiate (Kerberos/SPNEGO) authentication with reqwest.
//!
//! This example demonstrates:
//! - GET requests with current user authentication
//! - POST requests with JSON payloads
//! - Fallback authentication with explicit credentials
//!
//! # Usage
//!
//! ## GET with current user (Kerberos):
//! ```bash
//! cargo run --example negotiate_ad --features negotiate,json -- https://ad-server.corp.com/api
//! ```
//!
//! ## POST with JSON body:
//! ```bash
//! cargo run --example negotiate_ad --features negotiate,json -- https://ad-server.corp.com/api --post
//! ```
//!
//! ## With fallback credentials:
//! ```bash
//! cargo run --example negotiate_ad --features negotiate,json -- https://ad-server.corp.com/api --username user@DOMAIN.COM --password pass123
//! ```
//!
//! ## POST with credentials:
//! ```bash
//! cargo run --example negotiate_ad --features negotiate,json -- https://ad-server.corp.com/api --post --username user --password pass
//! ```

#[cfg(feature = "negotiate")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: negotiate_ad <url> [OPTIONS]");
        eprintln!();
        eprintln!("Options:");
        eprintln!("  --username <user>    Username for fallback authentication");
        eprintln!("  --password <pass>    Password for fallback authentication");
        eprintln!("  --post               Send POST request instead of GET");
        eprintln!("  --body <json>        Custom JSON body for POST (default: test query)");
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  # GET with current user (Kerberos):");
        eprintln!("  negotiate_ad https://ad-server.corp.com/api");
        eprintln!();
        eprintln!("  # POST with JSON:");
        eprintln!("  negotiate_ad https://ad-server.corp.com/api --post");
        eprintln!();
        eprintln!("  # With fallback credentials:");
        eprintln!("  negotiate_ad https://ad-server.corp.com/api --username user@DOMAIN.COM --password pass");
        std::process::exit(1);
    }

    let url = &args[1];

    // Parse command-line arguments
    let use_post = args.contains(&"--post".to_string());
    let username = args
        .iter()
        .position(|a| a == "--username")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let password = args
        .iter()
        .position(|a| a == "--password")
        .and_then(|i| args.get(i + 1))
        .cloned();
    let custom_body = args
        .iter()
        .position(|a| a == "--body")
        .and_then(|i| args.get(i + 1))
        .cloned();

    println!("=== Reqwest Negotiate Authentication Example ===");
    println!("URL: {}", url);

    // Build client with appropriate authentication
    let client = if let (Some(user), Some(pass)) = (username.as_ref(), password.as_ref()) {
        println!("Mode: Negotiate with fallback credentials");
        println!("Username: {}", user);
        reqwest::Client::builder()
            .negotiate_with_credentials(user, pass)
            .build()?
    } else {
        println!("Mode: Negotiate with current user (Kerberos)");
        reqwest::Client::builder()
            .negotiate()
            .build()?
    };

    // Send request (GET or POST)
    let resp = if use_post {
        println!("\nSending POST request with JSON body...");

        #[cfg(feature = "json")]
        {
            let json_body = if let Some(body_str) = custom_body {
                serde_json::from_str(&body_str)?
            } else {
                serde_json::json!({
                    "query": "select * from table",
                    "test": "negotiate authentication"
                })
            };

            println!("Body: {}", serde_json::to_string_pretty(&json_body)?);

            client
                .post(url)
                .header("accept", "application/json")
                .json(&json_body)
                .send()
                .await?
        }

        #[cfg(not(feature = "json"))]
        {
            eprintln!("Error: JSON support requires the 'json' feature");
            std::process::exit(1);
        }
    } else {
        println!("\nSending GET request...");
        client.get(url).send().await?
    };

    // Display response
    println!("\n=== Response ===");
    println!("Status: {}", resp.status());
    println!("\nHeaders:");
    for (name, value) in resp.headers() {
        println!("  {}: {:?}", name, value);
    }

    let body = resp.text().await?;
    println!("\nBody ({} bytes):", body.len());
    if body.len() <= 1000 {
        println!("{}", body);
    } else {
        println!("{}... (truncated)", &body[..1000]);
    }

    println!("\n=== Success ===");
    Ok(())
}

#[cfg(not(feature = "negotiate"))]
fn main() {
    eprintln!("This example requires the 'negotiate' feature to be enabled.");
    eprintln!("Try running with:");
    eprintln!("  cargo run --example negotiate_ad --features negotiate,json -- <url>");
    std::process::exit(1);
}

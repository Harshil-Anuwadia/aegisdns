use axum::{http::{Request, StatusCode, header}, middleware::Next, response::{Response, IntoResponse}};
use std::sync::OnceLock;
use base64::{Engine as _, engine::general_purpose::STANDARD};

static PASSWORD: OnceLock<String> = OnceLock::new();

pub fn initialize() -> anyhow::Result<()> {
    let path = config::paths::get_data_dir().join("admin-password");
    let password = if let Ok(pass) = std::env::var("AEGIS_ADMIN_PASSWORD") {
        if pass.is_empty() { load_or_create(&path)? } else { pass }
    } else { load_or_create(&path)? };
    anyhow::ensure!(password.len() >= 16 && password.len() <= 256 && !password.chars().any(char::is_control), "AEGIS_ADMIN_PASSWORD must contain 16–256 characters without control characters");
    PASSWORD.set(password).map_err(|_| anyhow::anyhow!("Authentication already initialized"))?;
    Ok(())
}
fn load_or_create(path: &std::path::Path) -> anyhow::Result<String> {
    match std::fs::read_to_string(path) {
        Ok(p) => Ok(p.trim_end_matches('\n').to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let bytes: [u8;32] = rand::random();
            let pass = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
            config::atomic_write(path, &pass)?;
            tracing::info!("Generated admin password stored privately at {}", path.display());
            Ok(pass)
        }, Err(e) => Err(e.into()),
    }
}

pub fn secure_equal(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

pub async fn auth_middleware(req: Request<axum::body::Body>, next: Next) -> Response {
    // The favicon endpoint makes outbound requests. Keep it behind the dashboard
    // credential so the DNS server cannot be used as a public fetch relay.
    let public = matches!(req.uri().path(), "/blocked" | "/logo.png");
    if !public {
        if !matches!(*req.method(), axum::http::Method::GET | axum::http::Method::HEAD)
            && req.headers().get("x-aegis-request").and_then(|v|v.to_str().ok()) != Some("1") {
            return (StatusCode::FORBIDDEN,"Missing same-origin request header").into_response();
        }
        // Browsers cannot add the custom header cross-origin without an authorized preflight.
        // No CORS permission is granted by this server.
        if req.headers().get("sec-fetch-site").and_then(|v|v.to_str().ok()) == Some("cross-site") {
            return (StatusCode::FORBIDDEN,"Cross-site administration is forbidden").into_response();
        }
        let valid = PASSWORD.get().is_some_and(|password| {
            req.headers().get(header::AUTHORIZATION).and_then(|h|h.to_str().ok())
                .and_then(|h|h.strip_prefix("Basic ")).and_then(|b|STANDARD.decode(b).ok())
                .and_then(|bytes|String::from_utf8(bytes).ok())
                .is_some_and(|creds|secure_equal(&creds,&format!("admin:{password}")))
        });
        if !valid {
            // Bound concurrent attackers at HTTP admission; delay failures without blocking the executor.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            return (StatusCode::UNAUTHORIZED, [(header::WWW_AUTHENTICATE,"Basic realm=\"AegisDNS Admin\", charset=\"UTF-8\"")], "Use the AegisDNS admin credential, not your system password.").into_response();
        }
    }
    let mut response = next.run(req).await;
    let h = response.headers_mut();
    h.insert(header::X_CONTENT_TYPE_OPTIONS, "nosniff".parse().unwrap());
    h.insert(header::REFERRER_POLICY, "no-referrer".parse().unwrap());
    h.insert(header::X_FRAME_OPTIONS, "DENY".parse().unwrap());
    h.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    h.insert(header::CONTENT_SECURITY_POLICY, "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'".parse().unwrap());
    // HSTS: if the dashboard is served over TLS (via a reverse proxy like Caddy/nginx),
    // this tells browsers to always use HTTPS for the next year and never accept HTTP.
    // This is a no-op when running plain HTTP on localhost, but costs nothing to include.
    h.insert(header::STRICT_TRANSPORT_SECURITY, "max-age=31536000; includeSubDomains".parse().unwrap());
    // Prevent Adobe Flash / PDF from making cross-domain requests (legacy hardening).
    h.insert("x-permitted-cross-domain-policies".parse::<axum::http::HeaderName>().unwrap(), "none".parse().unwrap());
    response
}

#[cfg(test)] mod tests {
    #[test] fn comparison() { assert!(super::secure_equal("abc","abc")); assert!(!super::secure_equal("abc","abd")); assert!(!super::secure_equal("abc","ab")); }
}

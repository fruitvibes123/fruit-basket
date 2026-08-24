//! `fb-acme serve`: tiny static-file server for Let's Encrypt HTTP-01
//! challenges. Bound to loopback; HAProxy is the only reachable inbound.
//!
//! Relocated verbatim from the original `acme-server` crate's `main.rs` under
//! the merged binary's `serve` subcommand. Logic +
                                       
         
//! hardening unchanged. The
//! original Axum-pilot lessons are preserved in the pilot's records.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use axum::{
    Router,
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::Response,
};
use tower_http::services::ServeDir;

const BIND_ADDR: &str = "127.0.0.1:8081";
const MOUNT_PATH: &str = "/.well-known/acme-challenge";
/// Default challenge dir. The image template points `ACME_CHALLENGE_DIR` at the
/// tmpfs `/run/fb-acme/challenges/` (spec §fb-acme HTTP-01 hardening);
/// this default is retained for the legacy/standalone invocation.
const DEFAULT_DIR: &str = "/var/lib/acme/acme-challenge";

#[derive(Clone)]
struct AppState {
    canonical_dir: Arc<PathBuf>,
}

                                                                        
                                                                           
                                                                         
                                                     
fn validate_dir(path: &Path) -> Result<PathBuf, String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| {
        format!(
            "ACME_CHALLENGE_DIR not accessible ({}): {e}",
            path.display()
        )
    })?;
    if meta.is_symlink() {
        return Err(format!(
            "ACME_CHALLENGE_DIR is a symlink: {}",
            path.display()
        ));
    }
    if !meta.is_dir() {
        return Err(format!(
            "ACME_CHALLENGE_DIR is not a directory: {}",
            path.display()
        ));
    }
    std::fs::canonicalize(path).map_err(|e| format!("ACME_CHALLENGE_DIR canonicalize failed: {e}"))
}

                                                                           
                                                                      
                                                                       
                                                                       
                                                                       
                                                                      
                                
async fn reject_symlink_components(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let uri_path = request.uri().path();
    let relative = match uri_path.strip_prefix(MOUNT_PATH) {
        Some(rest) => rest.trim_start_matches('/'),
        None => return Ok(next.run(request).await),
    };

    if relative.is_empty() {
        return Ok(next.run(request).await);
    }

    let mut probe = state.canonical_dir.as_path().to_path_buf();
    for component in Path::new(relative).components() {
        use std::path::Component;
        match component {
            Component::Normal(part) => probe.push(part),
                                                                        
                                                                         
                                       
            _ => return Err(StatusCode::NOT_FOUND),
        }
        match std::fs::symlink_metadata(&probe) {
            Ok(m) if m.file_type().is_symlink() => return Err(StatusCode::NOT_FOUND),
            Ok(_) => {}                                                     
            Err(_) => break,                                                    
        }
    }
    Ok(next.run(request).await)
}

fn build_app(canonical_dir: PathBuf) -> Router {
    let state = AppState {
        canonical_dir: Arc::new(canonical_dir.clone()),
    };
    Router::new()
        .nest_service(MOUNT_PATH, ServeDir::new(canonical_dir))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            reject_symlink_components,
        ))
        .with_state(state)
}

/// Run the HTTP-01 challenge server (the `serve` subcommand). Reads
/// `ACME_CHALLENGE_DIR` (default [`DEFAULT_DIR`]); validates it; binds
/// loopback `:8081`. Never returns under normal operation.
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let dir_str = std::env::var("ACME_CHALLENGE_DIR").unwrap_or_else(|_| DEFAULT_DIR.to_string());
    let canonical_dir = match validate_dir(Path::new(&dir_str)) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("FATAL: {e}");
            std::process::exit(1);
        }
    };

    let app = build_app(canonical_dir);
    let listener = tokio::net::TcpListener::bind(BIND_ADDR).await?;
    eprintln!("fb-acme serve listening on {BIND_ADDR}");
    axum::serve(listener, app).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tempfile::TempDir;
    use tower::ServiceExt;

    fn challenge_dir_with_token(name: &str, body: &[u8]) -> TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(name), body).unwrap();
        dir
    }

    fn request(uri: &str) -> axum::http::Request<Body> {
        axum::http::Request::builder()
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn serves_challenge_token() {
        let dir = challenge_dir_with_token("a-token", b"answer-payload");
        let canonical = std::fs::canonicalize(dir.path()).unwrap();
        let app = build_app(canonical);

        let resp = app
            .oneshot(request("/.well-known/acme-challenge/a-token"))
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"answer-payload");
    }

    #[tokio::test]
    async fn missing_token_returns_404() {
        let dir = challenge_dir_with_token("present", b"x");
        let canonical = std::fs::canonicalize(dir.path()).unwrap();
        let app = build_app(canonical);

        let resp = app
            .oneshot(request("/.well-known/acme-challenge/missing"))
            .await
            .unwrap();
        assert_eq!(resp.status(), 404);
    }

    #[tokio::test]
    async fn rejects_path_traversal() {
        let dir = challenge_dir_with_token("a", b"x");
        let canonical = std::fs::canonicalize(dir.path()).unwrap();
        let app = build_app(canonical);

                                                                              
                                                                         
        let resp = app
            .oneshot(request("/.well-known/acme-challenge/../../../etc/passwd"))
            .await
            .unwrap();
        assert!(
            !resp.status().is_success(),
            "path traversal must not succeed (got {})",
            resp.status()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_symlink_inside_challenge_dir() {
        let dir = tempfile::tempdir().unwrap();
                                                                
        std::os::unix::fs::symlink("/etc", dir.path().join("danger")).unwrap();
        let canonical = std::fs::canonicalize(dir.path()).unwrap();
        let app = build_app(canonical);

        let resp = app
            .oneshot(request("/.well-known/acme-challenge/danger/passwd"))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            404,
            "request through a symlinked component must be rejected"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rejects_symlink_pointing_to_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("real-token"), b"real").unwrap();
        std::os::unix::fs::symlink(dir.path().join("real-token"), dir.path().join("aliased"))
            .unwrap();
        let canonical = std::fs::canonicalize(dir.path()).unwrap();
        let app = build_app(canonical);

        let resp = app
            .oneshot(request("/.well-known/acme-challenge/aliased"))
            .await
            .unwrap();
        assert_eq!(resp.status(), 404, "even harmless symlinks are rejected");
    }

    #[test]
    fn validate_dir_accepts_real_directory() {
        let dir = tempfile::tempdir().unwrap();
        let result = validate_dir(dir.path());
        assert!(result.is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn validate_dir_rejects_symlinked_root() {
        let dir = tempfile::tempdir().unwrap();
        let actual = dir.path().join("real");
        std::fs::create_dir(&actual).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&actual, &link).unwrap();

        let err = validate_dir(&link).unwrap_err();
        assert!(
            err.contains("symlink"),
            "expected symlink rejection, got: {err}"
        );
    }

    #[test]
    fn validate_dir_rejects_nonexistent() {
        let result = validate_dir(Path::new("/this/path/does/not/exist"));
        assert!(result.is_err());
    }

    #[test]
    fn validate_dir_rejects_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        let err = validate_dir(&file).unwrap_err();
        assert!(err.contains("not a directory"));
    }
}

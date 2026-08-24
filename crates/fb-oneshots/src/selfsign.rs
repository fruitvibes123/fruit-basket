//! `fb-oneshots selfsign-acme-cert` — the bootstrap oneshot that resolves the
//! ACME first-boot chicken-and-egg (spec L746/L775): haproxy needs a cert to `bind
//! :443` before fb-acme can complete the ACME handshake. This self-signs a
//! temporary cert into `/persist/acme/<domain>/full.pem` IF that file is absent, so
//! haproxy can start; fb-acme replaces it with the real Let's Encrypt cert at
//! first opportunity. Idempotent + never-clobber: an existing cert (a real ACME cert
//! from a prior boot, or a prior self-signed one) is left untouched.

use std::io::Write as _;
use std::path::Path;

/// RFC-1123 FQDN validation (1..=253 chars; per-label 1..=63, `[A-Za-z0-9-]`, no
/// leading/trailing hyphen). Mirrors `recipes-image-builder`'s `validate_domain`, ported
/// here because that one is behind the `deploy` feature and this oneshot runs in the
/// non-deploy musl image. Load-bearing: `<domain>` is interpolated into the
/// `/persist/acme/<domain>/` path, so rejecting `/`, `..`, and control chars closes a
/// path-traversal vector even though the build already validated the baked domain.
pub fn valid_acme_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    if domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// Generate a self-signed P-256 leaf for `domain` and return the combined key‖cert PEM
/// HAProxy's `crt` directive expects (private key first, then the cert — matching
/// `fb-acme`'s `CertMaterial::full_pem`). `self_signed` sets Issuer == Subject. NOTE (L-3,
/// network-bringup holistic R3 — this corrects a prior FALSE claim here): `fb-cert-check` does
/// NOT detect self-signed — it only parses `notAfter`, and this bootstrap cert is valid until 2037, so
/// while the box is stuck on it the daily check stays GREEN (no alarm that real ACME never succeeded).
/// Issuer==Subject detection (so the alarm would flip while the bootstrap cert is in place; deploy-
/// overhaul spec L777) is DEFERRED to the deploy-and-transition cert-monitoring work. The validity
/// window is a fixed [2020, 2037] span (not `now`-relative): a wrong first-boot clock must
/// not mint a cert that reads "expired" once `ntpd` corrects the clock, which would make
/// haproxy refuse it on the next reload.
pub fn generate_selfsigned_pem(domain: &str) -> Result<String, String> {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| format!("P-256 keypair: {e}"))?;
    let key_pem = kp.serialize_pem();

    let mut params = rcgen::CertificateParams::new(vec![domain.to_string()])
        .map_err(|e| format!("certificate params (SAN {domain:?}): {e}"))?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, domain);
                                                                                          
                                                                    
    params.is_ca = rcgen::IsCa::NoCa;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    params.not_before = rcgen::date_time_ymd(2020, 1, 1);
    params.not_after = rcgen::date_time_ymd(2037, 12, 31);

    let cert = params
        .self_signed(&kp)
        .map_err(|e| format!("self-sign {domain:?}: {e}"))?;
    let cert_pem = cert.pem();

    Ok(format!("{}\n{}\n", key_pem.trim_end(), cert_pem.trim_end()))
}

/// Entry point: idempotently write a self-signed bootstrap cert to
/// `<persist_dir>/<domain>/full.pem` (mode 0600, in a 0700 dir) IF absent. An existing
/// `full.pem` (real ACME cert or prior self-signed) is left untouched — never clobber the
/// cert HAProxy is already serving.
pub fn selfsign_acme_cert(
    persist_dir: &Path,
    domain: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if !valid_acme_domain(domain) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid --domain {domain:?}: not an RFC-1123 hostname"),
        )
        .into());
    }
    let dir = persist_dir.join(domain);
    std::fs::create_dir_all(&dir)?;
    set_mode(&dir, 0o700)?;

    let full = dir.join("full.pem");
    if full.exists() {
        println!(
            "fb-oneshots selfsign-acme-cert: {} already present; no-op",
            full.display()
        );
        return Ok(());
    }

    let pem = generate_selfsigned_pem(domain)?;
    write_atomic_0600(&full, pem.as_bytes())?;
    println!(
        "fb-oneshots selfsign-acme-cert: wrote self-signed bootstrap cert to {}",
        full.display()
    );
    Ok(())
}

/// Write `contents` to `path` atomically at mode 0600: stage a sibling temp via a hardened
/// fresh-inode open, write, fsync, rename over `path` — so a crash never leaves a partial
/// `full.pem` HAProxy might pick up. Mirrors `fb-acme::renew::write_atomic_0600`.
/// `pub(crate)`: shared with `cert_reload`'s marker write (same hardened pattern, spec §4.1).
pub(crate) fn write_atomic_0600(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path has no parent dir")
    })?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "bad file name"))?;
    let tmp = dir.join(format!(".{file_name}.tmp"));

    let mut f = open_fresh_0600(&tmp)?;
    f.write_all(contents)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, path)
}

/// Open `path` as a FRESH inode at mode 0600 — `create_new` + `O_NOFOLLOW` (unix) so a
/// pre-planted symlink/file can't redirect the write; on a stale leftover, unlink-and-retry
/// once. Mirrors the hardened temp open shared across the cert-file writers.
fn open_fresh_0600(path: &Path) -> std::io::Result<std::fs::File> {
    fn attempt(path: &Path) -> std::io::Result<std::fs::File> {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
            opts.custom_flags(libc::O_NOFOLLOW);
        }
        opts.open(path)
    }
    match attempt(path) {
        Ok(f) => Ok(f),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(path)?;
            attempt(path)
        }
        Err(e) => Err(e),
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_acme_domain_accepts_fqdns() {
        assert!(valid_acme_domain("recipes.example.org"));
        assert!(valid_acme_domain("box.test"));
        assert!(valid_acme_domain("a.b-c.example123.com"));
    }

    #[test]
    fn valid_acme_domain_rejects_traversal_and_injection() {
                                                                                         
        assert!(!valid_acme_domain("../etc/haproxy"));
        assert!(!valid_acme_domain("a/b"));
        assert!(!valid_acme_domain(".."));
                                 
        assert!(!valid_acme_domain(""));
        assert!(!valid_acme_domain("has space"));
        assert!(!valid_acme_domain("x\nbind"));
        assert!(!valid_acme_domain(".lead"));
        assert!(!valid_acme_domain("trail."));
        assert!(!valid_acme_domain("-lead.com"));
        assert!(!valid_acme_domain(&format!("{}.com", "a".repeat(64))));
    }

    #[test]
    fn generated_pem_has_key_then_cert() {
        let pem = generate_selfsigned_pem("box.test").unwrap();
        let key_at = pem.find("PRIVATE KEY").expect("has a private key block");
        let cert_at = pem
            .find("BEGIN CERTIFICATE")
            .expect("has a certificate block");
        assert!(key_at < cert_at, "key precedes cert (HAProxy crt form)");
        assert!(pem.ends_with('\n'));
    }

    #[cfg(unix)]
    #[test]
    fn selfsign_writes_full_pem_0600_in_0700_dir() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        selfsign_acme_cert(tmp.path(), "box.test").unwrap();
        let dir = tmp.path().join("box.test");
        let full = dir.join("full.pem");
        assert!(full.exists());
        let body = std::fs::read_to_string(&full).unwrap();
        assert!(body.contains("PRIVATE KEY") && body.contains("BEGIN CERTIFICATE"));
        let dir_mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        let full_mode = std::fs::metadata(&full).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "per-domain dir is 0700");
        assert_eq!(full_mode, 0o600, "full.pem is 0600");
                                 
        assert!(!dir.join(".full.pem.tmp").exists());
    }

    #[test]
    fn selfsign_is_idempotent_never_clobbers() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("box.test");
        std::fs::create_dir_all(&dir).unwrap();
        let full = dir.join("full.pem");
        std::fs::write(&full, "EXISTING-ACME-CERT-SENTINEL").unwrap();
                                                                             
        selfsign_acme_cert(tmp.path(), "box.test").unwrap();
        assert_eq!(
            std::fs::read_to_string(&full).unwrap(),
            "EXISTING-ACME-CERT-SENTINEL"
        );
    }

    #[test]
    fn selfsign_rejects_bad_domain_without_writing() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(selfsign_acme_cert(tmp.path(), "../escape").is_err());
                                                                                       
                                                                                            
        assert_eq!(
            tmp.path().read_dir().unwrap().count(),
            0,
            "a rejected domain must create no dir/file"
        );
    }
}

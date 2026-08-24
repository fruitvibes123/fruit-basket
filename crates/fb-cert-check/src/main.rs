//! fb-cert-check: daily cert-expiry alarm via journald/console.
//!
//! Audit R-H3 close. Reads the TLS cert at the path given in arg 1, computes
//! days-until-expiry, writes one line to stdout (the supervisor captures it),
//! and exits non-zero if days ≤ 7 so an `is-failed`-style daily check flips
//! for the operator.
//!
//! Operator's only alarm path. No SMTP, no third-party
                                  
//! (by policy). Sub-4 may layer richer alarms.
//!
//! H-1 (network-bringup holistic R2): parses the cert `notAfter` IN-RUST via
//! `x509-parser` — the box ships NO `openssl` CLI (it lived only in the NixOS
//! `buildInputs`), so the old `openssl x509 -noout -enddate` shell-out hit
//! ENOENT and exited 2 on EVERY run, silently destroying the alarm. x509-parser
//! is already compiled in (rcgen pulls it), so this adds no image weight.
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

use std::process::ExitCode;

use x509_parser::pem::Pem;

const ALERT_DAYS: i64 = 7;

fn main() -> ExitCode {
    let path = match std::env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: fb-cert-check <pem-file>");
            return ExitCode::from(2);
        }
    };

    let pem_bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("fb-cert-check: could not read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let not_after = match cert_not_after(&pem_bytes) {
        Ok(ts) => ts,
        Err(e) => {
            eprintln!("fb-cert-check: {e} (in {path})");
            return ExitCode::from(2);
        }
    };
    let now = match now_unix() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("fb-cert-check: {e}");
            return ExitCode::from(2);
        }
    };
    let days = days_until(not_after, now);

    println!("fb-cert-check: cert at {path} expires in {days} days");

    if days <= ALERT_DAYS {
        eprintln!("fb-cert-check: ALERT — cert expires in {days} days (threshold {ALERT_DAYS})");
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// The `notAfter` (Unix seconds) of the FIRST `CERTIFICATE` PEM block in `pem_bytes`. The box's
/// `full.pem` is key‖chain — the PRIVATE KEY block comes FIRST (fb-acme `CertMaterial::full_pem`),
/// so we ITERATE and skip non-CERTIFICATE blocks rather than parsing the first block blindly. This
/// matches what `openssl x509` did implicitly (find the first cert, ignore the key); H-1 replaces it.
fn cert_not_after(pem_bytes: &[u8]) -> Result<i64, String> {
    for block in Pem::iter_from_buffer(pem_bytes) {
                                                                                                 
                                                                                                
        let block = block.map_err(|e| format!("malformed PEM: {e}"))?;
        if block.label != "CERTIFICATE" {
            continue;                                                        
        }
        let cert = block.parse_x509().map_err(|e| format!("parse x509: {e}"))?;
        return Ok(cert.validity().not_after.timestamp());
    }
    Err("no CERTIFICATE block found".to_string())
}

/// Whole days from `now` until `not_after` (both Unix seconds); negative once expired.
fn days_until(not_after_unix: i64, now_unix: i64) -> i64 {
    (not_after_unix - now_unix) / 86_400
}

fn now_unix() -> Result<i64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| format!("system clock is before 1970: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a self-signed cert and return `(key_pem, cert_pem)` — mirrors `fb-oneshots::selfsign`
    /// and the on-box `full.pem` layout (key first, then the cert).
    fn self_signed() -> (String, String) {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("keypair");
        let key_pem = kp.serialize_pem();
        let params = rcgen::CertificateParams::new(vec!["cert-check-test".to_string()])
            .expect("cert params");
        let cert = params.self_signed(&kp).expect("self-sign");
        (key_pem, cert.pem())
    }

    /// H-1 crux: a key‖chain `full.pem` (PRIVATE KEY first) must yield the CERT's notAfter — the
    /// leading key block is skipped, exactly as `openssl x509` did. The equality vs the cert-only PEM
    /// proves the prefix is ignored, not merely tolerated.
    #[test]
    fn cert_not_after_skips_leading_private_key() {
        let (key_pem, cert_pem) = self_signed();
        let full = format!("{key_pem}{cert_pem}");                               
        let from_full = cert_not_after(full.as_bytes()).expect("parse full.pem");
        let from_cert_only = cert_not_after(cert_pem.as_bytes()).expect("parse cert-only");
        assert_eq!(
            from_full, from_cert_only,
            "the leading private key must be skipped"
        );
        assert!(
            from_full > now_unix().unwrap(),
            "a fresh self-signed cert is not yet expired"
        );
    }

    /// A PEM with no CERTIFICATE block (key only) is an error, not a silent pass — the old shell-out's
    /// failure mode (exit 2) is preserved for a genuinely unreadable cert.
    #[test]
    fn cert_not_after_errors_when_no_certificate() {
        let (key_pem, _) = self_signed();
        assert!(cert_not_after(key_pem.as_bytes()).is_err());
    }

    #[test]
    fn days_until_is_signed_and_floored() {
        let now = 1_700_000_000;
        assert_eq!(days_until(now + 10 * 86_400, now), 10);
        assert_eq!(days_until(now, now), 0);
        assert_eq!(
            days_until(now - 3 * 86_400, now),
            -3,
            "expired certs report negative days"
        );
                                                                                      
        assert!(days_until(now + 7 * 86_400, now) <= ALERT_DAYS);
        assert!(days_until(now + 8 * 86_400, now) > ALERT_DAYS);
    }
}

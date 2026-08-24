//! The scheduled-renewal due-check: classify the on-disk cert, decide whether
//! an ACME order is genuinely needed (renewer spec
//! `2026-07-17-fb-acme-renew-schedule-design.md` §2).
//!
//! `full.pem` is key ‖ chain; classification is **leaf-only** (the first
//! CERTIFICATE block — spec §2.3): a real LE chain can carry a self-signed
//! *root* (e.g. ISRG Root X1), and a whole-file Issuer==Subject scan would
//! misclassify the whole cert as the bootstrap → the re-issuance loop returns.
//! The parse mirrors `fb-cert-check` (the H-1 in-Rust precedent) exactly:
//! `Pem::iter_from_buffer` → first `CERTIFICATE` → `pem.parse_x509()`.
//!
//! The inspection is TOTAL and fails toward renewal (spec §2.2): every
//! bad-read/bad-parse shape resolves to a variant that `decide()` maps to
//! *obtain*, never to a silent skip — and it never panics on untrusted bytes.

use std::path::Path;

use x509_parser::pem::Pem;

/// What the on-disk `full.pem` holds, per the renewer spec §2 four-way split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inspection {
    /// No `full.pem` at the path (fresh persist, first boot pre-bootstrap).
    Absent,
    /// Read or parse failure, or no CERTIFICATE block — corrupt/foreign bytes.
    Unparseable,
    /// The LEAF is self-signed (Issuer == Subject): on this box, always the
    /// `selfsign` bootstrap cert awaiting replacement (spec §2.5).
    SelfSigned,
    /// A well-formed, non-self-signed leaf; `not_after` drives the expiry test.
    Real {
        /// Leaf `notAfter` as Unix seconds.
        not_after_unix: i64,
    },
}

/// What a scheduled renewal cycle should do with the current [`Inspection`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// An order is genuinely needed — run the obtain path (which clock-gates
    /// and backs off internally).
    Obtain,
    /// The cert is healthy and far from expiry — no network, no key access.
    Idle,
    /// A Real cert but the clock is not yet trustworthy — defer the expiry
    /// comparison to the next cycle rather than mis-decide (spec §2.4).
    WaitClock,
}

/// Renew when the leaf is within this window of `notAfter` (spec §2: 30 days —
/// mirrors certbot's default posture; 28+ daily chances before expiry).
pub const RENEW_THRESHOLD_SECS: i64 = 30 * 24 * 3600;

/// The §2.6 guard floor — an INTERNAL-coherence tripwire, not a pin of LE's
/// actual (external, unpinnable) lifetime: the compile-time assert below
/// trips on a threshold/floor EDIT before it can silently re-arm the
/// re-issuance loop (renewed cert already inside the window ⇒ due every
/// cycle). LE default-profile roadmap (audit-R1 web-verified): 90 d today →
/// 64 d on 2027-02-10 → **45 d on 2028-02-16**. At 45 d this 60-day floor
/// claim is conservative-stale but the invariant still HOLDS (45 − 30 =
/// 15-day idle margin); only a sub-threshold profile (LE's 6-day) re-arms
/// the loop — the spec §2.6(c) threshold-as-a-fraction rework is the named
/// forward-debt that becomes live at the 2028 step.
pub const MIN_CERT_LIFETIME_SECS: i64 = 60 * 24 * 3600;

                                                                             
                                                                          
                                              
                                                
const _: () = assert!(RENEW_THRESHOLD_SECS < MIN_CERT_LIFETIME_SECS);

/// The pure scheduled-cycle decision (spec §2, the three-way split):
/// Absent/Unparseable/SelfSigned ⇒ [`Action::Obtain`] clock-independently;
/// Real defers to [`Action::WaitClock`] on an unsynced clock, else the
/// **signed one-sided** near-expiry test — an already-expired cert has
/// negative remaining time ⇒ due (never stranded not-due; spec §2.2).
pub fn decide(insp: &Inspection, clock_synced: bool, now_unix: i64, threshold_secs: i64) -> Action {
    match insp {
        Inspection::Absent | Inspection::Unparseable | Inspection::SelfSigned => Action::Obtain,
        Inspection::Real { not_after_unix } => {
            if !clock_synced {
                return Action::WaitClock;
            }
                                                                                
            if not_after_unix - now_unix <= threshold_secs {
                Action::Obtain
            } else {
                Action::Idle
            }
        }
    }
}

/// Seam over "read + classify the cert file" so the scheduled path is testable
/// with a stub (the `AcmeClient`/`ClockSync`/`Sleeper` pattern in `renew.rs`).
pub trait CertInspector {
    /// Classify the cert at `full_pem_path`. Total: never panics, never errors.
    fn inspect(&self, full_pem_path: &Path) -> Inspection;
}

/// Production inspector: reads the file and leaf-classifies it.
pub struct FileCertInspector;

impl CertInspector for FileCertInspector {
    fn inspect(&self, full_pem_path: &Path) -> Inspection {
        let pem_bytes = match std::fs::read(full_pem_path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Inspection::Absent,
                                                                         
                                                                              
            Err(_) => return Inspection::Unparseable,
        };
        classify_leaf(&pem_bytes)
    }
}

/// Leaf-only classification of a key‖chain PEM buffer (spec §2.3/§2.5).
fn classify_leaf(pem_bytes: &[u8]) -> Inspection {
    for block in Pem::iter_from_buffer(pem_bytes) {
                                                                              
        let Ok(block) = block else {
            return Inspection::Unparseable;
        };
        if block.label != "CERTIFICATE" {
            continue;                                                        
        }
        let Ok(cert) = block.parse_x509() else {
            return Inspection::Unparseable;
        };
                                                                          
                                                                        
                                                     
        return if cert.issuer().as_raw() == cert.subject().as_raw() {
            Inspection::SelfSigned
        } else {
            Inspection::Real {
                not_after_unix: cert.validity().not_after.timestamp(),
            }
        };
    }
                                                                            
    Inspection::Unparseable
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A self-signed leaf — the box's bootstrap shape (mirrors
    /// `fb-oneshots::selfsign` / fb-cert-check's test helper). Returns
    /// `(key_pem, cert_pem)`; the on-box `full.pem` layout is key-first.
    fn self_signed_leaf() -> (String, String) {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("keypair");
        let params = rcgen::CertificateParams::new(vec!["due-test.example.org".to_string()])
            .expect("cert params");
        let cert = params.self_signed(&kp).expect("self-sign");
        (kp.serialize_pem(), cert.pem())
    }

    /// A CA-signed-shaped leaf (Issuer ≠ Subject) with a pinned `not_after`,
    /// plus its self-signed root. Distinguished names are set EXPLICITLY on
    /// both — rcgen's default DN is empty, and two empty DNs would compare
    /// raw-equal, silently turning this fixture self-signed-shaped.
    /// Returns `(key_pem, leaf_pem, root_pem, not_after_unix)`.
    fn ca_signed_leaf() -> (String, String, String, i64) {
        let ca_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ca keypair");
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let mut ca_dn = rcgen::DistinguishedName::new();
        ca_dn.push(rcgen::DnType::CommonName, "due-test fake root");
        ca_params.distinguished_name = ca_dn;
        let ca_cert = ca_params.self_signed(&ca_kp).expect("ca self-sign");

        let not_after = rcgen::date_time_ymd(2030, 1, 1);
        let leaf_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("leaf keypair");
        let mut leaf_params =
            rcgen::CertificateParams::new(vec!["due-test.example.org".to_string()])
                .expect("leaf params");
        let mut leaf_dn = rcgen::DistinguishedName::new();
        leaf_dn.push(rcgen::DnType::CommonName, "due-test.example.org");
        leaf_params.distinguished_name = leaf_dn;
        leaf_params.not_after = not_after;
        let leaf = leaf_params
            .signed_by(&leaf_kp, &ca_cert, &ca_kp)
            .expect("ca-sign leaf");

        (
            leaf_kp.serialize_pem(),
            leaf.pem(),
            ca_cert.pem(),
            not_after.unix_timestamp(),
        )
    }

    fn inspect_bytes(dir: &tempfile::TempDir, bytes: &[u8]) -> Inspection {
        let path = dir.path().join("full.pem");
        std::fs::write(&path, bytes).expect("write fixture");
        FileCertInspector.inspect(&path)
    }

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 24 * 3600;

    #[test]
    fn absent_selfsigned_unparseable_are_obtain_regardless_of_clock() {
        for insp in [
            Inspection::Absent,
            Inspection::Unparseable,
            Inspection::SelfSigned,
        ] {
            for clock_synced in [false, true] {
                assert_eq!(
                    decide(&insp, clock_synced, NOW, RENEW_THRESHOLD_SECS),
                    Action::Obtain,
                            
                    "{insp:?} with clock_synced={clock_synced} must be Obtain"
                );
            }
        }
    }

    #[test]
    fn real_unsynced_clock_waits() {
        let insp = Inspection::Real {
            not_after_unix: NOW + 89 * DAY,
        };
        assert_eq!(
            decide(&insp, false, NOW, RENEW_THRESHOLD_SECS),
            Action::WaitClock,
                    
            "a Real cert on an unsynced clock defers, never mis-decides"
        );
    }

    #[test]
    fn real_healthy_is_idle() {
        let insp = Inspection::Real {
            not_after_unix: NOW + 89 * DAY,
        };
        assert_eq!(decide(&insp, true, NOW, RENEW_THRESHOLD_SECS), Action::Idle);
    }

    #[test]
    fn real_within_window_is_obtain() {
        let insp = Inspection::Real {
            not_after_unix: NOW + 15 * DAY,
        };
        assert_eq!(
            decide(&insp, true, NOW, RENEW_THRESHOLD_SECS),
            Action::Obtain,
                    
            "15 days out is inside the 30-day window"
        );
    }

            
    /// The outage guard: an ALREADY-EXPIRED cert must be due (the
    /// signed one-sided test), never stranded Idle by an unsigned/absolute
    /// comparison. Reachable when the box was off longer than
    /// lifetime − threshold.
    #[test]
    fn expired_real_is_obtain() {
        let insp = Inspection::Real {
            not_after_unix: NOW - DAY,
        };
        assert_eq!(
            decide(&insp, true, NOW, RENEW_THRESHOLD_SECS),
            Action::Obtain
        );
    }

                      
    /// Pin the near-expiry BOUNDARY — at exactly the
    /// threshold the cert is due (spec §2.2 is one-sided ≤, not <). A future
    /// `<` weakening must fail here.
    #[test]
    fn real_at_exact_threshold_is_obtain() {
        let insp = Inspection::Real {
            not_after_unix: NOW + RENEW_THRESHOLD_SECS,
        };
        assert_eq!(
            decide(&insp, true, NOW, RENEW_THRESHOLD_SECS),
            Action::Obtain
        );
    }

    #[test]
    fn absent_when_file_missing() {
        let tmp = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            FileCertInspector.inspect(&tmp.path().join("full.pem")),
            Inspection::Absent
        );
    }

    #[test]
    fn unparseable_when_not_a_cert() {
        let tmp = tempfile::tempdir().expect("tempdir");
                                         
        assert_eq!(
            inspect_bytes(&tmp, b"not a pem at all \x00\xff"),
            Inspection::Unparseable
        );
                                                                       
                                                     
        let (key_pem, _) = self_signed_leaf();
        assert_eq!(
            inspect_bytes(&tmp, key_pem.as_bytes()),
            Inspection::Unparseable
        );
    }

    #[test]
    fn self_signed_leaf_is_selfsigned() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (key_pem, cert_pem) = self_signed_leaf();
        let full = format!("{key_pem}{cert_pem}");
        assert_eq!(inspect_bytes(&tmp, full.as_bytes()), Inspection::SelfSigned);
    }

    #[test]
    fn real_leaf_reports_not_after() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (key_pem, leaf_pem, _, not_after_unix) = ca_signed_leaf();
        let full = format!("{key_pem}{leaf_pem}");
        assert_eq!(
            inspect_bytes(&tmp, full.as_bytes()),
            Inspection::Real { not_after_unix }
        );
    }

            
    /// The leaf-only guard: a real chain whose ROOT is self-signed must
    /// classify by the LEAF (Real), never by the root (the re-issuance-loop
    /// trap the spec §2.3 names).
    #[test]
    fn real_leaf_with_selfsigned_root_in_chain_is_real() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (key_pem, leaf_pem, root_pem, not_after_unix) = ca_signed_leaf();
        let full = format!("{key_pem}{leaf_pem}{root_pem}");
        assert_eq!(
            inspect_bytes(&tmp, full.as_bytes()),
            Inspection::Real { not_after_unix }
        );
    }

                      
    /// Pin the RAW-DER Issuer==Subject compare against a
    /// CN-string weakening. Issuer and subject share the SAME CN but differ
    /// in another RDN (the issuer carries an O the leaf lacks) — the raw-DER
    /// compare says Real; a CN-only compare would misread SelfSigned and
    /// re-arm the re-issuance loop (spec §2.5's robustness rationale).
    #[test]
    fn same_cn_ca_signed_leaf_is_real_not_selfsigned() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cn = "due-test.example.org";

        let ca_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ca keypair");
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let mut ca_dn = rcgen::DistinguishedName::new();
        ca_dn.push(rcgen::DnType::CommonName, cn);
        ca_dn.push(rcgen::DnType::OrganizationName, "due-test fake org");
        ca_params.distinguished_name = ca_dn;
        let ca_cert = ca_params.self_signed(&ca_kp).expect("ca self-sign");

        let leaf_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("leaf keypair");
        let mut leaf_params =
            rcgen::CertificateParams::new(vec![cn.to_string()]).expect("leaf params");
        let mut leaf_dn = rcgen::DistinguishedName::new();
        leaf_dn.push(rcgen::DnType::CommonName, cn);
        leaf_params.distinguished_name = leaf_dn;
        let leaf = leaf_params
            .signed_by(&leaf_kp, &ca_cert, &ca_kp)
            .expect("ca-sign leaf");

        let full = format!("{}{}", leaf_kp.serialize_pem(), leaf.pem());
        assert!(
            matches!(
                inspect_bytes(&tmp, full.as_bytes()),
                Inspection::Real { .. }
            ),
            "same-CN CA-signed leaf must be Real under the raw-DER compare"
        );
    }

                      
    /// Well-formed CERTIFICATE armor around NON-DER bytes
    /// exercises the `parse_x509`-failure arm specifically ⇒ Unparseable
    /// (⇒ due) — the arm the earlier fixtures never reached.
    #[test]
    fn cert_armor_with_bad_der_is_unparseable() {
        let tmp = tempfile::tempdir().expect("tempdir");
                                                                         
        let fake =
            "-----BEGIN CERTIFICATE-----\nbm90YWNlcnRpZmljYXRlIQ==\n-----END CERTIFICATE-----\n";
        assert_eq!(
            inspect_bytes(&tmp, fake.as_bytes()),
            Inspection::Unparseable
        );
    }
}

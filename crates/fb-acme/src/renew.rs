//! `fb-acme renew`: the scheduled ACME renewal client orchestration
//! flow. Gate on clock sync → obtain a cert via the
//! [`AcmeClient`] seam → persist atomically → exponential backoff on failure.
//!
//! The orchestration is written against the [`AcmeClient`] / [`ClockSync`] /
//! [`Sleeper`] seams so it is fully unit-tested with fakes; the live
//! `instant-acme` adapter lives in [`crate::instant_client`].

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::acme::{AcmeClient, AcmeError, BackoffDecision, ClockSync, RetryClass, next_backoff};

/// Which ACME directory the renewal targets (baked into the image at build time
           
/// via `--acme-mode`). Staging avoids burning production rate limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcmeMode {
    Production,
    Staging,
}

impl AcmeMode {
    /// The Let's Encrypt directory URL for this mode.
    pub fn directory_url(self) -> &'static str {
        match self {
            AcmeMode::Production => "https://acme-v02.api.letsencrypt.org/directory",
            AcmeMode::Staging => "https://acme-staging-v02.api.letsencrypt.org/directory",
        }
    }
}

/// Inputs for one renewal run. (The ACME directory selection lives on the
/// client — [`crate::instant_client::InstantAcmeClient`] — which is what talks
/// to the directory; [`AcmeMode`] maps a CLI flag to that URL.)
#[derive(Debug, Clone)]
pub struct RenewConfig {
    /// The domain to issue for (e.g. `recipes.example.org`).
    pub domain: String,
    /// The `/persist/acme` root; per-domain material lands in `<root>/<domain>/`.
    pub persist_dir: PathBuf,
}

/// Renewal failures, classified for the backoff loop.
#[derive(Debug, thiserror::Error)]
pub enum RenewError {
    #[error("system clock not yet past the image build-epoch floor; deferring ACME issuance")]
    ClockNotSynced,
    #[error("clock-sync check failed: {0}")]
    ClockCheck(String),
    #[error(transparent)]
    Acme(#[from] AcmeError),
    #[error("persisting certificate failed: {0}")]
    Persist(#[source] std::io::Error),
}

impl RenewError {
    fn retry_class(&self) -> RetryClass {
        match self {
                                                                                                 
            RenewError::ClockNotSynced | RenewError::ClockCheck(_) => RetryClass::Backoff,
            RenewError::Acme(e) => e.retry_class(),
                                                                               
                                                                           
            RenewError::Persist(_) => RetryClass::Fatal,
        }
    }
}

/// Sleep seam so the backoff loop is testable without real wall-clock waits.
#[allow(async_fn_in_trait)]
pub trait Sleeper {
    async fn sleep(&self, dur: Duration);
}

/// Production sleeper backed by the tokio timer.
pub struct TokioSleeper;

impl Sleeper for TokioSleeper {
    async fn sleep(&self, dur: Duration) {
        tokio::time::sleep(dur).await;
    }
}

/// One renewal attempt: gate on clock sync, obtain the cert, persist it.
/// Returns the path to the written `full.pem`.
pub async fn renew_once(
    client: &impl AcmeClient,
    cfg: &RenewConfig,
    clock: &impl ClockSync,
) -> Result<PathBuf, RenewError> {
    if !clock.is_synced().map_err(RenewError::ClockCheck)? {
        return Err(RenewError::ClockNotSynced);
    }
    let material = client
        .obtain_certificate(std::slice::from_ref(&cfg.domain))
        .await?;
    persist_cert(&cfg.persist_dir, &cfg.domain, &material).map_err(RenewError::Persist)
}

/// Fixed poll interval while waiting for the clock to advance past the build-epoch
/// floor (spec §753: "retries every 30s") — distinct from the ACME-error exponential
/// backoff. The box's busybox `ntpd` steps the clock; this just re-checks the floor.
             
const CLOCK_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Drive renewal with exponential backoff (spec §"ACME retry/backoff"). Retries
/// per the [`next_backoff`] schedule; bails on auth-class / persist failures.
pub async fn renew_with_backoff(
    client: &impl AcmeClient,
    cfg: &RenewConfig,
    clock: &impl ClockSync,
    sleeper: &impl Sleeper,
) -> Result<PathBuf, RenewError> {
    let mut attempt = 0u32;
    loop {
        match renew_once(client, cfg, clock).await {
            Ok(path) => return Ok(path),
                                                                                         
                                                                                          
                                                                                         
                                                                                  
            Err(RenewError::ClockNotSynced | RenewError::ClockCheck(_)) => {
                sleeper.sleep(CLOCK_POLL_INTERVAL).await;
            }
            Err(err) => match next_backoff(attempt, err.retry_class()) {
                BackoffDecision::Bail => return Err(err),
                BackoffDecision::Retry(dur) => {
                    sleeper.sleep(dur).await;
                    attempt = attempt.saturating_add(1);
                }
            },
        }
    }
}

/// One SCHEDULED renewal cycle (the daily periodic_loop path — spec §2):
/// inspect the on-disk cert locally, run the pure [`crate::due::decide`], and
/// only on [`crate::due::Action::Obtain`] enter the network-capable obtain
/// path. Returns `Ok(Some(full_pem_path))` when a cert was obtained,
/// `Ok(None)` on Idle/WaitClock.
///
/// **Local-before-network (spec §2.1, load-bearing):** `inspect` + `decide`
/// complete before `renew_with_backoff` is entered — every socket and the
/// `account.json` read live inside `obtain_certificate` (encapsulation
/// invariant; the zero-call `MockAcme` tests are the guard). Idle/WaitClock
/// cycles touch neither the network nor the account key.
///
                              
/// The decision is logged EVERY cycle (the boot-gate greps it).
pub async fn renew_scheduled(
    inspector: &impl crate::due::CertInspector,
    client: &impl AcmeClient,
    cfg: &RenewConfig,
    clock: &impl ClockSync,
    now_unix: i64,
    sleeper: &impl Sleeper,
) -> Result<Option<PathBuf>, RenewError> {
    use crate::due::{Action, Inspection, RENEW_THRESHOLD_SECS, decide};

    let insp = inspector.inspect(&cfg.persist_dir.join(&cfg.domain).join("full.pem"));
                                                                       
                                                                           
                                                                      
    let clock_synced = match clock.is_synced() {
        Ok(synced) => synced,
        Err(e) => {
            eprintln!("fb-acme renew: clock check failed ({e}); treating as unsynced");
            false
        }
    };
    match decide(&insp, clock_synced, now_unix, RENEW_THRESHOLD_SECS) {
        Action::Obtain => {
            let reason = match insp {
                Inspection::Absent => "absent",
                Inspection::Unparseable => "unparseable",
                Inspection::SelfSigned => "self-signed",
                Inspection::Real { .. } => "expiring",
            };
            println!("fb-acme renew: obtaining ({reason})");
            renew_with_backoff(client, cfg, clock, sleeper)
                .await
                .map(Some)
        }
        Action::Idle => {
            println!("fb-acme renew: cert healthy, not due; idle");
            Ok(None)
        }
        Action::WaitClock => {
            println!("fb-acme renew: clock unsynced; deferring");
            Ok(None)
        }
    }
}

/// Atomically persist the issued material to `<persist_dir>/<domain>/`:
/// `full.pem` (key ‖ chain, mode 0600 — HAProxy `crt`) + `privkey.pem`
                       
/// (mode 0600). The per-domain dir is mode 0700.
/// Returns the `full.pem` path. Writes go to a sibling temp file then rename,
/// so a crash never leaves a half-written cert HAProxy might pick up.
pub fn persist_cert(
    persist_dir: &Path,
    domain: &str,
    material: &crate::acme::CertMaterial,
) -> std::io::Result<PathBuf> {
    let dir = persist_dir.join(domain);
    std::fs::create_dir_all(&dir)?;
    set_mode(&dir, 0o700)?;

                                                                                      
                                                                                        
                                                                                 
                                                                                   
    let full_path = dir.join("full.pem");
    write_atomic_0600(
        &dir.join("privkey.pem"),
        material.private_key_pem.as_bytes(),
    )?;
    write_atomic_0600(&full_path, material.full_pem().as_bytes())?;
    Ok(full_path)
}

/// Write `contents` to `path` atomically at mode 0600: stage a sibling temp via
/// the hardened [`open_fresh_0600`], write, fsync, rename over `path`.
fn write_atomic_0600(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
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
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Open `path` as a FRESH inode at mode 0600 — `create_new` + `O_NOFOLLOW` (unix)
/// so a pre-planted symlink/file at `path` can't redirect the write/chmod through
/// to another file; on a stale leftover, unlink-and-retry once. Shared by the
/// cert-file writes here + the `account.json` write in [`crate::instant_client`]
                          
/// (mirrors recipes-admin's keys.rs hardened temp open).
pub(crate) fn open_fresh_0600(path: &Path) -> std::io::Result<std::fs::File> {
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
    use crate::acme::CertMaterial;
    use std::cell::RefCell;

    fn material() -> CertMaterial {
        CertMaterial {
            private_key_pem: "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----".into(),
            certificate_chain_pem: "-----BEGIN CERTIFICATE-----\nCRT\n-----END CERTIFICATE-----"
                .into(),
        }
    }

    /// Stateful fake: yields the configured results in sequence (Ok = success).
    struct MockAcme {
        results: RefCell<Vec<Result<CertMaterial, AcmeError>>>,
        calls: RefCell<u32>,
    }
    impl MockAcme {
        fn new(results: Vec<Result<CertMaterial, AcmeError>>) -> Self {
            Self {
                results: RefCell::new(results),
                calls: RefCell::new(0),
            }
        }
    }
    impl AcmeClient for MockAcme {
        async fn obtain_certificate(&self, _d: &[String]) -> Result<CertMaterial, AcmeError> {
            *self.calls.borrow_mut() += 1;
            if self.results.borrow().is_empty() {
                return Err(AcmeError::Other("mock exhausted".into()));
            }
            self.results.borrow_mut().remove(0)
        }
    }

    struct FakeClock(bool);
    impl ClockSync for FakeClock {
        fn is_synced(&self) -> Result<bool, String> {
            Ok(self.0)
        }
    }

    /// Records the requested sleep durations instead of sleeping.
    struct RecordingSleeper(RefCell<Vec<Duration>>);
    impl Sleeper for RecordingSleeper {
        async fn sleep(&self, dur: Duration) {
            self.0.borrow_mut().push(dur);
        }
    }

    fn cfg(persist: &Path) -> RenewConfig {
        RenewConfig {
            domain: "recipes.example.org".into(),
            persist_dir: persist.to_path_buf(),
        }
    }

    #[tokio::test]
    async fn renew_once_persists_full_pem_to_expected_path() {
        let tmp = tempfile::tempdir().unwrap();
        let client = MockAcme::new(vec![Ok(material())]);
        let path = renew_once(&client, &cfg(tmp.path()), &FakeClock(true))
            .await
            .unwrap();

        let expected = tmp.path().join("recipes.example.org").join("full.pem");
        assert_eq!(path, expected);
        let written = std::fs::read_to_string(&expected).unwrap();
        assert!(written.contains("PRIVATE KEY") && written.contains("CERTIFICATE"));
        assert!(
            tmp.path()
                .join("recipes.example.org")
                .join("privkey.pem")
                .exists()
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn persisted_files_are_0600_in_a_0700_dir() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
        let client = MockAcme::new(vec![Ok(material())]);
        renew_once(&client, &cfg(tmp.path()), &FakeClock(true))
            .await
            .unwrap();
        let domain_dir = tmp.path().join("recipes.example.org");
        let dir_mode = std::fs::metadata(&domain_dir).unwrap().permissions().mode() & 0o777;
        let full_mode = std::fs::metadata(domain_dir.join("full.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let key_mode = std::fs::metadata(domain_dir.join("privkey.pem"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "per-domain dir is 0700");
        assert_eq!(full_mode, 0o600, "full.pem is 0600");
        assert_eq!(key_mode, 0o600, "privkey.pem is 0600");
    }

    #[tokio::test]
    async fn renew_once_defers_when_clock_unsynced() {
        let tmp = tempfile::tempdir().unwrap();
        let client = MockAcme::new(vec![Ok(material())]);
        let err = renew_once(&client, &cfg(tmp.path()), &FakeClock(false))
            .await
            .unwrap_err();
        assert!(matches!(err, RenewError::ClockNotSynced));
                                                                           
        assert_eq!(*client.calls.borrow(), 0);
        assert!(!tmp.path().join("recipes.example.org").exists());
    }

    #[tokio::test]
    async fn backoff_retries_then_succeeds() {
        let tmp = tempfile::tempdir().unwrap();
        let client = MockAcme::new(vec![
            Err(AcmeError::Network("dns".into())),
            Err(AcmeError::Network("timeout".into())),
            Ok(material()),
        ]);
        let sleeper = RecordingSleeper(RefCell::new(Vec::new()));
        let path = renew_with_backoff(&client, &cfg(tmp.path()), &FakeClock(true), &sleeper)
            .await
            .unwrap();
        assert!(path.exists());
        assert_eq!(*client.calls.borrow(), 3, "two failures then success");
                                                
        assert_eq!(
            *sleeper.0.borrow(),
            vec![Duration::from_secs(300), Duration::from_secs(600)]
        );
    }

    #[tokio::test]
    async fn backoff_bails_on_account_error() {
        let tmp = tempfile::tempdir().unwrap();
        let client = MockAcme::new(vec![Err(AcmeError::Account("bad account key".into()))]);
        let sleeper = RecordingSleeper(RefCell::new(Vec::new()));
        let err = renew_with_backoff(&client, &cfg(tmp.path()), &FakeClock(true), &sleeper)
            .await
            .unwrap_err();
        assert!(matches!(err, RenewError::Acme(AcmeError::Account(_))));
        assert_eq!(*client.calls.borrow(), 1, "auth failures are not retried");
        assert!(sleeper.0.borrow().is_empty(), "no sleep before bailing");
    }

    #[tokio::test]
    async fn clock_unsynced_polls_at_fixed_30s_not_exponential() {
                                                                                           
                                                                                       
        struct CountingClock {
            calls: RefCell<u32>,
            synced_from: u32,
        }
        impl ClockSync for CountingClock {
            fn is_synced(&self) -> Result<bool, String> {
                let mut n = self.calls.borrow_mut();
                let synced = *n >= self.synced_from;
                *n += 1;
                Ok(synced)
            }
        }
        let tmp = tempfile::tempdir().unwrap();
        let client = MockAcme::new(vec![Ok(material())]);
        let sleeper = RecordingSleeper(RefCell::new(Vec::new()));
                                                                 
        let clock = CountingClock {
            calls: RefCell::new(0),
            synced_from: 2,
        };
        let path = renew_with_backoff(&client, &cfg(tmp.path()), &clock, &sleeper)
            .await
            .unwrap();
        assert!(path.exists());
        assert_eq!(
            *sleeper.0.borrow(),
            vec![Duration::from_secs(30), Duration::from_secs(30)],
            "clock-wait polls a fixed 30s, NOT 5min/10min exponential"
        );
        assert_eq!(
            *client.calls.borrow(),
            1,
            "ACME client called only once the clock synced (gate held twice, no attempt burn)"
        );
    }

    #[test]
    fn directory_urls_match_mode() {
        assert!(AcmeMode::Production.directory_url().contains("acme-v02"));
        assert!(AcmeMode::Staging.directory_url().contains("staging"));
    }

    /// Fixed-outcome inspector stub for the scheduled path (the due-check's
    /// own parse is covered by `due::tests`; here we drive the decision).
    struct StubInspector(crate::due::Inspection);
    impl crate::due::CertInspector for StubInspector {
        fn inspect(&self, _full_pem_path: &Path) -> crate::due::Inspection {
            self.0
        }
    }

    const NOW: i64 = 1_800_000_000;

                   
    /// The load-bearing zero-call guard: a healthy far-from-expiry
    /// cert makes the scheduled cycle Idle with the ACME client NEVER
    /// constructed into action — no order, no egress, no account-key touch
    /// (sufficient proxy under the spec §2.1 encapsulation invariant).
    #[tokio::test]
    async fn scheduled_run_skips_obtain_when_not_due() {
        let tmp = tempfile::tempdir().unwrap();
        let client = MockAcme::new(vec![Ok(material())]);
        let sleeper = RecordingSleeper(RefCell::new(Vec::new()));
        let inspector = StubInspector(crate::due::Inspection::Real {
            not_after_unix: NOW + 89 * 24 * 3600,
        });
        let outcome = renew_scheduled(
            &inspector,
            &client,
            &cfg(tmp.path()),
            &FakeClock(true),
            NOW,
            &sleeper,
        )
        .await
        .unwrap();
        assert_eq!(outcome, None, "Idle: nothing obtained, nothing written");
        assert_eq!(
            *client.calls.borrow(),
            0,
                    
            "obtain_certificate must NOT be called on the Idle path"
        );
        assert!(sleeper.0.borrow().is_empty(), "no backoff entered");
    }

            
    /// The WaitClock arm: a Real cert on an unsynced clock defers — again
    /// with zero client calls (never a mis-decided order on a bogus clock).
    #[tokio::test]
    async fn scheduled_run_defers_on_unsynced_clock() {
        let tmp = tempfile::tempdir().unwrap();
        let client = MockAcme::new(vec![Ok(material())]);
        let sleeper = RecordingSleeper(RefCell::new(Vec::new()));
        let inspector = StubInspector(crate::due::Inspection::Real {
            not_after_unix: NOW + 89 * 24 * 3600,
        });
        let outcome = renew_scheduled(
            &inspector,
            &client,
            &cfg(tmp.path()),
            &FakeClock(false),
            NOW,
            &sleeper,
        )
        .await
        .unwrap();
        assert_eq!(outcome, None);
        assert_eq!(
            *client.calls.borrow(),
            0,
                    
            "obtain_certificate must NOT be called on the WaitClock path"
        );
    }

            
    /// The bootstrap replacement: a self-signed leaf is due
    /// immediately; the scheduled cycle runs the real obtain path exactly once.
    #[tokio::test]
    async fn scheduled_run_obtains_when_selfsigned() {
        let tmp = tempfile::tempdir().unwrap();
        let client = MockAcme::new(vec![Ok(material())]);
        let sleeper = RecordingSleeper(RefCell::new(Vec::new()));
        let inspector = StubInspector(crate::due::Inspection::SelfSigned);
        let outcome = renew_scheduled(
            &inspector,
            &client,
            &cfg(tmp.path()),
            &FakeClock(true),
            NOW,
            &sleeper,
        )
        .await
        .unwrap();
        let written = outcome.expect("Obtain path persists and returns the path");
        assert!(written.exists());
        assert_eq!(
            *client.calls.borrow(),
            1,
            "exactly one order for the bootstrap replacement"
        );
    }

                                        
    /// Pin the THRESHOLD the seam passes to `decide` (the mutant:
    /// the const guard protects the const's value, not that `renew_scheduled` passes it). A Real cert
    /// just INSIDE the 30-day window is due; just OUTSIDE, idle — so a seam that passed a different
    /// threshold flips one of these.
    #[tokio::test]
    async fn scheduled_seam_passes_the_renew_threshold() {
        use crate::due::RENEW_THRESHOLD_SECS;
                                             
        let tmp = tempfile::tempdir().unwrap();
        let client = MockAcme::new(vec![Ok(material())]);
        let sleeper = RecordingSleeper(RefCell::new(Vec::new()));
        let inside = StubInspector(crate::due::Inspection::Real {
            not_after_unix: NOW + RENEW_THRESHOLD_SECS - 24 * 3600,
        });
        let out = renew_scheduled(
            &inside,
            &client,
            &cfg(tmp.path()),
            &FakeClock(true),
            NOW,
            &sleeper,
        )
        .await
        .unwrap();
        assert!(
            out.is_some() && *client.calls.borrow() == 1,
            "29d-out cert is due"
        );
                                              
        let tmp2 = tempfile::tempdir().unwrap();
        let client2 = MockAcme::new(vec![Ok(material())]);
        let sleeper2 = RecordingSleeper(RefCell::new(Vec::new()));
        let outside = StubInspector(crate::due::Inspection::Real {
            not_after_unix: NOW + RENEW_THRESHOLD_SECS + 24 * 3600,
        });
        let out2 = renew_scheduled(
            &outside,
            &client2,
            &cfg(tmp2.path()),
            &FakeClock(true),
            NOW,
            &sleeper2,
        )
        .await
        .unwrap();
        assert!(
            out2.is_none() && *client2.calls.borrow() == 0,
            "31d-out cert idles"
        );
    }

                                      
    /// A unit mirror of the boot-gate Idle leg using the REAL
    /// `FileCertInspector`: a healthy far-expiry Real cert at `<persist>/<domain>/full.pem` idles with
    /// zero orders. Pins the inspect PATH (the N1 mutant: dropping the domain from the join reads the
    /// wrong file ⇒ Absent ⇒ Obtain) at unit level, not solely via the boot-gate.
    #[tokio::test]
    async fn scheduled_real_far_cert_at_the_path_idles() {
        let tmp = tempfile::tempdir().unwrap();
        let c = cfg(tmp.path());
                                                                                                           
                                  
        let ca_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let mut ca_dn = rcgen::DistinguishedName::new();
        ca_dn.push(rcgen::DnType::CommonName, "seam-test fake root");
        ca_params.distinguished_name = ca_dn;
        let ca = ca_params.self_signed(&ca_kp).unwrap();
        let leaf_kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut leaf_params = rcgen::CertificateParams::new(vec![c.domain.clone()]).unwrap();
        let mut leaf_dn = rcgen::DistinguishedName::new();
        leaf_dn.push(rcgen::DnType::CommonName, c.domain.clone());
        leaf_params.distinguished_name = leaf_dn;
        leaf_params.not_after = rcgen::date_time_ymd(2035, 1, 1);                               
        let leaf = leaf_params.signed_by(&leaf_kp, &ca, &ca_kp).unwrap();
        let dir = c.persist_dir.join(&c.domain);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("full.pem"),
            format!("{}{}", leaf_kp.serialize_pem(), leaf.pem()),
        )
        .unwrap();

        let client = MockAcme::new(vec![Ok(material())]);
        let sleeper = RecordingSleeper(RefCell::new(Vec::new()));
        let out = renew_scheduled(
            &crate::due::FileCertInspector,
            &client,
            &c,
            &FakeClock(true),
            NOW,
            &sleeper,
        )
        .await
        .unwrap();
        assert_eq!(out, None, "healthy far cert at the real path ⇒ Idle");
        assert_eq!(
            *client.calls.borrow(),
            0,
                     
            "zero orders (the re-issuance loop is dead; unit mirror)"
        );
    }
}

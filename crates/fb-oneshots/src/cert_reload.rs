//! `fb-oneshots cert-reload-check` core — the HAProxy cert-reload watcher
//! (watcher spec `2026-07-17-haproxy-cert-reload-design.md` §4).
//!
//! One pure decision — [`decide`]: reload when a cert is present and the
//! marker (the last-SIGNALLED hash, on `/run` tmpfs) is absent or different;
//! noop otherwise. Marker-absent ⇒ **reload-on-Init** (spec §4.2, the F-1
//! fold): the first cycle after boot reloads rather than silently baselining,
//! closing the boot-race where fb-acme's real-cert write lands between
//! HAProxy's start-time read and the watcher's first poll.
//!
//! Three injected seams keep the core host-unit-testable without root/s6/
//! HAProxy: [`CertReader`] (hardened hash of the cert file), [`Marker`]
//! (last-signalled hash), [`Signaller`] (the actual `s6-svc -2`). The
//! production reader is hardened (spec §4.1 F-3): the ROOT process reads a
//! path whose uid-101-owned parent chain it does not fully trust, so it must
//! not block on a planted FIFO (`O_NONBLOCK` — a plain read-open of a
//! writerless FIFO blocks forever, wedging the loop), hashes only a regular
//! file (`fstat` → `S_ISREG`), bounds the bytes read, and refuses a
//! final-component symlink (`O_NOFOLLOW`). (The intermediate `<domain>` dir
//! is uid-101-owned and CAN be redirected — that grants nothing beyond the
//! F-6-accepted bounded reload; see the `HardenedCertReader::hash` open
//! block and spec §4.1 for the traced no-escalation argument.)

use std::path::Path;

/// What one watcher cycle should do (spec §4.2 two-state machine).
/// `Reload` carries the current cert hash so the caller can advance the
/// marker after a successful signal without re-reading (and without any
/// unwrap — this crate denies `clippy::unwrap_used`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Cert present and (marker absent | hash changed) — signal HAProxy.
    Reload(String),
    /// Steady state, or no cert to serve — nothing to do.
    Noop,
}

/// The pure reload decision over `(current cert hash, marker hash)`.
pub fn decide(current: Option<&str>, marker: Option<&str>) -> Action {
    match (current, marker) {
        (Some(cur), Some(seen)) if cur == seen => Action::Noop,
                                                                                
                                                                          
        (Some(cur), _) => Action::Reload(cur.to_string()),
                                                                               
                                                                   
        (None, _) => Action::Noop,
    }
}

/// Seam: cert path → `Some(content-hash-hex)`, or `None` for
/// absent/non-regular/unreadable (all treated as "nothing to reload").
pub trait CertReader {
    fn hash(&self, path: &Path) -> Option<String>;
}

/// Seam: the last-signalled hash at `/run/fb-cert-reload.marker`.
pub trait Marker {
    fn read(&self) -> Option<String>;
    fn write(&self, hash: &str) -> std::io::Result<()>;
}

/// Seam: deliver the reload (production: `s6-svc -2 /run/service/haproxy`).
pub trait Signaller {
    fn reload(&self) -> std::io::Result<()>;
}

/// Production [`CertReader`]: `O_NOFOLLOW | O_NONBLOCK` open, regular-file
/// only, bounded read, SHA-256 lowercase hex (spec §4.1/§4.3 — ≥64-bit
/// collision floor via an already-linked hasher; change-detection only,
/// not security-critical).
pub struct HardenedCertReader;

/// Bound on the bytes hashed — a real `full.pem` is a few KiB; a planted
/// giant file must not stall the root reader (spec §4.1 F-3). Beyond the
/// cap the hash is PREFIX-exact (two >1 MiB files sharing a 1 MiB prefix
             
/// hash equal): fine for real certs and for the bounded
/// reload-attempts-only power an oversized adversarial file could exercise.
const MAX_CERT_BYTES: u64 = 1024 * 1024;

impl CertReader for HardenedCertReader {
    fn hash(&self, path: &Path) -> Option<String> {
        use sha2::Digest as _;
        use std::io::Read as _;

        let mut opts = std::fs::OpenOptions::new();
        opts.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
                                                                  
                                                                               
                                                                       
                                                                              
                                                                         
                                                                               
                                                                        
                                                                            
                                                                         
                                                                            
                                                                            
                                                                           
                                                                            
            opts.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
                                                                             
        let mut file = opts.open(path).ok()?;

                                                                             
                                                                            
                                                                           
                                                                           
                                                                            
                                                                        
                                                    
        let meta = file.metadata().ok()?;
        if !meta.file_type().is_file() {
            return None;
        }

        let mut hasher = sha2::Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        let mut remaining = MAX_CERT_BYTES;
        while remaining > 0 {
            let want = buf.len().min(remaining as usize);
            match file.read(&mut buf[..want]) {
                Ok(0) => break,
                Ok(n) => {
                    hasher.update(&buf[..n]);
                    remaining -= n as u64;
                }
                                                                              
                Err(_) => return None,
            }
        }
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(64);
        for byte in digest {
            use std::fmt::Write as _;
                                                                        
                                         
            let _ = write!(hex, "{byte:02x}");
        }
        Some(hex)
    }
}

/// The marker file: the last-SIGNALLED cert hash, root-owned, directly under
/// `/run` (a box-init tmpfs — absent on every boot's first cycle, which is
/// exactly what makes reload-on-Init fire; spec §4.1).
pub const MARKER_PATH: &str = "/run/fb-cert-reload.marker";

/// The reload target — a FIXED constant, never rendered/tenant argv (spec
/// §4.1): the watcher's only power is SIGUSR2 to THIS service.
pub const HAPROXY_SERVICE_DIR: &str = "/run/service/haproxy";

/// One watcher cycle: hash the cert, decide, and on [`Action::Reload`] signal
/// HAProxy then advance the marker — **marker only after signal success**
                     
/// (fail-closed: a failed signal leaves the marker behind so
/// the next cycle retries). Logs the hash transition on Reload (fired or
/// signal-failed); quiet on Noop (spec §4.7 F-2 — no 10 s steady-state churn).
pub fn run(
    reader: &impl CertReader,
    marker: &impl Marker,
    signaller: &impl Signaller,
    cert_path: &Path,
) -> std::io::Result<Action> {
    let current = reader.hash(cert_path);
    let last = marker.read();
    match decide(current.as_deref(), last.as_deref()) {
        Action::Reload(hash) => {
            let old = last.as_deref().unwrap_or("(init)");
            if let Err(e) = signaller.reload() {
                eprintln!(
                    "fb-oneshots cert-reload-check: reload signal FAILED ({e}); \
                     marker not advanced ({old} -> {hash} pending); retrying next cycle"
                );
                return Err(e);
            }
                                                                              
                                                                          
                                                  
            marker.write(&hash)?;
            println!("fb-oneshots cert-reload-check: reloaded haproxy: {old} -> {hash}");
            Ok(Action::Reload(hash))
        }
        Action::Noop => Ok(Action::Noop),
    }
}

/// Production [`Marker`]: the last-signalled hash at [`MARKER_PATH`], written
/// atomically at mode 0600 via the shared hardened temp+fsync+rename pattern
/// (spec §4.1 — root-owned; the content is a public-cert hash, no secret).
pub struct FileMarker(pub std::path::PathBuf);

impl Marker for FileMarker {
    fn read(&self) -> Option<String> {
        let s = std::fs::read_to_string(&self.0).ok()?;
        let s = s.trim();
                                                                            
                                                                      
        if s.is_empty() {
            None
        } else {
            Some(s.to_string())
        }
    }

    fn write(&self, hash: &str) -> std::io::Result<()> {
        crate::selfsign::write_atomic_0600(&self.0, hash.as_bytes())
    }
}

/// Production [`Signaller`]: `s6-svc -2 <haproxy servicedir>` — s6-supervise
/// delivers SIGUSR2 to the HAProxy master, which re-execs itself keeping its
/// PID (the verified hitless reload; spec §2). Bare binary name per the
/// box-init `Command::new("s6-svscan")` precedent (PATH is the signed image's).
pub struct S6Signaller;

impl Signaller for S6Signaller {
    fn reload(&self) -> std::io::Result<()> {
        let status = std::process::Command::new("s6-svc")
            .args(["-2", HAPROXY_SERVICE_DIR])
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other(format!(
                "s6-svc -2 {HAPROXY_SERVICE_DIR} exited {status}"
            )))
        }
    }
}

/// Entry point for the `cert-reload-check` subcommand: re-validate the domain
/// at the sink (defense-in-depth, spec §4.8 — same `valid_acme_domain` the
/// selfsign oneshot uses; `<domain>` is a path segment), build the cert path,
/// and run one hardened check-and-maybe-signal cycle.
pub fn cert_reload_check(
    persist_dir: &Path,
    domain: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if !crate::selfsign::valid_acme_domain(domain) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid --domain {domain:?}: not an RFC-1123 hostname"),
        )
        .into());
    }
    let cert_path = persist_dir.join(domain).join("full.pem");
    run(
        &HardenedCertReader,
        &FileMarker(std::path::PathBuf::from(MARKER_PATH)),
        &S6Signaller,
        &cert_path,
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    struct FakeReader(Option<String>);
    impl CertReader for FakeReader {
        fn hash(&self, _path: &Path) -> Option<String> {
            self.0.clone()
        }
    }

    struct FakeMarker(RefCell<Option<String>>);
    impl Marker for FakeMarker {
        fn read(&self) -> Option<String> {
            self.0.borrow().clone()
        }
        fn write(&self, hash: &str) -> std::io::Result<()> {
            *self.0.borrow_mut() = Some(hash.to_string());
            Ok(())
        }
    }

    struct FakeSignaller {
        calls: Cell<u32>,
        fail: bool,
    }
    impl FakeSignaller {
        fn ok() -> Self {
            Self {
                calls: Cell::new(0),
                fail: false,
            }
        }
        fn failing() -> Self {
            Self {
                calls: Cell::new(0),
                fail: true,
            }
        }
    }
    impl Signaller for FakeSignaller {
        fn reload(&self) -> std::io::Result<()> {
            self.calls.set(self.calls.get() + 1);
            if self.fail {
                Err(std::io::Error::other("control FIFO absent"))
            } else {
                Ok(())
            }
        }
    }

    fn cert_path() -> std::path::PathBuf {
        std::path::PathBuf::from("/persist/acme/box.test/full.pem")
    }

    #[test]
    fn run_reloads_and_advances_marker_on_change() {
        let reader = FakeReader(Some("h2".into()));
        let marker = FakeMarker(RefCell::new(Some("h1".into())));
        let sig = FakeSignaller::ok();
        let action = run(&reader, &marker, &sig, &cert_path()).expect("run ok");
        assert_eq!(action, Action::Reload("h2".into()));
                
        assert_eq!(sig.calls.get(), 1, "exactly one reload");
        assert_eq!(marker.read().as_deref(), Some("h2"), "marker advanced");
    }

    #[test]
    fn run_noop_leaves_marker() {
        let reader = FakeReader(Some("h1".into()));
        let marker = FakeMarker(RefCell::new(Some("h1".into())));
        let sig = FakeSignaller::ok();
        let action = run(&reader, &marker, &sig, &cert_path()).expect("run ok");
        assert_eq!(action, Action::Noop);
                
        assert_eq!(sig.calls.get(), 0, "steady state: no signal");
        assert_eq!(marker.read().as_deref(), Some("h1"), "marker untouched");
    }

            
    /// Fail-closed: a failed signal (control FIFO absent, very early
    /// boot) must NOT advance the marker, so the next cycle retries.
    #[test]
    fn run_does_not_advance_marker_on_signal_failure() {
        let reader = FakeReader(Some("h2".into()));
        let marker = FakeMarker(RefCell::new(Some("h1".into())));
        let sig = FakeSignaller::failing();
        let err = run(&reader, &marker, &sig, &cert_path());
        assert!(err.is_err(), "signal failure surfaces as an error");
        assert_eq!(sig.calls.get(), 1);
        assert_eq!(
            marker.read().as_deref(),
            Some("h1"),
                    
            "marker NOT advanced on signal failure"
        );
    }

    /// Reload-on-Init at the run() level: marker absent (fresh boot tmpfs)
    /// with a cert present ⇒ reload + marker initialized.
    #[test]
    fn run_reloads_on_marker_absent() {
        let reader = FakeReader(Some("h1".into()));
        let marker = FakeMarker(RefCell::new(None));
        let sig = FakeSignaller::ok();
        let action = run(&reader, &marker, &sig, &cert_path()).expect("run ok");
        assert_eq!(action, Action::Reload("h1".into()));
                       
        assert_eq!(sig.calls.get(), 1, "reload-on-Init fires");
        assert_eq!(marker.read().as_deref(), Some("h1"));
    }

    #[test]
    fn run_absent_cert_is_noop() {
        let reader = FakeReader(None);
        let marker = FakeMarker(RefCell::new(Some("h1".into())));
        let sig = FakeSignaller::ok();
        let action = run(&reader, &marker, &sig, &cert_path()).expect("run ok");
        assert_eq!(action, Action::Noop);
        assert_eq!(sig.calls.get(), 0);
        assert_eq!(marker.read().as_deref(), Some("h1"), "marker unchanged");
    }

    /// FileMarker round-trip: atomic write then read-back, no temp leftover.
    #[test]
    fn file_marker_roundtrip_atomic() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("marker");
        let m = FileMarker(path.clone());
        assert_eq!(m.read(), None, "absent marker reads None");
        m.write("aabbcc").expect("write");
        assert_eq!(m.read().as_deref(), Some("aabbcc"));
        m.write("ddeeff").expect("rewrite");
        assert_eq!(m.read().as_deref(), Some("ddeeff"));
        assert!(
            !tmp.path().join(".marker.tmp").exists(),
            "no temp leftover (atomic rename)"
        );
    }

    #[test]
    fn decide_marker_absent_is_reload() {
                                                                             
                                    
        assert_eq!(
            decide(Some("h1"), None),
            Action::Reload("h1".to_string()),
            "marker-absent must reload, not baseline (F-1)"
        );
    }

    #[test]
    fn decide_changed_is_reload() {
        assert_eq!(
            decide(Some("h2"), Some("h1")),
            Action::Reload("h2".to_string())
        );
    }

    #[test]
    fn decide_same_is_noop() {
        assert_eq!(decide(Some("h1"), Some("h1")), Action::Noop);
    }

    #[test]
    fn decide_absent_cert_is_noop() {
        assert_eq!(decide(None, None), Action::Noop);
        assert_eq!(decide(None, Some("h1")), Action::Noop);
    }

    #[test]
    fn hardened_reader_hashes_regular_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let p = tmp.path().join("full.pem");
        std::fs::write(&p, b"cert bytes").expect("write");
        let h1 = HardenedCertReader.hash(&p).expect("regular file hashes");
        let h2 = HardenedCertReader.hash(&p).expect("stable");
        assert_eq!(h1, h2, "same bytes, same hash");
        assert_eq!(h1.len(), 64, "sha256 lowercase hex");
        assert!(
            h1.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        );
        std::fs::write(&p, b"different bytes").expect("rewrite");
        assert_ne!(
            HardenedCertReader.hash(&p).expect("still hashes"),
            h1,
            "different bytes, different hash"
        );
    }

    #[test]
    fn hardened_reader_absent_is_none() {
        let tmp = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            HardenedCertReader.hash(&tmp.path().join("missing.pem")),
            None
        );
    }

            
    /// A symlink at the FINAL component (`full.pem`) is treated as
    /// absent — `O_NOFOLLOW` fails the open with ELOOP. (Intermediate-dir
                 
    /// symlinks are a separate, accepted case; this pins only the
    /// final-component guard the flag actually delivers.)
    #[cfg(unix)]
    #[test]
    fn hardened_reader_rejects_symlink() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let target = tmp.path().join("target");
        std::fs::write(&target, b"real bytes").expect("write target");
        let link = tmp.path().join("full.pem");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");
        assert_eq!(
            HardenedCertReader.hash(&link),
            None,
                    
            "symlink => None"
        );
    }

            
    /// The load-bearing one: a FIFO planted at the cert path must be
    /// rejected WITHOUT wedging — a plain read-open of a writerless FIFO
    /// blocks forever. The probe runs in a thread with a timeout guard so a
    /// regression fails the test instead of hanging the suite.
    #[cfg(unix)]
    #[test]
    fn hardened_reader_rejects_fifo_without_blocking() {
        use std::os::unix::ffi::OsStrExt as _;

        let tmp = tempfile::tempdir().expect("tempdir");
        let fifo = tmp.path().join("full.pem");
        let c_path = std::ffi::CString::new(fifo.as_os_str().as_bytes()).expect("cstring");
                                                                    
        let rc = unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo");

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(HardenedCertReader.hash(&fifo));
        });
        match rx.recv_timeout(std::time::Duration::from_secs(5)) {
                    
            Ok(result) => assert_eq!(result, None, "FIFO => None"),
            Err(_) => panic!("reader BLOCKED on the FIFO — the O_NONBLOCK hardening is gone"),
        }
    }

    /// A directory at the cert path is non-regular ⇒ None (open of a dir
    /// succeeds read-only on Linux; the fstat S_ISREG check must reject it).
    #[cfg(unix)]
    #[test]
    fn hardened_reader_rejects_directory() {
        let tmp = tempfile::tempdir().expect("tempdir");
        assert_eq!(HardenedCertReader.hash(tmp.path()), None);
    }

                      
    /// ISOLATES the S_ISREG guard: /dev/null opens fine
    /// read-only and reads as instant EOF, so WITHOUT the guard the reader
    /// would return Some(sha256-of-empty); the guard alone maps a readable
    /// char device to None. (Dir/FIFO rejections are backstopped by read
    /// errors — this is the case only the guard catches.)
    #[cfg(unix)]
    #[test]
    fn hardened_reader_rejects_char_device() {
        assert_eq!(
            HardenedCertReader.hash(Path::new("/dev/null")),
            None,
            "a readable char device must be rejected by S_ISREG, not hashed as empty"
        );
    }

                     
    /// Pin the §4.8 sink-side domain re-validation in
    /// `cert_reload_check`: a traversal/bad `--domain` is rejected BEFORE the
    /// cert path is built (mirrors selfsign's `selfsign_rejects_bad_domain`).
    /// Deleting the `valid_acme_domain` guard leaves the rest of the suite
    /// green — this is the only test that fires on it.
    #[test]
    fn cert_reload_check_rejects_bad_domain() {
        let tmp = tempfile::tempdir().expect("tempdir");
        for bad in ["../escape", "a/b", "", "has space", "x\nbind"] {
            assert!(
                cert_reload_check(tmp.path(), bad).is_err(),
                "cert-reload-check must reject the bad domain {bad:?} at the sink"
            );
        }
    }
}

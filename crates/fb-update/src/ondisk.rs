//! The two on-disk write primitives (spec §4e arm + §5 e2fsck-gated rw mount) — the
//! syscall-touching half of the ADV engine + the boot-fs integrity gate.
//!
//! 1. The ADV arm/reclear, a faithful port of `advio.c::write_adv` (pinned syslinux):
//!    read the trailing `2×ADV_SIZE`, transform (T10 pure `set`/`clear`), reopen
//!    `O_RDWR|O_SYNC`, revalidate inode/dev/size (the write-race guard), pwrite BOTH
//!    copies and **CHECK the return** — the load-bearing difference from the loader's
//!    boot-time clear, which swallows its write error (the M1 residual). `sync` after.
//! 2. The `e2fsck -p` gate before every rw boot-fs mount: the exit-code BITMASK
//!    (`(rc & 0xFC) == 0 ⇒ proceed` — rc 0/1/2/3 are clean/corrected/reboot-rec, the
//!    common dirty-fs recovery; ≥4 ⇒ fail-closed), under a wall-clock timeout with a
//!    SIGKILL backstop (model box-init `prepare-persist` + `run_bounded`).

use std::io::Error as IoError;
use std::os::unix::fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;
use std::time::{Duration, Instant};

use crate::adv::{ADV_TOTAL_SIZE, clear_bootonce, set_bootonce};

/// The boot-fs fsck wall-clock bound (an fsck of the small 128 MiB boot-fs is fast; the
/// SIGKILL backstop keeps a hung scan from wedging apply). Named per box-init's
/// `FAST_TIMEOUT_SECS` precedent.
pub const FSCK_TIMEOUT_SECS: u64 = 60;

/// Why an on-disk ADV write refused. Every arm is fail-closed — the caller aborts the
/// apply (a failed arm means the update did NOT get promoted, which is safe).
#[derive(Debug)]
pub enum AdvIoError {
    /// open/fstat/read/write/sync failed.
    Io(IoError),
    /// The target is smaller than `2×ADV_SIZE` — not a valid `ldlinux.sys`.
    TooSmall,
    /// inode/dev/size changed between the read-open and the write-open — a write race
    /// (the `advio.c` `st_ino/st_dev/st_size` re-check). Refuse rather than clobber.
    Race,
    /// The `pwrite` returned fewer than `2×ADV_SIZE` bytes — a short/failed write. The
    /// loader's clear ignores this; we REFUSE (the whole point of the on-disk arm).
    ShortWrite,
    /// The pure ADV transform refused (an oversize label — cannot happen for our 6-byte
    /// slot labels, but propagated fail-closed rather than unwrapped).
    Transform(crate::adv::AdvError),
}

impl std::fmt::Display for AdvIoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdvIoError::Io(e) => write!(f, "ADV I/O: {e}"),
            AdvIoError::TooSmall => write!(f, "ADV target smaller than 2*ADV_SIZE"),
            AdvIoError::Race => write!(f, "ADV write race (inode/dev/size changed)"),
            AdvIoError::ShortWrite => write!(f, "ADV pwrite short/failed"),
            AdvIoError::Transform(e) => write!(f, "ADV transform refused: {e:?}"),
        }
    }
}

impl std::error::Error for AdvIoError {}

impl From<IoError> for AdvIoError {
    fn from(e: IoError) -> Self {
        AdvIoError::Io(e)
    }
}

/// Read the trailing `2×ADV_SIZE` of `path`, apply `transform`, and if it asks for a
/// write (`Ok(true)`) reopen `O_RDWR|O_SYNC`, revalidate inode/dev/size, pwrite BOTH
/// copies return-checked, and sync. Returns whether a write happened. The read-open
/// captures the authoritative (ino, dev, size) — we NEVER trust a caller-supplied size
/// (that would reintroduce the very TOCTOU the revalidation closes).
fn adv_rmw(
    path: &Path,
    transform: impl FnOnce(&mut [u8; ADV_TOTAL_SIZE]) -> Result<bool, crate::adv::AdvError>,
) -> Result<bool, AdvIoError> {
    let ro = std::fs::File::open(path)?;
    let meta = ro.metadata()?;
    let size = meta.len();
    if size < ADV_TOTAL_SIZE as u64 {
        return Err(AdvIoError::TooSmall);
    }
    let (ino, dev) = (meta.ino(), meta.dev());
    let adv_offset = size - ADV_TOTAL_SIZE as u64;

    let mut adv = [0u8; ADV_TOTAL_SIZE];
    ro.read_exact_at(&mut adv, adv_offset)?;
    drop(ro);

    let did = transform(&mut adv).map_err(AdvIoError::Transform)?;
    if !did {
        return Ok(false);                                                          
    }

                                                                                       
                                                                     
    let rw = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_SYNC)
        .open(path)?;
    let m2 = rw.metadata()?;
    if m2.ino() != ino || m2.dev() != dev || m2.len() != size {
        return Err(AdvIoError::Race);
    }
                                                                                   
                                                                                  
    rw.write_all_at(&adv, adv_offset)
        .map_err(|_| AdvIoError::ShortWrite)?;
    rw.sync_all()?;
    Ok(true)
}

/// ARM the BOOTONCE entry to `label` on disk (§4e): set-then-write, always writes.
pub fn arm_bootonce_on_disk(path: &Path, label: &str) -> Result<(), AdvIoError> {
    adv_rmw(path, |adv| set_bootonce(adv, label).map(|()| true)).map(|_| ())
}

/// RE-CLEAR the BOOTONCE entry on disk if present (§4e mark-good durable re-clear):
/// read-then-conditional — returns `Ok(true)` iff an entry existed and was cleared
/// (a write happened), `Ok(false)` if it was already clear (NO write performed).
pub fn reclear_bootonce_on_disk(path: &Path) -> Result<bool, AdvIoError> {
    adv_rmw(path, clear_bootonce)
}

/// Why the e2fsck gate refused. Fail-closed: the caller does NOT rw-mount the boot-fs.
#[derive(Debug, PartialEq, Eq)]
pub enum FsckError {
    /// e2fsck exited with an error bit set (`rc & 0xFC != 0`).
    Failed { code: i32 },
    /// e2fsck was SIGKILLed at the deadline (a hung scan ⇒ fail-closed).
    Timeout,
    /// e2fsck died by signal (crash — no exit code to bitmask ⇒ fail-closed, never a
    /// silent proceed).
    Signal,
    /// e2fsck could not be spawned / reaped.
    Spawn(String),
}

/// Preen-check `dev` (`e2fsck -p`) before an rw mount, under a wall-clock timeout with
/// a SIGKILL backstop. Proceeds iff `(rc & 0xFC) == 0` (the box-init `prepare-persist`
/// bitmask: rc 0/1/2/3 = clean/errors-corrected/reboot-recommended, the common
/// dirty-fs recovery; ≥4 ⇒ refuse). NOT a naive `&& mount` — that would false-divert
/// the rc=1 common recovery (audit F-4).
pub fn e2fsck_preen_gate(dev: &Path, timeout: Duration) -> Result<(), FsckError> {
    run_fsck("e2fsck", dev, timeout)
}

/// The gate core, parameterized on the program path (so a test can point at a shim by
/// absolute path without touching PATH).
fn run_fsck(program: &str, dev: &Path, timeout: Duration) -> Result<(), FsckError> {
    let mut child = std::process::Command::new(program)
        .arg("-p")
        .arg(dev)
        .spawn()
        .map_err(|e| FsckError::Spawn(e.to_string()))?;

                                                                                      
                                              
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child
            .try_wait()
            .map_err(|e| FsckError::Spawn(e.to_string()))?
        {
            Some(s) => break s,
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(FsckError::Timeout);
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    };

                                                                             
    let code = status.code().ok_or(FsckError::Signal)?;
    if code & 0xFC == 0 {
        Ok(())
    } else {
        Err(FsckError::Failed { code })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    /// Write an executable shell shim to `dir/name` and return its absolute path.
    fn shim(dir: &Path, name: &str, body: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        writeln!(f, "#!/bin/sh\n{body}").unwrap();
        let mut perm = f.metadata().unwrap().permissions();
        perm.set_mode(0o755);
        std::fs::set_permissions(&p, perm).unwrap();
        p
    }

    /// `run_fsck` against a freshly-written shim, retrying the multi-threaded fork/exec
    /// ETXTBSY race: a PARALLEL test's `Command::spawn` fork snapshots this thread's
    /// just-held shim write-fd, and until that child execs (CLOEXEC clears it) our exec
    /// of the shim fails `Text file busy`. TEST-ONLY: production `run_fsck` execs the
    /// baked `/sbin/e2fsck`, never a freshly-written file, so no production retry.
    fn run_fsck_shim(prog: &Path, timeout: Duration) -> Result<(), FsckError> {
        for _ in 0..50 {
            match run_fsck(prog.to_str().unwrap(), Path::new("/dev/whatever"), timeout) {
                Err(FsckError::Spawn(s)) if s.contains("Text file busy") => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                other => return other,
            }
        }
        panic!("shim exec stayed ETXTBSY after 50 retries");
    }

    #[test]
    fn e2fsck_bitmask_proceeds_0_to_3_diverts_on_error_bits() {
        let dir = tempfile::tempdir().unwrap();
        for (rc, ok) in [
            (0, true),
            (1, true),
            (2, true),
            (3, true),
            (4, false),
            (8, false),
            (16, false),
            (128, false),
        ] {
            let prog = shim(dir.path(), &format!("fsck{rc}"), &format!("exit {rc}"));
            let res = run_fsck_shim(&prog, Duration::from_secs(10));
            assert_eq!(res.is_ok(), ok, "rc={rc} gate ok={ok}");
            if !ok {
                assert_eq!(res, Err(FsckError::Failed { code: rc }));
            }
        }
    }

    #[test]
    fn e2fsck_timeout_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
                                                                                       
                                                                                        
                                                            
        let prog = shim(dir.path(), "fsck_hang", "exec sleep 999");
        let start = Instant::now();
        let res = run_fsck_shim(&prog, Duration::from_millis(400));
        assert_eq!(res, Err(FsckError::Timeout));
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "bounded, not blocked"
        );
    }

    #[test]
    fn e2fsck_signal_death_is_fail_closed() {
                                                                      
        let dir = tempfile::tempdir().unwrap();
        let prog = shim(dir.path(), "fsck_sig", "kill -9 $$");
        let res = run_fsck_shim(&prog, Duration::from_secs(10));
        assert_eq!(res, Err(FsckError::Signal), "signal-death is fail-closed");
    }

    #[test]
    fn e2fsck_missing_binary_is_spawn_err() {
        let res = run_fsck(
            "/nonexistent/e2fsck-xyz",
            Path::new("/dev/whatever"),
            Duration::from_secs(5),
        );
        assert!(matches!(res, Err(FsckError::Spawn(_))));
    }
}

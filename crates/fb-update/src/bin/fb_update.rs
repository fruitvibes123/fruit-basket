//! `fb-update` — the box-side A/B update applier (os-update A/B v1).
//!
//! Subcommands: `apply` (T14, verify-before-write an operator-pushed image to the
//! inactive slot + arm the one-try boot), `status` (T15), `reconcile-floors` (T16).
//! Invoked over ssh as root (the box's only login identity is the baked operator key;
//! `fb-update` is NOT a service). `apply` reads the §4c stream from stdin.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fb_update::apply::{ApplyCtx, apply};
use fb_update::selector::SeabiosGptSelector;
use fb_update::status::{StatusInputs, render_status};

/// The baked operator artifact-root pubkey on the verity rootfs (mirrors
/// initramfs-init's `ARTIFACT_ROOT_PUB`).
const ARTIFACT_ROOT_PUB: &str = "/etc/recipes/artifact-root.pub";
/// `/persist/update/` — floors + probation record + lock.
const UPDATE_DIR: &str = "/persist/update";
/// The rw mountpoint fb-update uses for the boot-fs (tmpfs `/run`).
const BOOT_MNT: &str = "/run/fb-update/boot";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("apply") => run_apply(&args[2..]),
        Some("status") => run_status(),
        Some("reconcile-floors") => run_reconcile_floors(),
        _ => {
            eprintln!("usage: fb-update <apply|status|reconcile-floors> [args]");
            ExitCode::from(2)
        }
    }
}

/// `fb-update status`: print the §4g machine-readable block to stdout. A read tool —
/// always exits 0 (a missing floor is a REPORTED field, not an abort).
fn run_status() -> ExitCode {
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let uptime_secs = std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.split('.').next()?.parse().ok())
        .unwrap_or(0);
    let inp = StatusInputs {
        cmdline,
        rootfs_etc: PathBuf::from("/etc/recipes"),
        update_dir: PathBuf::from(UPDATE_DIR),
        backup_dir: PathBuf::from("/persist/backup"),
        uptime_secs,
    };
    print!("{}", render_status(&inp));
    ExitCode::SUCCESS
}

/// `fb-update apply [--boot-dev <dev>]`: hold the update lock, assemble the box context,
/// stream+verify from stdin, and on success reboot into the armed slot. `--boot-dev` is
/// an explicit override; absent, the bin SELF-resolves the boot-fs partition by its
/// fixed GPT PARTUUID (`BOOT_FS_PARTUUID` — the ceremony ssh-execs a bare `fb-update
/// apply`, and disk enumeration is a boot-time fact). Everything else is read from the
/// running box.
fn run_apply(rest: &[String]) -> ExitCode {
    let boot_dev = match fb_update::selector::resolve_boot_dev(flag(rest, "--boot-dev")) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("fb-update apply: {e}");
            return ExitCode::from(2);
        }
    };

                                                                                         
                                                                
    let update_dir = Path::new(UPDATE_DIR);
    let _lock = match acquire_lock(update_dir) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("fb-update apply: cannot take the update lock: {e}");
            return ExitCode::from(19);
        }
    };

    let root_pubkey = match read_root_pubkey() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("fb-update apply: {e}");
            return ExitCode::from(19);
        }
    };
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let box_firmware = fb_update::cmdline::token_value(&cmdline, "fb.firmware")
        .unwrap_or("seabios")
        .to_string();
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let selector = SeabiosGptSelector {
        boot_dev,
        cmdline,
        boot_mnt: PathBuf::from(BOOT_MNT),
    };
    let ctx = ApplyCtx {
        root_pubkey: &root_pubkey,
        now_unix,
        box_firmware: &box_firmware,
        floors_dir: update_dir,
        update_dir,
    };

    let mut stdin = std::io::stdin().lock();
    match apply(&mut stdin, &selector, &ctx) {
        Ok(target) => {
            eprintln!("fb-update apply: armed {} — rebooting", target.as_str());
            reboot();
            ExitCode::SUCCESS                                     
        }
        Err(e) => {
            eprintln!("fb-update apply: refused: {e}");
            ExitCode::from(e.exit_code() as u8)
        }
    }
}

/// `fb-update reconcile-floors`: the `seed-update-floors` box-init oneshot body (§4f).
/// Runs pre-Services on EVERY boot + firmware; probation-aware; FAIL-CLOSED (any error
/// ⇒ non-zero exit ⇒ box-init `Rescue`). Reads the baked values from the verity rootfs
/// (`/etc/recipes/`) + the running slot/root_hash from `/proc/cmdline`, then reconciles.
fn run_reconcile_floors() -> ExitCode {
    let update_dir = Path::new(UPDATE_DIR);
    if let Err(e) = std::fs::create_dir_all(update_dir) {
        eprintln!("fb-update reconcile-floors: mkdir {UPDATE_DIR}: {e} → Rescue");
        return ExitCode::from(1);
    }
    let baked_version = match read_u64_file("/etc/recipes/image-version") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("fb-update reconcile-floors: {e} → Rescue");
            return ExitCode::from(1);
        }
    };
    let baked_minctr = match read_u64_file("/etc/recipes/min-delegation-ctr") {
        Ok(v) => v,
        Err(e) => {
            eprintln!("fb-update reconcile-floors: {e} → Rescue");
            return ExitCode::from(1);
        }
    };
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
                                                                                  
    let running =
        fb_update::cmdline::running_slot(&cmdline).zip(fb_update::cmdline::root_hash(&cmdline));
    match fb_update::floors::reconcile_floors(update_dir, baked_version, baked_minctr, running) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fb-update reconcile-floors: {e:?} → Rescue");
            ExitCode::from(1)
        }
    }
}

/// Read a file whose whole trimmed contents are a decimal u64.
fn read_u64_file(path: &str) -> Result<u64, String> {
    let s = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
    s.trim()
        .parse::<u64>()
        .map_err(|_| format!("{path} is not a decimal u64"))
}

/// Read + decode the 64-hex baked root pubkey. Hand-rolled hex (no `hex` crate on the
/// box graph — keeps the shipped tree + the T17 allowlist minimal).
fn read_root_pubkey() -> Result<[u8; 32], String> {
    let text = std::fs::read_to_string(ARTIFACT_ROOT_PUB)
        .map_err(|e| format!("read {ARTIFACT_ROOT_PUB}: {e}"))?;
    let hx = text.trim().as_bytes();
    if hx.len() != 64 {
        return Err("root pubkey is not 64 hex chars".to_string());
    }
    let nib = |b: u8| -> Result<u8, String> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err("root pubkey is not hex".to_string()),
        }
    };
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = (nib(hx[2 * i])? << 4) | nib(hx[2 * i + 1])?;
    }
    Ok(out)
}

/// A crude `--flag value` reader (no clap on the box).
fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// Take an exclusive `flock` on `<update_dir>/lock`, held until the returned File drops.
fn acquire_lock(update_dir: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::io::AsRawFd as _;
    std::fs::create_dir_all(update_dir)?;
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(update_dir.join("lock"))?;
                                                                                         
                        
    let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(f)
}

/// `sync` then `reboot(2)` (RB_AUTOBOOT). fb-update runs as root with CAP_SYS_BOOT
/// (T17: rendered without a uid-drop), the first non-PID-1 reboot caller.
fn reboot() {
                                                                                    
                                  
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_AUTOBOOT);
    }
}

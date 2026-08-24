//! `fb-update status` (spec §4g) — the machine-readable `key = value` block the
//! `orchard update` ceremony consumes to decide the manifest version + judge readiness.
//! A READ tool: unlike `apply`, a missing floor is REPORTED (a `*-unavailable` value +
//! `floor_health`), never a fail-closed abort. No secret material.

use std::path::{Path, PathBuf};

use crate::floors::{MINCTR_FLOOR_FILE, VERSION_FLOOR_FILE, read_floor_strict};
use crate::{Record, cmdline};

/// The box facts `render_status` reads (injected so the block logic is pure + testable;
/// the bin fills these from `/proc/cmdline`, the verity rootfs, `/persist/update`, the
/// backup dir, and `/proc/uptime`).
pub struct StatusInputs {
    /// `/proc/cmdline` (active-slot + firmware derivation).
    pub cmdline: String,
    /// The running verity rootfs `/etc/recipes/` (baked `image-version` /
    /// `min-delegation-ctr` — per-slot by construction).
    pub rootfs_etc: PathBuf,
    /// `/persist/update/` (floors + the probation record + last-failure).
    pub update_dir: PathBuf,
    /// fb-backup's artifact dir (latest mtime → `backup_age_secs`).
    pub backup_dir: PathBuf,
    /// `/proc/uptime` seconds (ntpd-convergence risk signal — R1-S-9).
    pub uptime_secs: u64,
}

/// A file's whole trimmed contents, or `None`.
fn read_trimmed(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
}

/// Seconds since the newest regular file's mtime under `dir` (the freshest backup).
fn newest_age_secs(dir: &Path) -> Option<u64> {
    let now = std::time::SystemTime::now();
    let mut newest: Option<std::time::SystemTime> = None;
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        if let Ok(m) = entry.metadata()
            && m.is_file()
            && let Ok(mtime) = m.modified()
        {
            newest = Some(newest.map_or(mtime, |n| n.max(mtime)));
        }
    }
    let mtime = newest?;
    Some(now.duration_since(mtime).map(|d| d.as_secs()).unwrap_or(0))
}

/// Render the §4g status block. Total: every field is always present (an unreadable
/// input becomes an explicit `unavailable`, never a crash or a silent omission).
pub fn render_status(inp: &StatusInputs) -> String {
    let active = cmdline::running_slot(&inp.cmdline)
        .map(|s| s.as_str().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let firmware = cmdline::token_value(&inp.cmdline, "fb.firmware")
        .unwrap_or("seabios")
        .to_string();

    let image_version = read_trimmed(&inp.rootfs_etc.join("image-version"))
        .unwrap_or_else(|| "unavailable".to_string());
    let min_delegation_ctr = read_trimmed(&inp.rootfs_etc.join("min-delegation-ctr"))
        .unwrap_or_else(|| "unavailable".to_string());

    let version_floor = read_floor_strict(&inp.update_dir.join(VERSION_FLOOR_FILE));
    let minctr_floor = read_floor_strict(&inp.update_dir.join(MINCTR_FLOOR_FILE));
    let vf = version_floor
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "unavailable".to_string());
    let mf = minctr_floor
        .map(|v| v.to_string())
        .unwrap_or_else(|_| "unavailable".to_string());
    let floor_health = match (version_floor.is_ok(), minctr_floor.is_ok()) {
        (true, true) => "ok".to_string(),
        (false, _) => "version-floor-unavailable".to_string(),
        (_, false) => "minctr-floor-unavailable".to_string(),
    };

    let probation = match std::fs::read(inp.update_dir.join("record")) {
        Ok(bytes) => match Record::parse(&bytes) {
            Ok(r) => format!(
                "candidate {} version={} ctr={} deadline={}",
                r.slot.as_str(),
                r.version,
                r.bundle_ctr,
                r.deadline_secs
            ),
            Err(_) => "malformed-record".to_string(),
        },
        Err(_) => "none".to_string(),
    };

    let last_failure =
        read_trimmed(&inp.update_dir.join("last-failure")).unwrap_or_else(|| "none".to_string());

    let backup_age = newest_age_secs(&inp.backup_dir)
        .map(|s| s.to_string())
        .unwrap_or_else(|| "unavailable".to_string());

                                                                                      
    format!(
        "active_slot = {active}\n\
         active_slot_source = /proc/cmdline fb.rootfs-dev PARTUUID\n\
         firmware = {firmware}\n\
         image_version = {image_version}\n\
         min_delegation_ctr = {min_delegation_ctr}\n\
         version_floor = {vf}\n\
         minctr_floor = {mf}\n\
         floor_health = {floor_health}\n\
         probation = {probation}\n\
         last_failure = {last_failure}\n\
         backup_age_secs = {backup_age}\n\
         uptime_secs = {}\n",
        inp.uptime_secs
    )
}

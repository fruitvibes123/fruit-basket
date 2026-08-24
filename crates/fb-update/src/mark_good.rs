//! `fb-mark-good` — the probation health-probe commit/rollback decide-core (spec §5
//! C-D), lifted from the 2026-06-22 TDD prototype (5/5 green, normative) with the R5-3
//! tightening: the record-match is slot AND byte-exact `root_hash`, not slot alone.
//!
//! The safety-critical decision is a PURE function ([`decide`]); the I/O (the ADV
//! re-clear, the TLS/cert/tenant probe, the DEFAULT patch, `reboot(2)`) are seams the
//! longrun binary owns. `commit_floors_and_clear` is the idempotent commit mutation
//! (set-not-increment floors + clear the record), safe to re-run after a crash (row 9).

use std::path::Path;

use crate::floors::{
    MINCTR_FLOOR_FILE, VERSION_FLOOR_FILE, commit_set, read_floor_strict, record_matches_running,
    write_floor_atomic,
};
use crate::{Record, Slot};

/// What fb-mark-good should do this iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// No probation record — steady state; do nothing (never re-probe a committed slot).
    Idle,
    /// A live probation, still unhealthy, within the deadline — keep waiting.
    Probe,
    /// A live probation that is healthy — commit (even past the deadline: healthy-wins).
    Commit,
    /// A live probation, unhealthy, past the deadline — roll back (reboot to DEFAULT).
    Rollback,
    /// A record exists but does NOT name the running system (slot OR root_hash mismatch
    /// — a stale record carried in by a restored `/persist`, row 21): clear it + record
    /// the failure, keep serving. NEVER commit its stale version/ctr (R5-3).
    Stale,
}

/// The pure decide (spec §5 C-D). `healthy` is the probe verdict (fail-closed AND of the
/// sub-checks); `uptime_secs` is the clock-free `/proc/uptime` (NOT a wall clock),
/// compared against the record's own `deadline_secs`.
pub fn decide(
    record: Option<&Record>,
    running: Slot,
    running_root_hash: &str,
    healthy: bool,
    uptime_secs: u64,
) -> Decision {
    let Some(record) = record else {
        return Decision::Idle;
    };
    if !record_matches_running(record, running, running_root_hash) {
        return Decision::Stale;
    }
    if healthy {
                                                                                  
                                                  
        Decision::Commit
    } else if uptime_secs >= record.deadline_secs {
        Decision::Rollback
    } else {
        Decision::Probe
    }
}

/// The idempotent commit mutation: set BOTH floors to the record's values
/// (set-not-increment — writer #2) and clear the record. Safe to re-run after a
/// crash-mid-commit (row 9): the floors converge (a re-set to the same value is a
/// no-op write) and the record clear is idempotent. The DEFAULT-slot patch (the other
/// half of commit) is the selector's job and runs BEFORE this (so a crash between them
/// re-runs both on the next iteration).
///
/// Precondition (held by construction): a Commit only fires on a record MATCHING the
/// running slot+root_hash, where the pre-Services reconcile FROZE the floors at the
/// pre-update value — so `record.value >= current` always. `commit_set`'s debug_assert
/// makes a violated precondition loud in tests/gates.
pub fn commit_floors_and_clear(update_dir: &Path, record: &Record) -> std::io::Result<()> {
    set_floor(&update_dir.join(VERSION_FLOOR_FILE), record.version)?;
    set_floor(&update_dir.join(MINCTR_FLOOR_FILE), record.bundle_ctr)?;
                                                                             
                                        
    match std::fs::remove_file(update_dir.join("record")) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Set one floor to `record_value` (set-not-increment). Reads the current floor (a
/// seeded floor is present by construction) and routes through the one durable writer.
fn set_floor(path: &Path, record_value: u64) -> std::io::Result<()> {
                                                                                   
                                                                                        
                                               
    let current = read_floor_strict(path).unwrap_or(0);
    let new = commit_set(current, record_value);
    if new != current {
        write_floor_atomic(path, new)?;
    }
    Ok(())
}

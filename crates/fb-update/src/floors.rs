//! The two anti-rollback floors (spec §4f): `version-floor` (the shipped-image serial)
//! and `minctr-floor` (the `UpdateImage` delegation counter), both under
//! `/persist/update/`. The R6 cert's convergence RESTS on this module's invariant:
//! **the floor writers are exactly two, and neither lowers a floor** —
//! [`reconcile_floor`] (`max`, with the R5-3 probation skip) and [`commit_set`]
//! (`set := record.value`, apply's guard already proved it ≥ the floor). No third
//! writer exists; on-disk writes route through [`write_floor_atomic`] so the audit
//! grep for writers has ONE primitive to chase.
//!
//! Fail-direction (R4-2): `apply` reads floors via [`read_floor_strict`] — absent OR
//! malformed is an ERROR (refuse the update), NEVER "read as 0". The `absent ⇒ 0` idiom
//! is reserved STRICTLY for the reconcile oneshot's internal genesis self-heal
//! (`stored.unwrap_or(0).max(baked) = baked`), where it can only RAISE the floor.

use std::io::Write as _;
use std::path::Path;

use crate::{Record, Slot};

/// The `/persist` update state directory (the reconcile oneshot `mkdir -p`s it, R5-4).
pub const UPDATE_DIR: &str = "/persist/update";
/// The image-serial floor file name (under [`UPDATE_DIR`]).
pub const VERSION_FLOOR_FILE: &str = "version-floor";
/// The delegation-counter floor file name (under [`UPDATE_DIR`]).
pub const MINCTR_FLOOR_FILE: &str = "minctr-floor";

/// Both floors, read together for the apply guards / status block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Floors {
    /// No accepted update may carry `manifest.version ≤` this.
    pub version_floor: u64,
    /// No accepted bundle may carry a delegation `monotonic_ctr <` this.
    pub minctr_floor: u64,
}

/// Why a strict floor read refused. Fail-closed: `apply` aborts on EITHER variant —
/// the two are distinguished only for the operator-facing message (absent says "the
/// reconcile oneshot has not seeded floors", malformed says "the floor file is
/// damaged").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloorError {
    /// The floor file does not exist (genuinely absent).
    Absent,
    /// Present but not a strict decimal u64 (or unreadable) — damaged state, refuse.
    Malformed,
}

/// APPLY's floor read (R4-2): absent ⇒ `Err(Absent)`, anything not a strict decimal
/// u64 (optionally LF-terminated) ⇒ `Err(Malformed)`. **NEVER returns a default** —
/// an attacker who can delete a floor file must gain a refusal, not a floor of 0.
pub fn read_floor_strict(path: &Path) -> Result<u64, FloorError> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(FloorError::Absent),
                                                                                    
                                                                                        
        Err(_) => return Err(FloorError::Malformed),
    };
    let s = std::str::from_utf8(&bytes).map_err(|_| FloorError::Malformed)?;
    let digits = s.strip_suffix('\n').unwrap_or(s);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(FloorError::Malformed);
    }
    digits.parse::<u64>().map_err(|_| FloorError::Malformed)
}

/// The every-boot reconcile value (writer #1, `max` — R5-3 probation-aware):
/// - `skip == false` (no matching probation record — a NORMAL boot): the floor becomes
///   `max(stored, baked)`; a genuinely-absent stored floor self-heals from the baked
///   value (`absent ⇒ 0` lives ONLY here, where it can only raise).
/// - `skip == true` (the record matches the running slot + root_hash — a PROBATION
///   boot): the running rootfs is the uncommitted CANDIDATE; maxing its baked values in
///   would advance the floor before mark-good's verdict and break the same-version
               
///   retry after a rollback. The floor stays EXACTLY `stored`.
///
/// `skip == true` requires a present stored floor by contract: the absent-floor-WITH-
/// matching-record case is the caller's R6-2 **Rescue** branch (damaged state — a
/// probation record whose floors vanished), decided BEFORE calling here. Reaching this
/// fn in that state is a caller bug, and the `expect` makes it loud.
pub fn reconcile_floor(stored: Option<u64>, baked: u64, skip: bool) -> u64 {
    if skip {
        stored.expect("caller asserts floor presence on a matching record (R6-2 Rescue branch)")
    } else {
        stored.unwrap_or(0).max(baked)
    }
}

/// Mark-good's commit value (writer #2, `set` — NOT increment, NOT max): the floor
/// becomes exactly `record_value`. Idempotent for the row-9 crash-mid-commit rerun
/// (`commit_set(v, v) == v`). Apply's guards proved `record_value` above the floors
/// when the record was written, so a regression here is a BUG — the debug_assert makes
/// it loud in every test/gate build without adding a third writer semantics in release.
pub fn commit_set(current: u64, record_value: u64) -> u64 {
    debug_assert!(
        record_value >= current,
        "commit would lower a floor ({record_value} < {current}) — apply's guard was bypassed"
    );
    record_value
}

/// Does the probation record describe the RUNNING system? True iff the record's slot
/// equals the running slot AND the record's `root_hash` equals the running cmdline's
/// `fb.root-hash` **byte-for-byte** (R6-1: both sides carry un-normalized 64-lowercase
/// hex; a case/format drift is fail-direction-safe — both outcomes are "don't touch" —
/// but must never be papered over with a case-fold). Slot-only matching is FORBIDDEN
/// (the R5 author-fix: a stale restored record naming the running slot but a different
/// root_hash must read as NOT-matching — row 21/22).
pub fn record_matches_running(
    record: &Record,
    running_slot: Slot,
    running_root_hash: &str,
) -> bool {
    record.slot == running_slot && record.root_hash == running_root_hash
}

/// Why the every-boot reconcile refused (⇒ the `seed-update-floors` oneshot exits
/// non-zero ⇒ box-init `Rescue`). Genesis + normal + probation boots all succeed; only
/// damaged state fails closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReconcileError {
    /// A floor file is present but not a strict decimal u64 (damaged).
    MalformedFloor(&'static str),
    /// A probation record matches the running system but its floor VANISHED (R6-2) — a
    /// restored/torn `/persist`. Rescue rather than let the candidate re-seed the floor.
    AbsentFloorWithMatchingRecord(&'static str),
    /// The probation record file is PRESENT but unreadable/unparseable (damaged) — a
    /// corrupted `/persist`. Rescue rather than silently treat it as "no probation" and let
    /// the running (uncommitted CANDIDATE) rootfs's baked values MAX the floor forward (the
    /// premature-advance class R5-3's skip closes; here reached via record corruption). Same
    /// fail-closed posture as [`Self::AbsentFloorWithMatchingRecord`].
    MalformedRecord,
}

/// Read a floor for RECONCILE: absent ⇒ `Ok(None)` (genesis — the non-skip branch will
/// self-heal from baked), present decimal ⇒ `Ok(Some(v))`, malformed/unreadable ⇒
/// `Err(Malformed)` (damaged ⇒ Rescue). Distinct from [`read_floor_strict`], which
/// treats absent as an error (apply's fail-closed posture).
fn read_floor_for_reconcile(path: &Path) -> Result<Option<u64>, FloorError> {
    match read_floor_strict(path) {
        Ok(v) => Ok(Some(v)),
        Err(FloorError::Absent) => Ok(None),
        Err(FloorError::Malformed) => Err(FloorError::Malformed),
    }
}

/// The every-boot, probation-aware floor reconcile (spec §4f) — the `seed-update-floors`
/// oneshot's core (in the tested lib, not shell — plan S9). `running` is the running
/// A/B `(slot, cmdline root_hash)` or `None` on a non-A/B box (MBR/UEFI-non-slot: no
/// probation possible, so it always seeds/maxes — the oneshot runs on EVERY firmware,
/// R5-2). Writes BOTH floors via the one durable writer; never lowers a floor.
///
/// `skip` is true iff a probation `record` names the running system byte-exactly
/// (slot AND root_hash — R6-1): the running rootfs is the uncommitted CANDIDATE, so its
/// baked values must NOT advance the floor (R5-3). A matching record with a vanished
/// floor is damaged state ⇒ [`ReconcileError::AbsentFloorWithMatchingRecord`] (R6-2).
pub fn reconcile_floors(
    update_dir: &Path,
    baked_version: u64,
    baked_minctr: u64,
    running: Option<(Slot, &str)>,
) -> Result<(), ReconcileError> {
                                                                                      
                                                                                          
    let record = read_record(update_dir)?;
    let skip = match (running, record) {
        (Some((slot, rh)), Some(record)) => record_matches_running(&record, slot, rh),
        _ => false,
    };
    reconcile_one(
        &update_dir.join(VERSION_FLOOR_FILE),
        baked_version,
        skip,
        VERSION_FLOOR_FILE,
    )?;
    reconcile_one(
        &update_dir.join(MINCTR_FLOOR_FILE),
        baked_minctr,
        skip,
        MINCTR_FLOOR_FILE,
    )?;
    Ok(())
}

/// Read the probation record, distinguishing ABSENT from DAMAGED: `Ok(None)` iff the file is
/// genuinely absent (`NotFound` — a normal / genesis boot, no probation), `Ok(Some)` iff it parses,
/// and `Err(MalformedRecord)` iff it is PRESENT but unreadable/unparseable (corrupted `/persist`).
/// The damaged case must NOT collapse to "no probation": that would let the running candidate's baked
/// values advance the floor (R5-3 premature-advance) — so it fails closed to Rescue, like a vanished
/// floor under a matching record (R6-2).
fn read_record(update_dir: &Path) -> Result<Option<Record>, ReconcileError> {
    match std::fs::read(update_dir.join("record")) {
        Ok(bytes) => Record::parse(&bytes)
            .map(Some)
            .map_err(|_| ReconcileError::MalformedRecord),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(ReconcileError::MalformedRecord),                                    
    }
}

/// Reconcile ONE floor: read (absent⇒genesis, malformed⇒Rescue), enforce the R6-2
/// absent-with-matching-record Rescue, compute the new value, write only when it changes.
fn reconcile_one(
    path: &Path,
    baked: u64,
    skip: bool,
    name: &'static str,
) -> Result<(), ReconcileError> {
    let stored =
        read_floor_for_reconcile(path).map_err(|_| ReconcileError::MalformedFloor(name))?;
    if skip && stored.is_none() {
        return Err(ReconcileError::AbsentFloorWithMatchingRecord(name));
    }
    let new = reconcile_floor(stored, baked, skip);
    if stored != Some(new) {
        write_floor_atomic(path, new).map_err(|_| ReconcileError::MalformedFloor(name))?;
    }
    Ok(())
}

/// Durable floor write (tmp+fsync+rename+dir-fsync — the floor is anti-rollback state;
/// a floor that evaporates on power loss re-opens the downgrade window). The ONLY
/// on-disk floor-write primitive: both writers (`reconcile`, `commit`) route through
/// here, so "no third writer" is greppable at one call site.
pub fn write_floor_atomic(path: &Path, value: u64) -> std::io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("floor path has no parent directory"))?;
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| std::io::Error::other("floor path has no utf-8 file name"))?;
    let tmp = dir.join(format!(".{file_name}.tmp"));
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(format!("{value}\n").as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

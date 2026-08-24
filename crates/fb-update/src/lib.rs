                                                                               
//! fb-update — the box-side A/B OS-update engine (os-update A/B v1).
//!
//! A firmware-agnostic engine (manifest verify via quince's clocked entry, two
//! anti-rollback floors, inactive-slot write, probation record, reboot) driving a
//! SeaBIOS-GPT `SlotSelector` (syslinux ADV boot-once + fixed-geometry
//! `extlinux.conf` field patches). Two bins: `fb-update` (apply / status /
//! reconcile-floors) and `fb-mark-good` (the probation health-probe
//! commit-or-rollback longrun).
//!
//! Module map (lands task-by-task): [`manifest`] (T8) · floors (T9) · adv (T10) ·
//! conf_patch (T11) · e2fsck + the on-disk ADV arm (T13) · stream/selector + apply
//! (T14) · mark_good (T18).
//!
                                                  
//! **Extraction note**: this lib
//! (selector + manifest + floors + ADV + conf-patch + PARTUUID resolve) is the
//! candidate for a future `SlotSelector` crate extraction when the UEFI arm (umbrella
//! C2) materializes as the SECOND consumer — extract at the second consumer, not now.

pub mod adv;
pub mod apply;
pub mod cmdline;
pub mod conf_patch;
pub mod floors;
pub mod manifest;
pub mod mark_good;
pub mod ondisk;
pub mod selector;
pub mod status;

/// The S0 clocked-verify plausibility floor (unix seconds), re-exported from quince so
/// the ceremony + tests share one constant.
pub use quince::MIN_PLAUSIBLE_CLOCK;

/// Per-slot rootfs partition size (spec §3 fixed const): 64 MiB. `apply` refuses a
/// `rootfs_size` above this before streaming a byte.
pub const SLOT_SIZE_BYTES: u64 = 64 * 1024 * 1024;
/// The kernel+initramfs boot budget within a slot's `/slot-x/` boot-fs dir (§4a): 56
/// MiB. `apply` refuses `kernel_size + initramfs_size` above this.
pub const SLOT_BOOT_BUDGET: u64 = 56 * 1024 * 1024;
/// Max update-manifest wire length (§4c) — bounded before allocation.
pub const MANIFEST_MAX_LEN: u64 = 4 * 1024;
/// The dragonfruit bundle file wire length (§4c): exactly 254 bytes.
pub const BUNDLE_LEN: u64 = 254;
/// The mark-good probation deadline seeded into each record (§5 C-D, named tunable).
pub const MARK_GOOD_DEADLINE_SECS: u64 = 300;

use std::io::Write as _;
use std::path::Path;

use crate::manifest::{ManifestError, kv_lines, parse_u64, validate_hex64_lower};

                                                                                          
                                                                                      
                                                                                        
                                               
#[cfg(feature = "sign")]
compile_error!("fb-update must never enable a `sign` feature — the box only verifies, never signs");

/// Slot A's GPT PARTUUID (spec §3 fixed const; the seabios-gpt bake pins it).
pub const SLOT_A_PARTUUID: &str = "04c92659-e47a-485b-b840-fe5561eaa0da";
/// Slot B's GPT PARTUUID (spec §3 fixed const).
pub const SLOT_B_PARTUUID: &str = "a5dff702-a9ff-41a1-9243-30e6136aba95";
/// The boot-fs partition's fixed GPT PARTUUID — a HAND-MIRROR of
/// `initramfs_init::installer::ESP_PARTUUID` (the same cross-crate mirror convention as
/// the two slot PARTUUIDs above; initramfs-init is a standalone workspace, not a dep).
/// Lets the bins SELF-resolve `--boot-dev` when the caller passes none: the `orchard
/// update` ceremony ssh-execs a bare `fb-update apply`, and the fb-mark-good longrun is
/// rendered without a device literal (a baked `/dev/vdaN` would be wrong on a
/// differently-enumerated disk — sda/nvme).
pub const BOOT_FS_PARTUUID: &str = "e9abb6ab-76cf-4b2e-aa9a-f53e2ae152dd";

/// One of the two A/B rootfs slots. The extlinux LABEL names (`slot-a`/`slot-b`), the
/// kernel dirs (`/slot-a/`, `/slot-b/`), and the fixed GPT PARTUUIDs all derive from
/// this one type so they cannot drift apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Slot {
    A,
    B,
}

impl Slot {
    /// The extlinux LABEL / boot-fs directory name.
    pub fn as_str(self) -> &'static str {
        match self {
            Slot::A => "slot-a",
            Slot::B => "slot-b",
        }
    }

    /// The slot's fixed rootfs-partition PARTUUID (spec §3).
    pub fn partuuid(self) -> &'static str {
        match self {
            Slot::A => SLOT_A_PARTUUID,
            Slot::B => SLOT_B_PARTUUID,
        }
    }

    /// The OTHER slot (the inactive target of an apply).
    pub fn other(self) -> Slot {
        match self {
            Slot::A => Slot::B,
            Slot::B => Slot::A,
        }
    }

    /// Parse a slot label (`slot-a`/`slot-b`). Anything else is `None` — callers
    /// refuse, never default (an unrecognized slot is row-3 territory).
    pub fn from_label(s: &str) -> Option<Slot> {
        match s {
            "slot-a" => Some(Slot::A),
            "slot-b" => Some(Slot::B),
            _ => None,
        }
    }
}

/// The probation record (`/persist/update/record`, spec §4f): written by `apply`
/// strictly BEFORE the ADV arm, consumed by the every-boot reconcile (probation skip)
/// and by `fb-mark-good` (the commit/rollback decide). `root_hash` carries the EXACT
/// manifest bytes (64 lowercase hex, byte-faithful — R6-1: the reconcile skip and the
/// mark-good match compare it byte-equal to the running cmdline's `fb.root-hash`,
/// no normalization on either side).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Record wire format version (1).
    pub format: u64,
    /// The slot the update was staged INTO (the armed, uncommitted candidate).
    pub slot: Slot,
    /// The manifest `version` (== the candidate's baked `image_version`).
    pub version: u64,
    /// The verified `UpdateImage` delegation `monotonic_ctr` (quince returned it).
    pub bundle_ctr: u64,
    /// The candidate's dm-verity root hash — exact manifest bytes (64 lowercase hex).
    pub root_hash: String,
    /// The mark-good probe deadline, in PROBATION-BOOT uptime seconds (clock-free:
    /// compared against `/proc/uptime`, never a wall clock).
    pub deadline_secs: u64,
}

/// The record's exact key set, wire order.
const RECORD_KEYS: [&str; 6] = [
    "format",
    "slot",
    "version",
    "bundle_ctr",
    "root_hash",
    "deadline_secs",
];

impl Record {
    /// Canonical serialization: `key = value`, LF, wire order — the same kv discipline
    /// as the §4a manifest (shared vocabulary, [`ManifestError`]).
    pub fn to_bytes(&self) -> Vec<u8> {
        format!(
            "format = {}\n\
             slot = {}\n\
             version = {}\n\
             bundle_ctr = {}\n\
             root_hash = {}\n\
             deadline_secs = {}\n",
            self.format,
            self.slot.as_str(),
            self.version,
            self.bundle_ctr,
            self.root_hash,
            self.deadline_secs,
        )
        .into_bytes()
    }

    /// Parse a stored record — whitelist + fail-closed exactly like the manifest
    /// (unknown ⇒ refuse, duplicate ⇒ refuse, all 6 required, values strictly typed).
    /// A malformed record is an error the CALLER classifies (mark-good treats it as
    /// stale-shaped, the reconcile as reconcile-normally) — never a silent default.
    pub fn parse(bytes: &[u8]) -> Result<Record, ManifestError> {
        let mut vals: [Option<&str>; 6] = [None; 6];
        for (k, v) in kv_lines(bytes)? {
            let Some(i) = RECORD_KEYS.iter().position(|kk| *kk == k) else {
                return Err(ManifestError::UnknownKey(k.to_string()));
            };
            if vals[i].is_some() {
                return Err(ManifestError::DuplicateKey(k.to_string()));
            }
            vals[i] = Some(v);
        }
        for (i, key) in RECORD_KEYS.iter().enumerate() {
            if vals[i].is_none() {
                return Err(ManifestError::MissingKey(key));
            }
        }
        let format = parse_u64(vals[0].expect("checked present"), "format")?;
        if format != 1 {
            return Err(ManifestError::BadFormat);
        }
        let slot_raw = vals[1].expect("checked present");
        let slot = Slot::from_label(slot_raw).ok_or(ManifestError::BadValue { key: "slot" })?;
        let root_hash = vals[4].expect("checked present");
        validate_hex64_lower(root_hash, "root_hash")?;
        Ok(Record {
            format,
            slot,
            version: parse_u64(vals[2].expect("checked present"), "version")?,
            bundle_ctr: parse_u64(vals[3].expect("checked present"), "bundle_ctr")?,
            root_hash: root_hash.to_string(),
            deadline_secs: parse_u64(vals[5].expect("checked present"), "deadline_secs")?,
        })
    }
}

/// Durable tmp+rename record write: stage `<dir>/.record.tmp`, fsync the file, rename
/// over `path`, fsync the DIRECTORY (the rename itself must survive power loss — the
/// record is written strictly before the ADV arm, and a record that vanishes after the
/// arm turns a probation boot into an unmarked one). The tmp name is fixed: writers are
/// serialized (apply holds the flock; mark-good runs once per cadence), and a crash
/// leftover is simply overwritten by the next writer.
pub fn write_record_atomic(path: &Path, record: &Record) -> std::io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("record path has no parent directory"))?;
    let tmp = dir.join(".record.tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(&record.to_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

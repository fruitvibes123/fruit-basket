//! `fb-update apply` — the normative apply orchestration (spec §5): read + verify the
//! manifest and bundle BEFORE any component byte, run the fail-closed guards, stream
//! the three components chunked to the inactive slot (write-then-verify), write the
//! probation record, then arm the one-try boot (THE PROMOTION POINT), then reboot.
//!
//! Every refusal is PRE-PROMOTION: no path reaches `arm_once` without the full cascade
//! and the guards passing, so a refused apply never changes the active slot or the
//! boot-fs default label, and the box keeps booting the old slot (the G5 invariant).
//! Each refusal is its own `ApplyError` variant with a distinct process exit code.

use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::floors::{FloorError, MINCTR_FLOOR_FILE, VERSION_FLOOR_FILE, read_floor_strict};
use crate::manifest::{ManifestError, UpdateManifest, parse_manifest};
use crate::selector::{ComponentSpec, SelErr, SlotDesc, SlotSelector};
use crate::{
    BUNDLE_LEN, MANIFEST_MAX_LEN, MARK_GOOD_DEADLINE_SECS, Record, SLOT_BOOT_BUDGET,
    SLOT_SIZE_BYTES, Slot, write_record_atomic,
};

/// The inputs the box supplies to `apply` (the bin fills these from the running box;
/// tests inject temp dirs + fixtures).
pub struct ApplyCtx<'a> {
    /// The baked operator artifact-root pubkey (the box's pinned trust anchor).
    pub root_pubkey: &'a [u8; 32],
    /// A trustworthy wall clock (post-ntpd-convergence; the clocked verify's `now`).
    pub now_unix: u64,
    /// The box's own firmware token (`fb.firmware` from `/proc/cmdline`), cross-checked
    /// against the manifest so a seabios-gpt image can't be pushed onto a non-gpt box.
    pub box_firmware: &'a str,
    /// `/persist/update/` — holds `version-floor`, `minctr-floor`.
    pub floors_dir: &'a Path,
    /// `/persist/update/` — holds `record` (the probation state) + the `lock`.
    pub update_dir: &'a Path,
}

/// Why `apply` refused. Every variant is pre-promotion (the disk's bootable state is
/// unchanged). The bin maps each to a distinct exit code.
#[derive(Debug)]
pub enum ApplyError {
    /// Framing/length-bound/EOF violation (bad len prefix, over-bound manifest, wrong
    /// bundle length, trailing bytes after the last component).
    BadStream(&'static str),
    /// The manifest failed the §4a whitelist parse.
    BadManifest(ManifestError),
    /// The bundle failed the clocked cascade (sig / purpose / window / ctr floor).
    Verify(quince::ClockedVerifyError),
    /// `manifest.firmware` ≠ `seabios-gpt`, or ≠ the box's own `fb.firmware`.
    FirmwareMismatch,
    /// `manifest.version` is not strictly above the version floor (anti-rollback).
    VersionNotAboveFloor { version: u64, floor: u64 },
    /// A floor file is absent or malformed — fail-closed, NEVER read as 0 (R4-2).
    FloorUnavailable(FloorError),
    /// A probation record already exists — an update is mid-cycle (checked under the
    /// lock; a second apply must not clobber it).
    ProbationInFlight,
    /// A declared component size exceeds its bound (`rootfs_size > SLOT_SIZE_BYTES`, or
    /// `kernel_size + initramfs_size > SLOT_BOOT_BUDGET`).
    SizeExceeded { which: &'static str },
    /// The selector refused (active slot unrecognized, a component came up short / hash
    /// mismatch on re-read, or an I/O fault).
    Selector(SelErr),
    /// Reading the stream / floors failed.
    Io(String),
}

impl std::fmt::Display for ApplyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApplyError::BadStream(w) => write!(f, "malformed update stream: {w}"),
            ApplyError::BadManifest(e) => write!(f, "malformed update manifest: {e:?}"),
            ApplyError::Verify(e) => write!(f, "bundle verify failed: {e:?}"),
            ApplyError::FirmwareMismatch => {
                write!(f, "firmware mismatch (manifest != seabios-gpt or != box)")
            }
            ApplyError::VersionNotAboveFloor { version, floor } => {
                write!(
                    f,
                    "version {version} is not above the floor {floor} (rollback refused)"
                )
            }
            ApplyError::FloorUnavailable(e) => {
                write!(
                    f,
                    "anti-rollback floor unavailable ({e:?}) — refusing (never read as 0)"
                )
            }
            ApplyError::ProbationInFlight => {
                write!(
                    f,
                    "an update is already in probation — refusing a concurrent apply"
                )
            }
            ApplyError::SizeExceeded { which } => write!(f, "{which} exceeds its size bound"),
            ApplyError::Selector(e) => write!(f, "slot selector refused: {e:?}"),
            ApplyError::Io(e) => write!(f, "apply I/O: {e}"),
        }
    }
}

impl std::error::Error for ApplyError {}

impl ApplyError {
    /// A distinct, stable process exit code per refusal class (the bin's `exit(code)`;
    /// the ceremony reads it to report why). Success is 0.
    pub fn exit_code(&self) -> i32 {
        match self {
            ApplyError::BadStream(_) => 10,
            ApplyError::BadManifest(_) => 11,
            ApplyError::Verify(_) => 12,
            ApplyError::FirmwareMismatch => 13,
            ApplyError::VersionNotAboveFloor { .. } => 14,
            ApplyError::FloorUnavailable(_) => 15,
            ApplyError::ProbationInFlight => 16,
            ApplyError::SizeExceeded { .. } => 17,
            ApplyError::Selector(_) => 18,
            ApplyError::Io(_) => 19,
        }
    }
}

/// Read exactly `n` bytes or fail (EOF-before-`n` ⇒ the caller's short-stream refusal).
fn read_exact_vec(reader: &mut dyn Read, n: usize) -> Result<Vec<u8>, ApplyError> {
    let mut buf = vec![0u8; n];
    reader
        .read_exact(&mut buf)
        .map_err(|e| ApplyError::Io(format!("short read ({n} bytes): {e}")))?;
    Ok(buf)
}

/// Read a little-endian u64 length prefix.
fn read_u64_le(reader: &mut dyn Read) -> Result<u64, ApplyError> {
    let mut b = [0u8; 8];
    reader
        .read_exact(&mut b)
        .map_err(|e| ApplyError::Io(format!("short read (u64 length): {e}")))?;
    Ok(u64::from_le_bytes(b))
}

/// The normative apply (spec §5). Returns the target (newly-armed) slot on success; the
/// bin then reboots. `reader` is the ssh-exec pipe (§4c framing).
pub fn apply<R: Read, S: SlotSelector>(
    reader: &mut R,
    selector: &S,
    ctx: &ApplyCtx<'_>,
) -> Result<Slot, ApplyError> {
                                                                                     
    let manifest_len = read_u64_le(reader)?;
    if manifest_len == 0 || manifest_len > MANIFEST_MAX_LEN {
        return Err(ApplyError::BadStream("manifest length out of bounds"));
    }
    let manifest_bytes = read_exact_vec(reader, manifest_len as usize)?;

    let bundle_len = read_u64_le(reader)?;
    if bundle_len != BUNDLE_LEN {
        return Err(ApplyError::BadStream("bundle length must be exactly 254"));
    }
    let bundle = read_exact_vec(reader, bundle_len as usize)?;

                                                                             
    let version_floor = read_floor_strict(&ctx.floors_dir.join(VERSION_FLOOR_FILE))
        .map_err(ApplyError::FloorUnavailable)?;
    let minctr_floor = read_floor_strict(&ctx.floors_dir.join(MINCTR_FLOOR_FILE))
        .map_err(ApplyError::FloorUnavailable)?;

                                                                                           
    let artifact_hash: [u8; 32] = Sha256::digest(&manifest_bytes).into();
    let bundle_ctr = quince::verify_artifact_clocked(
        ctx.root_pubkey,
        &bundle,
        &artifact_hash,
        quince::Purpose::UpdateImage,
        minctr_floor,
        ctx.now_unix,
    )
    .map_err(ApplyError::Verify)?;

                                                                            
    let m: UpdateManifest = parse_manifest(&manifest_bytes).map_err(ApplyError::BadManifest)?;

    if m.firmware != "seabios-gpt" || m.firmware != ctx.box_firmware {
        return Err(ApplyError::FirmwareMismatch);
    }
    if m.version <= version_floor {
        return Err(ApplyError::VersionNotAboveFloor {
            version: m.version,
            floor: version_floor,
        });
    }
    if m.rootfs_size > SLOT_SIZE_BYTES {
        return Err(ApplyError::SizeExceeded { which: "rootfs" });
    }
    if m.kernel_size.saturating_add(m.initramfs_size) > SLOT_BOOT_BUDGET {
        return Err(ApplyError::SizeExceeded {
            which: "kernel+initramfs",
        });
    }

                                                                                          
    if ctx.update_dir.join("record").exists() {
        return Err(ApplyError::ProbationInFlight);
    }

    let active = selector.active_slot().map_err(ApplyError::Selector)?;
    let target = active.other();

                                                                                 
    let rootfs_spec = ComponentSpec {
        len: m.rootfs_size,
        sha256: m.rootfs_sha256,
    };
    {
                                                                                   
                                                             
        let mut rootfs_src = reader.by_ref().take(m.rootfs_size);
        selector
            .stage_rootfs(target, &rootfs_spec, &mut rootfs_src)
            .map_err(ApplyError::Selector)?;
    }

    let kernel_spec = ComponentSpec {
        len: m.kernel_size,
        sha256: m.kernel_sha256,
    };
    let initramfs_spec = ComponentSpec {
        len: m.initramfs_size,
        sha256: m.initramfs_sha256,
    };
    let desc = SlotDesc {
        root_hash: m.root_hash.clone(),
        verity_hash_offset: m.verity_hash_offset,
    };
                                                                                        
                                                                                        
    selector
        .stage_boot(target, &desc, &kernel_spec, &initramfs_spec, &mut *reader)
        .map_err(ApplyError::Selector)?;

                                                                                         
    let mut trailing = [0u8; 1];
    match reader.read(&mut trailing) {
        Ok(0) => {}
        Ok(_) => return Err(ApplyError::BadStream("trailing bytes after initramfs")),
        Err(e) => return Err(ApplyError::Io(format!("EOF check: {e}"))),
    }

                                                                                   
    let record = Record {
        format: 1,
        slot: target,
        version: m.version,
        bundle_ctr,
        root_hash: m.root_hash,
        deadline_secs: MARK_GOOD_DEADLINE_SECS,
    };
    write_record_atomic(&ctx.update_dir.join("record"), &record)
        .map_err(|e| ApplyError::Io(format!("write record: {e}")))?;

    selector.arm_once(target).map_err(ApplyError::Selector)?;
    Ok(target)
}

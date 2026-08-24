//! Installer-mode path for the box PID-1 init (deploy-and-transition).
//!
//! Dispatched from [`crate::cmdline::BootMode::Installer`] (spec deploy-prod step 7). The same signed
//! init binary that boots the runtime, run with `fb.mode=installer` on its cmdline, partitions
//! the target disk and writes slot A from the `.img` the operator scp'd onto the old Debian root,
//! then reboots into the immutable runtime.
//!
//! **The dd-only redesign (O3, pure-Rust pre-baked installer):** the three filesystems the box needs
//! — the bootable boot-fs, the squashfs+verity rootfs, and the persist-skeleton ext4 — are baked at
//! BUILD time (controlled container) and concatenated into the `.img`. The installer execs NOTHING and
//! formats NOTHING in the un-appraised window; it only raw-`dd`s the pre-baked components onto a freshly
//! partitioned disk. The runtime kernel cmdline (the slot-A `extlinux.conf` APPEND, incl. the verity
//! offset + the defense triple) is BAKED into the boot-fs build-side; `fb.rootfs-dev` is byte-patched
//! into it operator-side by the deploy CLI before scp. The installer carries no `BootConfig`.
//!
//! **The load-bearing ordering** (spec steps 7.pre → 7h):
//! 7.pre mount old-root ro → read `.img` (+ its `.layout.toml` sidecar; + optional restore image)
            
//! into RAM → if restore-from, VERIFY the image signature **before any write** → unmount →
//! **only then** 7a write the partition table (boot-code bytes still zero → NOT bootable) → dd rootfs →
//! slot A → dd persist-skeleton → persist → zero slot B → dd the boot-fs → boot partition → **write the
//! 440-byte MBR stage-1 (`mbr.bin`) LAST** → reboot. A mount failure or a restore verify failure aborts
           
//! **before** the partition table is touched. The MBR boot-code write is the LAST destructive
//! step (bootable-last): the disk only becomes bootable at the very end, so any failure BEFORE the final
//! boot/ESP write leaves a cleanly-unbootable disk the operator re-installs. (A crash INSIDE that final
//! write is the one residual — a torn boot sector / ESP; on UEFI dm-verity reduces it to a non-silent
               
//! reboot loop, since slot A is written strictly earlier. Never a silent unverified run.)
//!
//! This module hosts the pure, host-testable units (cmdline source grammar, partition-layout math, the
//! 3-component `.img` slicing, and the install state-machine over an effects seam). The raw block I/O +
//! mount FFI live behind the seam ([`crate::installer_syscall`]) and are exercised by the QEMU
                
//! run.

use crate::install_target::{DiskInfo, select_target};
use core::fmt;

/// One `disk:<device>:<path>` install source from the installer cmdline. `device` is the bare
/// partition name (e.g. `sda1`, `vda1`, `nvme0n1p1`) WITHOUT the `/dev/` prefix — the deploy CLI
/// strips it (spec step 5 `findmnt` → strip `/dev/`); the init prepends `/dev/` when it mounts.
/// `path` is the file location on the mounted old-root (e.g. `/tmp/recipes-image-<sha>.img`).
///
/// The `disk:<device>:<path>` value of `fb.restore-from` — under the streaming redesign (spec D9)
/// this type serves the RESTORE source ONLY: the `.img` no longer lives on a filesystem (it is
/// staged raw at the disk tail — [`InstallSource::RawRegion`]). The UEFI signed-USB installer does
/// NOT use it (§9.5): it resolves a built-in PARTUUID instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskSource {
    pub device: String,
    pub path: String,
}

/// The installer's image source — typed so an absent/nullable source is structurally unrepresentable
/// (§9.5 R3-1, secure-by-construction). The SeaBIOS/kexec path always produces
/// [`InstallSource::RawRegion`] (parsed from `fb.image-raw` + its MANDATORY `fb.image-layout`
/// companion, spec §4 — a raw source without its layout is unrepresentable); the UEFI signed-USB
/// installer uses [`InstallSource::BuiltinDataPartuuid`] (resolved from the built-in
/// `INSTALLER_DATA_PARTUUID` — no raw tokens on its cmdline). [`prepare`] matches on this to pick
/// the source-resolution path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallSource {
    /// SeaBIOS-family kexec arm (spec D1): the operator staged the (patched) `.img` onto a raw
    /// region at the target-disk tail pre-kexec; `region` is the parsed `fb.image-raw` window and
    /// `layout` the parsed `fb.image-layout` component geometry riding the same append (D3).
    RawRegion {
        region: crate::installer_stream::RawRegion,
        layout: crate::installer_stream::StreamLayout,
    },
    /// UEFI signed-USB installer (§9.5): the box image lives on the USB's ext4 data partition, located
    /// by the built-in `INSTALLER_DATA_PARTUUID` constant (no operator-supplied source token).
    BuiltinDataPartuuid,
}

/// The installer's parsed sources (spec step 7.pre mutual-exclusion): `source` is REQUIRED for every
/// installer-mode invocation; `restore_from` is present only for the restore-from variant (SeaBIOS/kexec
/// only — §9.5 greenfield does not restore). On the SeaBIOS path both reference the SAME old-root device
                 
/// (the deploy CLI scp's both files to the same Debian partition) — a device mismatch is
/// rejected by [`parse_install_sources`] so the init mounts exactly one old-root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallSources {
    pub source: InstallSource,
    pub restore_from: Option<DiskSource>,
    /// `fb.min-ctr` — the operator's opt-in anti-rollback floor for the restore bundle's
    /// delegation `monotonic_ctr` (Task 4.3 spec §5, C1 §6e). Strict u64; absent/empty ⇒ 0
    /// (no floor — C1's default posture). Only defined WITH `fb.restore-from` (allowlist:
    /// a floor with nothing to floor is a malformed cmdline).
    pub min_ctr: u64,
}

/// A cmdline the installer cannot safely act on. Like [`crate::cmdline::CmdlineError`], each variant
/// maps to a fail-closed kernel-panic diagnostic in the PID-1 caller — the installer never proceeds
/// to write a disk from a malformed source spec.
#[derive(Debug, PartialEq, Eq)]
pub enum InstallerError {
    /// No `fb.image-raw` on the installer cmdline (or it was empty). Every SeaBIOS-family
    /// installer-mode invocation requires the staged-window source token (spec §4); absent is the
    /// "no install source" abort.
    MissingImageRaw,
    /// No `fb.image-layout` alongside `fb.image-raw` — the raw arm reads no sidecar file (spec
    /// D3), so the component geometry token is REQUIRED with the source token.
    MissingImageLayout,
    /// No `fb.image-sha256` on the raw arm — the digest is MANDATORY there (spec D4): the staged
    /// window is verified against it strictly before any destructive write.
    MissingImageSha256,
    /// A streaming token (`fb.image-raw` / `fb.image-layout`) failed its fail-closed grammar or
    /// geometry check ([`crate::installer_stream::StreamError`] carries the operator-visible
    /// reason).
    BadStreamToken(crate::installer_stream::StreamError),
    /// `fb.image-layout`'s leading `fw:` field disagrees with `fb.firmware` (spec D3 two-token
    /// agreement) — an append-composition/transcription bug in the operator tool; refuse before
    /// any write.
    FirmwareTokenMismatch {
        layout_fw: &'static str,
        cmdline_fw: &'static str,
    },
    /// A source value did not match the `disk:<device>:<path>` grammar (wrong scheme, missing field).
    MalformedSource { key: String, value: String },
    /// The `<device>` field is not an accepted bare partition name (ascii-lowercase + digits, no
    /// slashes) — fail closed rather than mount an unexpected path (whitelist, not blacklist).
    InvalidSourceDevice { key: String, device: String },
    /// The `<path>` field is not an accepted absolute, traversal-free path.
    InvalidSourcePath { key: String, path: String },
    /// `fb.restore-from` names a partition of a DIFFERENT disk than `fb.image-raw`'s window (the
    /// derivation compare, spec D5) — the init mounts ONE old-root, on the very disk being
    /// installed, so a split spec is a malformed cmdline.
    SourceDeviceMismatch { image: String, restore: String },
    /// The target disk is smaller than the fixed partitions (boot + slot A + slot B) plus a minimum
               
    /// persist — the installer aborts BEFORE writing any partition table (fail closed).
    DiskTooSmall { need_bytes: u64, have_bytes: u64 },
    /// The target disk is larger than MBR's 32-bit LBA addressing can express (> 2 TiB): a partition
    /// start or length exceeds `u32::MAX` sectors. MBR is the spec's partition scheme (step 7a — GPT
    /// rejected, BIOS+extlinux), so an un-addressable disk fails closed BEFORE any write rather than
    /// silently truncating a partition entry.
    DiskTooLargeForMbr { sectors: u64 },
    /// The `.img`'s `.layout.toml` sidecar could not be parsed (missing `[layout]` key, a non-integer
    /// or negative value, or a missing field). Without a trustworthy layout the installer cannot slice
    /// the `.img` — fail closed BEFORE any write (the layout is read in 7.pre).
    MalformedImageLayout { reason: String },
    /// A `.layout.toml` component (boot / persist-skeleton / rootfs) names a byte range that runs past
    /// the end of the `.img` read into RAM — a layout/image mismatch. Fail closed in 7.pre, BEFORE any
    /// write (slicing past the image would otherwise read garbage into slot A / the boot partition).
    ImageLayoutOutOfBounds {
        component: &'static str,
        end: u64,
        image_len: u64,
    },
    /// A sliced `.img` component is larger than the fixed partition it must be written to (rootfs >
    /// slot A, the boot-fs > the boot partition, or the persist-skeleton > persist). Fail closed BEFORE
    /// any write — a too-large component would otherwise overrun the partition into its neighbour.
    ComponentTooLargeForPartition {
        component: &'static str,
        bytes: u64,
        capacity: u64,
    },
    /// `fb.min-ctr`'s value is not a strict u64 (sign/junk/overflow). Fail closed — a floor that
    /// parses "almost" would silently weaken the operator's anti-rollback intent.
    MalformedMinCtr { value: String },
    /// `fb.min-ctr` present without `fb.restore-from` — the token is only defined for the restore
    /// variant (allowlist posture); a floor with nothing to floor is a malformed cmdline.
    MinCtrWithoutRestore,
    /// The staged raw window intersects an extent the install writes (or breaches the disk/tail
    /// bounds) — spec D2. `hit` names the extent (or `tail-bounds`); refused strictly BEFORE any
    /// destructive write (the streaming-installer geometry gate, `installer_stream`).
    StagingOverlapsInstall {
        window_start: u64,
        window_end: u64,
        hit: &'static str,
    },
    /// A chunked source read hit EOF before the expected byte count (truncated staging region /
    /// source file) — fail closed; during the pre-pass nothing was written, during a copy the
    /// bootcode is never reached (bootable-last holds).
    SourceShortRead {
        offset: u64,
        wanted: usize,
        got: usize,
    },
    /// The staged region's chunked SHA-256 does not match the mandatory `fb.image-sha256`
    /// (spec D4) — refused strictly BEFORE any destructive write.
    StagedImageDigestMismatch { expected: [u8; 32], got: [u8; 32] },
    /// A component's post-write `O_DIRECT` readback hash does not match its pre-pass digest
    /// (spec D7): the media did not receive the verified bytes — abort BEFORE bootcode
    /// (bootable-last), leaving the disk cleanly unbootable.
    ComponentReadbackMismatch { component: &'static str },
    /// An install operation (mount / read / verify / a disk write) failed. `op` names the step; the
    /// PID-1 caller turns this into a kernel-panic diagnostic. A failure in the 7.pre read/verify
                          
    /// phase aborts BEFORE any partition write.
    OpFailed { op: &'static str, reason: String },
}

impl fmt::Display for InstallerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingImageRaw => {
                write!(
                    f,
                    "fb.image-raw not set on installer cmdline (no staged install source)"
                )
            }
            Self::MissingImageLayout => {
                write!(
                    f,
                    "fb.image-layout not set on installer cmdline (the raw arm reads no sidecar — the layout token is required)"
                )
            }
            Self::MissingImageSha256 => {
                write!(
                    f,
                    "fb.image-sha256 not set on installer cmdline (mandatory on the raw arm — spec D4)"
                )
            }
            Self::BadStreamToken(e) => write!(f, "{e}"),
            Self::FirmwareTokenMismatch {
                layout_fw,
                cmdline_fw,
            } => write!(
                f,
                "fb.image-layout fw:{layout_fw} != fb.firmware {cmdline_fw} (append composition bug — refusing before any write)"
            ),
            Self::MalformedSource { key, value } => {
                write!(f, "{key} not a disk:<device>:<path> source: {value:?}")
            }
            Self::InvalidSourceDevice { key, device } => {
                write!(
                    f,
                    "{key} device not an accepted <a-z0-9> partition name: {device:?}"
                )
            }
            Self::InvalidSourcePath { key, path } => {
                write!(
                    f,
                    "{key} path not an accepted absolute traversal-free path: {path:?}"
                )
            }
            Self::SourceDeviceMismatch { image, restore } => write!(
                f,
                "image-raw disk {image:?} != restore-from device {restore:?}'s disk (init mounts one old-root on the install disk)"
            ),
            Self::MalformedMinCtr { value } => {
                write!(f, "fb.min-ctr not a strict u64: {value:?}")
            }
            Self::MinCtrWithoutRestore => write!(
                f,
                "fb.min-ctr set without fb.restore-from (the floor is only defined for a restore)"
            ),
            Self::DiskTooSmall {
                need_bytes,
                have_bytes,
            } => write!(
                f,
                "target disk {have_bytes} bytes < {need_bytes} bytes required for the partition layout"
            ),
            Self::DiskTooLargeForMbr { sectors } => write!(
                f,
                "partition sector value {sectors} exceeds MBR 32-bit addressing (disk > 2 TiB)"
            ),
            Self::MalformedImageLayout { reason } => {
                write!(f, "image .layout.toml malformed: {reason}")
            }
            Self::ImageLayoutOutOfBounds {
                component,
                end,
                image_len,
            } => write!(
                f,
                "image layout {component} ends at {end} bytes, past the {image_len}-byte .img"
            ),
            Self::ComponentTooLargeForPartition {
                component,
                bytes,
                capacity,
            } => write!(
                f,
                "image {component} is {bytes} bytes, larger than its {capacity}-byte partition"
            ),
            Self::StagingOverlapsInstall {
                window_start,
                window_end,
                hit,
            } => write!(
                f,
                "staging window [{window_start}, {window_end}) overlaps the install's {hit} — refusing before any write"
            ),
            Self::SourceShortRead {
                offset,
                wanted,
                got,
            } => write!(
                f,
                "source read at offset {offset} returned {got} of {wanted} bytes (truncated staging region/file)"
            ),
            Self::StagedImageDigestMismatch { expected, got } => {
                let hex =
                    |b: &[u8; 32]| -> String { b.iter().map(|x| format!("{x:02x}")).collect() };
                write!(
                    f,
                    "staged image SHA-256 {} does not match fb.image-sha256 {} — refusing before any write",
                    hex(got),
                    hex(expected)
                )
            }
            Self::ComponentReadbackMismatch { component } => write!(
                f,
                "post-write readback of {component} does not match its verified digest — media \
                 mismatch; aborting before bootcode (disk left unbootable)"
            ),
            Self::OpFailed { op, reason } => write!(f, "install step {op} failed: {reason}"),
        }
    }
}

                                                        

/// 512-byte LBA sector (the MBR/BIOS convention; target VPS disks are 512n/512e). Moved to the
/// extracted runtime layer (hotswap v4 §9/R3-I7) — re-exported so the installer's many byte↔sector
/// call sites and `installer_syscall` keep their `crate::installer::SECTOR_SIZE` path.
pub use fb_verity_rt::SECTOR_SIZE;

/// 1 MiB partition alignment (2048 × 512-byte sectors) — the modern-disk default; keeps every
/// partition start on a 1 MiB boundary (erase-block / RMW friendly).
const ALIGN_SECTORS: u64 = (1024 * 1024) / SECTOR_SIZE;

/// MBR partition type byte for a Linux partition (0x83). All four partitions use it: boot + persist
/// are ext4; the A/B slots are raw squashfs+verity (no FS), but 0x83 is the conventional "Linux data"
/// type and we address the slots by LBA, not by type.
const PART_TYPE_LINUX: u8 = 0x83;

                                                                                                     
                                                                                                    
                                                                                                    
                                                                                                         
                                                                                                 
                                                                                                      
                                                                                                     
                                                                                                      
                                                                                                     
                                                                                                         
                                                                           
const BOOT_SIZE_BYTES: u64 = 128 * 1024 * 1024;
const SLOT_SIZE_BYTES: u64 = 64 * 1024 * 1024;

/// Sectors reserved at the END of the disk for the backup GPT (UEFI only): 1 backup-header sector + 32
/// entry-array sectors (128 entries × 128 bytes ÷ 512 = 32). The PRIMARY GPT at the front (LBA0
/// protective MBR + LBA1 header + 32 entry sectors = 34 sectors) is already cleared by the 1 MiB-aligned
/// boot start. SeaBIOS/MBR has no tail reserve — persist runs to the very last sector.
const GPT_BACKUP_SECTORS: u64 = 33;

/// One MBR primary partition (computed; the raw-block writer turns these into the 16-byte table
/// entries). `start_lba` + `sector_count` are in 512-byte sectors; `bootable` sets the 0x80 boot
/// indicator (only the boot partition carries it — extlinux's MBR stage-1 boots the active partition).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partition {
    pub number: u8,
    pub start_lba: u64,
    pub sector_count: u64,
    pub part_type: u8,
    pub bootable: bool,
}

/// The partition layout (spec step 7a): boot (active, ext4) + slot A + slot B (raw squashfs+verity) +
/// [optional dha weights] + persist (remainder, ext4). `weights` is `Some` only for a dha box on a GPT
/// firmware (the 5th GPT partition between slot_b and persist, O4=GPT); `None` keeps the byte-identical
        
/// 4-partition layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionLayout {
    pub boot: Partition,
    pub slot_a: Partition,
    pub slot_b: Partition,
    /// dha Component E (O4=GPT): the RO dm-verity weights volume — a 5th GPT partition between `slot_b`
    /// and `persist`. `Some` only for a dha box on a GPT firmware; `None` = the 4-partition layout.
    pub weights: Option<Partition>,
    pub persist: Partition,
}

/// The boot-firmware strategy axis (spec §2.5). DUPLICATED from
/// `recipes_image_builder::firmware::Firmware` — the `.layout.toml` `firmware` string is the wire
/// contract (a 2-variant enum does not justify a shared crate; initramfs-init is a standalone
/// `panic=abort` workspace). Parsed from the sidecar in [`parse_image_layout`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Firmware {
    /// Legacy BIOS / SeaBIOS — MBR + ext4 boot-fs + extlinux + the 440-byte `mbr.bin` stage-1.
    #[default]
    Seabios,
    /// Legacy BIOS booting from a GPT disk (the dha-hosting box; the BIOS+GPT installer arm). Composes the
    /// SeaBIOS boot path (ext4 boot-fs, extlinux, APPEND) with the UEFI partition path (`build_gpt`,
    /// `SLOT_A_PARTUUID`, `resolve_partuuid`): the boot partition carries the GPT `legacy_boot` attribute
    /// and the Linux-fs type GUID, and `gptmbr.bin` is the protective-MBR stage-1 (vs SeaBIOS's
    /// `mbr.bin`). Wire token `"seabios-gpt"`.
    SeabiosGpt,
    /// UEFI — GPT + FAT ESP. The initramfs-init seams (GPT serializer + geometry + commit + the PARTUUID
    /// resolver) are BUILT + host-tested + OVMF-boot-proven; the deploy-side `--firmware uefi` build is
    /// un-deferred (the GPT commit arm runs on a real UEFI `.img`). Production substrate stays gated.
    Uefi,
}

impl Firmware {
    /// The `.layout.toml` wire token (matches `recipes_image_builder::firmware::Firmware::as_str`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Seabios => "seabios",
            Self::SeabiosGpt => "seabios-gpt",
            Self::Uefi => "uefi",
        }
    }

    /// Parse the `.layout.toml` `firmware` wire token; fail-closed (`None`) on an unknown value so a
    /// malformed sidecar can never silently default a firmware (the inverse of [`Firmware::as_str`]).
    pub fn from_wire(token: &str) -> Option<Self> {
        match token {
            "seabios" => Some(Self::Seabios),
            "seabios-gpt" => Some(Self::SeabiosGpt),
            "uefi" => Some(Self::Uefi),
            _ => None,
        }
    }
}

/// Compute the partition layout for a disk of `disk_size_bytes` (spec step 7a). Pure arithmetic —
/// host-unit-tested; the raw-block table write that consumes it is FFI (QEMU-gated). Fails closed
/// with [`InstallerError::DiskTooSmall`] if the disk can't hold the fixed partitions + a minimum
           
/// persist (so the installer aborts BEFORE touching the partition table).
///
       
/// `firmware` is the format seam: the boot + A/B-slot geometry (offsets/sizes) is shared, but two things
/// differ by partition-table format. (1) The 2 TiB MBR-overflow guard
/// ([`InstallerError::DiskTooLargeForMbr`]) is SeaBIOS/MBR-only — the GPT firmwares (UEFI, SeabiosGpt)
/// use 64-bit LBAs. (2) The GPT firmwares reserve [`GPT_BACKUP_SECTORS`] at the disk tail for the backup
/// GPT, so their persist partition is that much shorter; MBR persist runs to the last sector. (The
/// serialized table — MBR vs GPT — is chosen in [`commit`]; this function only computes the LBA geometry.)
pub fn compute_partition_layout(
    disk_size_bytes: u64,
    firmware: Firmware,
    weights_size_bytes: Option<u64>,
) -> Result<PartitionLayout, InstallerError> {
    let boot_sectors = BOOT_SIZE_BYTES / SECTOR_SIZE;
    let slot_sectors = SLOT_SIZE_BYTES / SECTOR_SIZE;
    let disk_sectors = disk_size_bytes / SECTOR_SIZE;

                                                                                                  
                                                                                                   
    let boot_start = ALIGN_SECTORS;
    let slot_a_start = align_up(boot_start + boot_sectors);
    let slot_b_start = align_up(slot_a_start + slot_sectors);

                                                                                                       
                                                                                                       
                                                                                                 
                                                                                               
    let weights = match weights_size_bytes {
        None => None,
        Some(ws) => {
            if firmware == Firmware::Seabios {
                return Err(InstallerError::OpFailed {
                    op: "compute_partition_layout",
                    reason: "weights partition requires a GPT firmware (MBR has no 5th primary)"
                        .to_string(),
                });
            }
            Some(Partition {
                number: 5,
                start_lba: align_up(slot_b_start + slot_sectors),
                sector_count: align_up(ws.div_ceil(SECTOR_SIZE)),
                part_type: PART_TYPE_LINUX,
                bootable: false,
            })
        }
    };

                                                                                           
    let persist_start = match &weights {
        Some(w) => align_up(w.start_lba + w.sector_count),
        None => align_up(slot_b_start + slot_sectors),
    };

                                                                                                          
                                                                                                    
    let tail_reserve = match firmware {
        Firmware::Seabios => 0,
        Firmware::Uefi | Firmware::SeabiosGpt => GPT_BACKUP_SECTORS,
    };

                                                                                                       
                                                                                                   
                              
    let min_total = persist_start + ALIGN_SECTORS + tail_reserve;
    if disk_sectors < min_total {
        return Err(InstallerError::DiskTooSmall {
            need_bytes: min_total * SECTOR_SIZE,
            have_bytes: disk_size_bytes,
        });
    }
                                                                                                    
                                                                                                      
                                                                                                    
                                                                                                   
                                                                             
    if firmware == Firmware::Seabios && disk_sectors > u64::from(u32::MAX) {
        return Err(InstallerError::DiskTooLargeForMbr {
            sectors: disk_sectors,
        });
    }
    let persist_sectors = disk_sectors - persist_start - tail_reserve;

    Ok(PartitionLayout {
        boot: Partition {
            number: 1,
            start_lba: boot_start,
            sector_count: boot_sectors,
            part_type: PART_TYPE_LINUX,
            bootable: true,
        },
        slot_a: Partition {
            number: 2,
            start_lba: slot_a_start,
            sector_count: slot_sectors,
            part_type: PART_TYPE_LINUX,
            bootable: false,
        },
        slot_b: Partition {
            number: 3,
            start_lba: slot_b_start,
            sector_count: slot_sectors,
            part_type: PART_TYPE_LINUX,
            bootable: false,
        },
        weights,
        persist: Partition {
            number: 4,
            start_lba: persist_start,
            sector_count: persist_sectors,
            part_type: PART_TYPE_LINUX,
            bootable: false,
        },
    })
}

/// Round `sectors` up to the next [`ALIGN_SECTORS`] (1 MiB) boundary.
fn align_up(sectors: u64) -> u64 {
    sectors.div_ceil(ALIGN_SECTORS) * ALIGN_SECTORS
}

                                                                                      
                                                                                                  
                                             

/// Derive the WHOLE-DISK device name from a partition name — the inverse of
/// [`partition_device_name`]. The installer wipes + repartitions the ENTIRE disk that holds the
            
/// old-root partition (the stage-on-root-partition binding: the `.img` is scp'd onto the
/// partition `/` is on, and the disk holding it is the target), and the raw-block writes (the
/// partition table + the `dd` of each pre-baked component — the dd-only installer execs no
/// `mke2fs`) target `/dev/<disk>` + `/dev/<disk><n>`.
///
                                     
/// A WHITELIST of the two real Linux partition-naming shapes,
/// because a purely-structural digit-strip CANNOT distinguish a bare digit-ending disk from a
                    
/// partition (`nvme0n1` / `mmcblk0` / `loop0` are bare DISKS, yet a naive strip
/// mis-derives them to `nvme0n` / `mmcblk` / `loop`):
///   - **p-form** (`nvme`/`mmcblk`/`loop` — disk names that END in a digit): a partition is
///     `<disk>p<partnum>` (`nvme0n1p1`→`nvme0n1`, `mmcblk0p2`→`mmcblk0`). WITHOUT the `p<digits>`
///     suffix the token is a bare disk → reject.
///   - **letter-form** (`sd`/`vd`/`hd`/`xvd` — disk names that END in a letter): a partition is
///     `<disk><partnum>` (`sda1`→`sda`, `vda2`→`vda`); the disk is the token minus its trailing digits.
///
/// Fails closed on a bare disk or an unrecognized shape — `fb.restore-from` must name a partition
/// (the streaming raw arm's same-disk rule derives the restore partition's whole disk to compare
/// against `fb.image-raw`'s disk; the UEFI arm derives its USB source disk the same way).
/// (The deploy CLI passes a real `findmnt`-discovered partition, so this only fires on a malformed
/// cmdline; a bogus `/dev/<disk>` would also fail to open downstream — this just rejects earlier.)
pub fn disk_from_partition(partition: &str) -> Result<String, InstallerError> {
    let reject = || InstallerError::InvalidSourceDevice {
        key: "fb.restore-from".to_string(),
        device: partition.to_string(),
    };
                                                                                                     
                                                                                                  
                                                                                                        
                                                             
    if ["nvme", "mmcblk", "loop"]
        .iter()
        .any(|p| partition.starts_with(p))
    {
        for (i, _) in partition.match_indices('p') {
            let (disk, rest) = partition.split_at(i);
            let partnum = &rest[1..];                
            if disk.ends_with(|c: char| c.is_ascii_digit())
                && !partnum.is_empty()
                && partnum.bytes().all(|b| b.is_ascii_digit())
            {
                return Ok(disk.to_string());
            }
        }
        return Err(reject());
    }
                                                                                              
                                                                                  
    let disk = partition.trim_end_matches(|c: char| c.is_ascii_digit());
    if disk.len() == partition.len() || disk.is_empty() {
        return Err(reject());
    }
    Ok(disk.to_string())
}

                                                                                  

/// Byte offsets/sizes of the three components concatenated into the `.img` (boot-fs ‖ persist-skeleton
/// ‖ rootfs), parsed from the build's `<img>.layout.toml` sidecar (`recipes_image_builder::image::Layout`).
/// The installer reads the sidecar in 7.pre and slices the in-RAM `.img` into the boot-fs (→ the boot
/// partition), the persist-skeleton (→ persist), and the rootfs (→ slot A). The sidecar's
/// `rootfs_verity_hash_offset` is IGNORED here (build-owned now — baked into the boot-fs APPEND, no
/// longer cross-checked at install). Mirrors the offsets the `deploy dryrun`/`deploy verify` drivers
/// consume — one self-describing source of truth travels with the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageLayout {
    pub boot_offset: u64,
    pub boot_size: u64,
    pub persist_skeleton_offset: u64,
    pub persist_skeleton_size: u64,
    pub rootfs_offset: u64,
    pub rootfs_size: u64,
    /// dha Component E (O4=GPT): the weights component's byte range within the `.img` — `Some` only for a
    /// dha `.img` (both together, emitted by `render_layout_toml`). The installer slices `[weights_offset
    /// .. +weights_size]` and dd's it into the 5th GPT partition. `None` ⇒ a non-dha `.img` (no weights
            
    /// component; the install path is byte-identical to a plain box). The build-side
    /// `weights_verity_hash_offset` key is IGNORED here (a boot-time cmdline concern, not an install slice).
    pub weights_offset: Option<u64>,
    pub weights_size: Option<u64>,
    /// The firmware the image was built for (`.layout.toml` `firmware` token) — selects [`commit`]'s
    /// partition-table serializer: [`build_mbr_sector`] (SeaBIOS) vs [`build_gpt`] (UEFI).
    pub firmware: Firmware,
}

/// Derive the `.layout.toml` sidecar path from the `.img` path (`/tmp/x.img` → `/tmp/x.layout.toml`),
/// matching the `deploy dryrun`/`deploy verify` `with_extension("layout.toml")` convention so the
/// deploy CLI scp's both files side-by-side and the installer finds the sidecar without a new cmdline
/// key. The returned path is read RELATIVE to the mounted old-root (the `InstallOps` impl joins it).
pub fn layout_sidecar_path(image_path: &str) -> Result<String, InstallerError> {
    std::path::Path::new(image_path)
        .with_extension("layout.toml")
        .to_str()
        .map(str::to_string)
        .ok_or_else(|| InstallerError::MalformedImageLayout {
            reason: format!("non-utf8 sidecar path for image {image_path:?}"),
        })
}

/// Parse the `[layout]` sidecar (the flat `key = value` table `render_layout_toml` emits). A
/// hand-rolled parser — NOT a `toml`/`serde` dependency: `initramfs-init` is the minimal `libc`-only
/// PID-1 init (separate `panic = "abort"` workspace, smallest-surface/sovereignty axis), and the file
/// is six non-negative integers + one `firmware` string under one `[layout]` header. Pure + host-tested.
/// Fail closed (`MalformedImageLayout`) on a missing/duplicate/non-integer/negative field or an unknown
/// `firmware` token — the installer never slices the `.img` from an untrustworthy layout.
pub fn parse_image_layout(contents: &str) -> Result<ImageLayout, InstallerError> {
    let bad = |reason: String| InstallerError::MalformedImageLayout { reason };

    let mut boot_offset = None;
    let mut boot_size = None;
    let mut persist_skeleton_offset = None;
    let mut persist_skeleton_size = None;
    let mut rootfs_offset = None;
    let mut rootfs_size = None;
    let mut weights_offset = None;
    let mut weights_size = None;
    let mut firmware = None;

    for raw in contents.lines() {
        let line = raw.trim();
                                                                                   
        if line.is_empty() || line.starts_with('[') || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(bad(format!("line is not `key = value`: {line:?}")));
        };
        let key = key.trim();
        let value = value.trim();
                                                                                                         
                                                                                                           
                                                                                          
        if key == "firmware" {
            if firmware.is_some() {
                return Err(bad(format!("duplicate layout key {key:?}")));
            }
            let token = value.trim_matches('"');
            firmware = Some(Firmware::from_wire(token).ok_or_else(|| {
                bad(format!(
                    "layout.firmware not a known firmware token: {value:?}"
                ))
            })?);
            continue;
        }
        let slot = match key {
            "boot_offset" => &mut boot_offset,
            "boot_size" => &mut boot_size,
            "persist_skeleton_offset" => &mut persist_skeleton_offset,
            "persist_skeleton_size" => &mut persist_skeleton_size,
            "rootfs_offset" => &mut rootfs_offset,
            "rootfs_size" => &mut rootfs_size,
                                                                                                    
            "weights_offset" => &mut weights_offset,
            "weights_size" => &mut weights_size,
            _ => continue,
        };
        if slot.is_some() {
            return Err(bad(format!("duplicate layout key {key:?}")));
        }
        let parsed = value.parse::<u64>().map_err(|_| {
            bad(format!(
                "layout.{key} not a non-negative integer: {value:?}"
            ))
        })?;
        *slot = Some(parsed);
    }

    let field =
        |opt: Option<u64>, name: &str| opt.ok_or_else(|| bad(format!("missing layout.{name}")));
                                                                                                            
                                                                                                          
                                                                                    
    if weights_offset.is_some() != weights_size.is_some() {
        return Err(bad(
            "weights_offset and weights_size must both be present (a dha .img) or both absent"
                .to_string(),
        ));
    }
    Ok(ImageLayout {
        boot_offset: field(boot_offset, "boot_offset")?,
        boot_size: field(boot_size, "boot_size")?,
        persist_skeleton_offset: field(persist_skeleton_offset, "persist_skeleton_offset")?,
        persist_skeleton_size: field(persist_skeleton_size, "persist_skeleton_size")?,
        rootfs_offset: field(rootfs_offset, "rootfs_offset")?,
        rootfs_size: field(rootfs_size, "rootfs_size")?,
        weights_offset,
        weights_size,
        firmware: firmware.ok_or_else(|| bad("missing layout.firmware".to_string()))?,
    })
}

/// Fail closed if a component is larger than the fixed partition it is written to: the pre-baked
/// boot-fs must fit the boot partition, the rootfs (squashfs+verity) slot A, and the
/// persist-skeleton the persist partition. The old borrowed-slice `check_image_fits`, re-founded
/// on the [`crate::installer_stream::ComponentSpans`] LENGTHS (spec D6 — no in-RAM image exists
/// to slice). Checked in `prepare` BEFORE any write — a too-large component would otherwise
/// overrun its partition into the next one's LBA range.
pub fn check_components_fit(
    layout: &PartitionLayout,
    spans: &crate::installer_stream::ComponentSpans,
) -> Result<(), InstallerError> {
    let check = |component: &'static str, len: u64, capacity: u64| {
        if len > capacity {
            return Err(InstallerError::ComponentTooLargeForPartition {
                component,
                bytes: len,
                capacity,
            });
        }
        Ok(())
    };
                                                                                                 
                                                                                                  
                                       
    check("boot", spans.boot.1, layout.boot.sector_count * SECTOR_SIZE)?;
    check(
        "rootfs",
        spans.rootfs.1,
        layout.slot_a.sector_count * SECTOR_SIZE,
    )?;
    check(
        "persist-skeleton",
        spans.skel.1,
        layout.persist.sector_count * SECTOR_SIZE,
    )?;
                                                                                          
                                                                                                
                                                                                                  
                                         
    if let Some((_, weights_len)) = spans.weights {
        let weights_capacity = layout
            .weights
            .as_ref()
            .map_or(0, |w| w.sector_count * SECTOR_SIZE);
        check("weights", weights_len, weights_capacity)?;
    }
    Ok(())
}

                                                                         

/// Serialize the 512-byte MBR sector-0 from the computed layout (pure — host-tested; the raw write to
/// `/dev/<disk>` offset 0 is the FFI). Boot code area (bytes 0..440) is left zero — the syslinux
/// `mbr.bin` stage-1 is written there as the LAST commit step ([`InstallOps::write_mbr_bootcode`],
/// `conv=notrunc`), which preserves the partition table (446..510) + boot signature (510..512) this
/// builds. Each 16-byte entry carries the 0x80 active flag (boot partition only), the 0x83 Linux type,
/// and the LBA start + sector count (u32 LE); CHS fields are the `FE FF FF` "use-LBA" sentinel — every
/// BIOS/syslinux path the box boots on uses LBA (the CHS triple is not consulted), to be confirmed
/// empirically by the Task 13 disk-boot QEMU run.
/// `DiskTooLargeForMbr` if any LBA/count exceeds u32 (defense-in-depth; `compute_partition_layout`
/// already gated `disk_sectors ≤ u32::MAX`).
pub fn build_mbr_sector(layout: &PartitionLayout) -> Result<[u8; 512], InstallerError> {
    let mut mbr = [0u8; 512];
    for (i, part) in [
        &layout.boot,
        &layout.slot_a,
        &layout.slot_b,
        &layout.persist,
    ]
    .iter()
    .enumerate()
    {
        let start =
            u32::try_from(part.start_lba).map_err(|_| InstallerError::DiskTooLargeForMbr {
                sectors: part.start_lba,
            })?;
        let count =
            u32::try_from(part.sector_count).map_err(|_| InstallerError::DiskTooLargeForMbr {
                sectors: part.sector_count,
            })?;
        let off = 446 + i * 16;
        mbr[off] = if part.bootable { 0x80 } else { 0x00 };
                                                                                              
        mbr[off + 1..off + 4].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
        mbr[off + 4] = part.part_type;
                                                       
        mbr[off + 5..off + 8].copy_from_slice(&[0xFE, 0xFF, 0xFF]);
        mbr[off + 8..off + 12].copy_from_slice(&start.to_le_bytes());
        mbr[off + 12..off + 16].copy_from_slice(&count.to_le_bytes());
    }
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    Ok(mbr)
}

                                                               

/// The fixed canonical PARTUUID of slot A (the rootfs partition; spec §5). A documented literal — NOT
/// derived (UEFI spec RT-1 F1): a constant is more deterministic, verity owns rootfs content + selection,
/// and no consumer reads a per-image PARTUUID. Baked into the slot-A GPT entry ([`build_gpt`]) AND into
/// the UEFI kernel's `CONFIG_CMDLINE` (`recipes_image_builder` duplicates this exact literal — a
/// cross-crate equality test guards the pair); the in-init resolver matches it against the on-disk GPT
/// to find the `/dev` node. Generated once as a random v4 UUID; carries no operator secret.
pub const SLOT_A_PARTUUID: &str = "04c92659-e47a-485b-b840-fe5561eaa0da";
/// The fixed canonical PARTUUID of slot B (the inactive A/B slot). Distinct from slot A for the A/B
/// layout; only slot A's is load-bearing (the cmdline matches it), but a fixed + distinct value keeps
/// the serialized table byte-deterministic. Generated once as a random v4 UUID.
pub const SLOT_B_PARTUUID: &str = "a5dff702-a9ff-41a1-9243-30e6136aba95";
/// dha Component E (O4=GPT): the fixed canonical PARTUUID of the RO dm-verity **weights** partition (the
/// 5th GPT entry, present only on a dha box). The cmdline carries `fb.weights-dev=PARTUUID=`this and the
/// in-init resolver matches it against the on-disk GPT to find the `/dev` node (like slot A). Will be
/// DUPLICATED in `recipes_image_builder::boot_fs` (the cmdline producer, E2), guarded by a cross-crate
/// equality test. Generated once as a random v4 UUID; carries no operator secret.
pub const WEIGHTS_PARTUUID: &str = "7d3b9f24-6a1c-4e58-b0d9-2c4f8a6e1b35";
/// §9.5 UEFI signed-USB installer: the fixed canonical PARTUUID of the USB's **ext4 data partition**
/// carrying the box `.img` + its `.layout.toml`. The UEFI installer resolves this against the on-disk
/// GPT ([`find_partition_by_partuuid`]) to locate its source partition — independent of device
/// enumeration order, with no operator-supplied install-source token. DUPLICATED in
/// `recipes_image_builder::boot_fs` (the USB GPT serializer, §9.5 Task 4.1), guarded by a cross-crate
/// equality test like [`SLOT_A_PARTUUID`]. Generated once as a random v4 UUID; carries no operator secret.
pub const INSTALLER_DATA_PARTUUID: &str = "988794b1-f4c5-49a3-aebe-12b2dd91e58d";
/// §9.5: the built-in path of the box `.img` on the UEFI installer USB's data partition (the
/// [`INSTALLER_DATA_PARTUUID`] ext4). A build-baked constant (no operator input), whitespace-free by
/// construction; the `.layout.toml` sidecar is derived from it via [`layout_sidecar_path`].
pub const INSTALLER_DATA_IMG_PATH: &str = "/box.img";
/// The ESP (boot) + persist partitions' unique GUIDs. Not load-bearing (nothing matches on them), but
/// fixed + distinct so the serialized table is byte-deterministic. Generated once as random v4 UUIDs.
const ESP_PARTUUID: &str = "e9abb6ab-76cf-4b2e-aa9a-f53e2ae152dd";
const PERSIST_PARTUUID: &str = "95f6532c-6953-4b27-8f85-2ba29fb4b91e";
/// The disk's GUID (the GPT header `disk_guid` field). A fixed constant so the table is byte-reproducible;
/// carries no operator secret.
const DISK_GUID: &str = "d91aff31-df15-4b91-9478-2ff7512c006e";
/// EFI System Partition type GUID (UEFI 2.10 Table 5-7) — the boot partition's PARTITION TYPE.
const ESP_TYPE_GUID: &str = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
/// Linux filesystem-data type GUID — the A/B slots' + persist's partition type (addressed by GUID/LBA).
const LINUX_FS_TYPE_GUID: &str = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";

pub use fb_verity_rt::guid_to_mixed_endian;
/// GPT geometry (UEFI 2.10 §5.3): 128 entries × 128 bytes, a 92-byte header, first usable LBA at 34
/// (LBA0 protective MBR + LBA1 header + 32 entry-array sectors). The read-side halves
/// (`GPT_NUM_ENTRIES`/`GPT_HEADER_BYTES`, `crc32`, `guid_to_mixed_endian`) moved to the extracted
/// runtime layer (hotswap v4 §9/R3-I7) — the WRITER below consumes them back from there so the two
/// sides can never diverge. `guid_to_mixed_endian` is re-exported for this module's tests + doc links.
use fb_verity_rt::{GPT_HEADER_BYTES, GPT_NUM_ENTRIES, crc32};
const GPT_ENTRY_SIZE: usize = 128;
const GPT_FIRST_USABLE_LBA: u64 = 34;

/// A serialized GPT, ready for the install-time block writes. `primary` is the front region (LBA0
/// protective MBR + LBA1 header + the 32-sector entry array = 34 sectors, written at LBA0); `backup` is
/// the tail region (the 32-sector entry array + the backup header = 33 sectors), written at
/// `backup_lba`. They are split because they land at different disk offsets; the FFI
/// ([`crate::installer_syscall`]) writes both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GptImage {
    pub primary: Vec<u8>,
    pub backup: Vec<u8>,
    pub backup_lba: u64,
}

/// Serialize the GPT (protective MBR + primary header + 128-entry array + the mirrored backup) for the
/// computed `layout` on a `disk_sectors`-sector disk (pure — host-tested; the raw block writes are the
/// FFI, OVMF-gated). The GPT analog of [`build_mbr_sector`], shared by both GPT firmwares. `firmware`
               
/// selects the boot partition's shape: UEFI gives it the ESP type GUID, no attributes, and
/// a non-active protective MBR; SeabiosGpt gives it the Linux-fs type GUID, the `legacy_boot` attribute
/// (bit 2), and the 0x80 active flag on the protective-MBR 0xEE entry — the only firmware-conditional
/// bytes. All GUIDs are fixed constants, so the output is byte-reproducible. Fails closed
/// ([`InstallerError::OpFailed`]) on a malformed constant GUID or a non-GPT firmware — never emit a
/// garbage table. `disk_sectors` MUST be the value passed to [`compute_partition_layout`] for this
/// `layout` (the caller — [`commit`] — threads one disk size).
pub fn build_gpt(
    layout: &PartitionLayout,
    disk_sectors: u64,
    firmware: Firmware,
) -> Result<GptImage, InstallerError> {
    let bad_guid = |g: &str| InstallerError::OpFailed {
        op: "build_gpt",
        reason: format!("malformed constant GUID {g:?}"),
    };

                                                                                             
    let mut entries = vec![0u8; GPT_NUM_ENTRIES as usize * GPT_ENTRY_SIZE];
                                                                                                       
                                                                                                    
                                                                                                          
                                                                                                   
                                                                
    const GPT_ATTR_LEGACY_BOOT: u64 = 1 << 2;
    let (boot_type_guid, boot_attrs): (&str, u64) = match firmware {
        Firmware::SeabiosGpt => (LINUX_FS_TYPE_GUID, GPT_ATTR_LEGACY_BOOT),
        Firmware::Uefi => (ESP_TYPE_GUID, 0),
        Firmware::Seabios => {
            return Err(InstallerError::OpFailed {
                op: "build_gpt",
                reason: "SeaBIOS/MBR firmware has no GPT".to_string(),
            });
        }
    };
    let mut table: Vec<(usize, &str, &str, &Partition, u64)> = vec![
        (0, boot_type_guid, ESP_PARTUUID, &layout.boot, boot_attrs),
        (1, LINUX_FS_TYPE_GUID, SLOT_A_PARTUUID, &layout.slot_a, 0u64),
        (2, LINUX_FS_TYPE_GUID, SLOT_B_PARTUUID, &layout.slot_b, 0u64),
        (
            3,
            LINUX_FS_TYPE_GUID,
            PERSIST_PARTUUID,
            &layout.persist,
            0u64,
        ),
    ];
                                                                                               
                                                                                                       
                                                                                                    
                                                                                                       
    if let Some(w) = &layout.weights {
        table.push((4, LINUX_FS_TYPE_GUID, WEIGHTS_PARTUUID, w, 0u64));
    }
    for (idx, type_guid, unique_guid, part, attrs) in table {
        let off = idx * GPT_ENTRY_SIZE;
        entries[off..off + 16]
            .copy_from_slice(&guid_to_mixed_endian(type_guid).ok_or_else(|| bad_guid(type_guid))?);
        entries[off + 16..off + 32].copy_from_slice(
            &guid_to_mixed_endian(unique_guid).ok_or_else(|| bad_guid(unique_guid))?,
        );
        entries[off + 32..off + 40].copy_from_slice(&part.start_lba.to_le_bytes());
        let last_lba = part.start_lba + part.sector_count - 1;             
        entries[off + 40..off + 48].copy_from_slice(&last_lba.to_le_bytes());
        entries[off + 48..off + 56].copy_from_slice(&attrs.to_le_bytes());                                                             
                                                                                   
    }
    let entries_crc = crc32(&entries);

    let disk_guid = guid_to_mixed_endian(DISK_GUID).ok_or_else(|| bad_guid(DISK_GUID))?;
    let last_usable = disk_sectors - GPT_FIRST_USABLE_LBA;                       
    let backup_header_lba = disk_sectors - 1;
    let backup_entries_lba = disk_sectors - GPT_BACKUP_SECTORS;                                             

                                                                                                 
    let header = |my_lba: u64, alt_lba: u64, entry_lba: u64| -> [u8; GPT_HEADER_BYTES] {
        let mut h = [0u8; GPT_HEADER_BYTES];
        h[0..8].copy_from_slice(b"EFI PART");
        h[8..12].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]);                
        h[12..16].copy_from_slice(&(GPT_HEADER_BYTES as u32).to_le_bytes());
                                                                        
        h[24..32].copy_from_slice(&my_lba.to_le_bytes());
        h[32..40].copy_from_slice(&alt_lba.to_le_bytes());
        h[40..48].copy_from_slice(&GPT_FIRST_USABLE_LBA.to_le_bytes());
        h[48..56].copy_from_slice(&last_usable.to_le_bytes());
        h[56..72].copy_from_slice(&disk_guid);
        h[72..80].copy_from_slice(&entry_lba.to_le_bytes());
        h[80..84].copy_from_slice(&GPT_NUM_ENTRIES.to_le_bytes());
        h[84..88].copy_from_slice(&(GPT_ENTRY_SIZE as u32).to_le_bytes());
        h[88..92].copy_from_slice(&entries_crc.to_le_bytes());
        let crc = crc32(&h);                                                                      
        h[16..20].copy_from_slice(&crc.to_le_bytes());
        h
    };
    let primary_header = header(1, backup_header_lba, 2);
    let backup_header = header(backup_header_lba, 1, backup_entries_lba);

                                                                                            
    let sector = SECTOR_SIZE as usize;
    let mut pmbr = [0u8; SECTOR_SIZE as usize];
                                                                                                          
                                                                                          
    if firmware == Firmware::SeabiosGpt {
        pmbr[446] = 0x80;
    }
    pmbr[447..450].copy_from_slice(&[0x00, 0x02, 0x00]);                        
    pmbr[450] = 0xEE;                       
    pmbr[451..454].copy_from_slice(&[0xFF, 0xFF, 0xFF]);                    
    pmbr[454..458].copy_from_slice(&1u32.to_le_bytes());                    
                                                                                                      
    let pmbr_size = u32::try_from(disk_sectors - 1).unwrap_or(u32::MAX);
    pmbr[458..462].copy_from_slice(&pmbr_size.to_le_bytes());
    pmbr[510] = 0x55;
    pmbr[511] = 0xAA;

                                     
    let mut primary = vec![0u8; 34 * sector];                                             
    primary[0..sector].copy_from_slice(&pmbr);
    primary[sector..sector + GPT_HEADER_BYTES].copy_from_slice(&primary_header);
    primary[2 * sector..2 * sector + entries.len()].copy_from_slice(&entries);

    let mut backup = vec![0u8; GPT_BACKUP_SECTORS as usize * sector];                                      
    backup[0..entries.len()].copy_from_slice(&entries);
    backup[32 * sector..32 * sector + GPT_HEADER_BYTES].copy_from_slice(&backup_header);

    Ok(GptImage {
        primary,
        backup,
        backup_lba: backup_entries_lba,
    })
}

/// The GPT READ side (`gpt_header_crc_valid` + `find_partition_by_partuuid`) — moved VERBATIM to
/// `fb_verity_rt::discover` (hotswap v4 §9/R3-I7); re-exported so the writer↔reader consistency
/// tests keep cross-checking `build_gpt`'s output through the same parse the runtime uses.
/// (io-flavored `Err` now; `installer_syscall::resolve_partuuid` re-wraps into [`InstallerError`].)
pub use fb_verity_rt::{find_partition_by_partuuid, gpt_header_crc_valid};

                                                                                               
                                                                                                   
                                                                                               
                                                                              
                                                                                              
                                                                                                
                                                     

                                                                   

/// SHA-256 of a buffer — the `sha2` no-default-features dep (core-only tree), mirroring the sibling
/// rambutan loader's `sha2_256`. Used by the UEFI installer to hash the box `.img` against the
/// loader-baked `fb.image-sha256` before any write.
pub fn sha2_256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// §9.5 verify-before-write: does `data` (the whole box `.img`) hash to `expected`? Plain compare — the
/// digest is PUBLIC (a const inside the SB-signed loader cmdline), so this is integrity, not a MAC
/// (mirrors rambutan's `initrd_digest_ok`). A mismatch is the UEFI installer's fail-closed halt.
pub fn verify_image_digest(data: &[u8], expected: &[u8; 32]) -> bool {
    &sha2_256(data) == expected
}

                                                                        

/// Which pre-baked `.img` component a [`InstallOps::dd_component`] call writes → its fixed partition:
/// the boot-fs → partition 1, the rootfs → slot A (partition 2), the persist-skeleton → persist
/// (partition 4). (Slot B, partition 3, is zeroed separately by [`InstallOps::zero_slot_b`].) dha
/// Component E adds the RO dm-verity weights volume → the 5th GPT partition (GPT firmwares only; a dha
/// `.img` is always GPT under O4=(a)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallComponent {
    Boot,
    Rootfs,
    PersistSkeleton,
    /// dha Component E: the RO dm-verity weights volume → the 5th GPT partition.
    Weights,
}

/// The serialized partition table handed to [`InstallOps::write_partition_table`] at 7a — the firmware
/// seam. SeaBIOS is a single 512-byte MBR sector at LBA0; UEFI's GPT splits into a primary (LBA0)
/// and a backup (the disk tail), which land at different offsets, so the variant carries both regions +
/// the backup's start LBA. Host-serialized ([`build_mbr_sector`] / [`build_gpt`]); the FFI writes the
/// raw bytes.
#[derive(Debug, Clone, Copy)]
pub enum PartitionTable<'a> {
    /// SeaBIOS: the 512-byte MBR sector, written at LBA0.
    Mbr(&'a [u8]),
    /// UEFI: the GPT — `primary` (protective MBR + header + entry array) at LBA0, `backup` (entry array
    /// + backup header) at `backup_lba` (a [`SECTOR_SIZE`]-sector LBA).
    Gpt {
        primary: &'a [u8],
        backup: &'a [u8],
        backup_lba: u64,
    },
}

/// The side-effecting operations the installer performs, as an effects seam (dependency injection so
/// the orchestration is host-testable). The real implementation ([`crate::installer_syscall`]) is raw
/// block I/O + the old-root mount + `reboot(2)` — it execs NOTHING and formats NOTHING (the three
/// filesystems are pre-baked build-side); it is exercised by the QEMU install run. Host units drive
/// [`run_install`] against a recording fake to lock the ORDERING invariants.
///
/// Two non-overlapping phases (mirrors [`run_install`] / [`prepare`] / [`commit`]):
/// - **7.pre — read/verify (NO destructive disk writes):** `mount_old_root`, `read_old_root_file`,
///   `verify_restore_image`, `unmount_old_root`.
/// - **commit (destructive; bootable-last):** everything from `write_partition_table` onward. The bytes
///   each `dd_component` writes are host-sliced + capacity-checked ([`image_slices`] /
///   [`check_image_fits`]) before the first write; the impl only seeks 0 + writes + fsyncs.
pub trait InstallOps {
                                                             
    /// Mount the old Debian root read-only at the install scratch mountpoint. A failure here aborts
               
    /// the install BEFORE any partition write. On the streaming raw arm this is RESTORE-ONLY (greenfield mounts nothing; the target binds from the token via set_target_disk) — the impl still re-derives + binds the
    /// destructive write target to this partition's whole disk (target = source disk); the UEFI arm
    /// uses [`InstallOps::mount_data_partition`] instead, which does NOT bind a target.
    fn mount_old_root(&mut self, device: &str) -> Result<(), InstallerError>;
    /// §9.5 UEFI: resolve the built-in [`INSTALLER_DATA_PARTUUID`] to its bare partition device name
    /// (e.g. `sda2`) by scanning the box's GPT disks (the real impl mirrors the runtime PARTUUID
    /// resolver). The UEFI installer's `prepare` arm uses this to locate its source partition; the
    /// returned name feeds [`InstallOps::mount_data_partition`] (and, Task 2.4, the source-disk
    /// exclusion). Non-destructive.
    fn resolve_partuuid(&mut self, partuuid: &str) -> Result<String, InstallerError>;
    /// §9.5 UEFI: mount the installer's source data partition (`device`, a bare partition name)
    /// read-only at the install scratch mountpoint. UNLIKE [`InstallOps::mount_old_root`], this does
    /// **not** set the destructive write target — the target is selected independently (§6 H-1). A
               
    /// failure aborts before any write.
    fn mount_data_partition(&mut self, device: &str) -> Result<(), InstallerError>;
    /// Read a file (the `.img`, its `.layout.toml`, the restore image, its `.sig`) from the mounted
    /// old-root into RAM.
    fn read_old_root_file(&mut self, path: &str) -> Result<Vec<u8>, InstallerError>;
    /// The logical size (bytes) of an old-root file, WITHOUT reading it (`metadata().len()`). Used to
                            
    /// enforce the restore-image cap BEFORE `read_old_root_file` allocates: the
    /// restore image is the one attacker-influenced input read into RAM at this panic=abort PID-1 gate.
    fn old_root_file_size(&mut self, path: &str) -> Result<u64, InstallerError>;
    /// Verify the restore image's detached signature against the operator-sovereign raw ed25519 ROOT
    /// pubkey (hex, baked into the initramfs). `min_ctr` is the parsed `fb.min-ctr` anti-rollback
    /// floor (0 = no floor), enforced INSIDE the quince cascade (Task 4.3 spec §5 / C1 §6e). A
                
    /// failure aborts BEFORE any partition write. LIVE since C1 (quince → dragonfruit,
    /// clock-free, `Purpose::Backup`).
    fn verify_restore_image(
        &mut self,
        image: &[u8],
        sig: &[u8],
        operator_root_pubkey_hex: &[u8],
        min_ctr: u64,
    ) -> Result<(), InstallerError>;
    /// The box's total RAM in bytes (`/proc/meminfo` MemTotal), for the RAM-aware restore cap
    /// (spec §4b-1). `None` = unreadable/unparseable — [`restore_cap`] then falls back to the
    /// static ceiling (the no-regression direction). Non-destructive.
    fn mem_total_bytes(&mut self) -> Option<u64>;
    /// Unmount the old-root before entering the destructive write phase.
    fn unmount_old_root(&mut self) -> Result<(), InstallerError>;

                                                      
    /// Read the target disk's total size (for [`compute_partition_layout`]). Non-destructive.
    fn disk_size_bytes(&mut self) -> Result<u64, InstallerError>;
    /// 7a: write the partition table + re-read it so the `/dev/<disk><n>` nodes appear. The FIRST
                
    /// destructive write; the 7.pre verify precedes it. [`PartitionTable`] is the firmware
    /// seam: SeaBIOS = the 512-byte MBR at LBA0 (boot-code 0..440 still zero → NOT yet bootable); UEFI =
    /// the GPT primary (LBA0) + backup (the disk tail). The disk is not bootable until its boot/ESP
           
    /// component lands (bootable-last). The impl writes the raw bytes (+ the stale-table
    /// invalidation on UEFI).
    fn write_partition_table(&mut self, table: PartitionTable) -> Result<(), InstallerError>;
    /// Raw-write a pre-baked component to its fixed partition (boot=1, slot A=2, persist=4). `bytes` is
    /// the host-sliced component (bounds- + capacity-checked before any write); the impl seeks 0 +
    /// writes + fsyncs the partition device. No mount, no format, no exec. KEPT for the restore
    /// Vec ONLY under the streaming redesign (the persist dd swap) — image components stream
    /// through the chunk primitives below (spec D6).
    fn dd_component(&mut self, which: InstallComponent, bytes: &[u8])
    -> Result<(), InstallerError>;

                                                                                              
                                                                                     
                                                                                  
                                                    

    /// Read up to `buf.len()` bytes at `offset` within the source (staged raw region, or the
    /// mounted source file on the UEFI arm) into `buf`; returns the byte count (0 = EOF; a
    /// partial count is legal — the driver loops). Non-destructive.
    fn read_source_chunk(
        &mut self,
        src: &crate::installer_stream::SourceHandle,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, InstallerError>;
    /// Write `buf` at `offset` within `which`'s partition device (destructive — commit phase only).
    fn write_partition_chunk(
        &mut self,
        which: InstallComponent,
        offset: u64,
        buf: &[u8],
    ) -> Result<(), InstallerError>;
    /// Read back up to `buf.len()` bytes at `offset` within `which`'s partition for the post-write
    /// verify. The real impl opens the device `O_DIRECT` with page-aligned buffers (spec D7 — a
    /// buffered read would re-verify the page cache the write itself populated). Non-destructive.
    fn read_partition_chunk(
        &mut self,
        which: InstallComponent,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, InstallerError>;
    /// Flush `which`'s partition device: once per component, after its copy loop, BEFORE its
    /// readback (spec D7 ordering).
    fn fsync_partition(&mut self, which: InstallComponent) -> Result<(), InstallerError>;
    /// 7d: zero slot B (the inactive slot starts empty), bounded by the layout's slot size.
    fn zero_slot_b(&mut self, layout: &PartitionLayout) -> Result<(), InstallerError>;
    /// The LAST destructive write (SeaBIOS-only): the 440-byte syslinux MBR stage-1 (`mbr.bin`, dd'd —
    /// NOT executed) to disk offset 0 with `conv=notrunc` (preserves the partition table written at
    /// 7a). The disk becomes bootable HERE — so any earlier dd failure leaves a cleanly-unbootable disk.
    fn write_mbr_bootcode(&mut self) -> Result<(), InstallerError>;
    /// The LAST destructive write (SeabiosGpt-only): the 440-byte GPT-aware syslinux stage-1
    /// (`gptmbr.bin`, dd'd — NOT executed) to disk offset 0 with `conv=notrunc` (preserves the
    /// protective MBR + GPT written at 7a, incl. the 0x80 active flag). It chains to the `legacy_boot`
    /// boot partition; the disk becomes bootable HERE — the GPT analog of `write_mbr_bootcode`.
    fn write_gptmbr_bootcode(&mut self) -> Result<(), InstallerError>;
    /// 7h: `sync()` + `reboot(2)` into the installed disk. Does not return on success.
    fn finalize_and_reboot(&mut self) -> Result<(), InstallerError>;

                                                                                      
    /// Enumerate the box's block disks as [`DiskInfo`] (`/sys/block` + each disk's `removable` flag) so
    /// the pure [`select_target`] can pick the independent install target (§6 H-1). Non-destructive.
    fn enumerate_disks(&mut self) -> Result<Vec<DiskInfo>, InstallerError>;
    /// Set the destructive-write target disk (the bare whole-disk name `select_target` returned). On the
    /// UEFI arm this — NOT `mount_old_root` — is what binds the target, so the wipe is independent of the
    /// source USB. Must be called before the commit phase on the `BuiltinDataPartuuid` path.
    fn set_target_disk(&mut self, disk: &str);
}

/// Inputs to [`run_install`] sourced from the initramfs + the parsed cmdline. (`target_disk` size +
/// device are owned by the [`InstallOps`] impl — operator-side auto-detection bakes the device, the
/// impl reads the size via `disk_size_bytes`.) Under the dd-only redesign the runtime kernel cmdline
/// (the boot-fs `extlinux.conf` APPEND) and the operator pubkey (the persist-skeleton) are BAKED into
/// the pre-baked components build-side, so the installer no longer carries a `BootConfig` or a pubkey.
pub struct InstallParams<'a> {
    /// The typed install source ([`InstallSource`]) + the optional restore image (`fb.restore-from`,
    /// SeaBIOS/kexec only).
    pub sources: &'a InstallSources,
    /// The raw 32-byte operator ed25519 ROOT pubkey, hex-encoded (initramfs-resident
    /// `/etc/recipes/artifact-root.pub`), the trust anchor for the restore-image signature (spec §6d;
    /// consumed only by the restore-from `verify_restore_image` — greenfield never reads it). Best-effort /
    /// possibly-empty; the fail-closed hex decode lives in `verify_restore_image` (C1).
    pub operator_root_pubkey_hex: &'a [u8],
    /// §9.5 UEFI verify-before-write: the SHA-256 the box `.img` must match (decoded from the
    /// loader-baked `fb.image-sha256`). `None` on SeaBIOS/kexec (no digest-verify) AND on a UEFI cmdline
    /// missing the token — the `BuiltinDataPartuuid` `prepare` arm fail-closes when it is `None`.
    pub image_sha256: Option<[u8; 32]>,
    /// §9.5 UEFI: the optional explicit whole-disk install target (`fb.install-to`, validated at parse).
    /// `None` ⇒ auto-select the single eligible internal disk. Consumed by [`select_target`] in
    /// [`run_install`]; `None`/ignored on SeaBIOS (which binds target = source).
    pub install_to: Option<&'a str>,
}

/// In-RAM data read + verified in 7.pre, consumed by the commit phase. Constructed ONLY by
/// [`prepare`] (after a successful mount → read → optional-verify → unmount); [`commit`] takes it by
/// value. The module's PUBLIC surface is exactly [`run_install`]: `prepare`/`commit` are private and
/// this token has private fields, so no external caller can reach the destructive phase except via
                     
/// `run_install` (which always sequences prepare→commit) — verify-before-write and
/// mount-fail-aborts-before-write hold for every caller of `run_install`. (The destructive
/// [`InstallOps`] methods are the effects seam and are `pub`; they are not meant to be called directly
/// — the ordering guarantee is the discipline of going through `run_install`, not a per-method type
/// proof. In the trust model no untrusted code holds the `ops` value, so this is sound.)
#[must_use]
struct PreparedInstall {
    /// The chunk source every commit-phase copy reads from (the staged raw window, or the mounted
    /// USB file on the UEFI arm) — no image bytes are ever held in RAM (spec D6: the Vec is gone;
    /// peak RAM is O(chunk)).
    source: crate::installer_stream::SourceHandle,
    /// The component geometry (image-relative offsets/lens) both arms were validated against —
    /// bounds- and fit-checked in [`prepare`] before minting.
    spans: crate::installer_stream::ComponentSpans,
    /// The digest pre-pass output (spec D7): whole-region digest verified against the mandatory
    /// `fb.image-sha256`, per-component digests consumed by the commit-phase readbacks.
    digests: crate::installer_stream::ComponentDigests,
    /// The firmware the `.img` was built for — selects [`commit`]'s partition-table serializer
    /// ([`build_mbr_sector`] vs [`build_gpt`]). Raw arm: the D3 token authority; UEFI: the sidecar.
    firmware: Firmware,
    /// The VERIFIED restore persist image (restore-from only; `None` for greenfield). EXACTLY ONE
    /// reader: `commit`'s dd swap (the image is dd'd at the PersistSkeleton slot in place of the
    /// skeleton copy — restore APPLIED, spec §4a / AC3). The old-root unmounts immediately after
    /// the verify, so there is no re-read path: the only `/persist` source is these verified bytes
    /// (the verify→write TOCTOU-free handoff).
    restore_image: Option<Vec<u8>>,
    /// The [`prepare`]-computed-and-geometry-checked partition layout, consumed by [`commit`]
    /// WITHOUT re-derivation (spec S5 fold: prepare/commit agreement by construction).
    partition_layout: PartitionLayout,
    /// The disk size `partition_layout` was computed from (the GPT serializer needs the sector
    /// count; carried so commit re-probes nothing).
    disk_bytes: u64,
}

/// Run the installer-mode flow (spec steps 7.pre → 7h). Validates + verifies everything
/// non-destructively (incl. the target selection/binding — raw arm: the `fb.image-raw` token;
/// UEFI: the independent §6 H-1 selection, both inside [`prepare`]), then — only on full success —
/// partitions the target disk, chunk-copies the staged components onto it with per-component
/// readbacks, writes the stage-1 bootcode LAST (bootable-last), and reboots into the runtime.
/// Fail-closed at every step; a prepare failure aborts before any destructive write.
pub fn run_install<O: InstallOps>(
    ops: &mut O,
    params: &InstallParams,
) -> Result<(), InstallerError> {
    let prepared = prepare(ops, params)?;
    commit(ops, params, prepared)
}

/// Hard STATIC ceiling on the restore-image read. The restore image is the one attacker-influenced
/// installer input (it comes from compromisable `/persist`), read into a `Vec` at a `panic=abort`
/// PID-1 gate — an unbounded read OOM-aborts the init. The effective bound is [`restore_cap`]
/// (min of this ceiling and the RAM-derived bound, spec §4b-1); the check is
/// `metadata().len() > cap ⇒ abort` strictly BEFORE the read. Deliberate TWIN of image-builder's
/// `RESTORE_ASSEMBLY_CEILING_BYTES` (the assembler refuses to BAKE past this; AC6 keeps the box
/// side dep-free, so the constant is duplicated, not shared) — keep the two in lockstep.
pub const MAX_RESTORE_IMAGE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// The detached `.sig` bundle is a FIXED 254 bytes (dragonfruit's `BUNDLE_FILE_LEN`). Cap its read
                   
/// generously: like the image it is attacker-influenced (a sibling on compromisable
/// `/persist`), and an uncapped read of a planted multi-GB `.sig` would OOM-abort the `panic=abort` init
/// BEFORE the verify runs (the image cap does NOT cover the `.sig`).
pub const MAX_RESTORE_SIG_BYTES: u64 = 4 * 1024;

/// Fixed headroom the RAM-aware restore cap reserves for the init + kernel + the streaming
/// engine's O(chunk) copy/`O_DIRECT` buffers + slack (spec D5). A RENAME of the pre-streaming
/// `RESTORE_RAM_HEADROOM_BYTES` with the VALUE kept (plan R1-8 — not a re-tune): the `.img` is no
/// longer held in RAM, so the formula below drops the held-image term, and this name cannot be
/// confused with orchard's retired operator-side headroom (spec D14).
pub const RESTORE_CAP_HEADROOM_BYTES: u64 = 256 * 1024 * 1024;

/// The RAM-aware restore-image cap (spec §4b-1 / D5): `min(static ceiling, MemTotal − headroom)`,
/// SATURATING (a tiny-RAM underflow yields 0 ⇒ every restore refuses — fail closed, no wrap).
/// The held-`.img` term is GONE (the streaming redesign holds no image bytes — net effect: MORE
/// restore headroom, same posture). `mem_total = None` (unreadable/unparseable `/proc/meminfo`)
/// ⇒ the static [`MAX_RESTORE_IMAGE_BYTES`] ceiling alone — a meminfo regression can never
/// LOOSEN the cap (no-regression direction). Pure — host-unit-tested in both directions.
pub fn restore_cap(mem_total: Option<u64>) -> u64 {
    match mem_total {
        None => MAX_RESTORE_IMAGE_BYTES,
        Some(total) => {
            MAX_RESTORE_IMAGE_BYTES.min(total.saturating_sub(RESTORE_CAP_HEADROOM_BYTES))
        }
    }
}

/// Hard cap on the UEFI arm's `.layout.toml` sidecar read (spec D10): the sidecar is a small flat
/// key=value table; a multi-GB file at its path is hostile/corrupt — refuse before allocating.
pub const MAX_LAYOUT_SIDECAR_BYTES: u64 = 64 * 1024;

/// Parse `/proc/meminfo`'s `MemTotal:  <n> kB` line to bytes. Any shape surprise ⇒ `None` (the
/// caller falls back to the static ceiling — never a guessed number). Pure — host-unit-tested.
pub fn parse_meminfo_total(meminfo: &str) -> Option<u64> {
    let line = meminfo.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kb = line
        .strip_prefix("MemTotal:")?
        .trim()
        .strip_suffix("kB")?
        .trim();
    kb.parse::<u64>().ok().map(|k| k.saturating_mul(1024))
}

/// The §4b-2/-3 restore-image identity pre-checks — a deliberate ~10-line REIMPLEMENTATION of
/// image-builder's `check_restore_identity` offsets (its twin names this one): AC6 keeps the box
/// installer at ZERO new deps, so the two anchor to the same spec §4b facts rather than a shared
/// crate. Magic first (a non-ext4 payload is the signed-daily-tar mixup, C-R2-5), then the journal
/// COMPAT bit (a journaled image would skip box-init's journal-absence-gated first-boot grow and
/// strand the restore at its baked size). The LABEL is not checked here — the box asserts it at
/// boot (`findfs LABEL=persist`), and the §6 gate asserts it on the booted system.
fn check_restore_image_identity(image: &[u8]) -> Result<(), InstallerError> {
    let sb = image
        .get(1024..1024 + 0x60)
        .ok_or_else(|| InstallerError::OpFailed {
            op: "restore-ext4-magic",
            reason: format!(
                "restore image is {} bytes — too short for an ext4 superblock",
                image.len()
            ),
        })?;
    let magic = u16::from_le_bytes([sb[56], sb[57]]);
    if magic != 0xEF53 {
        return Err(InstallerError::OpFailed {
            op: "restore-ext4-magic",
            reason: format!(
                "restore image is not ext4 (superblock magic {magic:#06x}, want 0xef53) — a \
                 signed daily TAR passed as the image? assemble with `orchard restore-image`"
            ),
        });
    }
    let compat = u32::from_le_bytes([sb[0x5C], sb[0x5D], sb[0x5E], sb[0x5F]]);
    if compat & 0x4 != 0 {
        return Err(InstallerError::OpFailed {
            op: "restore-journal-present",
            reason: "restore image has an ext4 journal (COMPAT has_journal) — box-init gates the \
                     first-boot grow on journal-ABSENCE; a journaled image strands the restore at \
                     its baked size (bake with `orchard restore-image`: -O ^has_journal)"
                .to_string(),
        });
    }
    Ok(())
}

/// 7.pre — the non-destructive validate/verify phase, per source arm (spec §5). NO destructive
                                             
/// disk writes happen here. Any failure (a mount failure, a verify/digest failure) aborts
/// before the commit phase. Returning a [`PreparedInstall`] is the proof
/// that 7.pre fully succeeded.
fn prepare<O: InstallOps>(
    ops: &mut O,
    params: &InstallParams,
) -> Result<PreparedInstall, InstallerError> {
    match &params.sources.source {
        InstallSource::RawRegion { region, layout } => prepare_raw(ops, params, region, layout),
        InstallSource::BuiltinDataPartuuid => prepare_uefi(ops, params),
    }
}

/// The SeaBIOS-family raw-tail arm (spec §5 steps 1–7, in exactly that order): bind the target
/// from the token (step 2 — greenfield mounts NOTHING), geometry-check the staged window against
/// the written set (step 3), bounds/fit-check the layout metadata (step 4), run the unchanged
/// restore read/verify flow when present (step 5, with the probed-length geometry re-check),
/// digest the staged region against the MANDATORY `fb.image-sha256` (step 6), mint (step 7).
fn prepare_raw<O: InstallOps>(
    ops: &mut O,
    params: &InstallParams,
    region: &crate::installer_stream::RawRegion,
    layout: &crate::installer_stream::StreamLayout,
) -> Result<PreparedInstall, InstallerError> {
    use crate::installer_stream as stream;
                                                                                                   
                                                                   
    ops.set_target_disk(&region.disk);
    let disk_bytes = ops.disk_size_bytes()?;
    let weights_size = layout.weights.map(|(_, len)| len);
    let partition_layout = compute_partition_layout(disk_bytes, layout.firmware, weights_size)?;
    let spans = stream::ComponentSpans::from_stream_layout(layout);
                                                                                                   
                                                                                                  
                                                         
    let tail_reserve = tail_reserve_bytes(layout.firmware);
    let geometry_err = |e: stream::StreamError| match e {
        stream::StreamError::StagingOverlapsInstall {
            window_start,
            window_end,
            hit,
        } => InstallerError::StagingOverlapsInstall {
            window_start,
            window_end,
            hit,
        },
        stream::StreamError::StagingWindowOutOfBounds { window_end, .. } => {
            InstallerError::StagingOverlapsInstall {
                window_start: region.offset,
                window_end,
                hit: "tail-bounds",
            }
        }
        other => InstallerError::BadStreamToken(other),
    };
    let set = stream::written_set(&partition_layout, disk_bytes, layout.firmware, spans.skel.1);
    stream::check_staging_disjoint(region, &set, disk_bytes, tail_reserve).map_err(geometry_err)?;
                                                                                                 
                                  
    stream::check_spans_in_bounds(&spans, region.len)?;
    check_components_fit(&partition_layout, &spans)?;
                                                                                                
                                                                                                        
                                                           
    let mut restore_image: Option<Vec<u8>> = None;
    if let Some(rf) = &params.sources.restore_from {
        ops.mount_old_root(&rf.device)?;
        let restore_size = ops.old_root_file_size(&rf.path)?;
                                                                                                    
                                                                                              
                                                                                       
        let prefix = spans.skel.1.max(restore_size);
        let set = stream::written_set(&partition_layout, disk_bytes, layout.firmware, prefix);
        stream::check_staging_disjoint(region, &set, disk_bytes, tail_reserve)
            .map_err(geometry_err)?;
        let cap = restore_cap(ops.mem_total_bytes());
        if restore_size > cap {
            return Err(InstallerError::OpFailed {
                op: "restore-size-cap",
                reason: format!(
                    "restore image {restore_size} bytes exceeds the {cap}-byte cap (static ceiling \
                     {MAX_RESTORE_IMAGE_BYTES}, RAM-aware — spec §4b-1)"
                ),
            });
        }
        let restore = ops.read_old_root_file(&rf.path)?;
                                                                                                    
                                                                                                  
                                                                                   
        let sig_path = format!("{}.sig", rf.path);
        let sig_size = ops.old_root_file_size(&sig_path)?;
        if sig_size > MAX_RESTORE_SIG_BYTES {
            return Err(InstallerError::OpFailed {
                op: "restore-sig-cap",
                reason: format!(
                    "restore .sig {sig_size} bytes exceeds the {MAX_RESTORE_SIG_BYTES}-byte cap (a valid bundle is 254 bytes)"
                ),
            });
        }
        let sig = ops.read_old_root_file(&sig_path)?;
                                                                                                    
        ops.verify_restore_image(
            &restore,
            &sig,
            params.operator_root_pubkey_hex,
            params.sources.min_ctr,
        )?;
                                                                                              
                                                                                                     
                                                 
        check_restore_image_identity(&restore)?;
                                                                                                 
                                                                                                
                              
        restore_image = Some(restore);
        ops.unmount_old_root()?;
    }
                                                                                                 
                                                                                                 
                                                                           
    let expected = params
        .image_sha256
        .ok_or(InstallerError::MissingImageSha256)?;
    let source = crate::installer_stream::SourceHandle::Raw(region.clone());
    let digests = stream::digest_prepass(ops, &source, &spans, &expected)?;
                                                                                                   
                
    Ok(PreparedInstall {
        source,
        spans,
        digests,
        firmware: layout.firmware,
        restore_image,
        partition_layout,
        disk_bytes,
    })
}

/// The §9.5 UEFI signed-USB arm, minus the whole-image Vec (spec D10): resolve + mount the USB
/// data partition, read the CAPPED sidecar, cross-check its firmware against the arm, select the
/// destructive target INDEPENDENTLY of the source (§6 H-1 — moved into prepare so the checked
/// partition layout can be carried by construction), then run the SAME chunked pass-1 digest as
            
/// the raw arm — strictly before any destructive write, exactly as today.
fn prepare_uefi<O: InstallOps>(
    ops: &mut O,
    params: &InstallParams,
) -> Result<PreparedInstall, InstallerError> {
    use crate::installer_stream as stream;
    let dev = ops.resolve_partuuid(INSTALLER_DATA_PARTUUID)?;
                                                                                                   
    let source_disk = disk_from_partition(&dev)?;
    ops.mount_data_partition(&dev)?;
                                                                                      
    let layout_path = layout_sidecar_path(INSTALLER_DATA_IMG_PATH)?;
    let sidecar_size = ops.old_root_file_size(&layout_path)?;
    if sidecar_size > MAX_LAYOUT_SIDECAR_BYTES {
        return Err(InstallerError::OpFailed {
            op: "layout-sidecar-cap",
            reason: format!(
                "layout sidecar {sidecar_size} bytes exceeds the {MAX_LAYOUT_SIDECAR_BYTES}-byte cap"
            ),
        });
    }
    let layout_bytes = ops.read_old_root_file(&layout_path)?;
    let image_layout = parse_image_layout(&String::from_utf8_lossy(&layout_bytes))?;
                                                                                                     
                                                                                                       
                                                                                             
                                                                                                     
                                                                                                    
                          
    if image_layout.firmware != Firmware::Uefi {
        return Err(InstallerError::OpFailed {
            op: "verify-image-firmware",
            reason: format!(
                "box.layout.toml firmware {:?} does not match the install arm \
                 (tampered layout or a wrong-firmware box.img)",
                image_layout.firmware
            ),
        });
    }
                                                                                            
                                                                                     
    if params.sources.restore_from.is_some() {
        return Err(InstallerError::OpFailed {
            op: "uefi-restore-unsupported",
            reason: "fb.restore-from is not supported on the UEFI install arm".to_string(),
        });
    }
                                                                                                 
                                                                                                
                                                                                                 
    let disks = ops.enumerate_disks()?;
    let target = select_target(&disks, params.install_to, &source_disk).map_err(|e| {
        InstallerError::OpFailed {
            op: "select-target",
            reason: e.to_string(),
        }
    })?;
    ops.set_target_disk(&target);
    let disk_bytes = ops.disk_size_bytes()?;
    let partition_layout =
        compute_partition_layout(disk_bytes, Firmware::Uefi, image_layout.weights_size)?;
    let spans = stream::ComponentSpans::from_image_layout(&image_layout);
                                                                                              
                                                                             
    let img_size = ops.old_root_file_size(INSTALLER_DATA_IMG_PATH)?;
    stream::check_spans_in_bounds(&spans, img_size)?;
    check_components_fit(&partition_layout, &spans)?;
                                                                                                    
                                                                                              
                                                                                                
                                                                 
    let expected = params
        .image_sha256
        .ok_or_else(|| InstallerError::OpFailed {
            op: "verify-image-digest",
            reason: "fb.image-sha256 absent on the UEFI installer cmdline".to_string(),
        })?;
    let source = stream::SourceHandle::OldRootFile(INSTALLER_DATA_IMG_PATH.to_string());
    let digests = stream::digest_prepass(ops, &source, &spans, &expected)?;
    Ok(PreparedInstall {
        source,
        spans,
        digests,
        firmware: Firmware::Uefi,
        restore_image: None,
        partition_layout,
        disk_bytes,
    })
}

/// 7a → 7h — the destructive write phase. Reachable ONLY with a [`PreparedInstall`], so 7.pre (incl.
/// the restore-image verify) has completed. Fail-closed at each step; on success
/// `finalize_and_reboot` does not return (the box reboots into the runtime).
fn commit<O: InstallOps>(
    ops: &mut O,
    _params: &InstallParams,
    prepared: PreparedInstall,
) -> Result<(), InstallerError> {
    use crate::installer_stream::{copy_and_verify, readback_verify};
                                                                                                   
                                                                                        
    let layout = &prepared.partition_layout;
    let spans = &prepared.spans;
                                                                                                  
                                                                                              
                                                                                       
    if let Some(restore) = &prepared.restore_image {
        let persist_capacity = layout.persist.sector_count * SECTOR_SIZE;
        if restore.len() as u64 > persist_capacity {
            return Err(InstallerError::ComponentTooLargeForPartition {
                component: "restore-image",
                bytes: restore.len() as u64,
                capacity: persist_capacity,
            });
        }
    }

                                                                                                        
                                                                                                          
                                                                                                           
                                                                                                     
    match prepared.firmware {
        Firmware::Seabios => {
            let mbr = build_mbr_sector(layout)?;
            ops.write_partition_table(PartitionTable::Mbr(&mbr))?;                                       
        }
                                                                                                        
                                                                                                         
                                                                                                       
                                                      
        Firmware::Uefi | Firmware::SeabiosGpt => {
            let gpt = build_gpt(layout, prepared.disk_bytes / SECTOR_SIZE, prepared.firmware)?;
            ops.write_partition_table(PartitionTable::Gpt {
                primary: &gpt.primary,
                backup: &gpt.backup,
                backup_lba: gpt.backup_lba,
            })?;
        }
    }
                                                                                               
                                                                                                 
                                                                                                    
    let (rootfs_off, rootfs_len) = spans.rootfs;
    copy_and_verify(
        ops,
        &prepared.source,
        rootfs_off,
        rootfs_len,
        InstallComponent::Rootfs,
        &prepared.digests.rootfs,
    )?;                                
                                                                                                       
                                                                                               
                                                                                                
                                                                                                
                                                               
    match &prepared.restore_image {
        Some(restore) => {
            ops.dd_component(InstallComponent::PersistSkeleton, restore)?;                                              
            let expected = sha2_256(restore);
            readback_verify(
                ops,
                InstallComponent::PersistSkeleton,
                restore.len() as u64,
                &expected,
            )?;
        }
        None => {
            let (skel_off, skel_len) = spans.skel;
            copy_and_verify(
                ops,
                &prepared.source,
                skel_off,
                skel_len,
                InstallComponent::PersistSkeleton,
                &prepared.digests.skel,
            )?;               
        }
    }
    ops.zero_slot_b(layout)?;                                         
                                                                                                   
                                                                                                   
                                                                                                   
                                                                                         
                                                                                 
    if let (Some((weights_off, weights_len)), Some(weights_digest)) =
        (spans.weights, prepared.digests.weights)
    {
        copy_and_verify(
            ops,
            &prepared.source,
            weights_off,
            weights_len,
            InstallComponent::Weights,
            &weights_digest,
        )?;                                            
    }
    let (boot_off, boot_len) = spans.boot;
    copy_and_verify(
        ops,
        &prepared.source,
        boot_off,
        boot_len,
        InstallComponent::Boot,
        &prepared.digests.boot,
    )?;                                                               
                                                                                                          
                                                                                                         
                                                                                                         
                         
    match prepared.firmware {
        Firmware::Seabios => ops.write_mbr_bootcode()?,
        Firmware::SeabiosGpt => ops.write_gptmbr_bootcode()?,
        Firmware::Uefi => {}
    }
    ops.finalize_and_reboot()                                                  
}

/// Bytes reserved at the disk TAIL per firmware (spec D2 constraint 2): the backup GPT on the GPT
/// firmwares; nothing on MBR (persist runs to the last sector).
pub fn tail_reserve_bytes(firmware: Firmware) -> u64 {
    match firmware {
        Firmware::Seabios => 0,
        Firmware::SeabiosGpt | Firmware::Uefi => GPT_BACKUP_SECTORS * SECTOR_SIZE,
    }
}

/// Build the installer's [`InstallSources`] for the boot firmware (§9.5 R2-1 — the firmware dispatch).
/// SeaBIOS-family parses `fb.image-raw` + `fb.image-layout` (+ optional `fb.restore-from`) via
/// [`parse_install_sources`], threading the dispatch firmware for the D3 two-token agreement. The
/// UEFI signed-USB installer carries NO raw tokens: its image lives on the USB's ext4 data
/// partition located by the built-in `INSTALLER_DATA_PARTUUID`, so the source is always
/// [`InstallSource::BuiltinDataPartuuid`] (the cmdline is not consulted for the source) and the §9.5
/// greenfield install never restores (`restore_from` is `None`). Bypassing `parse_install_sources` on
/// the UEFI arm is precisely what avoids its `MissingImageRaw` fail-closed abort firing on every UEFI
/// install (the R2-1 panic-reboot-every-boot regression). Pure — host-unit-tested.
pub fn installer_sources(
    firmware: Firmware,
    cmdline: &str,
) -> Result<InstallSources, InstallerError> {
    match firmware {
        Firmware::Uefi => Ok(InstallSources {
            source: InstallSource::BuiltinDataPartuuid,
            restore_from: None,
            min_ctr: 0,
        }),
                                                                                                         
                                                                                                  
                                                                                                          
                                                                                                       
        Firmware::Seabios | Firmware::SeabiosGpt => parse_install_sources(cmdline, firmware),
    }
}

/// Parse the installer-mode install sources from a kernel cmdline (space-separated `key=value`
/// tokens). `fb.image-raw=<disk>:<offset>:<len>` + `fb.image-layout=…` are REQUIRED (the raw arm
/// reads no sidecar — spec D3/D4); `fb.restore-from=…` is OPTIONAL. `arm_firmware` is the
/// `fb.firmware` value the caller dispatched on — the layout token's leading `fw:` field must
/// equal it (the D3 two-token agreement; `parse_image_layout` already restricts `fw:` to the two
/// raw-arm firmwares). Empty values are treated as absent (fail closed). Pure — host-unit-tested.
/// The SeaBIOS-family source path; the UEFI arm uses [`installer_sources`] (built-in PARTUUID).
pub fn parse_install_sources(
    cmdline: &str,
    arm_firmware: Firmware,
) -> Result<InstallSources, InstallerError> {
    let mut image_raw_value: Option<String> = None;
    let mut image_layout_value: Option<String> = None;
    let mut restore_from_raw: Option<String> = None;
    let mut min_ctr_raw: Option<String> = None;
    for tok in cmdline.split_whitespace() {
        let Some((key, val)) = tok.split_once('=') else {
            continue;                         
        };
                                                                                                 
        if val.is_empty() {
            continue;
        }
        match key {
            "fb.image-raw" => image_raw_value = Some(val.to_string()),
            "fb.image-layout" => image_layout_value = Some(val.to_string()),
            "fb.restore-from" => restore_from_raw = Some(val.to_string()),
            "fb.min-ctr" => min_ctr_raw = Some(val.to_string()),
            _ => {}
        }
    }
    let image_raw_value = image_raw_value.ok_or(InstallerError::MissingImageRaw)?;
    let region = crate::installer_stream::parse_image_raw(&image_raw_value)
        .map_err(InstallerError::BadStreamToken)?;
    let image_layout_value = image_layout_value.ok_or(InstallerError::MissingImageLayout)?;
    let layout = crate::installer_stream::parse_image_layout(&image_layout_value)
        .map_err(InstallerError::BadStreamToken)?;
                                                                                      
                                                                                                
                                          
    if layout.firmware != arm_firmware {
        return Err(InstallerError::FirmwareTokenMismatch {
            layout_fw: layout.firmware.as_str(),
            cmdline_fw: arm_firmware.as_str(),
        });
    }
    let restore_from = match restore_from_raw {
        Some(v) => Some(parse_source("fb.restore-from", &v)?),
        None => None,
    };
                                                                                           
                                                                                              
                                                                                           
                                                                                          
    if let Some(ref rf) = restore_from {
        let restore_disk = disk_from_partition(&rf.device)?;
        if restore_disk != region.disk {
            return Err(InstallerError::SourceDeviceMismatch {
                image: region.disk.clone(),
                restore: rf.device.clone(),
            });
        }
    }
                                                                                               
                                                                                             
    let min_ctr = match min_ctr_raw {
        Some(v) => {
            if restore_from.is_none() {
                return Err(InstallerError::MinCtrWithoutRestore);
            }
            v.parse::<u64>()
                .map_err(|_| InstallerError::MalformedMinCtr { value: v })?
        }
        None => 0,
    };
    Ok(InstallSources {
        source: InstallSource::RawRegion { region, layout },
        restore_from,
        min_ctr,
    })
}

/// Parse one `disk:<device>:<path>` source value. `splitn(3, ':')` keeps any `:` in the path intact
/// (only the scheme + device fields are colon-delimited). Wrong scheme or a missing field is a
/// malformed source (fail closed).
///
/// Contract (audit L-3): the path MUST NOT contain whitespace. `parse_install_sources` tokenizes the
/// cmdline on whitespace (kernel `/proc/cmdline` semantics — the kernel itself splits there), so a
/// space in a stage path would truncate the value mid-path. This fails closed here (a truncated path
           
/// fails the mount → abort), but the actionable guard is the deploy CLI rejecting a
/// whitespace-containing `--image-stage-dir`/`--restore-stage-dir` at preflight (Task 4.2).
fn parse_source(key: &str, value: &str) -> Result<DiskSource, InstallerError> {
    let mut parts = value.splitn(3, ':');
    let (Some("disk"), Some(device), Some(path)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(InstallerError::MalformedSource {
            key: key.to_string(),
            value: value.to_string(),
        });
    };
    if !is_valid_source_device(device) {
        return Err(InstallerError::InvalidSourceDevice {
            key: key.to_string(),
            device: device.to_string(),
        });
    }
    if !is_valid_source_path(path) {
        return Err(InstallerError::InvalidSourcePath {
            key: key.to_string(),
            path: path.to_string(),
        });
    }
    Ok(DiskSource {
        device: device.to_string(),
        path: path.to_string(),
    })
}

                                     
/// Whitelist the bare source-device token: non-empty ascii
/// lowercase + digits — covers `sda1`/`vda2`/`nvme0n1p1` and rules OUT slashes (so `mapper/…`,
/// traversal don't match), uppercase, and punctuation. The init prepends `/dev/`, so a slash here
/// would let the source escape `/dev/`. Mirrors `cmdline::is_valid_rootfs_dev` minus the `/dev/`
/// prefix (this token is the bare name; the runtime key carries the full path).
fn is_valid_source_device(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// Validate the source path: absolute, traversal-free, NUL-free. The init joins it under
/// `/mnt/old-root`, so a relative path or a `..` component could escape the mounted old-root —
/// fail closed (whitelist the shape, not blacklist patterns).
fn is_valid_source_path(s: &str) -> bool {
    s.starts_with('/') && !s.contains('\0') && !s.split('/').any(|component| component == "..")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seabios_gpt_wire_token_round_trips() {
                                                                                       
        assert_eq!(Firmware::SeabiosGpt.as_str(), "seabios-gpt");
        assert_eq!(
            Firmware::from_wire("seabios-gpt"),
            Some(Firmware::SeabiosGpt)
        );
        assert_eq!(Firmware::from_wire("bogus"), None);
    }

    #[test]
    fn seabios_gpt_layout_matches_uefi_geometry() {
                                                                                                     
                                                                                              
        let disk = 40u64 * 1024 * 1024 * 1024;          
        let gpt = compute_partition_layout(disk, Firmware::SeabiosGpt, None).unwrap();
        let uefi = compute_partition_layout(disk, Firmware::Uefi, None).unwrap();
        assert_eq!(gpt.boot.start_lba, uefi.boot.start_lba);
        assert_eq!(gpt.boot.sector_count, uefi.boot.sector_count);
        assert_eq!(gpt.slot_a.start_lba, uefi.slot_a.start_lba);
        assert_eq!(gpt.slot_b.start_lba, uefi.slot_b.start_lba);
        assert_eq!(gpt.persist.start_lba, uefi.persist.start_lba);
        assert_eq!(gpt.persist.sector_count, uefi.persist.sector_count);                            
    }

    #[test]
    fn seabios_gpt_skips_the_2tib_mbr_guard() {
                                                                                                     
                                                                                                   
        let huge = 3u64 * 1024 * 1024 * 1024 * 1024;                                
        assert!(matches!(
            compute_partition_layout(huge, Firmware::Seabios, None),
            Err(InstallerError::DiskTooLargeForMbr { .. })
        ));
        assert!(compute_partition_layout(huge, Firmware::SeabiosGpt, None).is_ok());
        assert!(compute_partition_layout(huge, Firmware::Uefi, None).is_ok());
    }

    #[test]
    fn weights_partition_sits_between_slot_b_and_persist() {
                                                                                                   
                                                                                        
        let disk = 40u64 * 1024 * 1024 * 1024;
        let weights_bytes = 5u64 * 1024 * 1024 * 1024;
        let l = compute_partition_layout(disk, Firmware::SeabiosGpt, Some(weights_bytes)).unwrap();
        let w = l.weights.expect("weights partition present");
        assert_eq!(
            w.start_lba,
            align_up(l.slot_b.start_lba + l.slot_b.sector_count),
            "weights starts right after slot_b"
        );
        assert!(
            w.sector_count * SECTOR_SIZE >= weights_bytes,
            "weights partition holds the requested bytes"
        );
        assert_eq!(
            l.persist.start_lba,
            align_up(w.start_lba + w.sector_count),
            "persist follows weights, not slot_b"
        );
        assert!(
            l.persist.sector_count >= ALIGN_SECTORS,
            "persist still grows to fill"
        );
    }

    #[test]
    fn none_weights_is_byte_identical_4_partition_layout() {
                                                                                                     
        let disk = 40u64 * 1024 * 1024 * 1024;
        let l = compute_partition_layout(disk, Firmware::SeabiosGpt, None).unwrap();
        assert!(l.weights.is_none());
        assert_eq!(
            l.persist.start_lba,
            align_up(l.slot_b.start_lba + l.slot_b.sector_count)
        );
    }

    #[test]
    fn weights_on_mbr_seabios_fails_closed() {
                                                                                              
        let disk = 40u64 * 1024 * 1024 * 1024;
        let weights_bytes = 5u64 * 1024 * 1024 * 1024;
        assert!(compute_partition_layout(disk, Firmware::Seabios, Some(weights_bytes)).is_err());
    }

    fn build_gpt_primary_for(fw: Firmware) -> Vec<u8> {
        let disk = 40u64 * 1024 * 1024 * 1024;          
        let layout = compute_partition_layout(disk, fw, None).unwrap();
        build_gpt(&layout, disk / SECTOR_SIZE, fw).unwrap().primary
    }

                                                                                                
                                                                                        
    fn gpt_entry(primary: &[u8], idx: usize) -> ([u8; 16], u64) {
        let off = 2 * SECTOR_SIZE as usize + idx * GPT_ENTRY_SIZE;
        let mut type_guid = [0u8; 16];
        type_guid.copy_from_slice(&primary[off..off + 16]);
        let attributes = u64::from_le_bytes(primary[off + 48..off + 56].try_into().unwrap());
        (type_guid, attributes)
    }

    #[test]
    fn seabios_gpt_boot_entry_has_legacy_boot_and_linux_type_guid() {
                                                                                                       
                                                                                
        let (type_guid, attrs) = gpt_entry(&build_gpt_primary_for(Firmware::SeabiosGpt), 0);
        assert_eq!(attrs & (1 << 2), 1 << 2, "legacy_boot bit 2 set");
        assert_eq!(type_guid, guid_to_mixed_endian(LINUX_FS_TYPE_GUID).unwrap());
    }

    #[test]
    fn seabios_gpt_protective_mbr_is_active() {
                                                                                                         
                                                         
        assert_eq!(build_gpt_primary_for(Firmware::SeabiosGpt)[446], 0x80);
    }

    #[test]
    fn uefi_gpt_attributes_and_type_guids_are_byte_unchanged() {
                                                                                                            
                                                                                                   
        let primary = build_gpt_primary_for(Firmware::Uefi);
        let (type_guid, attrs) = gpt_entry(&primary, 0);
        assert_eq!(attrs, 0, "UEFI boot entry attributes stay 0");
        assert_eq!(type_guid, guid_to_mixed_endian(ESP_TYPE_GUID).unwrap());
        assert_eq!(primary[446], 0x00, "UEFI protective MBR stays non-active");
    }

    #[test]
    fn weights_partition_emits_a_fifth_gpt_entry() {
                                                                                                      
                                                                                                
        let disk = 40u64 * 1024 * 1024 * 1024;
        let weights_bytes = 5u64 * 1024 * 1024 * 1024;
        let layout =
            compute_partition_layout(disk, Firmware::SeabiosGpt, Some(weights_bytes)).unwrap();
        let primary = build_gpt(&layout, disk / SECTOR_SIZE, Firmware::SeabiosGpt)
            .unwrap()
            .primary;
        let off = 2 * SECTOR_SIZE as usize + 4 * GPT_ENTRY_SIZE;
        assert_eq!(
            &primary[off..off + 16],
            &guid_to_mixed_endian(LINUX_FS_TYPE_GUID).unwrap()[..],
            "weights type GUID = Linux-fs"
        );
        assert_eq!(
            &primary[off + 16..off + 32],
            &guid_to_mixed_endian(WEIGHTS_PARTUUID).unwrap()[..],
            "weights unique GUID = WEIGHTS_PARTUUID"
        );
        let start = u64::from_le_bytes(primary[off + 32..off + 40].try_into().unwrap());
        assert_eq!(
            start,
            layout.weights.unwrap().start_lba,
            "entry LBA matches the layout"
        );
    }

    #[test]
    fn no_weights_means_gpt_entry_four_is_zeroed() {
                                                                                                 
        let disk = 40u64 * 1024 * 1024 * 1024;
        let layout = compute_partition_layout(disk, Firmware::SeabiosGpt, None).unwrap();
        let primary = build_gpt(&layout, disk / SECTOR_SIZE, Firmware::SeabiosGpt)
            .unwrap()
            .primary;
        let off = 2 * SECTOR_SIZE as usize + 4 * GPT_ENTRY_SIZE;
        assert!(
            primary[off..off + GPT_ENTRY_SIZE].iter().all(|&b| b == 0),
            "entry 4 is zeroed when there is no weights partition"
        );
    }

                                                                                                  
                                                                                                 
                                                                                                   
                                                      
    struct CarryFake {
        restore: Vec<u8>,
        staged: Vec<u8>,
    }

    /// Restore bytes that PASS the §4b identity pre-checks (ext4 magic, journal-absent), carrying a
    /// distinctive payload so the carry assert proves the exact bytes rode through.
    fn identity_ok_restore(payload: &[u8]) -> Vec<u8> {
        let mut img = vec![0u8; 8192];
        img[1024 + 56] = 0x53;
        img[1024 + 57] = 0xEF;
        img[..payload.len()].copy_from_slice(payload);
        img
    }

    /// The raw-arm carry fixture: a 1024-byte staged "image" + the matching cmdline tokens
    /// (window at 10 GiB on the 20 GiB fake disk — clear of every written extent).
    fn carry_staged() -> Vec<u8> {
        (0..1024u32).map(|i| (i % 251) as u8).collect()
    }
    const CARRY_CMDLINE_TOKENS: &str = "fb.image-raw=vda:10737418240:1024 \
        fb.image-layout=fw:seabios,boot:0:256,skel:256:256,rootfs:512:512";

    impl InstallOps for CarryFake {
        fn mount_old_root(&mut self, _device: &str) -> Result<(), InstallerError> {
            Ok(())
        }
        fn read_old_root_file(&mut self, path: &str) -> Result<Vec<u8>, InstallerError> {
            if path.ends_with(".sig") {
                Ok(vec![0u8; 254])
            } else {
                Ok(self.restore.clone())
            }
        }
        fn old_root_file_size(&mut self, path: &str) -> Result<u64, InstallerError> {
                                                                                                 
                                                                                               
            Ok(if path.ends_with(".sig") {
                254
            } else {
                self.restore.len() as u64
            })
        }
        fn verify_restore_image(
            &mut self,
            _image: &[u8],
            _s: &[u8],
            _k: &[u8],
            _min_ctr: u64,
        ) -> Result<(), InstallerError> {
            Ok(())
        }
        fn mem_total_bytes(&mut self) -> Option<u64> {
            None                                                                               
        }
        fn unmount_old_root(&mut self) -> Result<(), InstallerError> {
            Ok(())
        }
        fn disk_size_bytes(&mut self) -> Result<u64, InstallerError> {
                                                                                          
            Ok(20 * 1024 * 1024 * 1024)
        }
        fn write_partition_table(&mut self, _t: PartitionTable) -> Result<(), InstallerError> {
            unreachable!()
        }
        fn dd_component(&mut self, _w: InstallComponent, _b: &[u8]) -> Result<(), InstallerError> {
            unreachable!()
        }
        fn zero_slot_b(&mut self, _l: &PartitionLayout) -> Result<(), InstallerError> {
            unreachable!()
        }
        fn write_mbr_bootcode(&mut self) -> Result<(), InstallerError> {
            unreachable!()
        }
        fn write_gptmbr_bootcode(&mut self) -> Result<(), InstallerError> {
            unreachable!()
        }
        fn finalize_and_reboot(&mut self) -> Result<(), InstallerError> {
            unreachable!()
        }
                                                                                                 
                                                                                                  
                                                                                      
        fn read_source_chunk(
            &mut self,
            _src: &crate::installer_stream::SourceHandle,
            offset: u64,
            buf: &mut [u8],
        ) -> Result<usize, InstallerError> {
            let len = self.staged.len() as u64;
            if offset >= len {
                return Ok(0);
            }
            let n = buf.len().min((len - offset) as usize);
            buf[..n].copy_from_slice(&self.staged[offset as usize..offset as usize + n]);
            Ok(n)
        }
        fn write_partition_chunk(
            &mut self,
            _which: InstallComponent,
            _offset: u64,
            _buf: &[u8],
        ) -> Result<(), InstallerError> {
            unimplemented!("CarryFake does not exercise the chunk engine")
        }
        fn read_partition_chunk(
            &mut self,
            _which: InstallComponent,
            _offset: u64,
            _buf: &mut [u8],
        ) -> Result<usize, InstallerError> {
            unimplemented!("CarryFake does not exercise the chunk engine")
        }
        fn fsync_partition(&mut self, _which: InstallComponent) -> Result<(), InstallerError> {
            unimplemented!("CarryFake does not exercise the chunk engine")
        }
        fn set_target_disk(&mut self, _disk: &str) {
                                                                                          
        }
                                                                                           
        fn resolve_partuuid(&mut self, _partuuid: &str) -> Result<String, InstallerError> {
            unreachable!(
                "CarryFake exercises the raw-arm restore-from path; resolve_partuuid is UEFI-only"
            )
        }
        fn mount_data_partition(&mut self, _device: &str) -> Result<(), InstallerError> {
            unreachable!(
                "CarryFake exercises the raw-arm restore-from path; mount_data_partition is UEFI-only"
            )
        }
        fn enumerate_disks(&mut self) -> Result<Vec<DiskInfo>, InstallerError> {
            unreachable!(
                "CarryFake exercises the raw-arm restore-from path; enumerate_disks is UEFI-only"
            )
        }
    }

    #[test]
    fn prepare_carries_the_verified_restore_image() {
                                                                                                        
        let cmdline = format!("{CARRY_CMDLINE_TOKENS} fb.restore-from=disk:vda1:/tmp/b.tar.zst");
        let srcs = parse_install_sources(&cmdline, Firmware::Seabios).unwrap();
        let staged = carry_staged();
        let params = InstallParams {
            sources: &srcs,
            operator_root_pubkey_hex: b"",
            image_sha256: Some(sha2_256(&staged)),
            install_to: None,
        };
        let expected = identity_ok_restore(b"verified-persist-backup");
        let mut ops = CarryFake {
            restore: expected.clone(),
            staged,
        };
        let prepared = prepare(&mut ops, &params).expect("restore-from prepare succeeds");
        assert_eq!(
            prepared.restore_image.as_deref(),
            Some(&expected[..]),
            "the verified image must be carried (the old-root unmounts next → TOCTOU-free handoff)"
        );
                                                                                  
        assert_eq!(
            prepared.partition_layout,
            compute_partition_layout(20 * 1024 * 1024 * 1024, Firmware::Seabios, None).unwrap()
        );
    }

    #[test]
    fn prepare_greenfield_carries_no_restore_image() {
                                                                             
        let srcs = parse_install_sources(CARRY_CMDLINE_TOKENS, Firmware::Seabios).unwrap();
        let staged = carry_staged();
        let params = InstallParams {
            sources: &srcs,
            operator_root_pubkey_hex: b"",
            image_sha256: Some(sha2_256(&staged)),
            install_to: None,
        };
        let mut ops = CarryFake {
            restore: Vec::new(),
            staged,
        };
        let prepared = prepare(&mut ops, &params).expect("greenfield prepare succeeds");
        assert!(
            prepared.restore_image.is_none(),
            "greenfield carries no restore image"
        );
    }
}

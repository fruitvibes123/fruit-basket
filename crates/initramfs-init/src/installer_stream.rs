//! Streaming install engine — raw-tail staging tokens, geometry, copy plan, driver.
//!
                                                                                
//! The operator tool
//! stages the sentinel-patched `.img` onto a RAW byte region at the tail of the target disk
//! (below the GPT backup + every range the install writes) pre-kexec; this module owns the PURE
//! side of consuming it: the two cmdline token grammars (`fb.image-raw` / `fb.image-layout`, spec
//! §4), the staging-window geometry checks (spec D2), the digest pre-pass split, and the chunked
//! copy driver — all host-unit-tested over the `InstallOps` seam. No syscalls live here.
//!
                                     
//! Everything is fail-closed: each refusal is a typed
//! [`StreamError`] variant whose `Display` is the operator-visible diagnostic; the PID-1 caller
                      
//! turns any of them into a kernel-panic diagnostic BEFORE any destructive write.

use crate::installer::{Firmware, SECTOR_SIZE};

/// Chunk size for every streamed copy/hash loop (spec D12): the RAM floor of the whole install is
/// O(this). 8 MiB — PAGE-aligned (the D7 `O_DIRECT` readback's buffer-alignment contract; 4096 |
/// 8 MiB), a 512/1 MiB multiple, small enough to be irrelevant to RAM budgets, large enough that
/// per-chunk syscall overhead vanishes. Cross-crate TWIN (plan R1-9): orchard's streamer
/// (`orchard/src/deploy/stage_stream.rs`) carries the SAME value — the staging-window offset is
/// chosen as a multiple of it operator-side, and [`parse_image_raw`] REJECTS a non-multiple
/// offset, so drift is fail-closed (the box refuses, never mis-copies); keep the two in sync to
/// keep ceremonies working. Not configurable by design.
pub const INSTALL_COPY_CHUNK_BYTES: u64 = 8 * 1024 * 1024;

/// The parsed `fb.image-raw=<disk>:<offset>:<len>` staging region (spec §4): `<len>` bytes of
/// staged image at absolute byte `<offset>` on whole-disk `<disk>`. `len` is the EXACT `.img`
/// byte length (spec D4 — the digest domain); `offset` is `INSTALL_COPY_CHUNK_BYTES`-aligned
/// (the byte-exact-seek guarantee, spec D11 step 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRegion {
    /// Bare whole-disk device name (same grammar as `fb.install-to` —
    /// [`crate::install_target::valid_install_to_dev`]): no `/dev/` prefix, no partition suffix.
    pub disk: String,
    /// Absolute byte offset of the staged region on `disk`.
    pub offset: u64,
    /// Exact staged `.img` byte length (512-aligned by the builder's emit assert, spec D4).
    pub len: u64,
}

/// The parsed `fb.image-layout=…` composite token (spec §4 / D3): the build sidecar's component
/// geometry carried on the kexec append (the raw arm mounts nothing, so there is no file to read
/// it from). Offsets/lengths are IMAGE-relative (relative to the staged region start).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamLayout {
    /// The leading `fw:` field — must equal `fb.firmware` AND be raw-arm-acceptable (spec D3
    /// two-token agreement; the cross-check against `fb.firmware` happens in `prepare`, not here).
    pub firmware: Firmware,
    /// boot-fs component `(offset, len)`.
    pub boot: (u64, u64),
    /// persist-skeleton component `(offset, len)`.
    pub skel: (u64, u64),
    /// rootfs (squashfs+verity) component `(offset, len)`.
    pub rootfs: (u64, u64),
    /// Optional dha weights component `(offset, len)`; its `len` doubles as `weights_size` for
    /// partition sizing (as the sidecar's `weights_size` does today).
    pub weights: Option<(u64, u64)>,
}

/// A streaming-install token/geometry refusal. One variant per refusal class; `Display` is the
/// operator-visible reason (surfaced through the fail-closed panic-diagnostic path pre-write).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamError {
    /// `fb.image-raw` is not exactly `<disk>:<offset>:<len>` (missing/extra field, empty value).
    MalformedImageRaw { value: String },
    /// The `<disk>` field is not a bare whole-disk name (partition suffix, `/dev/` prefix,
    /// bad charset — the `fb.install-to` whitelist grammar).
    InvalidRawDisk { disk: String },
    /// An `fb.image-raw` numeric field is not a strict decimal u64 (sign, junk, hex, overflow).
    MalformedRawNumber { field: &'static str, value: String },
    /// `<offset>` is not 512-aligned (spec D2 constraint 1).
    UnalignedRawOffset { offset: u64 },
    /// `<offset>` is not a multiple of [`INSTALL_COPY_CHUNK_BYTES`] (spec D12 — the operator-side
    /// `dd oflag=seek_bytes` seek is exact only in chunk units).
    RawOffsetNotChunkAligned { offset: u64 },
    /// `<len>` is not 512-aligned (spec D4: the exact `.img` length is 512-aligned by the
    /// builder's emit assert — an unaligned length is a composition bug, never valid).
    UnalignedRawLen { len: u64 },
    /// `<len>` is zero (an empty staged image is structurally meaningless — fail closed).
    ZeroRawLen,
    /// `offset + len` overflows u64 — the region cannot exist on any disk.
    RawRegionOverflow { offset: u64, len: u64 },
    /// `fb.image-layout` violates the fixed grammar (`fw:` first, then exactly
    /// `boot,skel,rootfs[,weights]` in order — wrong order, duplicate, missing or extra entries,
    /// or a malformed entry shape). `value` is the offending entry (or the whole token).
    MalformedImageLayout { value: String, reason: &'static str },
    /// The `fw:` field is not a raw-arm firmware (`seabios` | `seabios-gpt`) — unknown words AND
    /// `uefi` both refuse (the UEFI arm keeps its sidecar file; this token is raw-arm-only).
    LayoutBadFirmware { value: String },
    /// A layout region's numeric field is not a strict decimal u64.
    MalformedLayoutNumber {
        component: &'static str,
        value: String,
    },
    /// A layout region has `len == 0` — no component is ever empty; fail closed.
    LayoutRegionEmpty { component: &'static str },
    /// A layout region's `offset + len` overflows u64.
    LayoutRegionOverflow { component: &'static str },
    /// Layout regions are not strictly ascending/disjoint (each next start must be ≥ the previous
    /// end) — overlapping or out-of-order regions would double-copy or shear components.
    LayoutRegionsNotAscending {
        prev: &'static str,
        next: &'static str,
    },
    /// The staging window breaches the disk bounds / GPT tail reserve (spec D2 constraint 2):
    /// `window_end > disk_bytes − tail_reserve` (or the window arithmetic itself overflows).
    StagingWindowOutOfBounds { window_end: u64, limit: u64 },
    /// The staging window intersects an extent the install writes (spec D2 constraint 3); `hit`
    /// is the first overlapped extent's label from [`written_set`].
    StagingOverlapsInstall {
        window_start: u64,
        window_end: u64,
        hit: &'static str,
    },
}

impl core::fmt::Display for StreamError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MalformedImageRaw { value } => {
                write!(f, "fb.image-raw not <disk>:<offset>:<len>: {value:?}")
            }
            Self::InvalidRawDisk { disk } => write!(
                f,
                "fb.image-raw disk not a bare whole-disk name (no /dev/, no partition): {disk:?}"
            ),
            Self::MalformedRawNumber { field, value } => {
                write!(
                    f,
                    "fb.image-raw {field} not a strict decimal u64: {value:?}"
                )
            }
            Self::UnalignedRawOffset { offset } => {
                write!(f, "fb.image-raw offset {offset} not 512-aligned")
            }
            Self::RawOffsetNotChunkAligned { offset } => write!(
                f,
                "fb.image-raw offset {offset} not a multiple of the {INSTALL_COPY_CHUNK_BYTES}-byte copy chunk"
            ),
            Self::UnalignedRawLen { len } => {
                write!(f, "fb.image-raw len {len} not 512-aligned")
            }
            Self::ZeroRawLen => write!(f, "fb.image-raw len is zero (no staged image)"),
            Self::RawRegionOverflow { offset, len } => {
                write!(f, "fb.image-raw offset {offset} + len {len} overflows u64")
            }
            Self::MalformedImageLayout { value, reason } => {
                write!(f, "fb.image-layout malformed ({reason}): {value:?}")
            }
            Self::LayoutBadFirmware { value } => write!(
                f,
                "fb.image-layout fw: not a raw-arm firmware (seabios|seabios-gpt): {value:?}"
            ),
            Self::MalformedLayoutNumber { component, value } => write!(
                f,
                "fb.image-layout {component} field not a strict decimal u64: {value:?}"
            ),
            Self::LayoutRegionEmpty { component } => {
                write!(f, "fb.image-layout {component} region is empty (len 0)")
            }
            Self::LayoutRegionOverflow { component } => {
                write!(f, "fb.image-layout {component} offset+len overflows u64")
            }
            Self::LayoutRegionsNotAscending { prev, next } => write!(
                f,
                "fb.image-layout {next} region starts before {prev} ends (must be ascending, disjoint)"
            ),
            Self::StagingWindowOutOfBounds { window_end, limit } => write!(
                f,
                "staging window ends at {window_end}, past the {limit}-byte disk/tail-reserve limit"
            ),
            Self::StagingOverlapsInstall {
                window_start,
                window_end,
                hit,
            } => write!(
                f,
                "staging window [{window_start}, {window_end}) overlaps the install's {hit}"
            ),
        }
    }
}

/// Parse `fb.image-raw=<disk>:<offset>:<len>` (spec §4). Fail-closed accept/reject per the
/// [`StreamError`] table; on success every numeric constraint (512 + chunk alignment, non-zero,
/// no overflow) holds by construction.
pub fn parse_image_raw(value: &str) -> Result<RawRegion, StreamError> {
    let mut parts = value.split(':');
    let (Some(disk), Some(offset_s), Some(len_s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(StreamError::MalformedImageRaw {
            value: value.to_string(),
        });
    };
                                                                                           
                                                             
    if !crate::install_target::valid_install_to_dev(disk) {
        return Err(StreamError::InvalidRawDisk {
            disk: disk.to_string(),
        });
    }
    let offset = strict_u64(offset_s).ok_or_else(|| StreamError::MalformedRawNumber {
        field: "offset",
        value: offset_s.to_string(),
    })?;
    let len = strict_u64(len_s).ok_or_else(|| StreamError::MalformedRawNumber {
        field: "len",
        value: len_s.to_string(),
    })?;
    if offset % SECTOR_SIZE != 0 {
        return Err(StreamError::UnalignedRawOffset { offset });
    }
    if offset % INSTALL_COPY_CHUNK_BYTES != 0 {
        return Err(StreamError::RawOffsetNotChunkAligned { offset });
    }
    if len == 0 {
        return Err(StreamError::ZeroRawLen);
    }
    if len % SECTOR_SIZE != 0 {
        return Err(StreamError::UnalignedRawLen { len });
    }
    if offset.checked_add(len).is_none() {
        return Err(StreamError::RawRegionOverflow { offset, len });
    }
    Ok(RawRegion {
        disk: disk.to_string(),
        offset,
        len,
    })
}

/// Parse `fb.image-layout=fw:<fw>,boot:<o>:<l>,skel:<o>:<l>,rootfs:<o>:<l>[,weights:<o>:<l>]`
/// (spec §4). Fixed entry order, exactly 4 or 5 entries, strict u64 fields, per-region overflow
/// checks, regions ascending + disjoint. Bounds vs the staged region length are NOT checked here
/// (that needs the [`RawRegion`] — `prepare` runs it as metadata-bounds, spec §5 step 4).
pub fn parse_image_layout(value: &str) -> Result<StreamLayout, StreamError> {
    let malformed = |v: &str, reason: &'static str| StreamError::MalformedImageLayout {
        value: v.to_string(),
        reason,
    };
    let entries: Vec<&str> = value.split(',').collect();
    if entries.len() != 4 && entries.len() != 5 {
        return Err(malformed(value, "expected fw + 3 or 4 component entries"));
    }
    let Some(fw_value) = entries[0].strip_prefix("fw:") else {
        return Err(malformed(entries[0], "first entry must be fw:<firmware>"));
    };
                                                                                                  
                                                                         
    let firmware = match Firmware::from_wire(fw_value) {
        Some(fw @ (Firmware::Seabios | Firmware::SeabiosGpt)) => fw,
        Some(Firmware::Uefi) | None => {
            return Err(StreamError::LayoutBadFirmware {
                value: fw_value.to_string(),
            });
        }
    };
    let boot = parse_layout_region(entries[1], "boot")?;
    let skel = parse_layout_region(entries[2], "skel")?;
    let rootfs = parse_layout_region(entries[3], "rootfs")?;
    let weights = match entries.get(4) {
        Some(e) => Some(parse_layout_region(e, "weights")?),
        None => None,
    };
                                                                                                   
                                                                            
    let mut regions = [
        ("boot", boot),
        ("skel", skel),
        ("rootfs", rootfs),
        ("", (0, 0)),
    ];
    let mut count = 3;
    if let Some(w) = weights {
        regions[3] = ("weights", w);
        count = 4;
    }
    for pair in regions[..count].windows(2) {
        let (prev_name, (prev_off, prev_len)) = pair[0];
        let (next_name, (next_off, _)) = pair[1];
        if next_off < prev_off + prev_len {
            return Err(StreamError::LayoutRegionsNotAscending {
                prev: prev_name,
                next: next_name,
            });
        }
    }
    Ok(StreamLayout {
        firmware,
        boot,
        skel,
        rootfs,
        weights,
    })
}

/// Parse one fixed-order layout entry `<component>:<offset>:<len>`. A wrong key at this position
/// (out-of-order, duplicated, or unknown) is a malformed layout — the grammar is positional.
fn parse_layout_region(entry: &str, component: &'static str) -> Result<(u64, u64), StreamError> {
    let mut parts = entry.split(':');
    let (Some(key), Some(offset_s), Some(len_s), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(StreamError::MalformedImageLayout {
            value: entry.to_string(),
            reason: "entry not <component>:<offset>:<len>",
        });
    };
    if key != component {
        return Err(StreamError::MalformedImageLayout {
            value: entry.to_string(),
            reason: "entries must be boot,skel,rootfs[,weights] in fixed order",
        });
    }
    let offset = strict_u64(offset_s).ok_or_else(|| StreamError::MalformedLayoutNumber {
        component,
        value: offset_s.to_string(),
    })?;
    let len = strict_u64(len_s).ok_or_else(|| StreamError::MalformedLayoutNumber {
        component,
        value: len_s.to_string(),
    })?;
    if len == 0 {
        return Err(StreamError::LayoutRegionEmpty { component });
    }
    if offset.checked_add(len).is_none() {
        return Err(StreamError::LayoutRegionOverflow { component });
    }
    Ok((offset, len))
}

/// Strict decimal u64: ASCII digits only — no sign (Rust's `FromStr` accepts a leading `+`), no
                                     
/// hex, no whitespace; overflow refuses (whitelist posture).
fn strict_u64(s: &str) -> Option<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u64>().ok()
}

                                              

/// One half-open byte extent `[start, end)` the install WRITES, labelled for the overlap
/// diagnostic (`what` feeds [`StreamError::StagingOverlapsInstall::hit`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ByteRange {
    pub what: &'static str,
    pub start: u64,
    pub end: u64,
}

/// Every byte extent the install writes on the target disk (spec D2 point 3): the partition-table
/// sectors per firmware (MBR sector 0; GPT primary LBA 0–33 + backup at the tail), the boot
/// partition, slot A, slot B (zeroed at 7d), the weights partition (when present), and the WRITTEN
/// persist prefix `[persist_start, persist_start + persist_prefix_len)` where `persist_prefix_len`
/// = max(skeleton len, restore len) — the caller resolves the max (on restore ceremonies the
/// disjointness is checked twice: skeleton-fast, then re-checked with the probed restore size,
/// spec §5 step 5).
pub fn written_set(
    layout: &crate::installer::PartitionLayout,
    disk_bytes: u64,
    firmware: Firmware,
    persist_prefix_len: u64,
) -> Vec<ByteRange> {
    let part = |what: &'static str, p: &crate::installer::Partition| ByteRange {
        what,
        start: p.start_lba * SECTOR_SIZE,
        end: (p.start_lba + p.sector_count) * SECTOR_SIZE,
    };
    let mut set = Vec::with_capacity(7);
    match firmware {
                                                           
        Firmware::Seabios => set.push(ByteRange {
            what: "mbr-table",
            start: 0,
            end: SECTOR_SIZE,
        }),
                                                                                                
                                                                                                 
        Firmware::SeabiosGpt | Firmware::Uefi => {
            set.push(ByteRange {
                what: "gpt-primary",
                start: 0,
                end: 34 * SECTOR_SIZE,
            });
            set.push(ByteRange {
                what: "gpt-backup",
                start: disk_bytes.saturating_sub(33 * SECTOR_SIZE),
                end: disk_bytes,
            });
        }
    }
    set.push(part("boot", &layout.boot));
    set.push(part("slot-a", &layout.slot_a));
    set.push(part("slot-b", &layout.slot_b));                                 
    if let Some(w) = &layout.weights {
        set.push(part("weights", w));
    }
                                                                                                  
                                                                                             
                                                                                              
    let persist_start = layout.persist.start_lba * SECTOR_SIZE;
    set.push(ByteRange {
        what: "persist-prefix",
        start: persist_start,
        end: persist_start.saturating_add(persist_prefix_len),
    });
    set
}

/// The D2 window checks, fail-closed and non-destructive: (constraint 2) the window is in-bounds —
/// `window.offset + window.len ≤ disk_bytes − tail_reserve_bytes` (the GPT backup reserve on the
/// GPT firmwares; 0 on MBR) — and (constraint 3) disjoint from every [`written_set`] extent.
/// The FIRST overlapping extent names the refusal.
pub fn check_staging_disjoint(
    window: &RawRegion,
    set: &[ByteRange],
    disk_bytes: u64,
    tail_reserve_bytes: u64,
) -> Result<(), StreamError> {
    let limit = disk_bytes.saturating_sub(tail_reserve_bytes);
                                                                                            
                                                                                                 
    let Some(window_end) = window.offset.checked_add(window.len) else {
        return Err(StreamError::StagingWindowOutOfBounds {
            window_end: u64::MAX,
            limit,
        });
    };
    if window_end > limit {
        return Err(StreamError::StagingWindowOutOfBounds { window_end, limit });
    }
                                                                                          
                                         
    for range in set {
        if window.offset < range.end && range.start < window_end {
            return Err(StreamError::StagingOverlapsInstall {
                window_start: window.offset,
                window_end,
                hit: range.what,
            });
        }
    }
    Ok(())
}

                                                                    

/// The geometry drift-guard fixture, shared VERBATIM with orchard (`prod_orchestrate.rs`'s
/// `staging_geometry` module carries the SAME table + the SAME pinned hash — the twin; the
                          
/// house pattern). Both crates independently implement the layout/window
/// arithmetic; both asserting these rows AND the identical [`GOLDEN_VECTORS_SHA256`] over the
/// table's `Debug` form is what proves the two implementations agree.
///
/// Row: `(disk_bytes, fw_wire, weights_size, skel_len, restore_len, img_len,
///        persist_start, window_offset, verdict)` — all byte units.
/// - `persist_start`: the computed persist partition start (weights-INCLUSIVE — the R1-1
///   regression axis). `0` when the layout itself refuses.
/// - `window_offset`: the tail window under test. For `ok`/`refuse=…` rows it equals the shared
///   placement formula `chunk_align_down(disk − tail_reserve − img_len)` (both crates assert);
///   for `given-refuse=…` rows it is a hostile operator-GIVEN window only the box-side check can
///   see (orchard's placement never produces it — its suite hash-locks the row and skips
///   placement).
/// - `verdict`: `ok` | `refuse=<hit>` | `given-refuse=<hit>` | `disk-too-small`, where `<hit>`
///   is the box-side refusal detail (`tail-bounds` ⇒ the bounds constraint; anything else ⇒ the
///   overlapped extent's `what` label).
pub type GoldenVector = (
    u64,
    &'static str,
    u64,
    u64,
    u64,
    u64,
    u64,
    u64,
    &'static str,
);

pub const GOLDEN_VECTORS: &[GoldenVector] = &[
                                                                
    (
        10_737_418_240,
        "seabios",
        0,
        33_554_432,
        0,
        167_772_160,
        269_484_032,
        10_569_646_080,
        "ok",
    ),
                                                                             
    (
        10_737_418_240,
        "seabios-gpt",
        0,
        33_554_432,
        0,
        167_772_160,
        269_484_032,
        10_561_257_472,
        "ok",
    ),
                                                                                                   
                                                    
    (
        32_212_254_720,
        "seabios-gpt",
        1_714_917_376,
        33_554_432,
        0,
        2_276_954_112,
        1_984_954_368,
        29_930_553_344,
        "ok",
    ),
                                                                                          
    (
        536_870_912,
        "seabios",
        0,
        33_554_432,
        209_715_200,
        167_772_160,
        269_484_032,
        369_098_752,
        "refuse=persist-prefix",
    ),
                                                                                                
                                                                             
    (
        10_737_418_240,
        "seabios-gpt",
        0,
        33_554_432,
        0,
        8_388_608,
        269_484_032,
        10_729_029_632,
        "given-refuse=tail-bounds",
    ),
                                                                         
    (
        10_737_418_240,
        "seabios",
        0,
        33_554_432,
        0,
        10_569_646_080,
        269_484_032,
        167_772_160,
        "refuse=slot-a",
    ),
                                                                                                
                                                                   
    (
        4_294_967_296,
        "seabios",
        0,
        7_340_032,
        0,
        4_018_143_232,
        269_484_032,
        276_824_064,
        "ok",
    ),
                                                                                        
    (
        209_715_200,
        "seabios",
        0,
        33_554_432,
        0,
        8_388_608,
        0,
        0,
        "disk-too-small",
    ),
];

/// SHA-256 (lowercase hex) over `format!("{GOLDEN_VECTORS:?}")` — the cross-crate pin. Orchard's
/// `staging_geometry` asserts the SAME constant over ITS copy of the table; any one-sided edit
/// breaks that crate's pin test (fail-closed drift guard). Update BOTH crates together, never one.
pub const GOLDEN_VECTORS_SHA256: &str =
    "8687624aec50ad11aa4463bab96fa69f3431774abe6b103ec57547ffed60ff10";

                                                                             

/// The chunk driver's source: the staged raw region (SeaBIOS-family arm) or a file on the mounted
/// source partition (the UEFI arm reuses the same engine over its USB data partition — spec D10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceHandle {
    Raw(RawRegion),
    OldRootFile(String),
}

/// The digest pre-pass output (spec D7): the whole-region SHA-256 (checked against the mandatory
/// `fb.image-sha256` — the EXTERNAL anchor) plus per-component subrange digests (box-derived
/// self-consistency values consumed by the post-write readbacks).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentDigests {
    pub whole: [u8; 32],
    pub boot: [u8; 32],
    pub skel: [u8; 32],
    pub rootfs: [u8; 32],
    pub weights: Option<[u8; 32]>,
}

/// A firmware + component-offset view usable by BOTH arms (plan R1-S4): the raw arm builds it
/// from [`StreamLayout`] (the cmdline token), the UEFI arm from the sidecar
/// [`crate::installer::ImageLayout`] — so [`digest_prepass`] takes ONE type and the UEFI arm has
/// a real conversion instead of a type mismatch. Offsets/lens are image-relative.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentSpans {
    pub firmware: Firmware,
    pub boot: (u64, u64),
    pub skel: (u64, u64),
    pub rootfs: (u64, u64),
    pub weights: Option<(u64, u64)>,
}

impl ComponentSpans {
    /// Raw arm: the parsed `fb.image-layout` IS the span set.
    pub fn from_stream_layout(l: &StreamLayout) -> Self {
        Self {
            firmware: l.firmware,
            boot: l.boot,
            skel: l.skel,
            rootfs: l.rootfs,
            weights: l.weights,
        }
    }

    /// UEFI arm: the sidecar `.layout.toml` carries the same offsets under field names.
    pub fn from_image_layout(l: &crate::installer::ImageLayout) -> Self {
        Self {
            firmware: l.firmware,
            boot: (l.boot_offset, l.boot_size),
            skel: (l.persist_skeleton_offset, l.persist_skeleton_size),
            rootfs: (l.rootfs_offset, l.rootfs_size),
            weights: match (l.weights_offset, l.weights_size) {
                (Some(o), Some(s)) => Some((o, s)),
                _ => None,
            },
        }
    }
}

/// Metadata-bounds check (spec §5 step 4): every component span must lie inside the source's
/// `total_len` bytes — the old borrowed-slice bounds checks re-founded on offsets/lengths
/// (spec D6). Overflow-safe; refuses with the historical `ImageLayoutOutOfBounds` class.
pub fn check_spans_in_bounds(
    spans: &ComponentSpans,
    total_len: u64,
) -> Result<(), crate::installer::InstallerError> {
    let mut regions = [
        ("boot", Some(spans.boot)),
        ("persist-skeleton", Some(spans.skel)),
        ("rootfs", Some(spans.rootfs)),
        ("weights", spans.weights),
    ];
    for (name, span) in regions.iter_mut() {
        let Some((offset, len)) = span else { continue };
        let end = offset.checked_add(*len).ok_or(
            crate::installer::InstallerError::ImageLayoutOutOfBounds {
                component: name,
                end: u64::MAX,
                image_len: total_len,
            },
        )?;
        if end > total_len {
            return Err(crate::installer::InstallerError::ImageLayoutOutOfBounds {
                component: name,
                end,
                image_len: total_len,
            });
        }
    }
    Ok(())
}

/// The stable component label used in typed errors (readback mismatches, short reads).
pub fn component_label(which: crate::installer::InstallComponent) -> &'static str {
    match which {
        crate::installer::InstallComponent::Boot => "boot",
        crate::installer::InstallComponent::Rootfs => "rootfs",
        crate::installer::InstallComponent::PersistSkeleton => "persist-skeleton",
        crate::installer::InstallComponent::Weights => "weights",
    }
}

/// One sequential chunked read of the whole source (spec §5 step 6): hashes the ENTIRE region
/// against `expected_whole` (refusing on mismatch — [`InstallerError::StagedImageDigestMismatch`])
/// while splitting the same byte stream at [`ComponentSpans`] boundaries into per-component
/// digests for the post-write readbacks (D7). Non-destructive; every failure aborts with the
/// disk untouched.
pub fn digest_prepass<O: crate::installer::InstallOps>(
    ops: &mut O,
    src: &SourceHandle,
    spans: &ComponentSpans,
    expected_whole: &[u8; 32],
) -> Result<ComponentDigests, crate::installer::InstallerError> {
    use sha2::{Digest, Sha256};
    let total = source_total_len(ops, src)?;
    let mut whole = Sha256::new();
    let mut boot = Sha256::new();
    let mut skel = Sha256::new();
    let mut rootfs = Sha256::new();
    let mut weights = spans.weights.map(|_| Sha256::new());
    let mut buf = vec![0u8; INSTALL_COPY_CHUNK_BYTES as usize];
    let mut pos: u64 = 0;
    while pos < total {
        let n = (total - pos).min(INSTALL_COPY_CHUNK_BYTES) as usize;
        read_source_exact(ops, src, pos, &mut buf[..n])?;
        let chunk = &buf[..n];
        whole.update(chunk);
        feed_span(&mut boot, spans.boot, pos, chunk);
        feed_span(&mut skel, spans.skel, pos, chunk);
        feed_span(&mut rootfs, spans.rootfs, pos, chunk);
        if let (Some(h), Some(span)) = (weights.as_mut(), spans.weights) {
            feed_span(h, span, pos, chunk);
        }
        pos += n as u64;
    }
    let got: [u8; 32] = whole.finalize().into();
    if got != *expected_whole {
        return Err(
            crate::installer::InstallerError::StagedImageDigestMismatch {
                expected: *expected_whole,
                got,
            },
        );
    }
    Ok(ComponentDigests {
        whole: got,
        boot: boot.finalize().into(),
        skel: skel.finalize().into(),
        rootfs: rootfs.finalize().into(),
        weights: weights.map(|h| h.finalize().into()),
    })
}

/// The source's total byte length: the staged region's exact `<len>` (raw arm) or the file size
/// (UEFI arm — the D10 pass-1/pass-2 model; a between-pass change is out of that arm's threat
/// model and would fail the digest anyway).
fn source_total_len<O: crate::installer::InstallOps>(
    ops: &mut O,
    src: &SourceHandle,
) -> Result<u64, crate::installer::InstallerError> {
    match src {
        SourceHandle::Raw(region) => Ok(region.len),
        SourceHandle::OldRootFile(path) => ops.old_root_file_size(path),
    }
}

/// Fill `buf` completely from the source at `offset`, looping over legal partial reads; EOF
/// before the buffer fills is a typed [`InstallerError::SourceShortRead`] (truncated region/file).
fn read_source_exact<O: crate::installer::InstallOps>(
    ops: &mut O,
    src: &SourceHandle,
    offset: u64,
    buf: &mut [u8],
) -> Result<(), crate::installer::InstallerError> {
    let wanted = buf.len();
    let mut done = 0usize;
    while done < wanted {
        let n = ops.read_source_chunk(src, offset + done as u64, &mut buf[done..])?;
        if n == 0 {
            return Err(crate::installer::InstallerError::SourceShortRead {
                offset: offset + done as u64,
                wanted,
                got: done,
            });
        }
        done += n;
    }
    Ok(())
}

/// Feed the intersection of `span` (image-relative half-open `(offset, len)`) with the chunk at
/// absolute `chunk_start` into `h`. Pure interval math; spans are parse-checked overflow-free.
fn feed_span(h: &mut sha2::Sha256, span: (u64, u64), chunk_start: u64, chunk: &[u8]) {
    use sha2::Digest;
    let (s0, sl) = span;
    let s1 = s0 + sl;
    let c1 = chunk_start + chunk.len() as u64;
    let lo = s0.max(chunk_start);
    let hi = s1.min(c1);
    if lo < hi {
        h.update(&chunk[(lo - chunk_start) as usize..(hi - chunk_start) as usize]);
    }
}

/// Chunk-copy `len` bytes from source offset `src_off` to the FRONT of `which`'s partition, then
/// fsync it, then re-read the written range through the impl's `O_DIRECT` readback and compare
/// against `expected` (spec D7 — write-then-verify strictly before bootable-last). Also usable
/// readback-only via [`readback_verify`] (the restore dd path).
pub fn copy_and_verify<O: crate::installer::InstallOps>(
    ops: &mut O,
    src: &SourceHandle,
    src_off: u64,
    len: u64,
    which: crate::installer::InstallComponent,
    expected: &[u8; 32],
) -> Result<(), crate::installer::InstallerError> {
    let mut buf = vec![0u8; INSTALL_COPY_CHUNK_BYTES as usize];
    let mut pos: u64 = 0;
    while pos < len {
        let n = (len - pos).min(INSTALL_COPY_CHUNK_BYTES) as usize;
        read_source_exact(ops, src, src_off + pos, &mut buf[..n])?;
        ops.write_partition_chunk(which, pos, &buf[..n])?;
        pos += n as u64;
    }
                                                                                                  
                                                                                               
                                         
    ops.fsync_partition(which)?;
    readback_verify(ops, which, len, expected)
}

/// The readback half of [`copy_and_verify`], standalone for writes that arrive via other paths
/// (the restore `dd_component` swap — spec D7 extends the readback to it): fsync, then re-read
/// `[0, len)` of `which`'s partition (`O_DIRECT` in the real impl) and compare against `expected`.
pub fn readback_verify<O: crate::installer::InstallOps>(
    ops: &mut O,
    which: crate::installer::InstallComponent,
    len: u64,
    expected: &[u8; 32],
) -> Result<(), crate::installer::InstallerError> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    let mut buf = vec![0u8; INSTALL_COPY_CHUNK_BYTES as usize];
    let mut pos: u64 = 0;
    while pos < len {
        let n = (len - pos).min(INSTALL_COPY_CHUNK_BYTES) as usize;
                                                                                                
                                                                                 
        let mut done = 0usize;
        while done < n {
            let got = ops.read_partition_chunk(which, pos + done as u64, &mut buf[done..n])?;
            if got == 0 {
                return Err(crate::installer::InstallerError::OpFailed {
                    op: "readback-short-read",
                    reason: format!(
                        "{} readback ended at {} of {len} bytes",
                        component_label(which),
                        pos + done as u64
                    ),
                });
            }
            done += got;
        }
        h.update(&buf[..n]);
        pos += n as u64;
    }
    let got: [u8; 32] = h.finalize().into();
    if got != *expected {
        return Err(
            crate::installer::InstallerError::ComponentReadbackMismatch {
                component: component_label(which),
            },
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

                                           

    #[test]
    fn image_raw_accepts_the_spec_example() {
                                                                               
        let r = parse_image_raw("vda:24461180928:2276954112").expect("spec example must parse");
        assert_eq!(
            r,
            RawRegion {
                disk: "vda".to_string(),
                offset: 24_461_180_928,
                len: 2_276_954_112,
            }
        );
    }

    #[test]
    fn image_raw_accepts_a_digit_ending_whole_disk() {
                                                                                            
        let r = parse_image_raw("nvme0n1:8388608:512").expect("nvme whole disk must parse");
        assert_eq!(r.disk, "nvme0n1");
        assert_eq!(r.offset, INSTALL_COPY_CHUNK_BYTES);
        assert_eq!(r.len, 512);
    }

                                                             

    #[test]
    fn image_raw_rejects_a_partition_suffixed_disk() {
        assert_eq!(
            parse_image_raw("vda1:8388608:512"),
            Err(StreamError::InvalidRawDisk {
                disk: "vda1".to_string()
            })
        );
    }

    #[test]
    fn image_raw_rejects_a_dev_prefixed_disk() {
        assert_eq!(
            parse_image_raw("/dev/vda:8388608:512"),
            Err(StreamError::InvalidRawDisk {
                disk: "/dev/vda".to_string()
            })
        );
    }

    #[test]
    fn image_raw_rejects_a_non_512_aligned_offset() {
        assert_eq!(
            parse_image_raw("vda:100:512"),
            Err(StreamError::UnalignedRawOffset { offset: 100 })
        );
    }

    #[test]
    fn image_raw_rejects_a_512_aligned_but_not_chunk_aligned_offset() {
                                                                                            
                                                                
        assert_eq!(
            parse_image_raw("vda:512:512"),
            Err(StreamError::RawOffsetNotChunkAligned { offset: 512 })
        );
    }

    #[test]
    fn image_raw_rejects_a_zero_len() {
        assert_eq!(
            parse_image_raw("vda:8388608:0"),
            Err(StreamError::ZeroRawLen)
        );
    }

    #[test]
    fn image_raw_rejects_a_non_512_aligned_len() {
                                                                                             
                                              
        assert_eq!(
            parse_image_raw("vda:8388608:513"),
            Err(StreamError::UnalignedRawLen { len: 513 })
        );
    }

    #[test]
    fn image_raw_rejects_non_numeric_fields() {
        assert_eq!(
            parse_image_raw("vda:abc:512"),
            Err(StreamError::MalformedRawNumber {
                field: "offset",
                value: "abc".to_string()
            })
        );
        assert_eq!(
            parse_image_raw("vda:8388608:0x200"),
            Err(StreamError::MalformedRawNumber {
                field: "len",
                value: "0x200".to_string()
            })
        );
                                                                                                     
        assert_eq!(
            parse_image_raw("vda:+8388608:512"),
            Err(StreamError::MalformedRawNumber {
                field: "offset",
                value: "+8388608".to_string()
            })
        );
    }

    #[test]
    fn image_raw_rejects_offset_plus_len_overflow() {
                                                                                                    
        let offset = u64::MAX - (INSTALL_COPY_CHUNK_BYTES - 1);                    
        let len = INSTALL_COPY_CHUNK_BYTES + 512;
        let value = format!("vda:{offset}:{len}");
        assert_eq!(
            parse_image_raw(&value),
            Err(StreamError::RawRegionOverflow { offset, len })
        );
    }

    #[test]
    fn image_raw_rejects_missing_and_extra_fields() {
        assert_eq!(
            parse_image_raw("vda:8388608"),
            Err(StreamError::MalformedImageRaw {
                value: "vda:8388608".to_string()
            })
        );
        assert_eq!(
            parse_image_raw("vda:8388608:512:9"),
            Err(StreamError::MalformedImageRaw {
                value: "vda:8388608:512:9".to_string()
            })
        );
        assert_eq!(
            parse_image_raw(""),
            Err(StreamError::MalformedImageRaw {
                value: String::new()
            })
        );
    }

                                              

    #[test]
    fn image_layout_accepts_the_spec_example_with_weights() {
                                                                                                  
        let l = parse_image_layout(
            "fw:seabios-gpt,boot:0:209715200,skel:209715200:33554432,\
             rootfs:243269632:318767104,weights:562036736:1714917376",
        )
        .expect("spec example must parse");
        assert_eq!(
            l,
            StreamLayout {
                firmware: Firmware::SeabiosGpt,
                boot: (0, 209_715_200),
                skel: (209_715_200, 33_554_432),
                rootfs: (243_269_632, 318_767_104),
                weights: Some((562_036_736, 1_714_917_376)),
            }
        );
    }

    #[test]
    fn image_layout_accepts_four_entries_without_weights() {
                                                                                              
                                                                                                   
                         
        let l = parse_image_layout(
            "fw:seabios,boot:0:1048576,skel:1048576:524288,rootfs:2097152:4194304",
        )
        .expect("4-entry layout must parse");
        assert_eq!(l.firmware, Firmware::Seabios);
        assert_eq!(l.weights, None);
        assert_eq!(l.rootfs, (2_097_152, 4_194_304));
    }

                                              

    #[test]
    fn image_layout_rejects_a_missing_fw_field() {
        let v = "boot:0:512,skel:512:512,rootfs:1024:512";
        assert!(matches!(
            parse_image_layout(v),
            Err(StreamError::MalformedImageLayout { .. })
        ));
    }

    #[test]
    fn image_layout_rejects_an_unknown_firmware_word() {
        assert_eq!(
            parse_image_layout("fw:coreboot,boot:0:512,skel:512:512,rootfs:1024:512"),
            Err(StreamError::LayoutBadFirmware {
                value: "coreboot".to_string()
            })
        );
    }

    #[test]
    fn image_layout_rejects_uefi_in_fw() {
                                                                                                  
        assert_eq!(
            parse_image_layout("fw:uefi,boot:0:512,skel:512:512,rootfs:1024:512"),
            Err(StreamError::LayoutBadFirmware {
                value: "uefi".to_string()
            })
        );
    }

    #[test]
    fn image_layout_rejects_wrong_entry_order() {
                                                                           
        assert!(matches!(
            parse_image_layout("fw:seabios,skel:512:512,boot:0:512,rootfs:1024:512"),
            Err(StreamError::MalformedImageLayout { .. })
        ));
    }

    #[test]
    fn image_layout_rejects_duplicate_keys() {
                                                                                      
        assert!(matches!(
            parse_image_layout("fw:seabios,boot:0:512,boot:512:512,rootfs:1024:512"),
            Err(StreamError::MalformedImageLayout { .. })
        ));
    }

    #[test]
    fn image_layout_rejects_overlapping_regions() {
                                                                                 
        assert_eq!(
            parse_image_layout("fw:seabios,boot:0:512,skel:512:1024,rootfs:1024:512"),
            Err(StreamError::LayoutRegionsNotAscending {
                prev: "skel",
                next: "rootfs"
            })
        );
    }

    #[test]
    fn image_layout_rejects_non_ascending_regions() {
                                                                        
        assert_eq!(
            parse_image_layout("fw:seabios,boot:0:512,skel:8192:512,rootfs:1024:512"),
            Err(StreamError::LayoutRegionsNotAscending {
                prev: "skel",
                next: "rootfs"
            })
        );
    }

    #[test]
    fn image_layout_rejects_weights_order_swap() {
                                                                                         
        assert!(matches!(
            parse_image_layout(
                "fw:seabios-gpt,boot:0:512,skel:512:512,weights:1024:512,rootfs:2048:512"
            ),
            Err(StreamError::MalformedImageLayout { .. })
        ));
    }

    #[test]
    fn image_layout_rejects_a_per_entry_overflow() {
        let off = u64::MAX - (INSTALL_COPY_CHUNK_BYTES - 1);
        let v =
            format!("fw:seabios,boot:0:512,skel:512:512,rootfs:{off}:{INSTALL_COPY_CHUNK_BYTES}");
        assert_eq!(
            parse_image_layout(&v),
            Err(StreamError::LayoutRegionOverflow {
                component: "rootfs"
            })
        );
    }

    #[test]
    fn image_layout_rejects_an_empty_region() {
        assert_eq!(
            parse_image_layout("fw:seabios,boot:0:512,skel:512:0,rootfs:1024:512"),
            Err(StreamError::LayoutRegionEmpty { component: "skel" })
        );
    }

    #[test]
    fn image_layout_rejects_non_numeric_region_fields() {
        assert_eq!(
            parse_image_layout("fw:seabios,boot:0:512,skel:512:512,rootfs:beef:512"),
            Err(StreamError::MalformedLayoutNumber {
                component: "rootfs",
                value: "beef".to_string()
            })
        );
    }

                                                                   

    /// The shared placement formula (orchard's `place_and_check_window` twin): the window sits at
    /// the extreme allowed tail, aligned DOWN to a chunk multiple.
    fn tail_window_offset(disk_bytes: u64, tail_reserve_bytes: u64, img_len: u64) -> u64 {
        let top = disk_bytes - tail_reserve_bytes - img_len;
        top - (top % INSTALL_COPY_CHUNK_BYTES)
    }

    fn sha256_hex(data: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(data.as_bytes());
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn golden_vectors_hash_is_pinned() {
                                                                                                  
        assert_eq!(
            sha256_hex(&format!("{GOLDEN_VECTORS:?}")),
            GOLDEN_VECTORS_SHA256,
            "GOLDEN_VECTORS changed — update the pin AND orchard's staging_geometry twin together"
        );
    }

    #[test]
    fn golden_vectors_drive_layout_and_window_verdicts() {
        for &(disk, fw_wire, weights, skel, restore, img, persist_start, window_off, verdict) in
            GOLDEN_VECTORS
        {
            let fw = Firmware::from_wire(fw_wire).expect("vector firmware");
            let weights_opt = (weights != 0).then_some(weights);
            let layout = crate::installer::compute_partition_layout(disk, fw, weights_opt);
            if verdict == "disk-too-small" {
                assert!(
                    matches!(
                        layout,
                        Err(crate::installer::InstallerError::DiskTooSmall { .. })
                    ),
                    "vector disk={disk}: expected DiskTooSmall"
                );
                continue;
            }
            let layout = layout.unwrap_or_else(|e| panic!("vector disk={disk}: layout: {e}"));
            assert_eq!(
                layout.persist.start_lba * SECTOR_SIZE,
                persist_start,
                "vector disk={disk} fw={fw_wire} weights={weights}: persist_start drift"
            );
            let tail_reserve = match fw {
                Firmware::Seabios => 0,
                Firmware::SeabiosGpt | Firmware::Uefi => 33 * SECTOR_SIZE,
            };
            let (kind, hit) = match verdict {
                "ok" => ("ok", ""),
                v => {
                    if let Some(h) = v.strip_prefix("refuse=") {
                        ("refuse", h)
                    } else if let Some(h) = v.strip_prefix("given-refuse=") {
                        ("given-refuse", h)
                    } else {
                        panic!("unknown verdict {v:?}")
                    }
                }
            };
                                                                                          
            if kind != "given-refuse" {
                assert_eq!(
                    tail_window_offset(disk, tail_reserve, img),
                    window_off,
                    "vector disk={disk} img={img}: window placement drift"
                );
            }
            let window = RawRegion {
                disk: "vda".to_string(),
                offset: window_off,
                len: img,
            };
            let prefix = skel.max(restore);
            let set = written_set(&layout, disk, fw, prefix);
            let result = check_staging_disjoint(&window, &set, disk, tail_reserve);
            match kind {
                "ok" => assert_eq!(
                    result,
                    Ok(()),
                    "vector disk={disk} img={img}: expected accept"
                ),
                "refuse" | "given-refuse" if hit == "tail-bounds" => assert!(
                    matches!(result, Err(StreamError::StagingWindowOutOfBounds { .. })),
                    "vector disk={disk}: expected tail-bounds refusal, got {result:?}"
                ),
                _ => match result {
                    Err(StreamError::StagingOverlapsInstall { hit: got, .. }) => {
                        assert_eq!(got, hit, "vector disk={disk}: wrong overlap extent")
                    }
                    other => panic!("vector disk={disk}: expected overlap={hit}, got {other:?}"),
                },
            }
        }
    }

    #[test]
    fn written_set_enumerates_every_written_extent() {
                                                                                              
        let disk = 32_212_254_720;
        let layout = crate::installer::compute_partition_layout(
            disk,
            Firmware::SeabiosGpt,
            Some(1_714_917_376),
        )
        .expect("layout");
        let set = written_set(&layout, disk, Firmware::SeabiosGpt, 33_554_432);
        let labels: Vec<&str> = set.iter().map(|r| r.what).collect();
        assert_eq!(
            labels,
            [
                "gpt-primary",
                "gpt-backup",
                "boot",
                "slot-a",
                "slot-b",
                "weights",
                "persist-prefix"
            ]
        );
                                                                                                 
                                                             
        assert_eq!((set[0].start, set[0].end), (0, 34 * SECTOR_SIZE));
        assert_eq!((set[1].start, set[1].end), (disk - 33 * SECTOR_SIZE, disk));
        let persist = set.last().unwrap();
        assert_eq!(persist.start, layout.persist.start_lba * SECTOR_SIZE);
        assert_eq!(persist.end - persist.start, 33_554_432);
                                                                                               
        let mbr_layout =
            crate::installer::compute_partition_layout(disk, Firmware::Seabios, None).expect("mbr");
        let mbr_set = written_set(&mbr_layout, disk, Firmware::Seabios, 1);
        let mbr_labels: Vec<&str> = mbr_set.iter().map(|r| r.what).collect();
        assert_eq!(
            mbr_labels,
            ["mbr-table", "boot", "slot-a", "slot-b", "persist-prefix"]
        );
        assert_eq!((mbr_set[0].start, mbr_set[0].end), (0, SECTOR_SIZE));
    }

    #[test]
    fn check_staging_disjoint_names_the_first_hit_extent() {
                                                                                         
        let disk = 10_737_418_240;
        let layout =
            crate::installer::compute_partition_layout(disk, Firmware::Seabios, None).expect("l");
        let set = written_set(&layout, disk, Firmware::Seabios, 1);
        let window = RawRegion {
            disk: "vda".to_string(),
            offset: 0,
            len: 8_388_608,
        };
        match check_staging_disjoint(&window, &set, disk, 0) {
            Err(StreamError::StagingOverlapsInstall { hit, .. }) => assert_eq!(hit, "mbr-table"),
            other => panic!("expected overlap, got {other:?}"),
        }
                                                                                   
        let evil = RawRegion {
            disk: "vda".to_string(),
            offset: u64::MAX - 511,
            len: 1024,
        };
        assert!(matches!(
            check_staging_disjoint(&evil, &set, disk, 0),
            Err(StreamError::StagingWindowOutOfBounds { .. })
        ));
    }

    #[test]
    fn image_layout_rejects_empty_and_truncated_values() {
        assert!(matches!(
            parse_image_layout(""),
            Err(StreamError::MalformedImageLayout { .. })
        ));
                                                                                                  
        assert!(matches!(
            parse_image_layout("fw:seabios,boot:0:512,skel:512:512"),
            Err(StreamError::MalformedImageLayout { .. })
        ));
        assert!(matches!(
            parse_image_layout(
                "fw:seabios,boot:0:512,skel:512:512,rootfs:1024:512,weights:2048:512,junk:4096:512"
            ),
            Err(StreamError::MalformedImageLayout { .. })
        ));
    }
}

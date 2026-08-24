//! Kernel `/proc/cmdline` parsing for the runtime boot path (spec "Initramfs as compiled Rust
                              
//! binary" steps 2/3 + the cmdline grammar + verity-offset handling +
//! `fb.rootfs-dev` device key — Task 1.6 inc-2, operator-approved 2026-05-26).
//!
//! Pure logic — no syscalls — so it is host-unit-tested. Every parse failure is a typed error the
                 
//! PID-1 caller converts to a kernel panic (the "all errors fatal" contract): a box
//! that cannot parse its own boot cmdline MUST NOT proceed to mount an unverified rootfs.
//!
//! **Runtime cmdline grammar** (what the per-slot extlinux APPEND carries):
//! `fb.root-hash=<hex> fb.verity-hash-offset=<bytes> fb.rootfs-dev=/dev/<dev>` +
//! the kernel-consumed hardening params (`ro lockdown=integrity ima_appraise=enforce
//! sysctl.kernel.yama.ptrace_scope=2`). `fb.rootfs-dev` is the block device backing the
//! verity rootfs; the deploy CLI auto-detects the disk + resolves the slot→partition operator-side
//! and bakes the resolved path in (the box's PID-1 does NO disk detection — smallest-surface, and
//! detection stays on the sovereign operator side). REQUIRED for runtime; installer mode names its
//! source via `fb.image-raw` instead, so `rootfs-dev` is not required there.

use crate::installer::Firmware;
use core::fmt;

/// Boot mode (spec step 6). Runtime is the Task 1.6 path; installer dispatch lands in the deploy
/// file — the parser recognizes the token now so an installer cmdline does NOT silently
/// parse as a runtime boot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootMode {
    Runtime,
    Installer,
}

/// The parsed runtime boot configuration (spec steps 3/4). `root_hash` is the dm-verity root digest
/// (hex, opaque here — validated by the kernel when the verity table is loaded). `verity_hash_offset`
/// is the BYTE offset where the squashfs ends + the hash tree begins inside the rootfs partition.
/// `rootfs_dev` is the block device the verity table reads (`Some` + whitelist-validated for a
/// runtime boot; `None` allowed in installer mode, which uses `fb.image-raw` instead).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootConfig {
    pub mode: BootMode,
    /// The firmware the box runs on (`fb.firmware` token; absent ⇒ Seabios). The verity
    /// pair rides the cmdline on BOTH firmwares (SB-loader plan L4 — on UEFI the cmdline is a
    /// const inside the signed rambutan loader); there is no other source.
    pub firmware: Firmware,
    pub root_hash: String,
    pub verity_hash_offset: u64,
    pub rootfs_dev: Option<String>,
    /// §9.5 UEFI installer: the box `.img` SHA-256 (decoded from `fb.image-sha256`, 64-char lowercase
    /// hex → 32 bytes) the installer verifies before any write. `None` whenever the token is absent
    /// (every runtime cmdline; a SeaBIOS installer). Decoded here (unlike `root_hash`, kept hex per the
                   
    /// deferral) because the verify-before-write consumer needs the raw digest.
    pub image_sha256: Option<[u8; 32]>,
    /// §9.5 UEFI installer: an optional explicit whole-disk install target (`fb.install-to=<dev>`),
    /// validated at parse via [`crate::install_target::valid_install_to_dev`]. `None` ⇒ auto-select the
    /// single eligible internal disk (§6). Consumed by the Task-2.4 target selection.
    pub install_to: Option<String>,
    /// dha Component E: the weights dm-verity volume triple (`fb.weights-dev`/`-hash`/`-offset`).
    /// `Some` only on a dha box (the bake emits all three together); `None` on every non-dha box.
            
    /// All-or-nothing — a partial set is a fail-closed parse error (B-H1), never a silent
    /// weights-less boot.
    pub weights: Option<WeightsConfig>,
}

/// The dha weights dm-verity volume's cmdline triple (Component E). `dev` is the weights partition's
/// PARTUUID (a GPT-firmware shape resolved against the on-disk GPT in init, like `rootfs_dev` — but a
/// SEPARATE validator from the rootfs whitelist, with no `/dev` form; R5-Info-3). `hash` is its
/// dm-verity root digest (hex, opaque here — kernel-validated). `offset` is the byte offset where the
/// weights squashfs ends + its hash tree begins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightsConfig {
    pub dev: String,
    pub hash: String,
    pub offset: u64,
}

/// A cmdline that the init cannot safely act on. Each variant maps to a kernel-panic diagnostic in
            
/// the PID-1 caller (missing/invalid keys are fatal, never defaulted).
#[derive(Debug, PartialEq, Eq)]
pub enum CmdlineError {
    MissingRootHash,
    MissingVerityOffset,
    InvalidVerityOffset(String),
    /// Runtime boot without `fb.rootfs-dev` — the init has no device to set up verity over
    /// (no in-init disk detection by design); kernel-panic rather than guess a device.
    MissingRootfsDev,
    /// `fb.rootfs-dev` is present but not an accepted `/dev/<a-z0-9>` device path. Fail closed
    /// rather than open an unexpected path (whitelist, not blacklist).
    InvalidRootfsDev(String),
    UnknownMode(String),
    /// `fb.firmware` is present but not `seabios`/`seabios-gpt`/`uefi` — fail closed (never default).
    UnknownFirmware(String),
    /// `fb.image-sha256` is present but not exactly 64 lowercase-hex chars — fail closed, never install
    /// from an unverifiable digest (§9.5).
    InvalidImageSha256(String),
    /// `fb.install-to` is present but not a valid WHOLE-disk device name (a partition, an unknown class,
    /// uppercase, slashes …) — fail closed, never set a partition/garbage destructive target (§9.5).
    InvalidInstallTo(String),
    /// A dha weights triple is partially specified (some of `fb.weights-dev`/`-hash`/`-offset` present,
    /// not all) — fail closed (B-H1): a dha box carries all three or none, never boots weights-less or
    /// mounts an unverified volume.
    IncompleteWeights,
    /// `fb.weights-dev` is present but not an accepted PARTUUID for this firmware (the weights volume is
    /// a GPT partition; a `/dev` node, a non-GPT firmware, or a malformed/uppercase GUID fails closed).
    InvalidWeightsDev(String),
    /// `fb.weights-offset` is present but not a `u64` — fail closed (never mount weights at a bogus offset).
    InvalidWeightsOffset(String),
}

impl fmt::Display for CmdlineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRootHash => write!(f, "fb.root-hash not set on cmdline"),
            Self::MissingVerityOffset => write!(f, "fb.verity-hash-offset not set on cmdline"),
            Self::InvalidVerityOffset(v) => {
                write!(f, "fb.verity-hash-offset not a u64: {v:?}")
            }
            Self::MissingRootfsDev => {
                write!(
                    f,
                    "fb.rootfs-dev not set on cmdline (required for runtime boot)"
                )
            }
            Self::InvalidRootfsDev(v) => {
                write!(
                    f,
                    "fb.rootfs-dev not an accepted /dev/<a-z0-9> device: {v:?}"
                )
            }
            Self::UnknownMode(v) => write!(f, "fb.mode unrecognized: {v:?}"),
            Self::UnknownFirmware(v) => {
                write!(
                    f,
                    "fb.firmware unrecognized (want seabios/seabios-gpt/uefi): {v:?}"
                )
            }
            Self::InvalidImageSha256(v) => {
                write!(f, "fb.image-sha256 not 64-char lowercase hex: {v:?}")
            }
            Self::InvalidInstallTo(v) => {
                write!(f, "fb.install-to not a valid whole-disk device: {v:?}")
            }
            Self::IncompleteWeights => write!(
                f,
                "fb.weights-dev/-hash/-offset must all be present (a dha box) or all absent"
            ),
            Self::InvalidWeightsDev(v) => {
                write!(
                    f,
                    "fb.weights-dev not an accepted PARTUUID for this firmware: {v:?}"
                )
            }
            Self::InvalidWeightsOffset(v) => {
                write!(f, "fb.weights-offset not a u64: {v:?}")
            }
        }
    }
}

/// Parse the runtime boot config from a kernel cmdline string (space-separated `key=value` tokens —
/// the form `/proc/cmdline` carries). `fb.mode` absent ⇒ Runtime (spec step 6); `fb.firmware`
/// absent ⇒ Seabios. `fb.root-hash` + `fb.verity-hash-offset` are REQUIRED on BOTH firmwares
                     
/// (a missing key is a kernel panic, not a default; SB-loader plan L4: SeaBIOS
/// bakes them into the extlinux APPEND, UEFI into the signed loader's cmdline const — one grammar,
/// one delivery path). `fb.rootfs-dev` is required + whitelist-validated for
/// any runtime boot (a `/dev` path on SeaBIOS, a `PARTUUID=` on UEFI/SeabiosGpt). Bare flags + kernel params (`ro`,
/// `lockdown=integrity`, `ima_appraise=enforce`, `sysctl.kernel.yama.ptrace_scope=2`) are ignored here.
pub fn parse_cmdline(cmdline: &str) -> Result<BootConfig, CmdlineError> {
    let mut root_hash: Option<String> = None;
    let mut offset_raw: Option<String> = None;
    let mut rootfs_dev: Option<String> = None;
    let mut mode = BootMode::Runtime;
    let mut firmware = Firmware::Seabios;                                                    
    let mut image_sha256_raw: Option<String> = None;
    let mut install_to_raw: Option<String> = None;
    let mut weights_dev_raw: Option<String> = None;
    let mut weights_hash_raw: Option<String> = None;
    let mut weights_offset_raw: Option<String> = None;

    for tok in cmdline.split_whitespace() {
        let Some((key, val)) = tok.split_once('=') else {
            continue;                         
        };
        match key {
            "fb.root-hash" => root_hash = Some(val.to_string()),
            "fb.verity-hash-offset" => offset_raw = Some(val.to_string()),
            "fb.rootfs-dev" => rootfs_dev = Some(val.to_string()),
            "fb.image-sha256" => image_sha256_raw = Some(val.to_string()),
            "fb.install-to" => install_to_raw = Some(val.to_string()),
            "fb.weights-dev" => weights_dev_raw = Some(val.to_string()),
            "fb.weights-hash" => weights_hash_raw = Some(val.to_string()),
            "fb.weights-offset" => weights_offset_raw = Some(val.to_string()),
            "fb.mode" => {
                mode = match val {
                    "runtime" => BootMode::Runtime,
                    "installer" => BootMode::Installer,
                    other => return Err(CmdlineError::UnknownMode(other.to_string())),
                }
            }
            "fb.firmware" => {
                firmware = Firmware::from_wire(val)
                    .ok_or_else(|| CmdlineError::UnknownFirmware(val.to_string()))?;
            }
            _ => {}
        }
    }

                                                                                         
                                                                                    
                                                                                       
                                                                                   
                                                                                        
                                    
    let (root_hash, verity_hash_offset) = validate_verity_pair(root_hash, offset_raw)?;

                                                                                              
                                                                                         
                                        
    let rootfs_dev = match mode {
        BootMode::Runtime => {
            let dev = rootfs_dev
                .filter(|s| !s.is_empty())
                .ok_or(CmdlineError::MissingRootfsDev)?;
            if !is_valid_rootfs_dev(&dev, firmware) {
                return Err(CmdlineError::InvalidRootfsDev(dev));
            }
            Some(dev)
        }
        BootMode::Installer => rootfs_dev.filter(|s| !s.is_empty()),
    };

                                                                                                           
                                                                                                      
                                                                                        
    let image_sha256 = match image_sha256_raw.filter(|s| !s.is_empty()) {
        Some(s) => Some(decode_hex_32(&s).ok_or(CmdlineError::InvalidImageSha256(s))?),
        None => None,
    };

                                                                                                        
                                                                                      
    let install_to = match install_to_raw.filter(|s| !s.is_empty()) {
        Some(s) if crate::install_target::valid_install_to_dev(&s) => Some(s),
        Some(s) => return Err(CmdlineError::InvalidInstallTo(s)),
        None => None,
    };

                                                                                                      
                                                                                                     
    let weights = parse_weights(
        weights_dev_raw,
        weights_hash_raw,
        weights_offset_raw,
        firmware,
    )?;

    Ok(BootConfig {
        mode,
        firmware,
        root_hash,
        verity_hash_offset,
        rootfs_dev,
        image_sha256,
        install_to,
        weights,
    })
}

/// Validate the dm-verity fb.root-hash + byte-offset pair (one cmdline delivery path, both
/// firmwares — SB-loader plan L4). fb.root-hash: non-empty (empty/absent ⇒
/// `MissingRootHash`); offset: a `u64` (absent ⇒ `MissingVerityOffset`, non-numeric ⇒
/// `InvalidVerityOffset`). The hash stays the hex `String` (decoded only by the
               
/// kernel/verity).
///
                                
/// DEFERRED: a stricter 64-lowercase-hex shape check on `fb.root-hash` is
/// NOT enforced here. The kernel's `verity_ctr` already rejects a wrong-length / non-hex digest
/// fail-closed; this matches the pre-existing SeaBIOS looseness (no regression this branch); and the
/// consumer that will ASSUME the 64-hex shape (the air-gapped signer's Thread-2 `decode_hex_32`) is not
/// in this surface. Tighten this single chokepoint when Thread-2 lands — the consumer + its test
/// fixtures arrive together, instead of 64-char-ifying ~15 unrelated fixtures now.
fn validate_verity_pair(
    root_hash: Option<String>,
    offset_raw: Option<String>,
) -> Result<(String, u64), CmdlineError> {
    let rh = root_hash
        .filter(|s| !s.is_empty())
        .ok_or(CmdlineError::MissingRootHash)?;
    let raw = offset_raw.ok_or(CmdlineError::MissingVerityOffset)?;
    let off = raw
        .parse::<u64>()
        .map_err(|_| CmdlineError::InvalidVerityOffset(raw.clone()))?;
    Ok((rh, off))
}

               
/// Decode a 64-char lowercase-hex string to `[u8; 32]` (the shared digest representation; mirrors
/// rambutan's `hex.rs`). `None` unless EXACTLY 64 chars, all `[0-9a-f]` — uppercase and wrong lengths
/// fail closed (whitelist, not blacklist). Used for `fb.image-sha256` (§9.5 verify-before-write).
fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

                                                                                 
                                                                                       
                                                                                   

                                     
/// Whitelist the rootfs device token, firmware-conditional — one
/// shape per firmware, not a blanket relax. `PARTUUID=<canonical lowercase GUID>` is the GPT-firmware
/// shape (UEFI, SeabiosGpt), resolved against the on-disk GPT in init; it is rejected on SeaBIOS
               
/// (its MBR boot partition isn't verity-covered and there's no GPT to resolve against, so
/// exposing the resolver FFI in PID-1 would be needless). `/dev/<name>` (non-empty ascii-lowercase plus
/// digits; covers `sda2`/`vda2`/`nvme0n1p2`) is the SeaBIOS shape and, preserved unchanged, UEFI; it is
/// rejected on SeabiosGpt, which selects slot-A by the baked PARTUUID only (like UEFI), so accepting a
/// `/dev` node there would needlessly widen the GPT firmware. Both shapes rule OUT slashes (so
/// `/dev/mapper/...`, `/dev/../etc`, traversal don't match), uppercase, and punctuation. A hostile or
/// malformed token fails closed (kernel panic) rather than opening an unexpected path. (NB: UEFI's
/// pre-existing `/dev` acceptance is preserved — the SeabiosGpt addition must not tighten the UEFI arm;
/// AC-invariant.)
fn is_valid_rootfs_dev(s: &str, firmware: Firmware) -> bool {
    if let Some(uuid) = s.strip_prefix("PARTUUID=") {
                                                                                                     
        return matches!(firmware, Firmware::Uefi | Firmware::SeabiosGpt)
            && is_canonical_lowercase_guid(uuid);
    }
                                                                                                    
    if firmware == Firmware::SeabiosGpt {
        return false;
    }
    match s.strip_prefix("/dev/") {
        Some(rest) => {
            !rest.is_empty()
                && rest
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        }
        None => false,
    }
}

/// Assemble the optional dha weights triple from its three raw cmdline tokens (Component E). Empty
/// values are treated as absent (mirrors `rootfs_dev`/`install_to`). ALL-OR-NOTHING: all absent ⇒
        
/// `None` (a non-dha box); all present ⇒ a validated `Some` (PARTUUID device + `u64` offset; the
/// hash stays opaque hex, kernel-validated); any partial set ⇒ `IncompleteWeights`, fail-closed (B-H1 —
/// never silently boot weights-less or mount an unverified volume).
fn parse_weights(
    dev: Option<String>,
    hash: Option<String>,
    offset_raw: Option<String>,
    firmware: Firmware,
) -> Result<Option<WeightsConfig>, CmdlineError> {
    match (
        dev.filter(|s| !s.is_empty()),
        hash.filter(|s| !s.is_empty()),
        offset_raw.filter(|s| !s.is_empty()),
    ) {
        (None, None, None) => Ok(None),
        (Some(dev), Some(hash), Some(offset_raw)) => {
            if !is_valid_weights_dev(&dev, firmware) {
                return Err(CmdlineError::InvalidWeightsDev(dev));
            }
            let offset = offset_raw
                .parse::<u64>()
                .map_err(|_| CmdlineError::InvalidWeightsOffset(offset_raw.clone()))?;
            Ok(Some(WeightsConfig { dev, hash, offset }))
        }
        _ => Err(CmdlineError::IncompleteWeights),
    }
}

/// Whitelist the weights device token: ALWAYS a canonical-lowercase `PARTUUID=` (the weights volume is a
/// 5th GPT partition under O4=(a) GPT, resolved against the on-disk GPT in init — like `rootfs_dev`).
/// SEPARATE from [`is_valid_rootfs_dev`] (R5-Info-3): there is NO `/dev` form, and PARTUUID resolution
/// needs a GPT, so it is accepted ONLY on the GPT firmwares (UEFI, SeabiosGpt) and fails closed on legacy
/// SeaBIOS/MBR. A `/dev` node, a mapper path, or a malformed/uppercase GUID fails the whitelist.
fn is_valid_weights_dev(s: &str, firmware: Firmware) -> bool {
    match s.strip_prefix("PARTUUID=") {
        Some(uuid) => {
            matches!(firmware, Firmware::Uefi | Firmware::SeabiosGpt)
                && is_canonical_lowercase_guid(uuid)
        }
        None => false,
    }
}

/// Whitelist a canonical LOWERCASE `8-4-4-4-12` hex GUID — the PARTUUID form a UEFI `rootfs-dev` carries
/// and the slot-A GPT entry stores. Uppercase, wrong group lengths, or a non-hex digit fail closed
/// (never resolve a malformed PARTUUID against the GPT). Lowercase-only mirrors the canonical literal in
/// `installer::SLOT_A_PARTUUID`.
fn is_canonical_lowercase_guid(s: &str) -> bool {
    let groups: Vec<&str> = s.split('-').collect();
    if groups.len() != 5
        || [8, 4, 4, 4, 12]
            != [
                groups[0].len(),
                groups[1].len(),
                groups[2].len(),
                groups[3].len(),
                groups[4].len(),
            ]
    {
        return false;
    }
    groups
        .iter()
        .all(|g| g.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
}

                                                                                                
                                                                                                
                                                                                                   
                                  

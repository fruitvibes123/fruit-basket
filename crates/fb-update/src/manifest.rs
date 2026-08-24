//! The §4a update manifest — hand-rolled `key = value` parser (the `parse_image_layout`
//! idiom: line-based, LF, UTF-8, no toml/serde dep on the box). WHITELIST + fail-closed
//! (R1-9): unknown keys REFUSE, duplicate keys REFUSE, all 12 fields required. The
//! signature binds the exact manifest bytes, so a duplicate can't be *injected* — the
//! refusal exists so the box parser and the operator composer can never diverge on
//! last-wins semantics.

/// The parsed §4a manifest. All fields required on the wire; `image_sha256` is
/// evidence/audit binding only (the box never sees the `.img`), everything else is
/// enforced by `apply`'s guards.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateManifest {
    /// Manifest wire format (1; anything else refuses as [`ManifestError::BadFormat`]).
    pub format: u64,
    /// Target firmware selector token. Kept a plain `String` at the parse boundary —
    /// the apply guard enforces `== "seabios-gpt"` AND `== the box's own fb.firmware`
    /// (rows 16/17); the parser is structural only.
    pub firmware: String,
    /// The target image's baked `image_version` (§4i) — the version-floor input.
    pub version: u64,
    /// SHA-256 of the source `.img` (informational binding, not enforced box-side).
    pub image_sha256: [u8; 32],
    /// The NEW slot's dm-verity root hash — kept as the EXACT wire bytes (64 lowercase
    /// hex, validated), never decoded/re-encoded: the record, the label patch, and the
    /// running cmdline compare these bytes byte-equal (R6-1 byte-faithful).
    pub root_hash: String,
    /// The verity hash-tree offset within the rootfs partition (the label's
    /// `fb.verity-hash-offset` patch value).
    pub verity_hash_offset: u64,
    /// SHA-256 of the rootfs component (write-then-verify before the promotion point).
    pub rootfs_sha256: [u8; 32],
    /// Rootfs component length (≤ `SLOT_SIZE_BYTES`, enforced by the apply guard).
    pub rootfs_size: u64,
    /// SHA-256 of the kernel component.
    pub kernel_sha256: [u8; 32],
    /// Kernel component length (with initramfs: ≤ `SLOT_BOOT_BUDGET`, apply guard).
    pub kernel_size: u64,
    /// SHA-256 of the initramfs component.
    pub initramfs_sha256: [u8; 32],
    /// Initramfs component length.
    pub initramfs_size: u64,
}

/// Why a manifest (or a probation record — shared kv vocabulary) failed to parse.
/// Fail-closed: every variant refuses the whole document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    /// A key outside the exact whitelist (fail-closed: new fields need a format bump).
    UnknownKey(String),
    /// A whitelisted key appearing twice (no last-wins divergence).
    DuplicateKey(String),
    /// A required key absent.
    MissingKey(&'static str),
    /// A key present with a value that fails its strict type (non-decimal u64,
    /// non-64-lowercase-hex, uppercase drift, wrong length).
    BadValue { key: &'static str },
    /// Structurally not the wire format: non-UTF-8, a non-`key = value` line, a blank
    /// line, a missing trailing LF, empty input — or an unsupported `format` version.
    BadFormat,
}

/// The manifest's exact key set (spec §4a, wire order).
const MANIFEST_KEYS: [&str; 12] = [
    "format",
    "firmware",
    "version",
    "image_sha256",
    "root_hash",
    "verity_hash_offset",
    "rootfs_sha256",
    "rootfs_size",
    "kernel_sha256",
    "kernel_size",
    "initramfs_sha256",
    "initramfs_size",
];

/// Split canonical `key = value` lines: UTF-8, every line non-empty and containing
/// ` = ` exactly as the delimiter (first occurrence), trailing LF REQUIRED. Shared by
/// the manifest and the probation record (one kv discipline, one error vocabulary).
pub(crate) fn kv_lines(bytes: &[u8]) -> Result<Vec<(&str, &str)>, ManifestError> {
    let s = std::str::from_utf8(bytes).map_err(|_| ManifestError::BadFormat)?;
    let body = s.strip_suffix('\n').ok_or(ManifestError::BadFormat)?;
    if body.is_empty() {
        return Err(ManifestError::BadFormat);
    }
    let mut out = Vec::new();
    for line in body.split('\n') {
        let (k, v) = line.split_once(" = ").ok_or(ManifestError::BadFormat)?;
        if k.is_empty() || v.is_empty() {
            return Err(ManifestError::BadFormat);
        }
        out.push((k, v));
    }
    Ok(out)
}

/// Strict decimal u64: ASCII digits only (no sign, no whitespace), range-checked.
pub(crate) fn parse_u64(v: &str, key: &'static str) -> Result<u64, ManifestError> {
    if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ManifestError::BadValue { key });
    }
    v.parse::<u64>()
        .map_err(|_| ManifestError::BadValue { key })
}

/// Exactly 64 lowercase hex chars (the byte-faithful root-hash shape — uppercase is
/// REFUSED at the boundary so no later compare can be asked to normalize, R6-1).
pub(crate) fn validate_hex64_lower(v: &str, key: &'static str) -> Result<(), ManifestError> {
    if v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(ManifestError::BadValue { key })
    }
}

/// 64 lowercase hex chars → the 32 raw bytes.
fn parse_hex32(v: &str, key: &'static str) -> Result<[u8; 32], ManifestError> {
    validate_hex64_lower(v, key)?;
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_nibble(v.as_bytes()[2 * i]);
        let lo = hex_nibble(v.as_bytes()[2 * i + 1]);
        *byte = (hi << 4) | lo;
    }
    Ok(out)
}

/// Nibble value of a validated lowercase hex char.
fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        _ => b - b'a' + 10,
    }
}

/// Parse + validate a §4a update manifest. Whitelist, fail-closed, all fields
/// required, strict value types; `format` must be 1.
pub fn parse_manifest(bytes: &[u8]) -> Result<UpdateManifest, ManifestError> {
    let mut vals: [Option<&str>; 12] = [None; 12];
    for (k, v) in kv_lines(bytes)? {
        let Some(i) = MANIFEST_KEYS.iter().position(|kk| *kk == k) else {
            return Err(ManifestError::UnknownKey(k.to_string()));
        };
        if vals[i].is_some() {
            return Err(ManifestError::DuplicateKey(k.to_string()));
        }
        vals[i] = Some(v);
    }
    for (i, key) in MANIFEST_KEYS.iter().enumerate() {
        if vals[i].is_none() {
            return Err(ManifestError::MissingKey(key));
        }
    }
    let get = |i: usize| vals[i].expect("presence checked above");

    let format = parse_u64(get(0), "format")?;
    if format != 1 {
        return Err(ManifestError::BadFormat);
    }
    let root_hash = get(4);
    validate_hex64_lower(root_hash, "root_hash")?;
    Ok(UpdateManifest {
        format,
        firmware: get(1).to_string(),
        version: parse_u64(get(2), "version")?,
        image_sha256: parse_hex32(get(3), "image_sha256")?,
        root_hash: root_hash.to_string(),
        verity_hash_offset: parse_u64(get(5), "verity_hash_offset")?,
        rootfs_sha256: parse_hex32(get(6), "rootfs_sha256")?,
        rootfs_size: parse_u64(get(7), "rootfs_size")?,
        kernel_sha256: parse_hex32(get(8), "kernel_sha256")?,
        kernel_size: parse_u64(get(9), "kernel_size")?,
        initramfs_sha256: parse_hex32(get(10), "initramfs_sha256")?,
        initramfs_size: parse_u64(get(11), "initramfs_size")?,
    })
}

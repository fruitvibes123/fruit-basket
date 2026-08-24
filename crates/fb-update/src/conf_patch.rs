//! The fixed-geometry `extlinux.conf` field patcher (spec §4d patch discipline) — the
//! in-memory half of the five patchable fields: the `DEFAULT` value (width 8,
//! space-padded) and each label's `fb.root-hash` (64) + `fb.verity-hash-offset` (12,
//! zero-padded). Anchored exactly-once scans, existing width + delimiter verified,
//! strictly length-preserving overwrite (`&mut [u8]` — the type cannot grow), and a
//! refusal never writes a byte (validate-all-then-write). Mirrors the shipped
//! `patch_rootfs_dev` idiom (orchard `prod.rs`): anchored content scan, in-place,
//! size/extents/inode never change. The on-disk pwrite + fsync + re-read-validate
//! discipline is the caller's (T14 apply / T18 mark-good commit).

use crate::Slot;

/// Why a conf patch refused (fail-closed: zero/&gt;1 anchors or a width/delimiter
/// mismatch means the conf is not the fixed-geometry template we baked — REFUSE,
/// never guess). The payload names the anchor that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchError {
    /// The anchor was not found.
    NotFound(&'static str),
    /// The anchor matched more than once (a malformed/duplicated conf).
    Ambiguous(&'static str),
    /// The field at the anchor does not have the fixed width/delimiter shape, or the
    /// replacement value does not fit the field exactly.
    WidthMismatch(&'static str),
}

/// Find `needle` exactly once in `hay`; return the match offset.
fn find_exactly_once(hay: &[u8], needle: &[u8], what: &'static str) -> Result<usize, PatchError> {
    let mut found: Option<usize> = None;
    if needle.is_empty() || hay.len() < needle.len() {
        return Err(PatchError::NotFound(what));
    }
    for at in 0..=(hay.len() - needle.len()) {
        if &hay[at..at + needle.len()] == needle {
            if found.is_some() {
                return Err(PatchError::Ambiguous(what));
            }
            found = Some(at);
        }
    }
    found.ok_or(PatchError::NotFound(what))
}

/// Verify the `width` bytes at `field` form one full-width token (no delimiter inside)
/// and are followed by a delimiter (space or newline) — i.e. the fixed-geometry shape
/// the bake produced. Anything else means template drift: REFUSE.
fn check_field_shape(
    conf: &[u8],
    field: usize,
    width: usize,
    what: &'static str,
) -> Result<(), PatchError> {
    let end = field + width;
    if end >= conf.len() {
        return Err(PatchError::WidthMismatch(what));
    }
    if conf[field..end].iter().any(|&b| b == b'\n' || b == b' ') {
        return Err(PatchError::WidthMismatch(what));
    }
    if conf[end] != b' ' && conf[end] != b'\n' {
        return Err(PatchError::WidthMismatch(what));
    }
    Ok(())
}

/// Width of the `DEFAULT` value field (space-padded label).
const DEFAULT_WIDTH: usize = 8;
const DEFAULT_ANCHOR: &str = "DEFAULT ";
const ROOT_HASH_ANCHOR: &str = "fb.root-hash=";
const ROOT_HASH_WIDTH: usize = 64;
const OFFSET_ANCHOR: &str = "fb.verity-hash-offset=";
const OFFSET_WIDTH: usize = 12;

/// Patch the `DEFAULT` value to `slot` (the COMMIT patch): locate the `DEFAULT `
/// directive exactly once, verify the width-8 field shape, overwrite with the
/// space-padded label. Length-preserving by type. The caller owes the single-sector
/// on-disk pwrite + fsync + **re-read-validate** (§4d: DEFAULT has no two-copy
/// redundancy — the re-read is its integrity belt).
pub fn patch_default(conf: &mut [u8], slot: Slot) -> Result<(), PatchError> {
    let anchor = find_exactly_once(conf, DEFAULT_ANCHOR.as_bytes(), "DEFAULT ")?;
    let field = anchor + DEFAULT_ANCHOR.len();
                                                                                 
                                                                                     
                                                                      
    let end = field + DEFAULT_WIDTH;
    if end >= conf.len() || conf[field..end].contains(&b'\n') || conf[end] != b'\n' {
        return Err(PatchError::WidthMismatch("DEFAULT "));
    }
    let label = slot.as_str().as_bytes();
    conf[field..end].fill(b' ');
    conf[field..field + label.len()].copy_from_slice(label);
    Ok(())
}

/// Patch `slot`'s label-stanza fields (the STAGE patch): within the `LABEL slot-x`
/// stanza (exactly one; bounded by the next `LABEL ` or EOF), overwrite
/// `fb.root-hash=` (64 bytes, byte-faithful — the verified manifest's exact bytes,
/// never case-folded) and `fb.verity-hash-offset=` (12 bytes, zero-padded decimal),
/// each anchored exactly once in the stanza. ALL validations run before ANY byte is
/// written — a refusal leaves the conf untouched.
pub fn patch_label_fields(
    conf: &mut [u8],
    slot: Slot,
    root_hash: &str,
    verity_hash_offset: u64,
) -> Result<(), PatchError> {
    if root_hash.len() != ROOT_HASH_WIDTH {
        return Err(PatchError::WidthMismatch("fb.root-hash="));
    }
    let offset_value = format!("{verity_hash_offset:012}");
    if offset_value.len() != OFFSET_WIDTH {
        return Err(PatchError::WidthMismatch("fb.verity-hash-offset="));
    }

                                                                                    
    let label_line = format!("LABEL {}\n", slot.as_str());
    let stanza_start = find_exactly_once(conf, label_line.as_bytes(), "LABEL ")? + label_line.len();
    let stanza_end = conf[stanza_start..]
        .windows(7)
        .position(|w| w == b"\nLABEL ")
        .map(|p| stanza_start + p + 1)
        .unwrap_or(conf.len());

                                                                              
    let stanza = &conf[stanza_start..stanza_end];
    let hash_field = stanza_start
        + find_exactly_once(stanza, ROOT_HASH_ANCHOR.as_bytes(), "fb.root-hash=")?
        + ROOT_HASH_ANCHOR.len();
    check_field_shape(conf, hash_field, ROOT_HASH_WIDTH, "fb.root-hash=")?;
    let offset_field = stanza_start
        + find_exactly_once(stanza, OFFSET_ANCHOR.as_bytes(), "fb.verity-hash-offset=")?
        + OFFSET_ANCHOR.len();
    check_field_shape(conf, offset_field, OFFSET_WIDTH, "fb.verity-hash-offset=")?;

    conf[hash_field..hash_field + ROOT_HASH_WIDTH].copy_from_slice(root_hash.as_bytes());
    conf[offset_field..offset_field + OFFSET_WIDTH].copy_from_slice(offset_value.as_bytes());
    Ok(())
}

//! Minimal running-cmdline extraction for the update engine (`/proc/cmdline`):
//! the running slot (via the `fb.rootfs-dev` PARTUUID) and the running
//! `fb.root-hash` — kept as the EXACT cmdline bytes, never normalized (R6-1: the
//! probation-skip and mark-good compares are byte-faithful on both sides).
//!
//! Deliberately a LOCAL extractor, not a dep on initramfs-init's full `parse_cmdline`
//! (pulling the installer crate into fb-update's shipped tree would bloat the T17
//! allowlist for two tokens). Token semantics mirror that parser exactly:
//! whitespace-split, `key=value` via the first `=`, LAST occurrence wins, bare flags
//! ignored.

use crate::Slot;

/// The value of `key` (e.g. `"fb.root-hash"`) in `cmdline`, last occurrence wins,
/// un-normalized. `None` when absent — callers refuse or classify, never default.
pub fn token_value<'a>(cmdline: &'a str, key: &str) -> Option<&'a str> {
    let mut found = None;
    for tok in cmdline.split_whitespace() {
        if let Some((k, v)) = tok.split_once('=')
            && k == key
        {
            found = Some(v);
        }
    }
    found
}

/// The running `fb.root-hash` — exact bytes, no case-fold, no re-encode.
pub fn root_hash(cmdline: &str) -> Option<&str> {
    token_value(cmdline, "fb.root-hash")
}

/// The running slot, derived from `fb.rootfs-dev=PARTUUID=<uuid>` against the two
/// fixed slot PARTUUIDs. `None` for an absent token, a non-PARTUUID form (the MBR
/// box's `/dev/vda3` — updates are refused there anyway), or an unrecognized UUID
/// (row 3: refuse, never guess).
pub fn running_slot(cmdline: &str) -> Option<Slot> {
    let dev = token_value(cmdline, "fb.rootfs-dev")?;
    let uuid = dev.strip_prefix("PARTUUID=")?;
    if uuid == Slot::A.partuuid() {
        Some(Slot::A)
    } else if uuid == Slot::B.partuuid() {
        Some(Slot::B)
    } else {
        None
    }
}

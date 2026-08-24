//! The syslinux ADV (auxiliary data vector) BOOTONCE transform (spec §4e) — a PURE
//! in-memory byte transform over `ldlinux.sys`'s last 1024 bytes; the on-disk arm
//! (O_SYNC + revalidate + return-checked pwrite) is `adv::ondisk` (T13).
//!
//! Faithful port of the pinned syslinux 6.04-pre1 semantics (`libinstaller/setadv.c`,
//! `com32/include/syslinux/advconst.h`; re-read from the pinned tarball — the context
//! map's verified-mechanism section is the ground truth):
//! - per-copy layout: `MAGIC1[0..4] ‖ checksum[4..8] ‖ data[8..508] ‖ MAGIC3[508..512]`;
//!   TWO redundant 512-byte copies back-to-back.
//! - `checksum = MAGIC2 − Σ(data dwords)` wrapping; a copy validates iff MAGIC1 + MAGIC3
//!   match AND `Σ(dwords[4..508]) == MAGIC2`.
//! - data = TLV entries `tag(1) ‖ len(1) ‖ payload(len)`; `ADV_END = 0` terminates;
//!   `ADV_BOOTONCE = 1` carries the once-label bytes (bare, no NUL).
//! - selection is COPY0-PREFERRED (`syslinux_validate_adv`): copy0 if self-consistent,
//!   else copy1, else reset-to-empty — a torn write (both copies valid, different)
//!   silently resolves to copy0, NEVER "torn ⇒ empty" (SPEC-R1 correction).
//! - every userland write re-syncs copy1 := copy0 (`cleanup_adv`).

/// Head signature (`ADV_MAGIC1`).
pub const ADV_MAGIC1: u32 = 0x5a2d_2fa5;
/// Checksum base (`ADV_MAGIC2`): `Σ(checksum ‖ data dwords) == this` on a valid copy.
pub const ADV_MAGIC2: u32 = 0xa304_1767;
/// Tail signature (`ADV_MAGIC3`).
pub const ADV_MAGIC3: u32 = 0xdd28_bf64;

/// One ADV copy (syslinux `ADV_SIZE`).
pub const ADV_COPY_SIZE: usize = 512;
/// Both redundant copies — the last 1024 bytes of `ldlinux.sys`.
pub const ADV_TOTAL_SIZE: usize = 2 * ADV_COPY_SIZE;

/// The TLV data area within one copy (`ADV_LEN = 500` bytes at `[8..508]`).
const DATA_START: usize = 8;
const DATA_END: usize = ADV_COPY_SIZE - 4;

/// `ADV_END` — terminates the TLV walk.
const TAG_END: u8 = 0;
/// `ADV_BOOTONCE` — the boot-once command entry.
const TAG_BOOTONCE: u8 = 1;

/// Why an ADV transform refused. The single failure mode mirrors setadv's `ENOSPC`
/// (an entry needs `len ≤ 255` and `tag+len+payload` to fit the 500-byte data area).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdvError {
    /// The entry does not fit the data area (or exceeds the 255-byte TLV length).
    NoSpace,
}

/// The empty (reset) ADV — byte-identical to `syslinux_reset_adv` + `cleanup_adv`
/// output and to what the bake stages (`syslinux-install::reset_adv`): all-zero data,
/// checksum == MAGIC2 exactly, both copies identical.
pub fn reset_adv() -> [u8; ADV_TOTAL_SIZE] {
    let mut adv = [0u8; ADV_TOTAL_SIZE];
    adv[0..4].copy_from_slice(&ADV_MAGIC1.to_le_bytes());
    adv[4..8].copy_from_slice(&ADV_MAGIC2.to_le_bytes());
    adv[DATA_END..ADV_COPY_SIZE].copy_from_slice(&ADV_MAGIC3.to_le_bytes());
    let (c0, c1) = adv.split_at_mut(ADV_COPY_SIZE);
    c1.copy_from_slice(c0);
    adv
}

/// `adv_consistent`: MAGIC1 + MAGIC3 match and `Σ(dwords[4..508]) == MAGIC2` (wrapping).
fn copy_consistent(copy: &[u8]) -> bool {
    let dword = |at: usize| u32::from_le_bytes(copy[at..at + 4].try_into().expect("4 bytes"));
    if dword(0) != ADV_MAGIC1 || dword(DATA_END) != ADV_MAGIC3 {
        return false;
    }
    let mut sum = 0u32;
    let mut at = 4;
    while at < DATA_END {
        sum = sum.wrapping_add(dword(at));
        at += 4;
    }
    sum == ADV_MAGIC2
}

/// `cleanup_adv`'s single-copy half: stamp MAGIC1/MAGIC3, recompute the checksum over
/// the data area.
fn seal_copy(copy: &mut [u8]) {
    copy[0..4].copy_from_slice(&ADV_MAGIC1.to_le_bytes());
    copy[DATA_END..ADV_COPY_SIZE].copy_from_slice(&ADV_MAGIC3.to_le_bytes());
    let mut sum = 0u32;
    let mut at = DATA_START;
    while at < DATA_END {
        sum = sum.wrapping_add(u32::from_le_bytes(
            copy[at..at + 4].try_into().expect("4 bytes"),
        ));
        at += 4;
    }
    let checksum = ADV_MAGIC2.wrapping_sub(sum);
    copy[4..8].copy_from_slice(&checksum.to_le_bytes());
}

/// `syslinux_validate_adv`, in place: copy0 valid ⇒ copy1 := copy0; else copy1 valid ⇒
/// copy0 := copy1; else BOTH := reset-to-empty. After this the two copies are identical
/// and copy0 is authoritative.
fn validate_normalize(adv: &mut [u8; ADV_TOTAL_SIZE]) {
    let (c0, c1) = adv.split_at_mut(ADV_COPY_SIZE);
    if copy_consistent(c0) {
        c1.copy_from_slice(c0);
    } else if copy_consistent(c1) {
        c0.copy_from_slice(c1);
    } else {
        *adv = reset_adv();
    }
}

/// The `syslinux_setadv` walk + write over ONE copy's data area: delete every existing
/// `tag` entry, then (if `payload` is non-empty) append `tag ‖ len ‖ payload` at the
/// walk position, zero the remainder. Returns Err(NoSpace) exactly where setadv sets
/// ENOSPC. Faithful port — including the delete-without-advance re-examination and the
/// corrupt-overrun-overwrite arm.
fn setadv(data: &mut [u8], tag: u8, payload: &[u8]) -> Result<(), AdvError> {
    if payload.len() > 255 {
        return Err(AdvError::NoSpace);
    }
    let mut at = 0usize;
    let mut left = data.len();
    while left >= 2 {
        let ptag = data[at];
        let plen = data[at + 1] as usize + 2;
        if ptag == TAG_END {
            break;
        }
        if ptag == tag {
            if plen >= left {
                                                                       
                break;
            }
                                                                                   
            data.copy_within(at + plen..at + left, at);
                                                                                     
                                                
            let tail = at + left - plen;
            data[tail..at + left].fill(0);
        } else {
            if plen > left {
                                                                 
                break;
            }
            left -= plen;
            at += plen;
        }
    }
    if !payload.is_empty() {
        if left < payload.len() + 2 {
            return Err(AdvError::NoSpace);
        }
        data[at] = tag;
        data[at + 1] = payload.len() as u8;
        data[at + 2..at + 2 + payload.len()].copy_from_slice(payload);
        at += payload.len() + 2;
        left -= payload.len() + 2;
    }
    data[at..at + left].fill(0);
    Ok(())
}

/// Walk one validated copy's data area for the BOOTONCE entry.
fn find_bootonce(data: &[u8]) -> Option<&[u8]> {
    let mut at = 0usize;
    let mut left = data.len();
    while left >= 2 {
        let ptag = data[at];
        let plen = data[at + 1] as usize + 2;
        if ptag == TAG_END || plen > left {
            return None;
        }
        if ptag == TAG_BOOTONCE {
            return Some(&data[at + 2..at + plen]);
        }
        left -= plen;
        at += plen;
    }
    None
}

/// Set the BOOTONCE entry to `label` (the §4e ARM transform): validate/normalize the
/// two copies (copy0-preferred; both-invalid ⇒ reset, the upstream `extlinux --once`
/// flow), replace any existing BOOTONCE entry, reseal, and mirror BOTH copies. A
/// refusal (`NoSpace`) leaves the buffer untouched.
pub fn set_bootonce(adv: &mut [u8; ADV_TOTAL_SIZE], label: &str) -> Result<(), AdvError> {
    let mut work = *adv;
    validate_normalize(&mut work);
    setadv(
        &mut work[DATA_START..DATA_END],
        TAG_BOOTONCE,
        label.as_bytes(),
    )?;
    seal_copy(&mut work[..ADV_COPY_SIZE]);
    let (c0, c1) = work.split_at_mut(ADV_COPY_SIZE);
    c1.copy_from_slice(c0);
    *adv = work;
    Ok(())
}

/// Clear the BOOTONCE entry if present (the §4e mark-good RE-CLEAR transform —
/// read-then-conditional): returns `Ok(true)` iff a BOOTONCE entry existed (it is now
/// cleared and both copies resealed), `Ok(false)` if the ADV was already clear (the
/// buffer is left byte-untouched, so the caller can skip the disk write entirely).
pub fn clear_bootonce(adv: &mut [u8; ADV_TOTAL_SIZE]) -> Result<bool, AdvError> {
    if read_bootonce(adv).is_none() {
        return Ok(false);
    }
    let mut work = *adv;
    validate_normalize(&mut work);
    setadv(&mut work[DATA_START..DATA_END], TAG_BOOTONCE, &[])?;
    seal_copy(&mut work[..ADV_COPY_SIZE]);
    let (c0, c1) = work.split_at_mut(ADV_COPY_SIZE);
    c1.copy_from_slice(c0);
    *adv = work;
    Ok(true)
}

/// Read the BOOTONCE payload, copy0-preferred (`syslinux_validate_adv` selection,
/// non-mutating): copy0 if self-consistent, else copy1, else `None` (both invalid ⇒
/// the loader would reset ⇒ nothing armed).
pub fn read_bootonce(adv: &[u8; ADV_TOTAL_SIZE]) -> Option<Vec<u8>> {
    let copy = if copy_consistent(&adv[..ADV_COPY_SIZE]) {
        &adv[..ADV_COPY_SIZE]
    } else if copy_consistent(&adv[ADV_COPY_SIZE..]) {
        &adv[ADV_COPY_SIZE..]
    } else {
        return None;
    };
    find_bootonce(&copy[DATA_START..DATA_END]).map(|p| p.to_vec())
}

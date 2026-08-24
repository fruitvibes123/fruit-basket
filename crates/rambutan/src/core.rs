//! Pure, host-tested loader logic: UCS-2 cmdline encoding, the initrd
//! digest gate, the LoadFile2 vendor-media device path, and the SB_REQUIRED
//! decision. No EFI calls — everything here runs under `cargo test` on the host; the
//! EFI shim (`main.rs`/`efi.rs`) is proven at the OVMF gate.

/// Encode the kernel cmdline as null-terminated UCS-2 LE for `LoadOptions` (the
/// `set_load_options` call itself lives in `main.rs`).
///
/// The cmdline grammar `render_uefi_cmdline` emits is printable ASCII + space; anything
/// else (non-ASCII, control chars, embedded NUL) is rejected fail-closed — an embedded
/// NUL would silently truncate the kernel-side parse, never sanitize. Returns the
/// `u16` count INCLUDING the terminating NUL, or `None` (too long for `out` / bad byte).
pub fn encode_cmdline_ucs2(s: &str, out: &mut [u16]) -> Option<u16> {
    let bytes = s.as_bytes();
    let total = bytes.len().checked_add(1)?;                     
    if total > out.len() || total > u16::MAX as usize {
        return None;
    }
    for (i, &b) in bytes.iter().enumerate() {
        if !(b.is_ascii_graphic() || b == b' ') {
            return None;
        }
        out[i] = u16::from(b);
    }
    out[bytes.len()] = 0x0000;
    Some(total as u16)
}

/// `LoadOptionsSize` is a byte count: `count` UCS-2 code units of 2 bytes each.
pub fn load_options_size_bytes(count: u16) -> u32 {
    u32::from(count) * 2
}

/// M1 allocation bound (deep-review finding M1): a size about to be handed to
/// `AllocatePool` is in-bounds iff `min <= size <= max`. The loader gates BOTH of
/// `read_whole_file`'s allocations through this — the `EFI_FILE_INFO` metadata buffer
/// and the file bytes — so a preposterous size from a corrupt filesystem / RAID
/// controller is refused as a clean early `None` (→ halt) instead of driving a doomed
/// huge allocation that fails generically. Inclusive at both ends: exactly `max` is
/// accepted, since the caps are sized above every real artifact (never rejects a
/// legitimate file). A pure predicate here (not inline in the uefi-only loader) so the
/// boundary is host-tested, matching the rest of this file's design.
pub fn alloc_size_in_bounds(size: usize, min: usize, max: usize) -> bool {
    size >= min && size <= max
}

/// SHA-256 of a buffer (the `sha2` no-default-features dep — core-only tree).
pub fn sha2_256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// The initrd integrity gate (spec §3.2.4): the in-memory buffer the loader will serve
/// over LoadFile2 must hash to the build-baked digest. Plain compare — this is an
/// integrity check against tampering, not a secret comparison; constant-time buys
/// nothing (the digest is public, baked into the signed loader).
pub fn initrd_digest_ok(data: &[u8], expected: &[u8; 32]) -> bool {
    &sha2_256(data) == expected
}

              
/// The `SB_REQUIRED` gate decision (spec §3.2.2): given the status + data
/// of a `GetVariable("SecureBoot", EFI_GLOBAL_VARIABLE)` read, proceed ONLY on
/// `EFI_SUCCESS` with exactly the single byte `0x01`. Absent variable (SB-less
/// firmware), read error, `0x00` (SB disabled), wrong size — all halt. Only consulted
/// when the baked `SB_REQUIRED` is true; `main.rs` feeds the raw read result here.
pub fn sb_check_passes(status: crate::efi::EfiStatus, value: Option<&[u8]>) -> bool {
    status == crate::efi::EFI_SUCCESS && value == Some(&[0x01u8][..])
}

/// An `EfiGuid` in its 16-byte on-wire form: d1/d2/d3 little-endian + d4 raw — the
/// same mixed-endian convention as GPT GUIDs (cross-reference the image installer's
/// `installer.rs::guid_to_mixed_endian`).
fn guid_wire_bytes(g: &crate::efi::EfiGuid) -> [u8; 16] {
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&g.d1.to_le_bytes());
    out[4..6].copy_from_slice(&g.d2.to_le_bytes());
    out[6..8].copy_from_slice(&g.d3.to_le_bytes());
    out[8..16].copy_from_slice(&g.d4);
    out
}

/// `LINUX_EFI_INITRD_MEDIA_GUID` on the wire (single definition: `efi.rs`).
pub fn initrd_guid_wire_bytes() -> [u8; 16] {
    guid_wire_bytes(&crate::efi::INITRD_MEDIA_GUID)
}

/// The vendor-media device path the kernel's EFI stub matches to locate a
/// LoadFile2-served initrd (this is its pure
/// serializer half): a MEDIA_DEVICE_PATH(0x04)/MEDIA_VENDOR_DP(0x03) node of length
/// 20 (4-byte header + 16-byte GUID), then the generic END node (0x7F/0xFF, length 4).
pub fn initrd_device_path_bytes() -> [u8; 24] {
    let mut dp = [0u8; 24];
    dp[0] = 0x04;                          
    dp[1] = 0x03;                            
    dp[2..4].copy_from_slice(&20u16.to_le_bytes());
    dp[4..20].copy_from_slice(&initrd_guid_wire_bytes());
    dp[20] = 0x7F;                        
    dp[21] = 0xFF;                                  
    dp[22..24].copy_from_slice(&4u16.to_le_bytes());
    dp
}

/// Assemble the full media device path of an ESP file for `LoadImage` (spec §3.2.5):
/// the parent device's nodes (END already stripped by the caller) + a
/// MEDIA(0x04)/FILEPATH(0x04) node carrying the UCS-2 NUL-terminated path + END.
/// A real media path makes DxeImageVerificationLib classify the load as fixed/
/// removable media — the verify-or-deny policy — never the unknown-origin edge.
/// Fail-closed `None` on a too-small buffer or a non-printable-ASCII path.
pub fn build_image_device_path(parent_nodes: &[u8], path: &str, out: &mut [u8]) -> Option<usize> {
    let path_units = path.len().checked_add(1)?;               
    let node_len = 4usize.checked_add(path_units.checked_mul(2)?)?;
    if node_len > u16::MAX as usize {
        return None;
    }
    let total = parent_nodes.len().checked_add(node_len)?.checked_add(4)?;         
    if total > out.len() {
        return None;
    }
    out[..parent_nodes.len()].copy_from_slice(parent_nodes);
    let mut pos = parent_nodes.len();
    out[pos] = 0x04;                          
    out[pos + 1] = 0x04;                              
    out[pos + 2..pos + 4].copy_from_slice(&(node_len as u16).to_le_bytes());
    pos += 4;
    for &b in path.as_bytes() {
        if !(b.is_ascii_graphic() || b == b' ') {
            return None;
        }
        out[pos..pos + 2].copy_from_slice(&u16::from(b).to_le_bytes());
        pos += 2;
    }
    out[pos..pos + 2].copy_from_slice(&0u16.to_le_bytes());             
    pos += 2;
    out[pos] = 0x7F;                        
    out[pos + 1] = 0xFF;                                  
    out[pos + 2..pos + 4].copy_from_slice(&4u16.to_le_bytes());
    Some(pos + 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_size_bounds_are_inclusive_and_fail_closed() {
                                                                                         
                                                                      
        assert!(alloc_size_in_bounds(1, 1, 100));          
        assert!(alloc_size_in_bounds(50, 1, 100));            
        assert!(alloc_size_in_bounds(100, 1, 100));                      
        assert!(!alloc_size_in_bounds(0, 1, 100));                          
        assert!(!alloc_size_in_bounds(101, 1, 100));                    
        assert!(!alloc_size_in_bounds(usize::MAX, 1, 100));                       
                                                                                       
                                                                                      
        assert!(!alloc_size_in_bounds(15, 16, 4096));                              
        assert!(alloc_size_in_bounds(16, 16, 4096));                               
        assert!(alloc_size_in_bounds(4096, 16, 4096));                       
        assert!(!alloc_size_in_bounds(4097, 16, 4096));                         
    }

    #[test]
    fn cmdline_encodes_to_null_terminated_ucs2_le() {
        let mut buf = [0u16; 64];
        let n = encode_cmdline_ucs2("ro x", &mut buf).unwrap();                   
        assert_eq!(n, 5);
        assert_eq!(&buf[..5], &[0x0072, 0x006F, 0x0020, 0x0078, 0x0000]);                       
        assert_eq!(load_options_size_bytes(n), 10);                    
    }

    #[test]
    fn cmdline_too_long_for_buffer_fails_closed() {
        let mut buf = [0u16; 4];
        assert!(encode_cmdline_ucs2("toolong", &mut buf).is_none());
    }

    #[test]
    fn initrd_digest_matches_and_mismatch_rejected() {
        let data = b"hello initrd";
        let good = sha2_256(data);
        assert!(initrd_digest_ok(data, &good));
        let mut bad = good;
        bad[0] ^= 1;
        assert!(!initrd_digest_ok(data, &bad));                          
    }

    #[test]
    fn initrd_vendor_media_device_path_bytes() {
        let dp = initrd_device_path_bytes();                                                
                                                                                       
                                                                     
        assert_eq!(dp[0], 0x04);
        assert_eq!(dp[1], 0x03);
        assert_eq!(u16::from_le_bytes([dp[2], dp[3]]), 20);
        assert_eq!(&dp[4..20], &initrd_guid_wire_bytes());
        assert_eq!(dp[20], 0x7F);
        assert_eq!(dp[21], 0xFF);
        assert_eq!(u16::from_le_bytes([dp[22], dp[23]]), 4);
    }

    #[test]
    fn initrd_guid_wire_form_is_mixed_endian() {
                                                                            
                                                                                     
                                                                      
        assert_eq!(
            initrd_guid_wire_bytes(),
            [
                0x27, 0xe4, 0x68, 0x55,                    
                0xfc, 0x68,                
                0x3d, 0x4f,                
                0xac, 0x74, 0xca, 0x55, 0x52, 0x31, 0xcc, 0x68,          
            ]
        );
    }

    #[test]
    fn sb_required_decision_is_fail_closed() {
        use crate::efi::{EFI_NOT_FOUND, EFI_SUCCESS};
                                                                                       
                                                                                     
        assert!(sb_check_passes(EFI_SUCCESS, Some(&[0x01])));
        assert!(!sb_check_passes(EFI_SUCCESS, Some(&[0x00])));
        assert!(!sb_check_passes(EFI_NOT_FOUND, None));                             
        assert!(!sb_check_passes(EFI_SUCCESS, Some(&[0x01, 0x00])));                       
        assert!(!sb_check_passes(EFI_SUCCESS, None));                    
        assert!(!sb_check_passes(EFI_NOT_FOUND, Some(&[0x01])));                              
    }

    #[test]
    fn hex_64_decodes_to_32_bytes_and_rejects_bad_input() {
                                                                                   
                                                                              
        let hex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        let got = crate::hex::decode_hex_32(hex).unwrap();
        assert_eq!(got[0], 0x00);
        assert_eq!(got[1], 0x11);
        assert_eq!(got[31], 0xff);
        assert!(crate::hex::decode_hex_32("ab").is_none());                
        assert!(crate::hex::decode_hex_32(&"zz".repeat(32)).is_none());           
                                                                                 
        assert!(crate::hex::decode_hex_32(&"AB".repeat(32)).is_none());
    }

    #[test]
    fn image_device_path_appends_filepath_and_end() {
                                                                                    
        let parent = [0x01, 0x01, 0x08, 0x00, 0xAA, 0xBB, 0xCC, 0xDD];
        let mut out = [0u8; 64];
        let n = build_image_device_path(&parent, "\\vmlinuz", &mut out).unwrap();
        assert_eq!(&out[..8], &parent);                                
                                                                                        
        assert_eq!(out[8], 0x04);
        assert_eq!(out[9], 0x04);
        assert_eq!(u16::from_le_bytes([out[10], out[11]]), 22);
        assert_eq!(u16::from_le_bytes([out[12], out[13]]), u16::from(b'\\'));
        assert_eq!(u16::from_le_bytes([out[28], out[29]]), 0);             
                   
        assert_eq!(out[30], 0x7F);
        assert_eq!(out[31], 0xFF);
        assert_eq!(u16::from_le_bytes([out[32], out[33]]), 4);
        assert_eq!(n, 34);
    }

    #[test]
    fn image_device_path_fails_closed_on_small_buffer_or_bad_path() {
        let parent = [0x01, 0x01, 0x08, 0x00, 0xAA, 0xBB, 0xCC, 0xDD];
        let mut tiny = [0u8; 16];
        assert!(build_image_device_path(&parent, "\\vmlinuz", &mut tiny).is_none());
        let mut out = [0u8; 64];
        assert!(build_image_device_path(&parent, "\\vm\0linuz", &mut out).is_none());
    }

    #[test]
    fn cmdline_rejects_non_printable_and_non_ascii_fail_closed() {
        let mut buf = [0u16; 64];
                                                                           
        assert!(encode_cmdline_ucs2("röot", &mut buf).is_none());
                                                                              
                                                        
        assert!(encode_cmdline_ucs2("ro\0x", &mut buf).is_none());
        assert!(encode_cmdline_ucs2("ro\nx", &mut buf).is_none());
    }
}

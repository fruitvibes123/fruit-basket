//! T10 KATs: the ADV BOOTONCE byte transform, pinned against syslinux 6.04-pre1's
//! `setadv.c`/`advconst.h` semantics (re-read from the pinned tarball 2026-07-15):
//! per-copy layout `MAGIC1[0..4] ‖ checksum[4..8] ‖ TLV data[8..508] ‖ MAGIC3[508..512]`,
//! two redundant copies, `checksum = MAGIC2 − Σ(data dwords)` (wrapping), TLV =
//! `tag(1) len(1) payload`, `ADV_END = 0`, `ADV_BOOTONCE = 1`, copy0-preferred
//! validation (`syslinux_validate_adv`), both-invalid ⇒ reset-to-empty.
//!
//! The `slot-b` KAT blob below is derived BY HAND from the source semantics (tag=01,
//! len=06, "slot-b" ⇒ data dwords 0x6C730601 + 0x622D746F = 0xCEA07A70; checksum =
//! 0xA3041767 − 0xCEA07A70 (mod 2³²) = 0xD4639CF7) — independent of the code under
//! test. The REAL-loader interaction (the pinned extlinux clearing + booting the armed
                                     
//! label) is proven on produced bytes by the update boot gate (T22), not here.

use fb_update::adv::{
    ADV_TOTAL_SIZE, AdvError, clear_bootonce, read_bootonce, reset_adv, set_bootonce,
};

/// Hand-construct the expected post-`set_bootonce("slot-b")` ADV (see module doc).
fn handmade_slot_b_adv() -> [u8; ADV_TOTAL_SIZE] {
    let mut copy = [0u8; 512];
    copy[0..4].copy_from_slice(&0x5a2d_2fa5u32.to_le_bytes());              
    copy[4..8].copy_from_slice(&0xd463_9cf7u32.to_le_bytes());                         
    copy[8] = 1;                
    copy[9] = 6;                 
    copy[10..16].copy_from_slice(b"slot-b");
    copy[508..512].copy_from_slice(&0xdd28_bf64u32.to_le_bytes());              
    let mut adv = [0u8; ADV_TOTAL_SIZE];
    adv[..512].copy_from_slice(&copy);
    adv[512..].copy_from_slice(&copy);
    adv
}

#[test]
fn checksum_matches_reset_adv_constants() {
                                                                                     
                                                                                  
                                                                  
    let adv = reset_adv();
    for copy in [&adv[..512], &adv[512..]] {
        assert_eq!(&copy[0..4], &0x5a2d_2fa5u32.to_le_bytes());
        assert_eq!(&copy[4..8], &0xa304_1767u32.to_le_bytes());
        assert!(copy[8..508].iter().all(|&b| b == 0));
        assert_eq!(&copy[508..512], &0xdd28_bf64u32.to_le_bytes());
    }
    assert_eq!(read_bootonce(&adv), None);
}

#[test]
fn set_produces_the_handmade_kat_bytes() {
    let mut adv = reset_adv();
    set_bootonce(&mut adv, "slot-b").unwrap();
    assert_eq!(
        adv,
        handmade_slot_b_adv(),
        "set_bootonce must emit the KAT bytes"
    );
}

#[test]
fn captured_slot_b_adv_parses() {
                                                                               
    assert_eq!(
        read_bootonce(&handmade_slot_b_adv()),
        Some(b"slot-b".to_vec())
    );
}

#[test]
fn set_then_read_roundtrips() {
    let mut adv = reset_adv();
    set_bootonce(&mut adv, "slot-b").unwrap();
    assert_eq!(read_bootonce(&adv), Some(b"slot-b".to_vec()));
                                                                                       
    set_bootonce(&mut adv, "slot-a").unwrap();
    assert_eq!(read_bootonce(&adv), Some(b"slot-a".to_vec()));
                                                                                  
    let (c0, c1) = adv.split_at(512);
    assert_eq!(c0, c1);
}

#[test]
fn copy0_preferred() {
                                                                                      
    let mut adv = handmade_slot_b_adv();
    adv[100] ^= 0xFF;                                                   
    assert_eq!(read_bootonce(&adv), Some(b"slot-b".to_vec()));

                                                                                          
                                                                                             
    let mut torn = [0u8; ADV_TOTAL_SIZE];
    let mut a = reset_adv();
    set_bootonce(&mut a, "slot-a").unwrap();
    let mut b = reset_adv();
    set_bootonce(&mut b, "slot-b").unwrap();
    torn[..512].copy_from_slice(&a[..512]);
    torn[512..].copy_from_slice(&b[512..]);
    assert_eq!(read_bootonce(&torn), Some(b"slot-a".to_vec()));

                                        
    let mut dead = handmade_slot_b_adv();
    dead[100] ^= 0xFF;
    dead[512 + 100] ^= 0xFF;
    assert_eq!(read_bootonce(&dead), None);
}

#[test]
fn clear_is_conditional() {
                                                                                   
                                                                                         
    let mut adv = handmade_slot_b_adv();
    assert_eq!(clear_bootonce(&mut adv), Ok(true));
    assert_eq!(read_bootonce(&adv), None);
    assert_eq!(
        adv,
        reset_adv(),
        "a cleared ADV is byte-identical to the reset ADV"
    );

    let before = adv;
    assert_eq!(clear_bootonce(&mut adv), Ok(false));
    assert_eq!(adv, before, "an already-clear ADV is untouched");
}

#[test]
fn set_refuses_oversize_label() {
                                                                                  
                                                                                
    let mut adv = reset_adv();
    let too_long = "x".repeat(499);
    assert_eq!(set_bootonce(&mut adv, &too_long), Err(AdvError::NoSpace));
    assert_eq!(adv, reset_adv(), "a refused set leaves the ADV untouched");
}

#[test]
fn both_invalid_resets_then_sets() {
                                                                                        
                                                                           
    let mut adv = [0xAAu8; ADV_TOTAL_SIZE];
    set_bootonce(&mut adv, "slot-b").unwrap();
    assert_eq!(adv, handmade_slot_b_adv());
}

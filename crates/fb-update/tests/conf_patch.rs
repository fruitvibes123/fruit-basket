//! T11: the fixed-geometry extlinux.conf field patcher (spec §4d patch discipline) —
//! anchored exactly-once scans, existing width + delimiter verified, length-preserving
//! overwrite, REFUSE on zero/>1 matches or width mismatch, and a refusal leaves the
//! buffer byte-untouched (never a partial write).

use fb_update::Slot;
use fb_update::conf_patch::{PatchError, patch_default, patch_label_fields};

/// The §4d two-label template at genesis (label-b fields = slot-a's values, real
/// width) — the shape T4's `render_boot_fs_extlinux` bakes.
fn canonical_conf() -> Vec<u8> {
    let h_a = "aa".repeat(32);
    format!(
        "DEFAULT slot-a  \n\
         PROMPT 0\n\
         NOESCAPE 1\n\
         TIMEOUT 30\n\
         LABEL slot-a\n\
         \x20 LINUX /slot-a/vmlinuz\n\
         \x20 INITRD /slot-a/initramfs\n\
         \x20 APPEND initrd=/slot-a/initramfs fb.root-hash={h_a} fb.verity-hash-offset=000034603008 fb.rootfs-dev=PARTUUID=04c92659-e47a-485b-b840-fe5561eaa0da panic=10 quiet\n\
         LABEL slot-b\n\
         \x20 LINUX /slot-b/vmlinuz\n\
         \x20 INITRD /slot-b/initramfs\n\
         \x20 APPEND initrd=/slot-b/initramfs fb.root-hash={h_a} fb.verity-hash-offset=000034603008 fb.rootfs-dev=PARTUUID=a5dff702-a9ff-41a1-9243-30e6136aba95 panic=10 quiet\n"
    )
    .into_bytes()
}

#[test]
fn patch_default_flips_slot() {
    let mut conf = canonical_conf();
    let before_len = conf.len();
    patch_default(&mut conf, Slot::B).unwrap();
    let s = String::from_utf8(conf.clone()).unwrap();
    assert!(
        s.starts_with("DEFAULT slot-b  \n"),
        "width-8 space-padded value"
    );
    assert_eq!(conf.len(), before_len, "length-preserving");
                                                     
    assert_eq!(&conf[17..], &canonical_conf()[17..]);
}

#[test]
fn patch_default_ambiguous_refuses() {
    let mut conf = canonical_conf();
    conf.extend_from_slice(b"DEFAULT slot-a  \n");
    let before = conf.clone();
    assert_eq!(
        patch_default(&mut conf, Slot::B),
        Err(PatchError::Ambiguous("DEFAULT "))
    );
    assert_eq!(conf, before, "a refusal never writes");
}

#[test]
fn patch_default_notfound_refuses() {
    let mut conf = b"PROMPT 0\nTIMEOUT 30\n".to_vec();
    assert_eq!(
        patch_default(&mut conf, Slot::B),
        Err(PatchError::NotFound("DEFAULT "))
    );
}

#[test]
fn patch_label_b_fields_in_stanza() {
    let mut conf = canonical_conf();
    let before_len = conf.len();
    let new_hash = "bb".repeat(32);
    patch_label_fields(&mut conf, Slot::B, &new_hash, 35_651_584).unwrap();
    let s = String::from_utf8(conf.clone()).unwrap();
    assert_eq!(conf.len(), before_len, "length-preserving");

    let (stanza_a, stanza_b) = s.split_once("LABEL slot-b\n").unwrap();
                                                      
    assert!(stanza_a.contains(&format!("fb.root-hash={}", "aa".repeat(32))));
    assert!(stanza_a.contains("fb.verity-hash-offset=000034603008"));
                                                                         
    assert!(stanza_b.contains(&format!("fb.root-hash={new_hash}")));
    assert!(stanza_b.contains("fb.verity-hash-offset=000035651584"));
                                                                             
    assert_eq!("000035651584".parse::<u64>().unwrap(), 35_651_584);
}

#[test]
fn patch_width_mismatch_refuses() {
    let mut conf = canonical_conf();
    let before = conf.clone();
                                              
    assert_eq!(
        patch_label_fields(&mut conf, Slot::B, &"bb".repeat(32)[..63], 1),
        Err(PatchError::WidthMismatch("fb.root-hash="))
    );
    assert_eq!(conf, before);
                                           
    assert_eq!(
        patch_label_fields(&mut conf, Slot::B, &"bb".repeat(32), 1_000_000_000_000),
        Err(PatchError::WidthMismatch("fb.verity-hash-offset="))
    );
    assert_eq!(
        conf, before,
        "the root-hash write must not land when the offset refuses"
    );
}

#[test]
fn patch_is_byte_faithful_root_hash() {
                                                                                      
                                                                                    
                                                                          
    let mut conf = canonical_conf();
    let mixed = format!("AbCd{}", &"ef".repeat(30));
    patch_label_fields(&mut conf, Slot::B, &mixed, 7).unwrap();
    let s = String::from_utf8(conf).unwrap();
    let stanza_b = s.split_once("LABEL slot-b\n").unwrap().1;
    assert!(stanza_b.contains(&format!("fb.root-hash={mixed}")));
}

#[test]
fn patched_conf_reparses_to_the_intended_state() {
                                                                                  
    let mut conf = canonical_conf();
    let new_hash = "cd".repeat(32);
    patch_label_fields(&mut conf, Slot::B, &new_hash, 34_603_008).unwrap();
    patch_default(&mut conf, Slot::B).unwrap();
    let s = String::from_utf8(conf).unwrap();
    assert!(s.starts_with("DEFAULT slot-b  \n"));
    let stanza_b = s.split_once("LABEL slot-b\n").unwrap().1;
    let hash_tok = stanza_b.split_once("fb.root-hash=").unwrap().1;
    assert_eq!(&hash_tok[..64], new_hash.as_str());
}

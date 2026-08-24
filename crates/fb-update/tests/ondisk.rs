//! T13: the on-disk ADV arm/reclear primitive (mirrors `advio.c::write_adv`: O_SYNC +
//! inode/dev/size revalidate + RETURN-CHECKED pwrite — unlike the loader's swallowed
//! clear). Runs host-native over temp files (no mount/root). The e2fsck bitmask +
//! bounded-timeout gate is unit-tested inside `src/ondisk.rs` (it spawns a shim by
//! absolute path, no PATH mutation).

use fb_update::adv::{ADV_TOTAL_SIZE, read_bootonce, reset_adv, set_bootonce};
use fb_update::ondisk::{AdvIoError, arm_bootonce_on_disk, reclear_bootonce_on_disk};

/// A fake `ldlinux.sys`: `core_len` bytes of filler then a reset ADV as the last 1024.
fn fake_ldlinux(dir: &std::path::Path, core_len: usize) -> std::path::PathBuf {
    let path = dir.join("ldlinux.sys");
    let mut bytes = vec![0x90u8; core_len];
    bytes.extend_from_slice(&reset_adv());
    std::fs::write(&path, &bytes).unwrap();
    path
}

/// Read back the trailing ADV of a file.
fn tail_adv(path: &std::path::Path) -> [u8; ADV_TOTAL_SIZE] {
    let bytes = std::fs::read(path).unwrap();
    let mut adv = [0u8; ADV_TOTAL_SIZE];
    adv.copy_from_slice(&bytes[bytes.len() - ADV_TOTAL_SIZE..]);
    adv
}

#[test]
fn arm_then_reclear_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let path = fake_ldlinux(dir.path(), 4096);

                                                                                        
    arm_bootonce_on_disk(&path, "slot-b").unwrap();
    assert_eq!(read_bootonce(&tail_adv(&path)), Some(b"slot-b".to_vec()));
    let core = std::fs::read(&path).unwrap();
    assert!(
        core[..4096].iter().all(|&b| b == 0x90),
        "core bytes preserved"
    );
    assert_eq!(core.len(), 4096 + ADV_TOTAL_SIZE, "file length preserved");

                                                                    
    assert!(
        reclear_bootonce_on_disk(&path).unwrap(),
        "cleared a set entry"
    );
    assert_eq!(read_bootonce(&tail_adv(&path)), None);

                                                                          
    let before = std::fs::read(&path).unwrap();
    assert!(
        !reclear_bootonce_on_disk(&path).unwrap(),
        "already-clear ADV reports no-op"
    );
    assert_eq!(std::fs::read(&path).unwrap(), before);
}

#[test]
fn arm_matches_the_pure_transform_bytes() {
                                                                                       
    let dir = tempfile::tempdir().unwrap();
    let path = fake_ldlinux(dir.path(), 8192);
    arm_bootonce_on_disk(&path, "slot-a").unwrap();
    let mut expected = reset_adv();
    set_bootonce(&mut expected, "slot-a").unwrap();
    assert_eq!(tail_adv(&path), expected);
}

#[test]
fn arm_refuses_a_too_small_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tiny");
    std::fs::write(&path, [0u8; 512]).unwrap();                
    assert!(matches!(
        arm_bootonce_on_disk(&path, "slot-b"),
        Err(AdvIoError::TooSmall)
    ));
}

#[test]
fn arm_missing_file_is_io_err() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        arm_bootonce_on_disk(&dir.path().join("absent"), "slot-b"),
        Err(AdvIoError::Io(_))
    ));
}

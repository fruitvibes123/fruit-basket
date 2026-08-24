//! ROOT-GATED device-level roundtrip: `setup_verity_device` over a real scratch block device →
//! mount RO → read → `dev_remove` → node gone. Requires root + /dev/mapper/control + a verity-baked
//! scratch device, so it is `#[ignore]`d and env-gated (the standing boot-gate discipline: PANIC when
//! invoked `--ignored` without the env — no invocation may report success without asserting).
                                      
//! The hotswap boot-gate (Task 10) exercises this same path on produced
//! bytes inside the gate VM; this test exists for direct root-container runs.
//!
//! Env: `FB_VERITY_RT_SCRATCH_DEV` = a block device whose content is `<squashfs, 4096-padded><verity
//! hash tree>`; `FB_VERITY_RT_ROOT_HASH` = the tree's root hash (hex); `FB_VERITY_RT_HASH_OFFSET` =
//! the byte offset where the hash tree begins.

use fb_verity_rt::{CorruptionMode, dev_remove, setup_verity_device};

#[test]
#[ignore = "root + scratch verity device required (FB_VERITY_RT_SCRATCH_DEV/_ROOT_HASH/_HASH_OFFSET); run in a root container or the boot-gate VM"]
fn setup_mount_read_teardown_roundtrip() {
    let dev = std::env::var("FB_VERITY_RT_SCRATCH_DEV")
        .expect("FB_VERITY_RT_SCRATCH_DEV not set — this gate must not silently pass");
    let root_hash = std::env::var("FB_VERITY_RT_ROOT_HASH")
        .expect("FB_VERITY_RT_ROOT_HASH not set — this gate must not silently pass");
    let offset: u64 = std::env::var("FB_VERITY_RT_HASH_OFFSET")
        .expect("FB_VERITY_RT_HASH_OFFSET not set — this gate must not silently pass")
        .parse()
        .expect("FB_VERITY_RT_HASH_OFFSET must be a u64");

    let name = "fb-verity-rt-selftest";
    let node = setup_verity_device(name, &dev, &root_hash, offset, CorruptionMode::Default)
        .expect("verity setup over the scratch device");
    assert!(node.exists(), "mknod'd verity node present: {node:?}");

                                                                                                    
    let mnt = tempfile::tempdir().expect("mount dir");
    let status = std::process::Command::new("mount")
        .args(["-t", "squashfs", "-o", "ro"])
        .arg(&node)
        .arg(mnt.path())
        .status()
        .expect("spawn mount");
    assert!(status.success(), "mount of the verity view succeeds");
    let listed = std::fs::read_dir(mnt.path())
        .expect("read mounted root")
        .count();
    assert!(listed > 0, "mounted squashfs lists at least one entry");
    let status = std::process::Command::new("umount")
        .arg(mnt.path())
        .status()
        .expect("spawn umount");
    assert!(status.success(), "umount succeeds");

    dev_remove(name).expect("DM_DEV_REMOVE tears the device down");
    assert!(!node.exists(), "the /dev node is unlinked after dev_remove");
}

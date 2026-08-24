//! The box's dm-verity device setup — the BootConfig-coupled wrappers over the extracted
//! [`fb_verity_rt`] runtime layer (hotswap v4 §9/R3-I7 moved the vendored device-mapper ioctl
//! machinery + the pure builders there VERBATIM so the post-boot fb-weights swap sequencer shares
//! this one audited implementation; see `fb-verity-rt/src/verity.rs` for the kernel-verification
//! provenance). What stays here is exactly the init-owned policy: the two dm device NAMES and the
//! per-volume corruption modes.

use crate::cmdline::BootConfig;
use fb_verity_rt::{CorruptionMode, setup_verity_device};
use std::io;
use std::path::PathBuf;

/// The dm-verity device name we create under /dev/mapper for the ROOTFS.
const DM_DEVICE_NAME: &str = "recipes-root";

/// dha Component E: the weights dm-verity device name under /dev/mapper. Distinct from
/// [`DM_DEVICE_NAME`] so the rootfs and weights verity targets coexist (both live for the box's uptime).
const DM_WEIGHTS_NAME: &str = "dha-weights";

/// Set up the dm-verity device over `cfg.rootfs_dev` using the cmdline root hash + hash-tree offset,
/// returning the path to the verity block-device node to mount at /sysroot. Fail-closed: any ioctl
/// error propagates (the PID-1 caller turns it into a kernel panic). `RestartOnCorruption` — the
/// rootfs posture: fail-loud rather than serve tampered blocks.
pub fn setup_verity(cfg: &BootConfig) -> io::Result<PathBuf> {
    let dev = cfg
        .rootfs_dev
        .as_deref()
        .ok_or_else(|| io::Error::other("rootfs_dev missing (runtime boot invariant)"))?;
    setup_verity_device(
        DM_DEVICE_NAME,
        dev,
        &cfg.root_hash,
        cfg.verity_hash_offset,
        CorruptionMode::RestartOnCorruption,
    )
}

/// dha Component E: set up the SECOND dm-verity device over the weights partition at
/// [`CorruptionMode::Default`] (opt-count-`0` = **EIO** on corruption — a corrupt weights block surfaces
/// as a typed read error the tenant handles, NOT a box reboot; there is no weights A/B, so
/// `restart_on_corruption` would boot-loop with no recovery, H-R4-1). `dev` is the weights partition's
/// resolved `/dev` node (the caller resolved its `PARTUUID` against the on-disk GPT, exactly like the
/// rootfs). Returns the `/dev/dha-weights` block node to mount RO at the weights mount dir. A DISTINCT dm
/// name from the rootfs device so both verity targets coexist for the box's uptime.
pub fn setup_weights_verity(
    dev: &str,
    root_hash: &str,
    verity_hash_offset: u64,
) -> io::Result<PathBuf> {
    setup_verity_device(
        DM_WEIGHTS_NAME,
        dev,
        root_hash,
        verity_hash_offset,
        CorruptionMode::Default,
    )
}

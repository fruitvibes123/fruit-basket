//! fb-verity-rt — runtime dm-verity setup/teardown + GPT-PARTUUID device discovery.
//!
//! Extracted VERBATIM from `initramfs-init` (hotswap-model v4 spec §9 / R3-I7) so the post-boot
//! fb-weights swap sequencer and the boot-time init share ONE audited implementation (the quince
//! extraction shape — two consumers, one source). Two modules, one concern each:
//!
//! - [`verity`] — the vendored device-mapper ioctl layer: `setup_verity_device` (create → table-load
//!   → resume → mknod), the NEW [`verity::dev_remove`] (`DM_DEV_REMOVE`, the swap's teardown), and the
//!   pure builders (target-table params, ioctl buffers, dev_t decode) it marshals with.
//! - [`discover`] — runtime PARTUUID→/dev resolution: the `/sys/block` disk scan + the pure primary-GPT
//!   read-side parse (header CRC, mixed-endian GUID match), plus the shared pure helpers the
//!   initramfs-init GPT WRITER also consumes (`crc32`, `guid_to_mixed_endian`, geometry consts).
//!
//! Every kernel-mechanism constant is verified against the pinned linux-6.18.34 source, not asserted;
                                    
//! the struct sizes are pinned by compile-time asserts so a
//! layout drift is a build error. The syscall sequences are exercised by the produced-bytes boot
//! gates; the pure halves are host-unit-tested here.

#![forbid(unsafe_op_in_unsafe_fn)]
                                                                                                      
                                                                                 
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

pub mod discover;
pub mod verity;

pub use discover::{
    GPT_HEADER_BYTES, GPT_NUM_ENTRIES, SECTOR_SIZE, crc32, find_partition_by_partuuid,
    gpt_header_crc_valid, guid_to_mixed_endian, is_candidate_disk_class, partition_device_name,
    resolve_partuuid, resolve_partuuid_at,
};
pub use verity::{
    CorruptionMode, HASH_BLOCK_SIZE, VERITY_SALT, block_device_size, dev_remove, hash_start_block,
    lock_exclusive_nonblocking, mount_squashfs_ro, setup_verity_device, umount,
    verity_target_params,
};

//! Vendored pure-Rust dm-verity device setup/teardown via the device-mapper ioctl interface (moved
//! VERBATIM from `initramfs-init/src/verity.rs`, Task 1.6 inc-2 → extracted per hotswap v4 §9/R3-I7;
           
//! Resolved VENDORED — no `device-mapper-rs` dep, smallest surface + operator-owned per the
//! sovereignty axis).
//!
//! **Every constant + struct here is verified against the pinned kernel tree**
                                    
//! (linux-6.18.34): `include/uapi/linux/dm-ioctl.h` (the `dm_ioctl` /
//! `dm_target_spec` layout, the command enum — `DM_DEV_CREATE_CMD=3`, `DM_DEV_REMOVE_CMD=4`,
//! `DM_DEV_SUSPEND_CMD=6`, `DM_TABLE_LOAD_CMD=9` — `DM_VERSION_MAJOR`, `DM_READONLY_FLAG`),
//! `Documentation/admin-guide/device-mapper/verity.rst` (the target table grammar +
//! `restart_on_corruption`), and `include/linux/miscdevice.h` (`MAPPER_CTRL_MINOR = 236`) +
//! `drivers/md/dm-ioctl.c` (`.nodename = "mapper/control"`; `dev_remove` at `:977` — header-only,
//! no params). The struct sizes are pinned by compile-time asserts so a layout drift is a build
//! error, not a boot-time surprise.
//!
//! The PURE parts (table-param string, ioctl-buffer marshalling, dev_t decode) are host-unit-tested
//! below; the syscall sequence ([`setup_verity_device`] / [`dev_remove`]) is exercised by the QEMU
//! boot gates (rootfs + dha weights + the hotswap swap sequencer).

use core::mem::size_of;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

                                                                                                    

const DM_NAME_LEN: usize = 128;
const DM_UUID_LEN: usize = 129;
const DM_MAX_TYPE_NAME: usize = 16;

/// `DM_READONLY_FLAG (1 << 0)` — dm-verity is a read-only target.
const DM_READONLY_FLAG: u32 = 1 << 0;

           
/// Fixed all-zero dm-verity salt — MUST match the image-builder's `verity::FIXED_SALT` (a
/// mismatched salt computes a different root hash → every block read fails). 32 bytes / 64 hex.
pub const VERITY_SALT: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The dm-verity data/hash block size the whole stack bakes and mounts with (bytes).
pub const HASH_BLOCK_SIZE: u64 = 4096;

/// `struct dm_ioctl` — the header at the start of every device-mapper ioctl payload (dm-ioctl.h:103).
#[repr(C)]
struct DmIoctl {
    version: [u32; 3],
    data_size: u32,
    data_start: u32,
    target_count: u32,
    open_count: i32,
    flags: u32,
    event_nr: u32,
    padding: u32,
    dev: u64,
    name: [u8; DM_NAME_LEN],
    uuid: [u8; DM_UUID_LEN],
    data: [u8; 7],
}
                                                                                                      
                                                                                                   
const _: () = assert!(size_of::<DmIoctl>() == 312);

/// `struct dm_target_spec` — one per target, immediately after the header (dm-ioctl.h:153).
#[repr(C)]
struct DmTargetSpec {
    sector_start: u64,
    length: u64,
    status: i32,
    next: u32,
    target_type: [u8; DM_MAX_TYPE_NAME],
}
                                               
const _: () = assert!(size_of::<DmTargetSpec>() == 40);

                                                                                                    

const _IOC_NRBITS: u32 = 8;
const _IOC_TYPEBITS: u32 = 8;
const _IOC_TYPESHIFT: u32 = _IOC_NRBITS;     
const _IOC_SIZESHIFT: u32 = _IOC_TYPESHIFT + _IOC_TYPEBITS;      
const _IOC_DIRSHIFT: u32 = _IOC_SIZESHIFT + 14;                              
const _IOC_WRITE: u32 = 1;
const _IOC_READ: u32 = 2;
const DM_IOCTL_TYPE: u32 = 0xfd;

const fn iowr(nr: u32) -> u32 {
    ((_IOC_READ | _IOC_WRITE) << _IOC_DIRSHIFT)
        | (DM_IOCTL_TYPE << _IOC_TYPESHIFT)
        | nr
        | ((size_of::<DmIoctl>() as u32) << _IOC_SIZESHIFT)
}

                                                                                        
                                                                                              
                                                                                              
                                                                           
const DM_DEV_CREATE: u32 = iowr(3);
const DM_DEV_REMOVE: u32 = iowr(4);
const DM_DEV_SUSPEND: u32 = iowr(6);
const DM_TABLE_LOAD: u32 = iowr(9);

/// DM interface version we declare. Only the MAJOR (4) is load-bearing — the kernel rejects a
/// mismatched major (`DM_VERSION_MAJOR = 4` in the pinned header); minor/patch are compat-checked
/// and the kernel writes its own back.
const DM_VERSION: [u32; 3] = [4, 0, 0];

                                                                                                    

/// How dm-verity reacts to a block that fails hash verification — the trailing optional-param field of
/// the target table (verity.rst). `RestartOnCorruption` ⇒ `1 restart_on_corruption` (the kernel reboots
/// on mismatch — the rootfs posture: fail-loud rather than serve tampered blocks). `Default` ⇒ `0` (zero
/// optional params ⇒ the kernel returns **EIO** to the reader — the weights-volume posture: a corrupt
/// weights block surfaces as a typed read error, NOT a boot-loop, since there is no weights A/B; H-R4-1).
/// There is no `eio` table verb — opt-count `0` IS the EIO mode (`DM_VERITY_MODE_EIO`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorruptionMode {
    /// opt-count `0` ⇒ EIO to the reader (weights volume).
    Default,
    /// `1 restart_on_corruption` ⇒ reboot on mismatch (rootfs).
    RestartOnCorruption,
}

/// Build the dm-verity target table parameter string (verity.rst grammar):
/// `<ver> <data_dev> <hash_dev> <data_bsz> <hash_bsz> <#data_blks> <hash_start_blk> <alg> <digest>
/// <salt> <#opt> <opt...>`. Same device for data + hash (hash tree appended in the same partition,
/// starting past the data at `hash_start_block`); fixed salt; the trailing corruption-mode opt-params
/// per `mode` (see [`CorruptionMode`]).
pub fn verity_target_params(
    dev: &str,
    root_hash: &str,
    num_data_blocks: u64,
    hash_start_block: u64,
    mode: CorruptionMode,
) -> String {
    let opts = match mode {
        CorruptionMode::Default => "0",
        CorruptionMode::RestartOnCorruption => "1 restart_on_corruption",
    };
    format!(
        "1 {dev} {dev} 4096 4096 {num_data_blocks} {hash_start_block} sha256 {root_hash} {VERITY_SALT} {opts}"
    )
}

           
/// Convert the verity hash-tree byte offset to the dm-verity table's `hash_start_block`
/// (the offset travels in BYTES, the kernel table is in BLOCKS). Errors if the offset is not block
/// aligned (the hash tree must begin on a block boundary) — fail closed, not floor-and-proceed.
///
                           
/// **Forward contract on the `.img` assembler:** because a non-4096-aligned
/// offset is rejected fail-closed, the assembler MUST pad the squashfs up to a 4096 boundary before
/// appending the verity hash tree AND report the PADDED size (= `num_data_blocks * 4096`, where the
/// hash tree actually begins) as the offset. Appending at the unpadded squashfs size → reject;
/// padding but reporting the unpadded size → `hash_start_block` points mid-data → every read fails.
pub fn hash_start_block(offset_bytes: u64, block_size: u64) -> io::Result<u64> {
    if block_size == 0 || !offset_bytes.is_multiple_of(block_size) {
        return Err(io::Error::other(format!(
            "verity-hash-offset {offset_bytes} is not a multiple of hash block size {block_size}"
        )));
    }
    Ok(offset_bytes / block_size)
}

/// View a `repr(C)`, gap-free, all-fields-initialized struct as its native-endian bytes. Safe here:
/// both structs are `#[repr(C)]`, have no padding gaps (asserted above), and are fully initialized
/// by the callers before this is used — so every byte is defined. x86_64 native endianness is what
/// the kernel expects for these ioctl structs.
fn struct_bytes<T>(v: &T) -> &[u8] {
                                                                      
    unsafe { std::slice::from_raw_parts((v as *const T).cast::<u8>(), size_of::<T>()) }
}

fn name_field(name: &str) -> [u8; DM_NAME_LEN] {
    let mut buf = [0u8; DM_NAME_LEN];
    let b = name.as_bytes();
                                                                                                
    assert!(b.len() < DM_NAME_LEN, "dm device name too long");
    buf[..b.len()].copy_from_slice(b);
    buf
}

/// A header-only ioctl payload (DM_DEV_CREATE / DM_DEV_REMOVE / resume): just `struct dm_ioctl`,
/// no targets.
fn build_header_buf(name: &str, flags: u32) -> Vec<u8> {
    let hdr = DmIoctl {
        version: DM_VERSION,
        data_size: size_of::<DmIoctl>() as u32,
        data_start: size_of::<DmIoctl>() as u32,
        target_count: 0,
        open_count: 0,
        flags,
        event_nr: 0,
        padding: 0,
        dev: 0,
        name: name_field(name),
        uuid: [0u8; DM_UUID_LEN],
        data: [0u8; 7],
    };
    struct_bytes(&hdr).to_vec()
}

/// The DM_TABLE_LOAD payload: `dm_ioctl` header + one `dm_target_spec` (target_type "verity") + the
/// NUL-terminated param string, 8-byte aligned. `length` is the verity device size in 512-byte
/// sectors. Read-only flag set (verity targets are RO).
fn build_table_load_buf(name: &str, params: &str, length_sectors: u64) -> Vec<u8> {
    let hdr_len = size_of::<DmIoctl>();
    let spec_len = size_of::<DmTargetSpec>();
    let param_bytes = params.as_bytes();
                                                                                                 
    let target_block = spec_len + param_bytes.len() + 1;
    let target_block_aligned = target_block.next_multiple_of(8);
    let total = hdr_len + target_block_aligned;

    let mut target_type = [0u8; DM_MAX_TYPE_NAME];
    target_type[..6].copy_from_slice(b"verity");

    let hdr = DmIoctl {
        version: DM_VERSION,
        data_size: total as u32,
        data_start: hdr_len as u32,
        target_count: 1,
        open_count: 0,
        flags: DM_READONLY_FLAG,
        event_nr: 0,
        padding: 0,
        dev: 0,
        name: name_field(name),
        uuid: [0u8; DM_UUID_LEN],
        data: [0u8; 7],
    };
    let spec = DmTargetSpec {
        sector_start: 0,
        length: length_sectors,
        status: 0,
        next: target_block_aligned as u32,
        target_type,
    };

    let mut buf = Vec::with_capacity(total);
    buf.extend_from_slice(struct_bytes(&hdr));
    buf.extend_from_slice(struct_bytes(&spec));
    buf.extend_from_slice(param_bytes);
    buf.push(0);                                  
    buf.resize(total, 0);                              
    buf
}

/// Decode the kernel's `huge_encode_dev()` u64 (the `dm_ioctl.dev` field after DM_DEV_CREATE) into
/// `(major, minor)` per `include/linux/kdev_t.h::new_decode_dev` (reached via `huge_decode_dev`) — so
/// we can `mknod` the verity block device deterministically rather than depending on devtmpfs node
/// naming/timing. The masks match the kernel literals EXACTLY (major `(dev&0xfff00)>>8`, minor high
                           
/// `0xfff00`) — the audit narrowed the minor high-mask from a wider superset; the dm
/// dev_t returns through `huge_encode_dev`=`new_encode_dev` (≤ u32) so neither form ever truncates.
fn decode_dm_dev(dev: u64) -> (u32, u32) {
    let major = ((dev & 0x000f_ff00) >> 8) as u32;
    let minor = ((dev & 0xff) | ((dev >> 12) & 0x000f_ff00)) as u32;
    (major, minor)
}

                                                                                                    

/// The device-generic dm-verity setup (create → load the verity table with the per-`mode` corruption
/// opt-params → resume → `mknod` the block node `/dev/<name>`), returning the node path to mount.
/// Shared by the initramfs rootfs (`RestartOnCorruption`), the dha boot-anchored weights volume
/// (`Default`/EIO), and the hotswap runtime weights setup (`Default`/EIO). Fail-closed: any ioctl
/// error propagates (the caller decides panic vs degrade — PID-1 panics, the s6-scoped weights
/// helper exits non-zero).
pub fn setup_verity_device(
    name: &str,
    dev: &str,
    root_hash: &str,
    verity_hash_offset: u64,
    mode: CorruptionMode,
) -> io::Result<PathBuf> {
                                                                                                 
                                                                                               
    let hsb = hash_start_block(verity_hash_offset, HASH_BLOCK_SIZE)
        .map_err(|e| io::Error::other(format!("verity offset: {e}")))?;
    let num_data_blocks = hsb;
    let length_sectors = num_data_blocks * (HASH_BLOCK_SIZE / 512);                              

    let params = verity_target_params(dev, root_hash, num_data_blocks, hsb, mode);

                                                                                    
                                                                                    
                                                                                     
    if !Path::new(dev).exists() {
        return Err(io::Error::other(format!(
            "verity device node not found: {dev}"
        )));
    }

    let control =
        open_dm_control().map_err(|e| io::Error::other(format!("open-dm-control: {e}")))?;

                                        
    let create = build_header_buf(name, 0);
    let create = dm_ioctl(&control, DM_DEV_CREATE, create)
        .map_err(|e| io::Error::other(format!("DM_DEV_CREATE: {e}")))?;
                                                                                               
    let dev_t_raw = u64::from_ne_bytes(create[40..48].try_into().expect("dm_ioctl.dev @ 40..48"));

                                                       
    let table = build_table_load_buf(name, &params, length_sectors);
    dm_ioctl(&control, DM_TABLE_LOAD, table)
        .map_err(|e| io::Error::other(format!("DM_TABLE_LOAD ({dev}): {e}")))?;

                                                                     
    let resume = build_header_buf(name, 0);
    dm_ioctl(&control, DM_DEV_SUSPEND, resume)
        .map_err(|e| io::Error::other(format!("DM_DEV_SUSPEND: {e}")))?;

                                                                                       
    let (major, minor) = decode_dm_dev(dev_t_raw);
    let node = PathBuf::from(format!("/dev/{name}"));
    mknod_block(&node, major, minor)
        .map_err(|e| io::Error::other(format!("mknod-verity-block: {e}")))?;
    Ok(node)
}

/// Tear down a dm device created by [`setup_verity_device`] (the hotswap swap step: after the
/// `umount`, before the raw-partition rewrite). `DM_DEV_REMOVE` is header-only (`{DM_DEV_REMOVE_CMD,
/// NO_PARAMS}`, dm-ioctl.c:977); the kernel destroys the mapped device — an open holder yields
/// `EBUSY`, which the caller handles with a bounded retry (spec §5 step 2). Also unlinks the
/// `/dev/<name>` node WE mknod'd at setup (no udev/devtmpfs manages our manual node); an
/// already-absent node is fine (the remove is idempotent-ish across a crashed prior teardown).
pub fn dev_remove(name: &str) -> io::Result<()> {
    let control =
        open_dm_control().map_err(|e| io::Error::other(format!("open-dm-control: {e}")))?;
    let remove = build_header_buf(name, 0);
                                                                                      
                                                                                                
                                                                                
                                                                                                 
                                                                               
    let ioctl_result = dm_ioctl(&control, DM_DEV_REMOVE, remove);
                                                                                                   
                                                                                              
                                                                                             
                                                                                                
                                                                                         
    let unlink_result = match std::fs::remove_file(format!("/dev/{name}")) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    };
    ioctl_result?;                                                                 
    unlink_result.map_err(|e| io::Error::other(format!("unlink-verity-node ({name}): {e}")))
}

/// Open `/dev/mapper/control` (the DM control node — misc major 10, `MAPPER_CTRL_MINOR = 236`).
/// devtmpfs auto-creates it via the misc `.nodename = "mapper/control"`; if it is missing we mknod
/// it ourselves (robust against a devtmpfs that hasn't materialized it).
fn open_dm_control() -> io::Result<std::fs::File> {
    use std::fs::OpenOptions;
    let path = Path::new("/dev/mapper/control");
    if !path.exists() {
        std::fs::create_dir_all("/dev/mapper")?;
        mknod_char(path, 10, 236)?;
    }
    OpenOptions::new().read(true).write(true).open(path)
}

/// Issue a device-mapper ioctl with an in/out buffer, returning the (kernel-mutated) buffer.
fn dm_ioctl(control: &std::fs::File, request: u32, mut buf: Vec<u8>) -> io::Result<Vec<u8>> {
    use std::os::unix::io::AsRawFd;
                                                                                                 
                                                                                    
    let rc = unsafe {
                                                                                                       
                                                                                           
        libc::ioctl(
            control.as_raw_fd(),
            request as libc::Ioctl,
            buf.as_mut_ptr(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(buf)
}

fn mknod_char(path: &Path, major: u32, minor: u32) -> io::Result<()> {
    mknod(path, libc::S_IFCHR, major, minor)
}

fn mknod_block(path: &Path, major: u32, minor: u32) -> io::Result<()> {
    mknod(path, libc::S_IFBLK, major, minor)
}

/// `mount(2)` a verity block node RO at `target`: squashfs, `MS_RDONLY|MS_NODEV|MS_NOSUID|
/// MS_NOEXEC` (the model volume holds DATA only — nothing on it may ever be a device node, setuid,
/// or an execve target; `PROT_READ` mmap of the payload is unaffected). The runtime twin of
/// initramfs-init's boot-time weights mount, owned here so the swap/setup callers stay
/// `forbid(unsafe_code)`.
pub fn mount_squashfs_ro(node: &Path, target: &Path) -> io::Result<()> {
    let mut src = node.as_os_str().as_bytes().to_vec();
    src.push(0);
    let mut tgt = target.as_os_str().as_bytes().to_vec();
    tgt.push(0);
    let fstype = c"squashfs";
    let flags = libc::MS_RDONLY | libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC;
                                                                                               
    let rc = unsafe {
        libc::mount(
            src.as_ptr().cast(),
            tgt.as_ptr().cast(),
            fstype.as_ptr(),
            flags,
            std::ptr::null(),
        )
    };
    if rc < 0 {
        return Err(io::Error::other(format!(
            "mount {} -> {}: {}",
            node.display(),
            target.display(),
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// `BLKGETSIZE64` = `_IOR(0x12,114,size_t)` (pinned `include/uapi/linux/fs.h:286`) — dir=READ at
/// bit 30, size 8 at 16, type 0x12 at 8, nr 114. Computed, not hardcoded; locked by the
/// ioctl-numbers test.
const BLKGETSIZE64: u32 = (2u32 << 30) | ((size_of::<u64>() as u32) << 16) | (0x12u32 << 8) | 114;

/// A block device's size in bytes via `BLKGETSIZE64` (the swap's fit-check input).
pub fn block_device_size(dev: &Path) -> io::Result<u64> {
    use std::os::unix::io::AsRawFd;
    let f = std::fs::File::open(dev)?;
    let mut size: u64 = 0;
                                                                       
    let rc = unsafe { libc::ioctl(f.as_raw_fd(), BLKGETSIZE64 as libc::Ioctl, &mut size) };
    if rc < 0 {
        return Err(io::Error::other(format!(
            "BLKGETSIZE64 {}: {}",
            dev.display(),
            io::Error::last_os_error()
        )));
    }
    Ok(size)
}

/// `umount2(2)` a mount point (no flags — a held-busy EBUSY propagates for the caller's bounded
/// retry, spec §5 step 2; never `MNT_FORCE`/`MNT_DETACH`, which would hide a real holder).
pub fn umount(target: &Path) -> io::Result<()> {
    let mut tgt = target.as_os_str().as_bytes().to_vec();
    tgt.push(0);
                                            
    let rc = unsafe { libc::umount2(tgt.as_ptr().cast(), 0) };
    if rc < 0 {
                                                                                                   
                                                                                               
                                                                                                  
                                                                                                    
                                              
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Take an EXCLUSIVE, NON-BLOCKING `flock` on `path` (creating it), returning the held lock file —
/// the lock releases when the `File` drops. `EWOULDBLOCK` (a concurrent holder) surfaces as an
/// `Err` so the caller REFUSES cleanly instead of queueing behind a half-done peer (the hotswap
/// swap-lock discipline; contrast fb-update's blocking `LOCK_EX`). Hosted here so the
/// `forbid(unsafe_code)` consumers get the one audited flock call site.
pub fn lock_exclusive_nonblocking(path: &Path) -> io::Result<std::fs::File> {
    use std::os::unix::io::AsRawFd;
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)?;
                                                                                
    let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc < 0 {
        return Err(io::Error::other(format!(
            "flock {}: {}",
            path.display(),
            io::Error::last_os_error()
        )));
    }
    Ok(f)
}

fn mknod(path: &Path, kind: libc::mode_t, major: u32, minor: u32) -> io::Result<()> {
    let mut c = path.as_os_str().as_bytes().to_vec();
    c.push(0);
                                                                             
    let rc = unsafe {
        let dev = libc::makedev(major, minor);
        libc::mknod(c.as_ptr().cast(), kind | 0o600, dev)
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_params_match_verity_rst_grammar() {
        let p = verity_target_params(
            "/dev/vda2",
            "deadbeef",
            2048,
            2048,
            CorruptionMode::RestartOnCorruption,
        );
        assert_eq!(
            p,
            format!(
                "1 /dev/vda2 /dev/vda2 4096 4096 2048 2048 sha256 deadbeef {VERITY_SALT} 1 restart_on_corruption"
            )
        );
                                                                                                   
        assert_eq!(p.split_whitespace().count(), 12);
    }

    #[test]
    fn corruption_mode_default_emits_zero_opt_params() {
                                                                                                          
                                                                                                       
        let p = verity_target_params("/dev/vda5", "deadbeef", 2048, 2048, CorruptionMode::Default);
        assert!(
            p.ends_with(&format!("{VERITY_SALT} 0")),
            "Default must end in '<salt> 0' (zero opt-params = EIO), got: {p}"
        );
                                                                                            
        assert_eq!(p.split_whitespace().count(), 11);
    }

    #[test]
    fn corruption_mode_restart_matches_rootfs_table() {
                                                                                                       
                                               
        let p = verity_target_params(
            "/dev/vda2",
            "deadbeef",
            2048,
            2048,
            CorruptionMode::RestartOnCorruption,
        );
        assert!(p.ends_with(&format!("{VERITY_SALT} 1 restart_on_corruption")));
        assert_eq!(p.split_whitespace().count(), 12);
    }

    #[test]
    fn salt_matches_builder_fixed_salt() {
                                                                                                    
        assert_eq!(VERITY_SALT.len(), 64);
        assert!(VERITY_SALT.bytes().all(|b| b == b'0'));
    }

    #[test]
    fn hash_start_block_converts_and_rejects_misalignment() {
                                                                                                  
                                                                                                
                                                                                     
        assert_eq!(hash_start_block(8_388_608, HASH_BLOCK_SIZE).unwrap(), 2048);
        assert_eq!(hash_start_block(4096, HASH_BLOCK_SIZE).unwrap(), 1);
        let e = hash_start_block(8_388_609, HASH_BLOCK_SIZE).unwrap_err();
        assert!(
            e.to_string()
                .contains("verity-hash-offset 8388609 is not a multiple of hash block size 4096"),
            "got: {e}"
        );
        assert!(hash_start_block(8192, 0).is_err());
    }

    #[test]
    fn ioctl_numbers_match_verified_encoding() {
                                                                                                    
                                                                                                
                                                                                                 
                                                                  
        let base = (3u32 << 30) | (312u32 << 16) | (0xfdu32 << 8);
        assert_eq!(DM_DEV_CREATE, base | 3);
        assert_eq!(DM_DEV_REMOVE, base | 4);
        assert_eq!(DM_DEV_SUSPEND, base | 6);
        assert_eq!(DM_TABLE_LOAD, base | 9);
                                                                                     
        assert_eq!(BLKGETSIZE64, 0x8008_1272);
    }

    #[test]
    fn table_load_buf_layout_is_correct() {
        let params = verity_target_params(
            "/dev/sda2",
            "abcd",
            10,
            10,
            CorruptionMode::RestartOnCorruption,
        );
        let buf = build_table_load_buf("recipes-root", &params, 80);

                                                                                     
        let data_start = u32::from_ne_bytes(buf[16..20].try_into().unwrap());
        assert_eq!(data_start, 312);
                                         
        let target_count = u32::from_ne_bytes(buf[20..24].try_into().unwrap());
        assert_eq!(target_count, 1);
                                                   
        let flags = u32::from_ne_bytes(buf[28..32].try_into().unwrap());
        assert_eq!(flags & DM_READONLY_FLAG, DM_READONLY_FLAG);
                                                                   
        let data_size = u32::from_ne_bytes(buf[12..16].try_into().unwrap());
        assert_eq!(data_size as usize, buf.len());
        assert_eq!(buf.len() % 8, 0);
                                                              
        assert_eq!(&buf[48..60], b"recipes-root");
        assert_eq!(buf[60], 0);

                                                                                          
        let spec = 312usize;
        let length = u64::from_ne_bytes(buf[spec + 8..spec + 16].try_into().unwrap());
        assert_eq!(length, 80);
        assert_eq!(&buf[spec + 24..spec + 30], b"verity");
                                                                                     
        let pstart = spec + 40;
        assert!(buf[pstart..].starts_with(params.as_bytes()));
        assert_eq!(buf[pstart + params.len()], 0);
    }

    #[test]
    fn header_buf_is_exactly_one_struct() {
        let buf = build_header_buf("recipes-root", 0);
        assert_eq!(buf.len(), 312);
        let data_size = u32::from_ne_bytes(buf[12..16].try_into().unwrap());
        assert_eq!(data_size, 312);
        let target_count = u32::from_ne_bytes(buf[20..24].try_into().unwrap());
        assert_eq!(target_count, 0);
                                                                           
        let major = u32::from_ne_bytes(buf[0..4].try_into().unwrap());
        assert_eq!(major, 4);
    }

    #[test]
    fn decode_dm_dev_round_trips_huge_encode() {
                                                                                                   
        let encode = |major: u64, minor: u64| -> u64 {
            (minor & 0xff) | (major << 8) | ((minor & !0xff) << 12)
        };
        for (major, minor) in [(254u32, 0u32), (253, 7), (254, 300), (10, 236)] {
            let (dm, dn) = decode_dm_dev(encode(major as u64, minor as u64));
            assert_eq!(
                (dm, dn),
                (major, minor),
                "round-trip major={major} minor={minor}"
            );
        }
    }
}

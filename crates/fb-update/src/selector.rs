//! The `SlotSelector` firmware seam (spec §4h): the engine ([`crate::apply`]) is
//! firmware-agnostic; a `SlotSelector` impl owns the substrate-specific placement —
//! which slot is active, how a component is written to the inactive slot, how the
//! one-try boot is armed/committed. v1 ships [`SeabiosGptSelector`]; the UEFI arm
//! (umbrella C2) adds a second impl behind the same trait.
//!
//! Contract: a component is streamed CHUNKED (4 MiB) from a bounded reader and
//! write-then-verified (re-read + hash) against its [`ComponentSpec`] before the impl
//! returns Ok. `arm_once` is THE PROMOTION POINT — the first byte that makes the next
//! boot try the new slot; everything before it must be reversible/inert.

use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

use crate::Slot;

/// A component's declared length + SHA-256 (from the verified manifest). The selector
/// verifies BOTH after writing (a short stream ⇒ `ComponentTooShort`, a content
/// mismatch ⇒ `HashMismatch`).
#[derive(Debug, Clone)]
pub struct ComponentSpec {
    pub len: u64,
    pub sha256: [u8; 32],
}

/// The per-slot boot metadata patched into the label stanza (the byte-faithful
/// `root_hash` — R6-1 — plus the verity hash-tree offset). The rootfs PARTUUID is the
/// target slot's fixed const, so it is derived, not carried here.
#[derive(Debug, Clone)]
pub struct SlotDesc {
    pub root_hash: String,
    pub verity_hash_offset: u64,
}

/// Why a selector operation refused.
#[derive(Debug)]
pub enum SelErr {
    /// `/proc/cmdline`'s `fb.rootfs-dev` PARTUUID is neither slot's (or absent) — the
    /// running system is not an A/B seabios-gpt box (row 3: refuse, never guess).
    ActiveSlotUnknown,
    /// A component stream ended before its declared length.
    ComponentTooShort { which: &'static str },
    /// A component's re-read hash ≠ the manifest's (write-then-verify failure).
    HashMismatch { which: &'static str },
    /// A device/mount/patch/ADV I/O fault (the message names the operation).
    Io(String),
}

/// Read exactly `spec.len` bytes from `src` in 4 MiB chunks (NO whole-image buffering),
/// feeding `sink` each chunk and hashing as we go. Verifies length + SHA-256 at the end
/// (write-then-verify's on-the-way-in half; the impl's re-read is the other half).
pub fn stream_verified(
    src: &mut dyn Read,
    spec: &ComponentSpec,
    which: &'static str,
    mut sink: impl FnMut(&[u8]) -> std::io::Result<()>,
) -> Result<(), SelErr> {
    const CHUNK: usize = 4 * 1024 * 1024;
    let mut hasher = Sha256::new();
    let mut remaining = spec.len;
    let mut buf = vec![0u8; CHUNK.min(spec.len.max(1) as usize).max(1)];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        let n = src
            .read(&mut buf[..want])
            .map_err(|e| SelErr::Io(format!("{which} read: {e}")))?;
        if n == 0 {
            return Err(SelErr::ComponentTooShort { which });
        }
        hasher.update(&buf[..n]);
        sink(&buf[..n]).map_err(|e| SelErr::Io(format!("{which} write: {e}")))?;
        remaining -= n as u64;
    }
    let got: [u8; 32] = hasher.finalize().into();
    if got != spec.sha256 {
        return Err(SelErr::HashMismatch { which });
    }
    Ok(())
}

/// The firmware seam. Impls are the substrate-specific slot machinery.
pub trait SlotSelector {
    /// The slot the running system booted from (`/proc/cmdline` `fb.rootfs-dev`).
    fn active_slot(&self) -> Result<Slot, SelErr>;
    /// Stream the rootfs to `target`'s slot PARTITION (raw; no mount), write-then-verify.
    fn stage_rootfs(
        &self,
        target: Slot,
        spec: &ComponentSpec,
        src: &mut dyn Read,
    ) -> Result<(), SelErr>;
    /// e2fsck-gate + rw-mount the boot-fs, write `target`'s `/slot-x/{vmlinuz,initramfs}`
    /// from `src` (kernel FIRST, then initramfs — exactly their declared sizes, in
    /// order), patch the label's byte-faithful fields to `desc`, sync + unmount.
    fn stage_boot(
        &self,
        target: Slot,
        desc: &SlotDesc,
        kernel: &ComponentSpec,
        initramfs: &ComponentSpec,
        src: &mut dyn Read,
    ) -> Result<(), SelErr>;
    /// Arm the one-try boot for `target` (syslinux ADV BOOTONCE). THE PROMOTION POINT.
    fn arm_once(&self, target: Slot) -> Result<(), SelErr>;
    /// Commit `target` as the new `DEFAULT` (mark-good's success path).
    fn commit_default(&self, target: Slot) -> Result<(), SelErr>;
    /// Durably re-clear a stale BOOTONCE (mark-good's §4e re-clear); `Ok(true)` iff one
    /// was present.
    fn reclear(&self) -> Result<bool, SelErr>;
}

/// The SeaBIOS-GPT substrate impl (v1). The block-device paths (partition resolve, dd,
                                     
/// e2fsck+mount, file writes) are proven on produced bytes by the update boot gate
/// (T22); the pure ordering + refusal cascade is unit-tested via a fake in `tests/apply.rs`.
pub struct SeabiosGptSelector {
    /// The boot-fs partition device (resolved once by the bin, e.g. `/dev/vda2`).
    pub boot_dev: std::path::PathBuf,
    /// The running cmdline (`/proc/cmdline`) for the active-slot derivation.
    pub cmdline: String,
    /// The rw mountpoint the impl uses for the boot-fs (e.g. `/run/fb-update/boot`).
    pub boot_mnt: std::path::PathBuf,
}

impl SlotSelector for SeabiosGptSelector {
    fn active_slot(&self) -> Result<Slot, SelErr> {
        crate::cmdline::running_slot(&self.cmdline).ok_or(SelErr::ActiveSlotUnknown)
    }

    fn stage_rootfs(
        &self,
        target: Slot,
        spec: &ComponentSpec,
        src: &mut dyn Read,
    ) -> Result<(), SelErr> {
        use std::os::unix::fs::FileExt as _;
                                                                                        
        let dev = resolve_slot_partition(target.partuuid())?;
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(&dev)
            .map_err(|e| SelErr::Io(format!("open {}: {e}", dev.display())))?;
        let mut off = 0u64;
        stream_verified(src, spec, "rootfs", |chunk| {
            f.write_all_at(chunk, off)?;
            off += chunk.len() as u64;
            Ok(())
        })?;
        f.sync_all()
            .map_err(|e| SelErr::Io(format!("rootfs sync: {e}")))?;
                                                                                  
        verify_partition_hash(&dev, spec, "rootfs")
    }

    fn stage_boot(
        &self,
        target: Slot,
        desc: &SlotDesc,
        kernel: &ComponentSpec,
        initramfs: &ComponentSpec,
        src: &mut dyn Read,
    ) -> Result<(), SelErr> {
        crate::ondisk::e2fsck_preen_gate(
            &self.boot_dev,
            std::time::Duration::from_secs(crate::ondisk::FSCK_TIMEOUT_SECS),
        )
        .map_err(|e| SelErr::Io(format!("boot-fs e2fsck: {e:?}")))?;
        mount_ext4_rw(&self.boot_dev, &self.boot_mnt)?;
        let result = (|| {
            let slot_dir = self.boot_mnt.join(target.as_str());
            write_component_file(&slot_dir.join("vmlinuz"), kernel, "kernel", src)?;
            write_component_file(&slot_dir.join("initramfs"), initramfs, "initramfs", src)?;
                                                                                               
                                                                                                
                                                                                                      
                                                                                                 
                                                                                                      
                                                                                                      
                                                              
            fsync_dir(&slot_dir)?;
            patch_label_on_disk(&self.boot_mnt, target, desc)?;
            Ok(())
        })();
                                                                 
        let _ = umount(&self.boot_mnt);
        result
    }

    fn arm_once(&self, target: Slot) -> Result<(), SelErr> {
                                                                                        
        with_boot_mount(&self.boot_dev, &self.boot_mnt, |mnt| {
            crate::ondisk::arm_bootonce_on_disk(&mnt.join("syslinux/ldlinux.sys"), target.as_str())
                .map_err(|e| SelErr::Io(format!("ADV arm: {e}")))
        })
    }

    fn commit_default(&self, target: Slot) -> Result<(), SelErr> {
        with_boot_mount(&self.boot_dev, &self.boot_mnt, |mnt| {
            commit_default_on_disk(&mnt.join("syslinux/extlinux.conf"), target)
        })
    }

    fn reclear(&self) -> Result<bool, SelErr> {
        with_boot_mount(&self.boot_dev, &self.boot_mnt, |mnt| {
            crate::ondisk::reclear_bootonce_on_disk(&mnt.join("syslinux/ldlinux.sys"))
                .map_err(|e| SelErr::Io(format!("ADV reclear: {e}")))
        })
    }
}

                                                                     

/// Resolve the boot-fs partition device for the bins: an explicit `--boot-dev` wins
/// (tests / operator override); otherwise resolve the fixed [`crate::BOOT_FS_PARTUUID`]
/// via the local udev-free GPT scan. Self-resolution is what lets the ceremony ssh-exec
/// a bare `fb-update apply` and the fb-mark-good longrun render without a device
/// literal (disk enumeration — vda/sda/nvme — is a boot-time fact, not a bake-time one).
pub fn resolve_boot_dev(explicit: Option<&str>) -> Result<std::path::PathBuf, String> {
    match explicit {
        Some(d) => Ok(std::path::PathBuf::from(d)),
        None => gpt::resolve_partuuid(crate::BOOT_FS_PARTUUID)
            .map(std::path::PathBuf::from)
            .map_err(|e| format!("resolve boot-fs PARTUUID={}: {e}", crate::BOOT_FS_PARTUUID)),
    }
}

fn resolve_slot_partition(partuuid: &str) -> Result<std::path::PathBuf, SelErr> {
                                                                                   
                                                                                       
                                                                         
    gpt::resolve_partuuid(partuuid)
        .map(std::path::PathBuf::from)
        .map_err(|e| SelErr::Io(format!("resolve PARTUUID={partuuid}: {e}")))
}

fn verify_partition_hash(
    dev: &Path,
    spec: &ComponentSpec,
    which: &'static str,
) -> Result<(), SelErr> {
    use std::io::Read as _;
    let mut f = std::fs::File::open(dev).map_err(|e| SelErr::Io(format!("reopen {which}: {e}")))?;
    let mut hasher = Sha256::new();
    let mut remaining = spec.len;
    let mut buf = vec![0u8; (4 * 1024 * 1024).min(spec.len.max(1) as usize).max(1)];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        let n = f
            .read(&mut buf[..want])
            .map_err(|e| SelErr::Io(format!("{which} re-read: {e}")))?;
        if n == 0 {
            return Err(SelErr::ComponentTooShort { which });
        }
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }
    if <[u8; 32]>::from(hasher.finalize()) == spec.sha256 {
        Ok(())
    } else {
        Err(SelErr::HashMismatch { which })
    }
}

fn write_component_file(
    path: &Path,
    spec: &ComponentSpec,
    which: &'static str,
    src: &mut dyn Read,
) -> Result<(), SelErr> {
    use std::io::Write as _;
    let mut f =
        std::fs::File::create(path).map_err(|e| SelErr::Io(format!("create {which}: {e}")))?;
    stream_verified(src, spec, which, |chunk| f.write_all(chunk))?;
    f.sync_all()
        .map_err(|e| SelErr::Io(format!("{which} sync: {e}")))?;
    Ok(())
}

/// fsync a DIRECTORY so a newly-created dirent under it is durable (the no-journal boot-fs discipline;
/// `write_record_atomic`/`write_floor_atomic` do the same after their renames). Opening a dir read-only
/// and `sync_all`ing it is the portable POSIX way to flush the directory inode.
fn fsync_dir(dir: &Path) -> Result<(), SelErr> {
    std::fs::File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| SelErr::Io(format!("fsync dir {}: {e}", dir.display())))
}

fn patch_label_on_disk(mnt: &Path, target: Slot, desc: &SlotDesc) -> Result<(), SelErr> {
    let conf_path = mnt.join("syslinux/extlinux.conf");
    let mut conf = std::fs::read(&conf_path).map_err(|e| SelErr::Io(format!("read conf: {e}")))?;
    crate::conf_patch::patch_label_fields(
        &mut conf,
        target,
        &desc.root_hash,
        desc.verity_hash_offset,
    )
    .map_err(|e| SelErr::Io(format!("patch label: {e:?}")))?;
    write_back_synced(&conf_path, &conf)
}

fn commit_default_on_disk(conf_path: &Path, target: Slot) -> Result<(), SelErr> {
    let mut conf = std::fs::read(conf_path).map_err(|e| SelErr::Io(format!("read conf: {e}")))?;
    crate::conf_patch::patch_default(&mut conf, target)
        .map_err(|e| SelErr::Io(format!("patch DEFAULT: {e:?}")))?;
    write_back_synced(conf_path, &conf)?;
                                                                                        
    let back = std::fs::read(conf_path).map_err(|e| SelErr::Io(format!("re-read conf: {e}")))?;
    if back == conf {
        Ok(())
    } else {
        Err(SelErr::Io("DEFAULT re-read mismatch after commit".into()))
    }
}

fn write_back_synced(path: &Path, bytes: &[u8]) -> Result<(), SelErr> {
    use std::io::Write as _;
                                                                                     
                                     
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| SelErr::Io(format!("open conf rw: {e}")))?;
    f.write_all(bytes)
        .map_err(|e| SelErr::Io(format!("write conf: {e}")))?;
    f.sync_all()
        .map_err(|e| SelErr::Io(format!("conf sync: {e}")))
}

fn with_boot_mount<T>(
    dev: &Path,
    mnt: &Path,
    f: impl FnOnce(&Path) -> Result<T, SelErr>,
) -> Result<T, SelErr> {
    crate::ondisk::e2fsck_preen_gate(
        dev,
        std::time::Duration::from_secs(crate::ondisk::FSCK_TIMEOUT_SECS),
    )
    .map_err(|e| SelErr::Io(format!("boot-fs e2fsck: {e:?}")))?;
    mount_ext4_rw(dev, mnt)?;
    let r = f(mnt);
    let _ = umount(mnt);
    r
}

fn mount_ext4_rw(dev: &Path, mnt: &Path) -> Result<(), SelErr> {
    std::fs::create_dir_all(mnt).map_err(|e| SelErr::Io(format!("mkdir mnt: {e}")))?;
    let cdev = cstr(dev)?;
    let cmnt = cstr(mnt)?;
    let fstype = c"ext4";
                                                                            
    let rc = unsafe {
        libc::mount(
            cdev.as_ptr(),
            cmnt.as_ptr(),
            fstype.as_ptr(),
            0,
            std::ptr::null(),
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(SelErr::Io(format!(
            "mount {}: {}",
            dev.display(),
            std::io::Error::last_os_error()
        )))
    }
}

fn umount(mnt: &Path) -> Result<(), SelErr> {
    let cmnt = cstr(mnt)?;
                                         
    let rc = unsafe { libc::umount(cmnt.as_ptr()) };
    if rc == 0 {
        Ok(())
    } else {
        Err(SelErr::Io(format!(
            "umount {}: {}",
            mnt.display(),
            std::io::Error::last_os_error()
        )))
    }
}

fn cstr(p: &Path) -> Result<std::ffi::CString, SelErr> {
    use std::os::unix::ffi::OsStrExt as _;
    std::ffi::CString::new(p.as_os_str().as_bytes())
        .map_err(|e| SelErr::Io(format!("path has interior NUL: {e}")))
}

/// A minimal udev-free GPT PARTUUID→device resolver (the box has no udev; mirrors
/// `installer_syscall::resolve_partuuid`'s approach). Kept local so fb-update's shipped
/// tree does not pull the whole installer crate.
mod gpt {
    pub fn resolve_partuuid(partuuid: &str) -> Result<String, String> {
        for entry in std::fs::read_dir("/sys/block")
            .map_err(|e| e.to_string())?
            .flatten()
        {
            let name = entry.file_name();
            let Some(disk) = name.to_str() else { continue };
            if !is_candidate(disk) {
                continue;
            }
            let dev = format!("/dev/{disk}");
            if let Some(part) = scan_disk(&dev, partuuid)? {
                return Ok(part);
            }
        }
        Err(format!("no partition with PARTUUID={partuuid}"))
    }

    fn is_candidate(disk: &str) -> bool {
        disk.starts_with("vd")
            || disk.starts_with("sd")
            || disk.starts_with("nvme")
            || disk.starts_with("hd")
    }

    /// Read the primary GPT header + entries, find a partition whose unique GUID matches
    /// `partuuid` (canonical 8-4-4-4-12), return its device node.
    fn scan_disk(dev: &str, partuuid: &str) -> Result<Option<String>, String> {
        use std::io::{Read, Seek, SeekFrom};
        let want = parse_guid(partuuid).ok_or_else(|| format!("bad PARTUUID {partuuid}"))?;
        let mut f = match std::fs::File::open(dev) {
            Ok(f) => f,
            Err(_) => return Ok(None),
        };
                                                                   
        let mut hdr = [0u8; 512];
        if f.seek(SeekFrom::Start(512)).is_err() || f.read_exact(&mut hdr).is_err() {
            return Ok(None);
        }
        if &hdr[0..8] != b"EFI PART" {
            return Ok(None);
        }
        let ent_lba = u64::from_le_bytes(hdr[72..80].try_into().unwrap());
        let count = u32::from_le_bytes(hdr[80..84].try_into().unwrap());
        let size = u32::from_le_bytes(hdr[84..88].try_into().unwrap()) as usize;
        if size < 128 || count > 256 {
            return Ok(None);
        }
        if f.seek(SeekFrom::Start(ent_lba * 512)).is_err() {
            return Ok(None);
        }
        let mut table = vec![0u8; count as usize * size];
        if f.read_exact(&mut table).is_err() {
            return Ok(None);
        }
        for i in 0..count as usize {
            let e = &table[i * size..i * size + 128];
            if e[0..16].iter().all(|&b| b == 0) {
                continue;                                 
            }
            if guid_bytes(&e[16..32]) == want {
                return Ok(Some(partition_node(dev, i as u32 + 1)));
            }
        }
        Ok(None)
    }

    fn partition_node(dev: &str, n: u32) -> String {
                                               
        if dev.chars().last().is_some_and(|c| c.is_ascii_digit()) {
            format!("{dev}p{n}")
        } else {
            format!("{dev}{n}")
        }
    }

    /// Parse a canonical PARTUUID (`8-4-4-4-12`) into the raw 16 mixed-endian GPT bytes.
    fn parse_guid(s: &str) -> Option<[u8; 16]> {
        let hex: Vec<u8> = s.bytes().filter(|&b| b != b'-').collect();
        if hex.len() != 32 {
            return None;
        }
        let mut raw = [0u8; 16];
        for (i, byte) in raw.iter_mut().enumerate() {
            let hi = nib(hex[2 * i])?;
            let lo = nib(hex[2 * i + 1])?;
            *byte = (hi << 4) | lo;
        }
                                                           
        Some([
            raw[3], raw[2], raw[1], raw[0], raw[5], raw[4], raw[7], raw[6], raw[8], raw[9],
            raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
        ])
    }

    fn guid_bytes(b: &[u8]) -> [u8; 16] {
        let mut out = [0u8; 16];
        out.copy_from_slice(&b[..16]);
        out
    }

    fn nib(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
}

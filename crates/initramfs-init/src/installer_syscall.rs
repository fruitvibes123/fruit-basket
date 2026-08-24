//! `SyscallInstallOps` — the real, side-effecting [`InstallOps`] implementation for the box installer
//! (deploy-and-transition; install steps 7.pre → 7h).
//!
//! All FFI. The pure orchestration + the error-prone offset/MBR math live in [`crate::installer`]
//! (host-unit-tested behind the [`InstallOps`] seam); this module is the irreducible syscall layer —
//! the old-root mount, raw block I/O, `reboot(2)` — and is exercised by the QEMU install run,
//! NOT host units (it touches real block devices). It is written against the verified kernel mechanism
                                    
//! (mechanism-verified): the `BLKGETSIZE64`/`BLKRRPART` ioctl numbers are
//! `_IOR`/`_IO`-computed and cross-checked against their well-known constants.
//!
//! **The dd-only redesign (O3):** the installer execs NOTHING and formats NOTHING in the un-appraised
//! window — the three filesystems (the bootable boot-fs, the squashfs+verity rootfs, the persist
//! skeleton) are pre-baked build-side and `dd`'d WHOLE onto the freshly-partitioned disk. The only
//! initramfs-resident artifact it needs is `mbr.bin` (a static syslinux blob, SeaBIOS-only); there is
//! no mkfs tool, no bootloader installer, no subprocess spawn at all, and no mount of the new
//! partitions (1/2/3/4) — the grep-able spec §8 invariant.
//!
//! **Fail-closed:** every method maps a failure to [`InstallerError::OpFailed`]; the PID-1 caller turns
                 
//! any `Err` into the kmsg+reboot path. A 7.pre failure aborts before any write (the
//! [`crate::installer::run_install`] state machine guarantees the ordering).

use crate::install_target::{DiskInfo, is_candidate_disk_class};
use crate::installer::{
    InstallComponent, InstallOps, InstallerError, PartitionLayout, PartitionTable,
    disk_from_partition,
};
use fb_verity_rt::partition_device_name;
use std::ffi::CString;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::io::AsRawFd;

use sha2::{Digest, Sha256};

/// Scratch mountpoint for the old Debian root (mounted read-only — the ONLY mount the installer
                
/// performs; the new partitions are written raw, never mounted). Initramfs-resident.
const OLD_ROOT_MNT: &str = "/mnt/old-root";
/// The syslinux MBR stage-1 blob — a static file in the initramfs, `dd`'d to the disk (never executed
/// in the installer). The ONLY initramfs-resident tool/blob the dd-only installer needs.
const MBR_BIN: &str = "/usr/share/syslinux/mbr.bin";
/// The syslinux GPT-aware MBR stage-1 blob — the protective-MBR analog of `mbr.bin` for the SeabiosGpt
/// arm. A static initramfs file, `dd`'d to the disk (never executed). It chains to the GPT partition
/// carrying the `legacy_boot` attribute.
const GPTMBR_BIN: &str = "/usr/share/syslinux/gptmbr.bin";

/// The syslinux MBR stage-1 occupies the first 440 bytes of sector 0. The partition table (bytes
/// 446..510) and boot signature (510..512) — written by `write_partition_table` — must be preserved,
/// so only 440 bytes are overwritten (mirrors the spec's `dd bs=440 count=1 conv=notrunc`).
const MBR_BOOTCODE_LEN: usize = 440;

                                                                                                    

/// `BLKGETSIZE64 = _IOR(0x12, 114, size_t)` — read the block device size in BYTES into a `u64`.
/// `(READ=2 << 30) | (sizeof(size_t)=8 << 16) | (0x12 << 8) | 114` = `0x8008_1272` (the well-known
/// constant on 64-bit Linux).
const BLKGETSIZE64: u32 = (2 << 30) | (8 << 16) | (0x12 << 8) | 114;
const _: () = assert!(BLKGETSIZE64 == 0x8008_1272);

/// `BLKRRPART = _IO(0x12, 95)` — re-read the partition table so the kernel registers the new
/// `/dev/<disk><n>` nodes after the MBR write. `(0x12 << 8) | 95` = `0x125f`.
const BLKRRPART: u32 = (0x12 << 8) | 95;
const _: () = assert!(BLKRRPART == 0x125f);

/// The real installer effects. `disk_device` (e.g. `sda`) is bound from the `fb.image-raw` token
/// (via `set_target_disk`, the raw arm) or re-derived from the restore partition at
/// [`InstallOps::mount_old_root`]; it is the raw-block write target for every later step.
pub struct SyscallInstallOps {
    disk_device: Option<String>,
    /// Cached read fd for the chunk source (the whole target disk on the raw arm; the O_NOFOLLOW
    /// regular source file on the UEFI arm) — opened once at the first `read_source_chunk`.
    source_fd: Option<fs::File>,
    /// Cached per-component write fds (indexed by [`component_index`]); `fsync_partition` flushes
    /// the component's fd once after its copy loop (spec D7 ordering).
    write_fds: [Option<fs::File>; 4],
    /// Cached per-component `O_DIRECT` readback fds — a SEPARATE open from the write fd so the
    /// verify read exercises the block layer, not the page cache the write populated (spec D7).
    direct_fds: [Option<fs::File>; 4],
    /// Page-aligned bounce buffer for the `O_DIRECT` reads (the alignment contract); allocated
    /// once at the first readback, chunk-sized + one alignment unit.
    direct_buf: Option<AlignedBuf>,
}

impl Default for SyscallInstallOps {
    fn default() -> Self {
        Self::new()
    }
}

impl SyscallInstallOps {
    pub fn new() -> Self {
        Self {
            disk_device: None,
            source_fd: None,
            write_fds: [None, None, None, None],
            direct_fds: [None, None, None, None],
            direct_buf: None,
        }
    }

    /// The auto-detected whole-disk device (set at `mount_old_root`). Fail-closed if reached before
    /// the mount (the `run_install` ordering makes this unreachable, but never guess a device).
    fn disk(&self) -> Result<&str, InstallerError> {
        self.disk_device.as_deref().ok_or_else(|| {
            op_err_str(
                "disk-device",
                "target disk not resolved (mount step skipped)",
            )
        })
    }

    /// `/dev/<disk><n>` for the fixed partition number (boot=1, slot A=2, slot B=3, persist=4).
    fn part_path(&self, number: u8) -> Result<String, InstallerError> {
        Ok(partition_device_name(self.disk()?, number))
    }
}

/// Decode a raw 32-byte ed25519 pubkey from 64 ASCII-hex bytes. `None` on wrong length / non-hex —
/// panic-free (no `unwrap` on attacker/operator bytes; the PID-1 `deny(unwrap_used)` ratchet holds). No
/// PKIX/DER/PEM anywhere in the box verify path (spec §6d): a raw 32-byte key, hex-encoded.
fn decode_root_pubkey(hex: &[u8]) -> Option<[u8; 32]> {
    let hex = hex.trim_ascii_end();                                                                               
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in hex.chunks_exact(2).enumerate() {
        let hi = char::from(pair[0]).to_digit(16)?;
        let lo = char::from(pair[1]).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

                   
/// Hard read ceiling for any old-root file (defense-in-depth): a regular file on the RO
/// old-root mount cannot grow, but `take(CEILING)` makes the alloc bound structural regardless of the stat.
/// 8 GiB ≫ any legitimate `.img` (read whole into RAM); the attacker-influenced restore image + `.sig`
/// are capped far tighter BEFORE their read (`prepare`).
const OLD_ROOT_READ_CEILING: u64 = 8 * 1024 * 1024 * 1024;

/// Open an old-root file WITHOUT following a final-component symlink (`O_NOFOLLOW`) and reject anything
                   
/// that is not a REGULAR file. The restore image + its `.sig` are attacker-influenced
/// (siblings on compromisable `/persist`): planted as a symlink to `/dev/zero` they would defeat the size
/// cap (`fs::metadata` FOLLOWS symlinks; a char device reports `len()==0`) and then read with no EOF →
/// unbounded `Vec` → PID-1 OOM. `O_NOFOLLOW` refuses the symlink. `O_NONBLOCK` makes the open of a
/// writerless FIFO return immediately (an `O_RDONLY` open of one otherwise BLOCKS forever → PID-1 HANG
                  
/// mid-`prepare`, before any verify) so the `is_file()`/`S_ISREG` check can then refuse
/// the device/fifo. `O_NONBLOCK` is a no-op for the subsequent regular-file read (regular files never
/// return `EAGAIN`). Returns the open fd + the regular file's true length.
pub fn open_regular_nofollow(full: &str) -> Result<(fs::File, u64), InstallerError> {
    let f = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(full)
        .map_err(op("open-old-root-file"))?;
    let meta = f.metadata().map_err(op("stat-old-root-file"))?;
    if !meta.file_type().is_file() {
        return Err(op_err_str(
            "open-old-root-file",
            "old-root path is not a regular file (symlink / device / fifo rejected)",
        ));
    }
    Ok((f, meta.len()))
}

                     
/// Read a regular old-root file (symlink/device-rejected), hard-bounded by `ceiling`.
pub fn read_regular_capped(full: &str, ceiling: u64) -> Result<Vec<u8>, InstallerError> {
    let (f, len) = open_regular_nofollow(full)?;
    let mut buf = Vec::with_capacity(len.min(ceiling) as usize);
    f.take(ceiling)
        .read_to_end(&mut buf)
        .map_err(op("read-old-root-file"))?;
    Ok(buf)
}

impl InstallOps for SyscallInstallOps {
                                                             

    fn mount_old_root(&mut self, device: &str) -> Result<(), InstallerError> {
                                                                                                   
                             
        self.disk_device = Some(disk_from_partition(device)?);
        let source = format!("/dev/{device}");
        mkdir_p(OLD_ROOT_MNT, 0o755).map_err(op("mkdir-old-root"))?;
                                                                                                      
                                                     
        do_mount(&source, OLD_ROOT_MNT, Some("ext4"), libc::MS_RDONLY).map_err(op("mount-old-root"))
    }

    fn resolve_partuuid(&mut self, partuuid: &str) -> Result<String, InstallerError> {
                                                                                                       
                                                                                         
                                                                                                        
                                                                                                
        let dev_path = resolve_partuuid(partuuid)?;
        dev_path
            .strip_prefix("/dev/")
            .map(str::to_string)
            .ok_or_else(|| {
                op_err_str(
                    "resolve-partuuid",
                    "resolved device path is not under /dev/",
                )
            })
    }

    fn mount_data_partition(&mut self, device: &str) -> Result<(), InstallerError> {
                                                                                                      
                                                                                                     
                                                                                                      
        let source = format!("/dev/{device}");
        mkdir_p(OLD_ROOT_MNT, 0o755).map_err(op("mkdir-old-root"))?;
        do_mount(&source, OLD_ROOT_MNT, Some("ext4"), libc::MS_RDONLY)
            .map_err(op("mount-data-partition"))
    }

    fn read_old_root_file(&mut self, path: &str) -> Result<Vec<u8>, InstallerError> {
                                                                                                      
                                                                                                            
                                                                                                
        read_regular_capped(&format!("{OLD_ROOT_MNT}{path}"), OLD_ROOT_READ_CEILING)
    }

    fn old_root_file_size(&mut self, path: &str) -> Result<u64, InstallerError> {
                                                                                                   
                                                                                                       
                                                                                                                 
                                                                                            
          
                                                                                                         
                                                                                                       
                                                                                                            
                                                                                                       
                                                                                                
        Ok(open_regular_nofollow(&format!("{OLD_ROOT_MNT}{path}"))?.1)
    }

    fn mem_total_bytes(&mut self) -> Option<u64> {
                                                                                                     
                                                                                      
        let meminfo = fs::read_to_string("/proc/meminfo").ok()?;
        crate::installer::parse_meminfo_total(&meminfo)
    }

    fn verify_restore_image(
        &mut self,
        image: &[u8],
        sig: &[u8],
        operator_root_pubkey_hex: &[u8],
        min_ctr: u64,
    ) -> Result<(), InstallerError> {
                                                                                                        
                                                                                                            
                                                                                                          
                                                                                                       
                                                                                                    
                                                                                                         
                                                                                                           
        let root_pubkey = decode_root_pubkey(operator_root_pubkey_hex).ok_or_else(|| {
            op_err_str(
                "verify-restore-image",
                "pinned operator root pubkey absent or malformed",
            )
        })?;
        let artifact_hash: [u8; 32] = Sha256::digest(image).into();
        quince::verify_artifact(
            &root_pubkey,
            sig,
            &artifact_hash,
            quince::Purpose::Backup,
            min_ctr,
        )
        .map(|_verified| ())
                                                                                                           
                                                                                                       
        .map_err(|e| {
            op_err_str(
                "verify-restore-image",
                &format!("restore image verification failed: {e:?}"),
            )
        })
    }

    fn unmount_old_root(&mut self) -> Result<(), InstallerError> {
        do_umount(OLD_ROOT_MNT).map_err(op("unmount-old-root"))
    }

                                                      

    fn disk_size_bytes(&mut self) -> Result<u64, InstallerError> {
        let disk = self.disk()?;
        let dev = fs::OpenOptions::new()
            .read(true)
            .open(format!("/dev/{disk}"))
            .map_err(op("open-disk-for-size"))?;
        let mut size: u64 = 0;
                                                                                                      
                                                                          
        let rc = unsafe { libc::ioctl(dev.as_raw_fd(), BLKGETSIZE64 as libc::Ioctl, &mut size) };
        if rc < 0 {
            return Err(op("blkgetsize64")(io::Error::last_os_error()));
        }
        Ok(size)
    }

    fn write_partition_table(&mut self, table: PartitionTable) -> Result<(), InstallerError> {
                                                                                                  
                                                                                                         
                                                                    
        let path = format!("/dev/{}", self.disk()?);
        match table {
            PartitionTable::Mbr(sector) => {
                if sector.len() != 512 {
                    return Err(op_err_str(
                        "write-partition-table",
                        &format!("expected a 512-byte MBR sector, got {} bytes", sector.len()),
                    ));
                }
                write_raw_at_zero(&path, sector).map_err(op("write-partition-table"))?;
            }
            PartitionTable::Gpt {
                primary,
                backup,
                backup_lba,
            } => {
                let sector = crate::installer::SECTOR_SIZE;
                                                                                                  
                                                                              
                if primary.len() as u64 != 34 * sector {
                    return Err(op_err_str(
                        "write-partition-table",
                        &format!(
                            "expected a {}-byte GPT primary, got {}",
                            34 * sector,
                            primary.len()
                        ),
                    ));
                }
                                                                                                        
                                                                                                   
                if backup.len() as u64 != 33 * sector {
                    return Err(op_err_str(
                        "write-partition-table",
                        &format!(
                            "expected a {}-byte GPT backup (32 entry sectors + 1 header), got {}",
                            33 * sector,
                            backup.len()
                        ),
                    ));
                }
                                                                                                      
                                                                                                      
                                                                                                      
                                                                                                        
                                                                                                        
                                                                                                        
                let esp_first_lba = u64::from_le_bytes([
                    primary[1056],
                    primary[1057],
                    primary[1058],
                    primary[1059],
                    primary[1060],
                    primary[1061],
                    primary[1062],
                    primary[1063],
                ]);
                zero_at(&path, esp_first_lba * sector, sector)
                    .map_err(op("invalidate-stale-esp"))?;
                zero_at(&path, backup_lba * sector, backup.len() as u64)
                    .map_err(op("invalidate-stale-gpt-backup"))?;
                                                                                            
                write_raw_at_zero(&path, primary).map_err(op("write-gpt-primary"))?;
                write_raw_at(&path, backup_lba * sector, backup).map_err(op("write-gpt-backup"))?;
            }
        }
        blkrrpart(&path).map_err(op("blkrrpart"))?;
        Ok(())
    }

    fn dd_component(
        &mut self,
        which: InstallComponent,
        bytes: &[u8],
    ) -> Result<(), InstallerError> {
                                                                                                   
                                                                                               
                                                                                                   
                                               
        let part = self.part_path(component_partition_number(which))?;
        write_raw_at_zero(&part, bytes).map_err(op("dd-component"))
    }

                                                                                                 
                                                

    fn read_source_chunk(
        &mut self,
        src: &crate::installer_stream::SourceHandle,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, InstallerError> {
        use crate::installer_stream::SourceHandle;
        use std::os::unix::fs::FileExt;
                                                                                           
                                                                                             
                                                                                               
        if self.source_fd.is_none() {
            let fd = match src {
                SourceHandle::Raw(_) => fs::OpenOptions::new()
                    .read(true)
                    .open(format!("/dev/{}", self.disk()?))
                    .map_err(op("open-staged-source"))?,
                SourceHandle::OldRootFile(path) => {
                    let (f, _) = open_regular_nofollow(&format!("{OLD_ROOT_MNT}{path}"))?;
                    f
                }
            };
            self.source_fd = Some(fd);
        }
        let fd = self
            .source_fd
            .as_ref()
            .ok_or_else(|| op_err_str("read-source-chunk", "source fd vanished (unreachable)"))?;
        let abs = match src {
                                                                                               
                                                                                                 
                                                                           
            SourceHandle::Raw(region) => region.offset.saturating_add(offset),
            SourceHandle::OldRootFile(_) => offset,
        };
        fd.read_at(buf, abs).map_err(op("read-source-chunk"))
    }

    fn write_partition_chunk(
        &mut self,
        which: InstallComponent,
        offset: u64,
        buf: &[u8],
    ) -> Result<(), InstallerError> {
        use std::os::unix::fs::FileExt;
        if self.write_fds[component_index(which)].is_none() {
            let part = self.part_path(component_partition_number(which))?;
            let fd = fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&part)
                .map_err(op("open-partition-write"))?;
            self.write_fds[component_index(which)] = Some(fd);
        }
        let fd = self.write_fds[component_index(which)]
            .as_ref()
            .ok_or_else(|| {
                op_err_str("write-partition-chunk", "write fd vanished (unreachable)")
            })?;
        fd.write_all_at(buf, offset)
            .map_err(op("write-partition-chunk"))
    }

    fn read_partition_chunk(
        &mut self,
        which: InstallComponent,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, InstallerError> {
        use std::os::unix::fs::FileExt;
        if self.direct_fds[component_index(which)].is_none() {
            let part = self.part_path(component_partition_number(which))?;
            let fd = fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECT)
                .open(&part)
                .map_err(op("open-partition-direct"))?;
            self.direct_fds[component_index(which)] = Some(fd);
        }
                                                                                                 
                                                                                                 
                                                                                                
                                                                                                
                                                                                                  
                                                                                                  
                                                                                                
                                                
        let buf_capacity = crate::installer_stream::INSTALL_COPY_CHUNK_BYTES as usize;
        if self.direct_buf.is_none() {
            self.direct_buf = Some(AlignedBuf::new(buf_capacity));
        }
        let want = buf.len().min(buf_capacity);
        let padded = want.div_ceil(DIRECT_ALIGN) * DIRECT_ALIGN;
        let fd = self.direct_fds[component_index(which)]
            .as_ref()
            .ok_or_else(|| {
                op_err_str("read-partition-chunk", "direct fd vanished (unreachable)")
            })?;
        let bounce = self
            .direct_buf
            .as_mut()
            .ok_or_else(|| op_err_str("read-partition-chunk", "bounce buffer vanished"))?;
        let n = fd
            .read_at(bounce.slice_mut(padded), offset)
            .map_err(op("read-partition-chunk"))?;
        let usable = n.min(want);
        buf[..usable].copy_from_slice(&bounce.slice_mut(padded)[..usable]);
        Ok(usable)
    }

    fn fsync_partition(&mut self, which: InstallComponent) -> Result<(), InstallerError> {
                                                                                            
                                                                                               
        match &self.write_fds[component_index(which)] {
            Some(fd) => fd.sync_all().map_err(op("fsync-partition")),
                                                                                                 
                                                                                          
            None => Err(op_err_str(
                "fsync-partition",
                "no chunk writes recorded for this component",
            )),
        }
    }

    fn zero_slot_b(&mut self, layout: &PartitionLayout) -> Result<(), InstallerError> {
                                                                                                  
                                          
        let slot_b = self.part_path(3)?;
        let bytes = layout.slot_b.sector_count * crate::installer::SECTOR_SIZE;
        zero_device(&slot_b, bytes).map_err(op("zero-slot-b"))
    }

    fn write_mbr_bootcode(&mut self) -> Result<(), InstallerError> {
                                                                                                        
                                                                                                  
                                                                                                   
                                                              
        let mbr_code = fs::read(MBR_BIN).map_err(op("read-mbr-bin"))?;
        if mbr_code.len() < MBR_BOOTCODE_LEN {
            return Err(op_err_str(
                "write-mbr-bootcode",
                "mbr.bin shorter than the 440-byte boot-code area",
            ));
        }
        let disk = format!("/dev/{}", self.disk()?);
        write_raw_at_zero(&disk, &mbr_code[..MBR_BOOTCODE_LEN]).map_err(op("write-mbr-bootcode"))
    }

    fn write_gptmbr_bootcode(&mut self) -> Result<(), InstallerError> {
                                                                                                        
                                                                                                   
                                                                                                      
                                                                                                     
        let gptmbr_code = fs::read(GPTMBR_BIN).map_err(op("read-gptmbr-bin"))?;
        if gptmbr_code.len() < MBR_BOOTCODE_LEN {
            return Err(op_err_str(
                "write-gptmbr-bootcode",
                "gptmbr.bin shorter than the 440-byte boot-code area",
            ));
        }
        let disk = format!("/dev/{}", self.disk()?);
        write_raw_at_zero(&disk, &gptmbr_code[..MBR_BOOTCODE_LEN])
            .map_err(op("write-gptmbr-bootcode"))
    }

    fn finalize_and_reboot(&mut self) -> Result<(), InstallerError> {
                                                                                                      
                                                                                                       
                                         
                                                                                                    
                             
        unsafe {
            libc::sync();
            libc::reboot(libc::RB_AUTOBOOT);
        }
                                                                                                      
        Err(op("reboot")(io::Error::last_os_error()))
    }

    fn enumerate_disks(&mut self) -> Result<Vec<DiskInfo>, InstallerError> {
                                                                                              
                                                                                                           
                                                                                                      
                                                                    
        let dir = fs::read_dir("/sys/block").map_err(op("enumerate-disks"))?;
        let mut disks = Vec::new();
        for entry in dir.flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let removable = fs::read_to_string(format!("/sys/block/{name}/removable"))
                .map(|s| s.trim() == "1")
                .unwrap_or(true);
            disks.push(DiskInfo {
                class_ok: is_candidate_disk_class(&name),
                name,
                removable,
            });
        }
        Ok(disks)
    }

    fn set_target_disk(&mut self, disk: &str) {
                                                                                                  
                                                                                                          
                                                                                            
        self.disk_device = Some(disk.to_string());
    }
}

                                                                                                   

/// The fixed partition number each component is written to: boot=1, slot A (rootfs)=2, persist=4,
/// weights=5 (dha Component E — the 5th GPT partition; a dha image is always GPT, O4=(a), so the
/// weights arm never runs on a 4-primary MBR). Slot B (3) is zeroed, never component-written.
fn component_partition_number(which: InstallComponent) -> u8 {
    match which {
        InstallComponent::Boot => 1,
        InstallComponent::Rootfs => 2,
        InstallComponent::PersistSkeleton => 4,
        InstallComponent::Weights => 5,
    }
}

/// Dense 0..4 index for the per-component fd caches.
fn component_index(which: InstallComponent) -> usize {
    match which {
        InstallComponent::Boot => 0,
        InstallComponent::Rootfs => 1,
        InstallComponent::PersistSkeleton => 2,
        InstallComponent::Weights => 3,
    }
}

/// The `O_DIRECT` alignment unit: one page (4096) — satisfies every 512n/512e/4Kn logical-block
/// requirement for buffer address, file offset, and read length (the D12 chunk const is a page
/// multiple, so driver offsets comply by construction).
const DIRECT_ALIGN: usize = 4096;

/// A page-aligned bounce buffer for `O_DIRECT` reads: over-allocate one alignment unit and carve
                                             
/// the aligned window (no external allocator crate).
/// The backing Vec never reallocates after construction, so the alignment holds for its lifetime.
struct AlignedBuf {
    raw: Vec<u8>,
    aligned_start: usize,
}

impl AlignedBuf {
    fn new(capacity: usize) -> Self {
        let raw = vec![0u8; capacity + DIRECT_ALIGN];
        let addr = raw.as_ptr() as usize;
        let aligned_start = (DIRECT_ALIGN - (addr % DIRECT_ALIGN)) % DIRECT_ALIGN;
        Self { raw, aligned_start }
    }

    /// The aligned window's first `len` bytes (`len ≤ capacity`); the returned slice's pointer is
    /// `DIRECT_ALIGN`-aligned — the `O_DIRECT` buffer contract.
    fn slice_mut(&mut self, len: usize) -> &mut [u8] {
        &mut self.raw[self.aligned_start..self.aligned_start + len]
    }
}

                                                                                                   

/// Map an `io::Error` to [`InstallerError::OpFailed`] for a named step.
fn op(step: &'static str) -> impl Fn(io::Error) -> InstallerError {
    move |e| InstallerError::OpFailed {
        op: step,
        reason: e.to_string(),
    }
}

/// [`InstallerError::OpFailed`] from a static reason string.
fn op_err_str(step: &'static str, reason: &str) -> InstallerError {
    InstallerError::OpFailed {
        op: step,
        reason: reason.to_string(),
    }
}

fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::other("interior NUL in path"))
}

/// `mount(2)` (mirrors `mount::do_mount` — duplicated rather than widening that module's API, since
/// the installer mounts a real ext4 filesystem, not the runtime pseudo-mounts).
fn do_mount(
    source: &str,
    target: &str,
    fstype: Option<&str>,
    flags: libc::c_ulong,
) -> io::Result<()> {
    let source = cstr(source)?;
    let target = cstr(target)?;
    let fstype = fstype.map(cstr).transpose()?;
    let fstype_ptr = fstype.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
                                                                                                
                                   
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype_ptr,
            flags,
            std::ptr::null(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn do_umount(target: &str) -> io::Result<()> {
    let target = cstr(target)?;
                                         
    let rc = unsafe { libc::umount(target.as_ptr()) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `mkdir -p` with an explicit mode on the final component (best-effort on the parents). Used only for
/// the old-root scratch mountpoint (the new partitions are never mounted).
fn mkdir_p(path: &str, mode: u32) -> io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(path)
}

/// Write `bytes` to a block device at `offset` WITHOUT truncating (block devices can't be truncated;
/// `truncate` is not set), then fsync. The GPT backup lands at a non-zero tail offset; the MBR sector,
/// the dd'd components, and the 440-byte MBR boot code all write at offset 0 ([`write_raw_at_zero`]).
fn write_raw_at(dev: &str, offset: u64, bytes: &[u8]) -> io::Result<()> {
    let mut f = fs::OpenOptions::new().read(true).write(true).open(dev)?;
    f.seek(SeekFrom::Start(offset))?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// [`write_raw_at`] at offset 0 — the common case (the MBR/GPT-primary sector, the dd'd components, the
/// MBR boot code).
fn write_raw_at_zero(dev: &str, bytes: &[u8]) -> io::Result<()> {
    write_raw_at(dev, 0, bytes)
}

/// Zero `len` bytes at `offset` on a block device, in 1 MiB chunks, then fsync. Used for slot B (at 0,
       
/// [`zero_device`]) and the stale-structure invalidation (the ESP VBR + the old GPT backup, each at
/// its LBA).
fn zero_at(dev: &str, offset: u64, len: u64) -> io::Result<()> {
    let mut f = fs::OpenOptions::new().read(true).write(true).open(dev)?;
    f.seek(SeekFrom::Start(offset))?;
    let zeros = [0u8; 1024 * 1024];
    let mut remaining = len;
    while remaining > 0 {
        let chunk = remaining.min(zeros.len() as u64) as usize;
        f.write_all(&zeros[..chunk])?;
        remaining -= chunk as u64;
    }
    f.sync_all()
}

/// [`zero_at`] at offset 0 — zero the first `len` bytes (the inactive slot B).
fn zero_device(dev: &str, len: u64) -> io::Result<()> {
    zero_at(dev, 0, len)
}

/// `BLKRRPART` — re-read the partition table on a just-repartitioned disk.
fn blkrrpart(disk: &str) -> io::Result<()> {
    let f = fs::OpenOptions::new().read(true).write(true).open(disk)?;
                                                                           
    let rc = unsafe { libc::ioctl(f.as_raw_fd(), BLKRRPART as libc::Ioctl) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

                                                                                                    

/// Resolve a PARTUUID to its `/dev/<disk><n>` partition node. The whole scan (the `/sys/block`
/// candidate-disk walk + the pure primary-GPT parse + the 20 × 500 ms bare-metal enumeration poll +
                             
/// the first-match semantics and the accepted forward-debt) moved VERBATIM
/// to [`fb_verity_rt::resolve_partuuid`] (hotswap v4 §9/R3-I7) — the fb-weights swap sequencer
/// resolves the weights partition through the SAME code. This shim re-wraps its io-flavored error
/// into [`InstallerError`] for the installer state machine, byte-preserving the FATAL-line text
/// (op `resolve-partuuid` + the candidate-disks diagnostic). The scan mechanics are fixture-tested
/// in fb-verity-rt; the raw-block path is proven in the Phase-5 OVMF / boot gates.
pub fn resolve_partuuid(partuuid: &str) -> Result<String, InstallerError> {
    fb_verity_rt::resolve_partuuid(partuuid)
        .map_err(|e| op_err_str("resolve-partuuid", &e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aligned_buf_window_is_page_aligned_across_sizes() {
                                                                                                  
                                                                                                   
        for capacity in [4096usize, 8 * 1024 * 1024, 12_288] {
            let mut buf = AlignedBuf::new(capacity);
            let full = buf.slice_mut(capacity);
            assert_eq!(full.as_ptr() as usize % DIRECT_ALIGN, 0, "cap {capacity}");
            assert_eq!(full.len(), capacity);
            let tail = buf.slice_mut(512);
            assert_eq!(tail.as_ptr() as usize % DIRECT_ALIGN, 0);
        }
    }

    #[test]
    fn direct_read_padding_rounds_up_to_the_alignment_unit() {
                                                                                                
                                                                         
        for (want, padded) in [(1usize, 4096usize), (4096, 4096), (4097, 8192), (512, 4096)] {
            assert_eq!(want.div_ceil(DIRECT_ALIGN) * DIRECT_ALIGN, padded);
        }
    }

    #[test]
    fn component_partition_mapping_is_the_fixed_layout() {
                                                                                                   
                                                  
        assert_eq!(component_partition_number(InstallComponent::Boot), 1);
        assert_eq!(component_partition_number(InstallComponent::Rootfs), 2);
        assert_eq!(
            component_partition_number(InstallComponent::PersistSkeleton),
            4
        );
        assert_eq!(component_partition_number(InstallComponent::Weights), 5);
        let mut seen = [false; 4];
        for c in [
            InstallComponent::Boot,
            InstallComponent::Rootfs,
            InstallComponent::PersistSkeleton,
            InstallComponent::Weights,
        ] {
            let i = component_index(c);
            assert!(!seen[i], "duplicate fd-cache index {i}");
            seen[i] = true;
        }
    }
}

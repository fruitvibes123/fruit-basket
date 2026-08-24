//! Runtime PARTUUID → `/dev` device discovery (moved VERBATIM from `initramfs-init`'s
//! `installer_syscall.rs`/`installer.rs`/`install_target.rs` read-side, hotswap v4 §9/R3-I7): the
//! `/sys/block` disk scan + the pure primary-GPT parse (header CRC, mixed-endian GUID match) + the
//! naming helpers. The initramfs-init GPT WRITER (`build_gpt`) imports the shared pure primitives
//! ([`crc32`], [`guid_to_mixed_endian`], the geometry consts) back from here — one source, two sides.
//!
//! The scan is fixture-testable via [`resolve_partuuid_at`] (sysfs/dev roots + poll bounds injected);
//! [`resolve_partuuid`] is the absolute-path production wrapper (`/sys/block` + `/dev`, the
//! 20 × 500 ms bare-metal enumeration poll).

use std::fs;
use std::io::{self, Read};
use std::path::Path;

/// One disk sector, bytes (the GPT geometry unit; UEFI 2.10 §5.3).
pub const SECTOR_SIZE: u64 = 512;

/// GPT geometry (UEFI 2.10 §5.3): 128 entries max, a 92-byte header.
pub const GPT_NUM_ENTRIES: u32 = 128;
pub const GPT_HEADER_BYTES: usize = 92;

/// The installable whole-disk classes (rules out loop/dm/ram/etc.).
const DISK_CLASSES: [&str; 6] = ["sd", "vd", "hd", "xvd", "nvme", "mmcblk"];

/// Does `name` begin with an installable disk class (`sd`/`vd`/`hd`/`xvd`/`nvme`/`mmcblk`)? Pure;
/// shared by the installer's target selection, its `/sys/block` enumeration `class_ok`, and the
/// PARTUUID scan below.
pub fn is_candidate_disk_class(name: &str) -> bool {
    DISK_CLASSES.iter().any(|p| name.starts_with(p))
}

/// Derive a partition device path from a disk device + partition number, per the Linux
/// partition-naming convention: append the number directly for letter-suffixed disks
/// (`sda`→`sda2`, `vda`→`vda2`), but insert `p` when the disk name ends in a digit
/// (`nvme0n1`→`nvme0n1p2`, `mmcblk0`→`mmcblk0p2`) so the partition number isn't fused into the
/// device's own trailing digits.
pub fn partition_device_name(disk_device: &str, number: u8) -> String {
    let sep = if disk_device.ends_with(|c: char| c.is_ascii_digit()) {
        "p"
    } else {
        ""
    };
    format!("/dev/{disk_device}{sep}{number}")
}

/// Encode a canonical `8-4-4-4-12` GUID string to its 16-byte GPT on-disk (mixed-endian) form: the
/// first three fields are little-endian, the trailing 2+6 bytes are big-endian (spec §5 / UEFI 2.10
/// §5.3.1). Hex digits may be upper- or lower-case (the spec's TYPE GUIDs are written upper-case, the
/// PARTUUID literals lower-case). Whitelist the shape; any malformed input — wrong group count/lengths
/// or a non-hex digit — returns `None` (fail closed: never write a garbage GUID into a partition table).
pub fn guid_to_mixed_endian(s: &str) -> Option<[u8; 16]> {
    let groups: Vec<&str> = s.split('-').collect();
    if groups.len() != 5
        || [8, 4, 4, 4, 12]
            != [
                groups[0].len(),
                groups[1].len(),
                groups[2].len(),
                groups[3].len(),
                groups[4].len(),
            ]
    {
        return None;
    }
                                                                                                         
    let joined: String = groups.concat();
    let mut raw = [0u8; 16];
    for (i, b) in raw.iter_mut().enumerate() {
        *b = u8::from_str_radix(&joined[i * 2..i * 2 + 2], 16).ok()?;
    }
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&[raw[3], raw[2], raw[1], raw[0]]);                       
    out[4..6].copy_from_slice(&[raw[5], raw[4]]);                       
    out[6..8].copy_from_slice(&[raw[7], raw[6]]);                       
    out[8..16].copy_from_slice(&raw[8..16]);                                            
    Some(out)
}

/// Reflected CRC-32 (IEEE 802.3 polynomial `0xEDB88320`) — the checksum GPT headers + entry arrays
/// carry (UEFI 2.10 §5.3.1/§5.3.2). Bitwise / table-free: this layer is `libc`-only, and a
/// handful of per-install CRCs have no need of a 1 KiB lookup table.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();                                            
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Validate a primary GPT header's own CRC32 (field [16..20], computed with that field zeroed —
/// UEFI 2.10 §5.3.1). `header` must be at least the 92 header bytes.
pub fn gpt_header_crc_valid(header: &[u8]) -> bool {
    if header.len() < GPT_HEADER_BYTES {
        return false;
    }
    let stored = u32::from_le_bytes([header[16], header[17], header[18], header[19]]);
    let mut h = header[..GPT_HEADER_BYTES].to_vec();
    h[16..20].copy_from_slice(&[0, 0, 0, 0]);
    crc32(&h) == stored
}

/// Scan a primary-GPT blob (the first 34 sectors read from a disk — LBA0 protective MBR + LBA1 header +
/// the LBA2 entry array) for the partition whose UNIQUE GUID equals `partuuid`, returning its 1-based
/// partition number. This is the runtime PARTUUID→/dev resolution (`fb.rootfs-dev=PARTUUID=…`, the
/// weights partition, the fb-weights swap): the GPT selects the partition by GUID, so the runtime finds
/// the `/dev` node this way rather than from a baked path. Pure (host-tested); the disk read + the
/// `/dev` name assembly are [`resolve_partuuid_at`]. Fail-closed (`Err`) on a missing /
/// non-`EFI PART` header, a bad header CRC32, or a malformed `partuuid`; `Ok(None)` when no entry matches.
pub fn find_partition_by_partuuid(gpt: &[u8], partuuid: &str) -> io::Result<Option<u32>> {
    let err = |reason: String| io::Error::other(format!("find-partition-by-partuuid: {reason}"));
    let sector = SECTOR_SIZE as usize;
    let header = gpt
        .get(sector..sector + GPT_HEADER_BYTES)
        .ok_or_else(|| err("GPT blob shorter than LBA1 + the 92-byte header".to_string()))?;
    if &header[0..8] != b"EFI PART" {
        return Err(err(
            "GPT primary header signature is not 'EFI PART'".to_string()
        ));
    }
                                                                                                         
                                                                                                        
                                                                                                          
                                                                                                           
    if !gpt_header_crc_valid(header) {
        return Err(err("GPT primary header CRC32 is invalid".to_string()));
    }
    let target = guid_to_mixed_endian(partuuid)
        .ok_or_else(|| err(format!("malformed PARTUUID {partuuid:?}")))?;

    let part_entry_lba = u64::from_le_bytes([
        header[72], header[73], header[74], header[75], header[76], header[77], header[78],
        header[79],
    ]);
    let num_entries = u32::from_le_bytes([header[80], header[81], header[82], header[83]]);
    let entry_size = u32::from_le_bytes([header[84], header[85], header[86], header[87]]) as usize;
    if entry_size < 32 {
        return Err(err(format!(
            "GPT entry size {entry_size} too small for a unique GUID"
        )));
    }
    let entries_start = usize::try_from(part_entry_lba)
        .ok()
        .and_then(|lba| lba.checked_mul(sector))
        .ok_or_else(|| err("GPT entry-array LBA out of range".to_string()))?;
                                                                                    
    let count = (num_entries as usize).min(GPT_NUM_ENTRIES as usize);
    for i in 0..count {
        let off = entries_start + i * entry_size;
        let Some(entry) = gpt.get(off..off + entry_size) else {
            break;                                                         
        };
                                                               
        if entry[0..16].iter().all(|&b| b == 0) {
            continue;
        }
        if entry.get(16..32) == Some(target.as_slice()) {
            return Ok(Some((i + 1) as u32));                            
        }
    }
    Ok(None)
}

/// Read the first `sectors` sectors of a block device (or fixture file) into RAM (the primary GPT
/// region; no mount).
fn read_first_sectors(dev: &Path, sectors: u64) -> io::Result<Vec<u8>> {
    let mut f = fs::File::open(dev)?;
    let mut buf = vec![0u8; (sectors * SECTOR_SIZE) as usize];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

/// Resolve a PARTUUID to its `/dev/<disk><n>` partition node by scanning the box's block DISKS for the
/// GPT entry matching it (mirrors the kernel's `root=PARTUUID=` resolution). The runtime cmdline /
/// persisted weights record carry a PARTUUID (no `/dev` path) because the GPT selects the partition by
/// GUID. Reads each candidate disk's first 34 sectors (the primary GPT; a pure block read, no mount),
/// parses it with [`find_partition_by_partuuid`], and returns the FIRST match. Fail-closed if no disk
/// carries the PARTUUID. If two disks carry the SAME PARTUUID (a hypervisor-level capability —
/// conceded threat model), the choice is `/sys/block` readdir-order-dependent — matching the kernel's
/// own `root=PARTUUID=` first-match semantics; dm-verity binds the resolved device's CONTENT to the
               
/// root hash, so a decoy with a matching GUID but different content fails closed.
/// ACCEPTED FORWARD-DEBT (audit R1 F-3): the first-match short-circuit means a decoy that sorts first
/// forces a PERMANENT reboot loop (verity fails → reboot → re-pick the decoy …) — a physical-access DoS,
/// never a serve-wrong-content bypass. Accepted because physical disk attach already implies BMC-below-
/// the-OS, the explicitly-sacrificial bare-metal threat model; the alternative (keep scanning other disks
/// past a verity-setup failure) would couple this resolver to verity setup for no integrity gain.
///
/// Polls for up to 10 s (20 × 500 ms): on real hardware (USB, SATA) block devices take time to
/// enumerate; QEMU virtio appears instantly. A single-pass scan reliably misses the boot device on
/// bare metal. The scan mechanics are fixture-tested via [`resolve_partuuid_at`]; this absolute-path
/// wrapper is proven in the OVMF/boot gates.
pub fn resolve_partuuid(partuuid: &str) -> io::Result<String> {
    resolve_partuuid_at(
        Path::new("/sys/block"),
        Path::new("/dev"),
        partuuid,
        20,
        std::time::Duration::from_millis(500),
    )
}

/// The injectable core of [`resolve_partuuid`]: scan `sys_block`'s entries as candidate disks, read
/// each disk's GPT from `dev_dir/<disk>`, and return the `dev_dir`-anchored partition node path on a
/// PARTUUID match — polling `attempts` × `delay` for asynchronous device/node materialisation
/// (devtmpfsd queues `/dev/sdaN` after `/dev/sda`, so the GPT scan can succeed while the partition
/// node is still pending; only return once the node exists). Production passes `/sys/block` + `/dev` +
/// the 20 × 500 ms bare-metal poll; tests pass fixture dirs + a single attempt.
pub fn resolve_partuuid_at(
    sys_block: &Path,
    dev_dir: &Path,
    partuuid: &str,
    attempts: u32,
    delay: std::time::Duration,
) -> io::Result<String> {
    for attempt in 0..attempts.max(1) {
        if attempt > 0 {
                                                                                              
            let ts = libc::timespec {
                tv_sec: delay.as_secs() as libc::time_t,
                tv_nsec: i64::from(delay.subsec_nanos()) as libc::c_long,
            };
                                                                                       
            unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
        }
                                                                                                       
                                                                                         
        let Ok(dir) = fs::read_dir(sys_block) else {
            continue;
        };
        for entry in dir.flatten() {
            let name = entry.file_name();
            let Some(disk) = name.to_str() else { continue };
                                                                                                   
                                                    
            if !is_candidate_disk_class(disk) {
                continue;
            }
                                                                                                  
                                                      
            let Ok(head) = read_first_sectors(&dev_dir.join(disk), 34) else {
                continue;
            };
            if let Ok(Some(n)) = find_partition_by_partuuid(&head, partuuid) {
                                                                                                      
                                                                                                        
                let name = partition_device_name(disk, n as u8);
                let bare = name
                    .strip_prefix("/dev/")
                    .expect("partition_device_name emits /dev/-prefixed paths");
                let path = dev_dir.join(bare);
                                                                                             
                                                                                     
                if path.exists() {
                    return Ok(path_to_string(&path));
                }
                                                             
            }
        }
    }
                                                                                                    
                                                                                                  
                                                                                                
                                                                                              
    let seen: Vec<String> = fs::read_dir(sys_block)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| is_candidate_disk_class(n))
        .collect();
    Err(io::Error::other(format!(
        "no block disk carries PARTUUID {partuuid:?}; candidate disks seen: {seen:?}"
    )))
}

fn path_to_string(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    #[test]
    fn candidate_disk_classes_whitelist() {
        for ok in ["sda", "vdb", "hdc", "xvda", "nvme0n1", "mmcblk0"] {
            assert!(is_candidate_disk_class(ok), "{ok} should be a candidate");
        }
        for bad in ["loop0", "dm-0", "ram0", "zram0", "sr0", "fd0"] {
            assert!(!is_candidate_disk_class(bad), "{bad} must be excluded");
        }
    }

    #[test]
    fn partition_device_name_follows_linux_convention() {
        assert_eq!(partition_device_name("sda", 2), "/dev/sda2");
        assert_eq!(partition_device_name("vda", 5), "/dev/vda5");
        assert_eq!(partition_device_name("nvme0n1", 2), "/dev/nvme0n1p2");
        assert_eq!(partition_device_name("mmcblk0", 1), "/dev/mmcblk0p1");
    }

    #[test]
    fn guid_encoding_is_mixed_endian_and_fail_closed() {
                                                                                                 
        let g = guid_to_mixed_endian("00112233-4455-6677-8899-AABBCCDDEEFF").unwrap();
        assert_eq!(
            g,
            [
                0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
                0xEE, 0xFF
            ]
        );
                            
        assert_eq!(
            guid_to_mixed_endian("00112233-4455-6677-8899-aabbccddeeff").unwrap(),
            g
        );
                                        
        for bad in [
            "0011223344556677-8899-AABBCCDDEEFF",
            "00112233-4455-6677-8899",
            "g0112233-4455-6677-8899-AABBCCDDEEFF",
            "",
        ] {
            assert!(guid_to_mixed_endian(bad).is_none(), "{bad:?} must reject");
        }
    }

    #[test]
    fn crc32_matches_ieee_vector() {
                                                                                  
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

                                                                             

    const FIXTURE_PARTUUID: &str = "8d95a559-e243-40ba-a1a9-e60ab27ba967";

    /// A 34-sector primary-GPT blob with ONE used entry (partition `part_num`) carrying
    /// `FIXTURE_PARTUUID` as its unique GUID. Header CRC computed for real, so the parse path's
    /// CRC gate passes; every other field minimal-valid.
    fn gpt_blob(part_num: u32) -> Vec<u8> {
        let sector = SECTOR_SIZE as usize;
        let mut blob = vec![0u8; 34 * sector];
                       
        let entry_size = 128u32;
        {
            let h = &mut blob[sector..sector + GPT_HEADER_BYTES];
            h[0..8].copy_from_slice(b"EFI PART");
            h[8..12].copy_from_slice(&[0x00, 0x00, 0x01, 0x00]);                
            h[12..16].copy_from_slice(&(GPT_HEADER_BYTES as u32).to_le_bytes());
            h[72..80].copy_from_slice(&2u64.to_le_bytes());                       
            h[80..84].copy_from_slice(&GPT_NUM_ENTRIES.to_le_bytes());
            h[84..88].copy_from_slice(&entry_size.to_le_bytes());
        }
                                                                 
        let idx = (part_num - 1) as usize;
        let off = 2 * sector + idx * entry_size as usize;
        blob[off..off + 16].copy_from_slice(&[0xAB; 16]);                                  
        blob[off + 16..off + 32].copy_from_slice(&guid_to_mixed_endian(FIXTURE_PARTUUID).unwrap());
                                                                  
        let crc = crc32(&blob[sector..sector + GPT_HEADER_BYTES]);
        blob[sector + 16..sector + 20].copy_from_slice(&crc.to_le_bytes());
        blob
    }

    #[test]
    fn find_partition_matches_unique_guid() {
        let blob = gpt_blob(2);
        assert_eq!(
            find_partition_by_partuuid(&blob, FIXTURE_PARTUUID).unwrap(),
            Some(2)
        );
                                              
        assert_eq!(
            find_partition_by_partuuid(&blob, "00000000-0000-0000-0000-000000000001").unwrap(),
            None
        );
                                               
        let mut bad = blob.clone();
        bad[SECTOR_SIZE as usize + 40] ^= 0xFF;
        assert!(find_partition_by_partuuid(&bad, FIXTURE_PARTUUID).is_err());
                                       
        assert!(find_partition_by_partuuid(&[0u8; 4096], FIXTURE_PARTUUID).is_err());
    }

                                                                                            

    struct Fixture {
        _root: tempfile::TempDir,
        sys_block: PathBuf,
        dev: PathBuf,
    }

    /// A fixture tree: `<root>/sys_block/<disk>` entries (empty files stand in for the sysfs dirs —
    /// only the NAME is read) + `<root>/dev/<disk>` GPT-blob files + optional partition nodes.
    fn fixture(disks: &[(&str, Option<u32>)], nodes: &[&str]) -> Fixture {
        let root = tempfile::tempdir().expect("tempdir");
        let sys_block = root.path().join("sys_block");
        let dev = root.path().join("dev");
        fs::create_dir_all(&sys_block).expect("mk sys_block");
        fs::create_dir_all(&dev).expect("mk dev");
        for (disk, part) in disks {
            fs::File::create(sys_block.join(disk)).expect("sysfs name entry");
            let mut f = fs::File::create(dev.join(disk)).expect("disk blob");
            let blob = match part {
                Some(n) => gpt_blob(*n),
                None => vec![0u8; 34 * SECTOR_SIZE as usize],                         
            };
            f.write_all(&blob).expect("write blob");
        }
        for node in nodes {
            fs::File::create(dev.join(node)).expect("partition node");
        }
        Fixture {
            _root: root,
            sys_block,
            dev,
        }
    }

    fn resolve(fx: &Fixture, partuuid: &str) -> io::Result<String> {
        resolve_partuuid_at(
            &fx.sys_block,
            &fx.dev,
            partuuid,
            1,
            std::time::Duration::ZERO,
        )
    }

    #[test]
    fn resolves_partuuid_to_dev_node() {
        let fx = fixture(&[("vda", Some(5))], &["vda5"]);
        let got = resolve(&fx, FIXTURE_PARTUUID).expect("resolves");
        assert_eq!(got, fx.dev.join("vda5").to_string_lossy());
    }

    #[test]
    fn skips_non_candidate_and_non_gpt_disks() {
                                                                                                
                                   
        let fx = fixture(
            &[("loop0", Some(2)), ("vdb", None), ("vdc", Some(3))],
            &["loop0p2", "vdc3"],
        );
        let got = resolve(&fx, FIXTURE_PARTUUID).expect("resolves via vdc");
        assert_eq!(got, fx.dev.join("vdc3").to_string_lossy());
    }

    #[test]
    fn absent_partition_node_is_not_returned() {
                                                                                                     
                                                                               
        let fx = fixture(&[("vda", Some(5))], &[]);
        let e = resolve(&fx, FIXTURE_PARTUUID).unwrap_err();
        let msg = e.to_string();
        assert!(
            msg.contains("no block disk carries PARTUUID") && msg.contains("vda"),
            "diagnostic names the seen candidates: {msg}"
        );
    }

    #[test]
    fn unknown_partuuid_fails_closed_with_candidates() {
        let fx = fixture(&[("vda", Some(5))], &["vda5"]);
        let e = resolve(&fx, "00000000-0000-0000-0000-000000000001").unwrap_err();
        assert!(e.to_string().contains("candidate disks seen"));
    }
}

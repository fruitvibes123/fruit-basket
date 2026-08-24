//! The boot-time weights-verity-setup (hotswap v4 spec §3, plan Task 4): read the persisted signed
//! weights record → quince-verify it CLOCK-FREE → resolve the weights partition by its fixed GPT
//! PARTUUID → set up runtime dm-verity (EIO mode) → mount the model volume RO at `/models`.
//!
//! Invoked as `/usr/bin/fb-weights setup || exit 1` from the ENGINE leaf's s6 `run` script (rendered
//! by the image-builder), AFTER the cgroup placement and BEFORE the uid-drop `exec` — so it runs as
         
//! ROOT (the tenant uid never holds the DM/mount capability) and every failure exits non-zero,
//! which fails the run and lets the engine's s6 restart-cap `down` ONLY that service (NEVER a
         
//! box-init Rescue/Reboot — the structural half).
//!
//! **Rider 1 (the clock-at-boot decision, spec §6):** this boot-time read may run before ntpd
//! convergence (the engine must be able to start without waiting on time sync), so it uses the
//! **clock-free** `quince::verify_artifact` — signature + `Purpose::Weights` + the `min_ctr ≥
//! floor` anti-rollback all ENFORCED; only the delegation expiry window is skipped, which a
//! no-clock box cannot evaluate. The window IS enforced at swap time (`verify_artifact_clocked`,
//! post-ntpd — Task 5), the locus where fresh operator intent arrives. No ntpd-before-engine
//! ordering is introduced.
//!
//! The orchestration is host-tested over the [`SetupOps`] seam (the installer's `InstallOps`
//! pattern); the real FFI ([`SyscallSetupOps`]) is exercised by the produced-bytes boot gate.

use crate::stores::{parse_weights_manifest, read_record_strict};
use sha2::{Digest, Sha256};
use std::io;
use std::path::{Path, PathBuf};

/// The weights DATA partition's fixed GPT unique GUID — the bake writes the 5th GPT entry with this
/// PARTUUID (one fixed layout constant, like the A/B slot PARTUUIDs). Mirrors
/// `initramfs-init::installer::WEIGHTS_PARTUUID` byte-for-byte (the two crates share no lib edge;
/// the produced-bytes boot gate proves the pair end-to-end — a drift = the helper cannot resolve
        
/// the partition = the gate's leg goes red).
pub const WEIGHTS_PARTUUID: &str = "7d3b9f24-6a1c-4e58-b0d9-2c4f8a6e1b35";

/// The dm device name for the RUNTIME-verity model volume (distinct from the boot-anchored
/// `dha-weights` name so the shapes are never confusable in `/dev/mapper` listings).
pub const DM_NAME: &str = "fbw-model";

/// Where the verified model volume mounts (baked as an empty dir on the RO rootfs).
pub const MODELS_MOUNT: &str = "/models";

/// The baked operator artifact-root pubkey on the verity rootfs (the same trust anchor fb-update's
/// apply reads — one operator root for every box-side verify).
pub const ARTIFACT_ROOT_PUB: &str = "/etc/recipes/artifact-root.pub";

/// The FFI seam for [`run_setup`] — host tests drive a fake; the box runs [`SyscallSetupOps`].
pub trait SetupOps {
    /// Is `target` ALREADY a mountpoint? The swap sequencer sets up the verity device + mounts
    /// `/models` with the new root ITSELF (so it can real-inference health-check the new model
    /// BEFORE committing the record, spec §5 step 6→7), then restarts the engine — whose run
    /// script re-invokes this helper. A fresh boot never pre-mounts `/models`; only a mid-swap
    /// restart (or an engine-crash restart within one boot) does, both root-owned trusted states.
    fn already_mounted(&mut self, target: &Path) -> io::Result<bool>;
    /// Best-effort remove a STALE `fbw-model` dm device left mapped by a prior failed setup (a
    /// torn-weights boot: the first attempt creates the device then EIOs at the mount, leaving it
    /// mapped; audit R1 L-2). Tolerates "already absent" so a clean boot (no device) is a no-op.
    fn remove_stale_device(&mut self, name: &str) -> io::Result<()>;
    /// Resolve the weights partition's `/dev` node by GPT PARTUUID.
    fn resolve_partuuid(&mut self, partuuid: &str) -> io::Result<String>;
    /// Set up the runtime dm-verity device (EIO corruption mode) and return the mapper node.
    fn setup_verity(
        &mut self,
        name: &str,
        dev: &str,
        root_hash: &str,
        verity_offset: u64,
    ) -> io::Result<PathBuf>;
    /// Mount the verity node RO (squashfs) at `target`.
    fn mount_ro_squashfs(&mut self, node: &Path, target: &Path) -> io::Result<()>;
}

/// The verified boot-time setup sequence. Fail-closed: the FIRST error propagates (→ the bin's
/// non-zero exit → the s6 run dies → engine-scoped down). Order is trust-first: nothing from the
/// record is ACTED on (no device touch, no parse-driven branching) before the quince verify
/// succeeds over the raw bytes.
pub fn run_setup(
    ops: &mut dyn SetupOps,
    weights_dir: &Path,
    root_pubkey: &[u8; 32],
) -> io::Result<()> {
                                                                                                  
                                                                                                    
                                                                                                  
                                                                                                  
                                                                                                 
                                                                                                   
    if ops.already_mounted(Path::new(MODELS_MOUNT))? {
        return Ok(());
    }

                                                                   
    let record = read_record_strict(weights_dir)?;

                                                                                                
                                                                    
    let artifact_hash: [u8; 32] = Sha256::digest(&record.manifest_bytes).into();
    quince::verify_artifact(
        root_pubkey,
        &record.sig,
        &artifact_hash,
        quince::Purpose::Weights,
        record.floor_ctr,
    )
    .map_err(|e| io::Error::other(format!("weights manifest verify failed: {e:?}")))?;

                                              
    let manifest = parse_weights_manifest(&record.manifest_bytes)?;

                                                                                                
                                                                                                  
                                                                                                    
                                                                                                 
                                                                                      
    ops.remove_stale_device(DM_NAME)?;

                                                                                                  
                                        
    let dev = ops.resolve_partuuid(WEIGHTS_PARTUUID)?;
    let node = ops.setup_verity(DM_NAME, &dev, &manifest.root_hash, manifest.verity_offset)?;
    ops.mount_ro_squashfs(&node, Path::new(MODELS_MOUNT))?;
    Ok(())
}

/// The real, side-effecting ops (root; boot-gate-proven). Verity runs in EIO mode — a corrupt
/// weights block surfaces as a typed read error to the engine, never a box reboot (H-R4-1).
pub struct SyscallSetupOps;

impl SetupOps for SyscallSetupOps {
    fn already_mounted(&mut self, target: &Path) -> io::Result<bool> {
        is_mount_point(target)
    }

    fn remove_stale_device(&mut self, name: &str) -> io::Result<()> {
                                                                                                 
                                                                                                   
                                                             
        match fb_verity_rt::dev_remove(name) {
            Ok(()) => Ok(()),
            Err(e) if matches!(e.raw_os_error(), Some(libc::ENXIO) | Some(libc::ENODEV)) => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn resolve_partuuid(&mut self, partuuid: &str) -> io::Result<String> {
        fb_verity_rt::resolve_partuuid(partuuid)
    }

    fn setup_verity(
        &mut self,
        name: &str,
        dev: &str,
        root_hash: &str,
        verity_offset: u64,
    ) -> io::Result<PathBuf> {
        fb_verity_rt::setup_verity_device(
            name,
            dev,
            root_hash,
            verity_offset,
            fb_verity_rt::CorruptionMode::Default,
        )
    }

    fn mount_ro_squashfs(&mut self, node: &Path, target: &Path) -> io::Result<()> {
                                                                                                    
                                                                                               
                                       
        fb_verity_rt::mount_squashfs_ro(node, target)
    }
}

/// Is `target` the second field of any `/proc/mounts` line — i.e. a live mountpoint? Parses the
/// fstab-style table (the mount target is column 2, octal-escaped); an exact match on the decoded
/// path. Fail-closed to "not mounted" only when `/proc/mounts` is unreadable is WRONG (it would
/// re-drive the create+mount into an EEXIST wedge), so an unreadable `/proc/mounts` propagates as
/// an error — the boot path has `/proc` mounted (box-init mounts it before any service starts).
pub fn is_mount_point(target: &Path) -> io::Result<bool> {
    let mounts = std::fs::read_to_string("/proc/mounts")
        .map_err(|e| io::Error::other(format!("read /proc/mounts: {e}")))?;
    Ok(mounts_table_has_target(&mounts, &target.to_string_lossy()))
}

/// The pure half of [`is_mount_point`]: does the fstab-style `/proc/mounts` text carry `want` as a
/// mount target (column 2, octal-unescaped)? Exact match (so `/models` never matches `/models2`).
fn mounts_table_has_target(mounts: &str, want: &str) -> bool {
    mounts.lines().any(|line| {
        line.split_whitespace()
            .nth(1)
            .is_some_and(|m| unescape_mount_field(m) == want)
    })
}

/// Decode the octal escapes `/proc/mounts` uses for spaces/tabs/newlines/backslashes in a field
/// (`\040` space, `\011` tab, `\012` newline, `\134` backslash). `/models` has none, but decoding
/// keeps the exact-match honest against a pathological mount target.
fn unescape_mount_field(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    let mut bytes = field.bytes();
    while let Some(b) = bytes.next() {
        if b == b'\\' {
            let o: Vec<u8> = bytes.by_ref().take(3).collect();
            if o.len() == 3
                && let Ok(s) = std::str::from_utf8(&o)
                && let Ok(code) = u8::from_str_radix(s, 8)
            {
                out.push(code as char);
                continue;
            }
            out.push('\\');
            out.push_str(&String::from_utf8_lossy(&o));
        } else {
            out.push(b as char);
        }
    }
    out
}

/// Read + decode the 64-hex baked operator root pubkey (mirrors `fb-update`'s reader — hand-rolled
/// hex, no extra dep on the box binary).
pub fn read_root_pubkey(path: &Path) -> io::Result<[u8; 32]> {
    let s = std::fs::read_to_string(path)
        .map_err(|e| io::Error::other(format!("root pubkey {}: {e}", path.display())))?;
    let hexs = s.trim();
    if hexs.len() != 64 {
        return Err(io::Error::other("root pubkey is not 64 hex chars"));
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let hi = hex_val(hexs.as_bytes()[2 * i])?;
        let lo = hex_val(hexs.as_bytes()[2 * i + 1])?;
        *byte = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_val(b: u8) -> io::Result<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(io::Error::other("root pubkey is not lowercase hex")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stores::{
        WeightsManifest, WeightsRecord, render_weights_manifest, write_record_atomic,
    };
    use dragonfruit::{Attestation, BundleFile, Delegation, sign_attestation, sign_delegation};
    use ed25519_dalek::SigningKey;

    /// Mint a REAL operator-signed Weights bundle over `manifest_bytes` with delegation ctr `ctr`
    /// (dev-only signer — the quince fixture pattern). Returns (root_pubkey, sig).
    fn signed_weights(
        manifest_bytes: &[u8],
        purpose: quince::Purpose,
        ctr: u64,
    ) -> ([u8; 32], [u8; 254]) {
        let root = SigningKey::from_bytes(&[1u8; 32]);
        let worker = SigningKey::from_bytes(&[2u8; 32]);
        let deleg = Delegation {
            worker_pubkey: worker.verifying_key().to_bytes(),
            purpose,
            not_before: 0,
            not_after: 100,                                                                          
            monotonic_ctr: ctr,
        };
        let root_sig = sign_delegation(&root, &deleg);
        let deleg_bytes = deleg.to_canonical();
        let delegation_id: [u8; 32] = Sha256::digest(deleg_bytes).into();
        let artifact_hash: [u8; 32] = Sha256::digest(manifest_bytes).into();
        let att = Attestation {
            artifact_hash,
            purpose,
            delegation_id,
        };
        let worker_sig = sign_attestation(&worker, &att);
        let bf = BundleFile {
            delegation_bytes: deleg_bytes,
            root_sig,
            attestation_bytes: att.to_canonical(),
            worker_sig,
        };
        (root.verifying_key().to_bytes(), bf.to_bytes())
    }

    fn manifest_bytes() -> Vec<u8> {
        render_weights_manifest(&WeightsManifest {
            root_hash: "ab".repeat(32),
            verity_offset: 8_388_608,
            image_sha256: [0xCD; 32],
            image_size: 8_650_752,
        })
    }

    /// Records every ops call; hands back scripted values.
    #[derive(Default)]
    struct FakeOps {
        calls: Vec<String>,
        /// Scripted `already_mounted` return (the swap-restart idempotency path).
        mounted: bool,
    }
    impl SetupOps for FakeOps {
        fn already_mounted(&mut self, target: &Path) -> io::Result<bool> {
            self.calls
                .push(format!("already_mounted:{}", target.display()));
            Ok(self.mounted)
        }
        fn remove_stale_device(&mut self, name: &str) -> io::Result<()> {
            self.calls.push(format!("remove_stale:{name}"));
            Ok(())
        }
        fn resolve_partuuid(&mut self, partuuid: &str) -> io::Result<String> {
            self.calls.push(format!("resolve:{partuuid}"));
            Ok("/dev/vda5".to_string())
        }
        fn setup_verity(
            &mut self,
            name: &str,
            dev: &str,
            root_hash: &str,
            verity_offset: u64,
        ) -> io::Result<PathBuf> {
            self.calls
                .push(format!("verity:{name}:{dev}:{root_hash}:{verity_offset}"));
            Ok(PathBuf::from(format!("/dev/{name}")))
        }
        fn mount_ro_squashfs(&mut self, node: &Path, target: &Path) -> io::Result<()> {
            self.calls
                .push(format!("mount:{}:{}", node.display(), target.display()));
            Ok(())
        }
    }

    fn write_record(dir: &Path, ctr: u64, floor: u64, purpose: quince::Purpose) -> [u8; 32] {
        let mb = manifest_bytes();
        let (root_pub, sig) = signed_weights(&mb, purpose, ctr);
        write_record_atomic(
            dir,
            &WeightsRecord {
                floor_ctr: floor,
                manifest_bytes: mb,
                sig,
            },
        )
        .expect("write record");
        root_pub
    }

    #[test]
    fn happy_path_verifies_then_resolves_verity_mounts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_pub = write_record(dir.path(), 5, 5, quince::Purpose::Weights);
        let mut ops = FakeOps::default();                                         
        run_setup(&mut ops, dir.path(), &root_pub).expect("setup succeeds");
        assert_eq!(
            ops.calls,
            vec![
                format!("already_mounted:{MODELS_MOUNT}"),
                format!("remove_stale:{DM_NAME}"),
                format!("resolve:{WEIGHTS_PARTUUID}"),
                format!("verity:{DM_NAME}:/dev/vda5:{}:8388608", "ab".repeat(32)),
                format!("mount:/dev/{DM_NAME}:{MODELS_MOUNT}"),
            ]
        );
    }

    #[test]
    fn mounts_table_target_match_is_exact_and_unescaped() {
        let table = "\
proc /proc proc rw,nosuid 0 0
/dev/mapper/fbw-model /models squashfs ro,nodev,nosuid,noexec 0 0
/dev/vda4 /persist ext4 rw 0 0
";
        assert!(mounts_table_has_target(table, "/models"));
        assert!(mounts_table_has_target(table, "/persist"));
                                                    
        assert!(!mounts_table_has_target(table, "/model"));
        assert!(!mounts_table_has_target(table, "/models2"));
        assert!(!mounts_table_has_target("", "/models"));
                                                                                            
        assert!(mounts_table_has_target(
            "/dev/x /mnt/a\\040b ext4 rw 0 0\n",
            "/mnt/a b"
        ));
    }

    #[test]
    fn already_mounted_is_a_noop_success() {
                                                                                                    
                                                                                                
                                                                                                
                                                                      
        let dir = tempfile::tempdir().expect("tempdir");
                                                                                                    
                                                                                     
        let root_pub = write_record(dir.path(), 4, 5, quince::Purpose::Weights);
        let mut ops = FakeOps {
            mounted: true,
            ..FakeOps::default()
        };
        run_setup(&mut ops, dir.path(), &root_pub).expect("already-mounted setup is a no-op Ok");
        assert_eq!(
            ops.calls,
            vec![format!("already_mounted:{MODELS_MOUNT}")],
            "no resolve/verity/mount when already mounted"
        );
    }

    #[test]
    fn expired_window_is_accepted_at_boot_clock_free() {
                                                                                                  
                                                                                     
        let dir = tempfile::tempdir().expect("tempdir");
        let root_pub = write_record(dir.path(), 5, 5, quince::Purpose::Weights);
        assert!(run_setup(&mut FakeOps::default(), dir.path(), &root_pub).is_ok());
    }

    #[test]
    fn below_floor_record_refuses_before_any_device_op() {
                                                                                                  
                                                                                
        let dir = tempfile::tempdir().expect("tempdir");
        let root_pub = write_record(dir.path(), 4, 5, quince::Purpose::Weights);
        let mut ops = FakeOps::default();
        let e = run_setup(&mut ops, dir.path(), &root_pub).unwrap_err();
        assert!(e.to_string().contains("verify failed"), "{e}");
        assert_eq!(
            ops.calls,
            vec![format!("already_mounted:{MODELS_MOUNT}")],
            "only the mount probe ran; no device op before trust: {:?}",
            ops.calls
        );
    }

    #[test]
    fn wrong_purpose_bundle_is_rejected() {
                                                                                                
        let dir = tempfile::tempdir().expect("tempdir");
        let root_pub = write_record(dir.path(), 5, 5, quince::Purpose::UpdateImage);
        let mut ops = FakeOps::default();
        assert!(run_setup(&mut ops, dir.path(), &root_pub).is_err());
        assert_eq!(ops.calls, vec![format!("already_mounted:{MODELS_MOUNT}")]);
    }

    #[test]
    fn tampered_manifest_bytes_are_rejected() {
                                                                                                    
        let dir = tempfile::tempdir().expect("tempdir");
        let mb = manifest_bytes();
        let (root_pub, sig) = signed_weights(&mb, quince::Purpose::Weights, 5);
        let mut tampered = mb.clone();
        tampered[10] ^= 0x01;
        write_record_atomic(
            dir.path(),
            &WeightsRecord {
                floor_ctr: 5,
                manifest_bytes: tampered,
                sig,
            },
        )
        .expect("write");
        let mut ops = FakeOps::default();
        assert!(run_setup(&mut ops, dir.path(), &root_pub).is_err());
        assert_eq!(ops.calls, vec![format!("already_mounted:{MODELS_MOUNT}")]);
    }

    #[test]
    fn wrong_root_key_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _real = write_record(dir.path(), 5, 5, quince::Purpose::Weights);
        let wrong = SigningKey::from_bytes(&[9u8; 32])
            .verifying_key()
            .to_bytes();
        let mut ops = FakeOps::default();
        assert!(run_setup(&mut ops, dir.path(), &wrong).is_err());
        assert_eq!(ops.calls, vec![format!("already_mounted:{MODELS_MOUNT}")]);
    }

    #[test]
    fn absent_record_fails_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut ops = FakeOps::default();
        assert!(run_setup(&mut ops, dir.path(), &[0u8; 32]).is_err());
        assert_eq!(ops.calls, vec![format!("already_mounted:{MODELS_MOUNT}")]);
    }

    #[test]
    fn root_pubkey_reader_round_trips_and_rejects_malformed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("artifact-root.pub");
        std::fs::write(&p, format!("{}\n", "0f".repeat(32))).expect("write");
        assert_eq!(read_root_pubkey(&p).expect("decode"), [0x0F; 32]);
        for bad in ["", "zz", &"a".repeat(63), &"A".repeat(64)] {
            std::fs::write(&p, bad).expect("write");
            assert!(read_root_pubkey(&p).is_err(), "{bad:?} must reject");
        }
    }
}

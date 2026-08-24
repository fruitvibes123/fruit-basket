//! T14: the normative apply ordering + the refuse-before-promote invariant, driven by
//! a FakeSelector over an in-memory stream (the real SeabiosGptSelector's block-device
//! writes are proven on produced bytes in T22). Every refusal class leaves the PROMOTION
//! POINT (the ADV arm) uncalled — the box keeps booting the old slot.

use std::cell::RefCell;
use std::io::Read;
use std::sync::atomic::{AtomicU64, Ordering};

use fb_update::apply::{ApplyCtx, ApplyError, apply};
use fb_update::manifest::UpdateManifest;
use fb_update::selector::{ComponentSpec, SelErr, SlotDesc, SlotSelector};
use fb_update::{Record, Slot};
use sha2::{Digest, Sha256};

                                                                                 

use dragonfruit::{
    Attestation, BundleFile, Delegation, Purpose, sign_attestation, sign_delegation,
};
use ed25519_dalek::SigningKey;

/// Mint a valid UpdateImage bundle over `manifest_bytes` at `ctr`, window bracketing
/// the clocked-verify plausibility floor. Returns (root_pub, 254-byte bundle).
fn sign_manifest(manifest_bytes: &[u8], ctr: u64) -> ([u8; 32], Vec<u8>) {
    let root = SigningKey::from_bytes(&[7u8; 32]);
    let worker = SigningKey::from_bytes(&[9u8; 32]);
    let floor = fb_update::MIN_PLAUSIBLE_CLOCK;
    let deleg = Delegation {
        worker_pubkey: worker.verifying_key().to_bytes(),
        purpose: Purpose::UpdateImage,
        not_before: floor,
        not_after: floor + 1_000_000,
        monotonic_ctr: ctr,
    };
    let root_sig = sign_delegation(&root, &deleg);
    let deleg_bytes = deleg.to_canonical();
    let delegation_id: [u8; 32] = Sha256::digest(deleg_bytes).into();
    let artifact_hash: [u8; 32] = Sha256::digest(manifest_bytes).into();
    let att = Attestation {
        artifact_hash,
        purpose: Purpose::UpdateImage,
        delegation_id,
    };
    let worker_sig = sign_attestation(&worker, &att);
    let bf = BundleFile {
        delegation_bytes: deleg_bytes,
        root_sig,
        attestation_bytes: att.to_canonical(),
        worker_sig,
    };
    (root.verifying_key().to_bytes(), bf.to_bytes().to_vec())
}

                     

const NOW: u64 = fb_update::MIN_PLAUSIBLE_CLOCK + 500;

fn component(byte: u8, len: usize) -> Vec<u8> {
    vec![byte; len]
}

/// Build a canonical manifest string over three components (rootfs/kernel/initramfs).
fn manifest_string(version: u64, rootfs: &[u8], kernel: &[u8], initramfs: &[u8]) -> String {
    let hx = |b: &[u8]| hex::encode(Sha256::digest(b));
    format!(
        "format = 1\n\
         firmware = seabios-gpt\n\
         version = {version}\n\
         image_sha256 = {img}\n\
         root_hash = {root}\n\
         verity_hash_offset = 34603008\n\
         rootfs_sha256 = {rfs}\n\
         rootfs_size = {rlen}\n\
         kernel_sha256 = {ks}\n\
         kernel_size = {klen}\n\
         initramfs_sha256 = {is}\n\
         initramfs_size = {ilen}\n",
        img = "ab".repeat(32),
        root = "0123456789abcdef".repeat(4),
        rfs = hx(rootfs),
        rlen = rootfs.len(),
        ks = hx(kernel),
        klen = kernel.len(),
        is = hx(initramfs),
        ilen = initramfs.len(),
    )
}

/// Assemble the §4c apply stream: u64-le manifest_len ‖ manifest ‖ u64-le bundle_len ‖
/// bundle ‖ rootfs ‖ kernel ‖ initramfs.
fn stream(
    manifest: &[u8],
    bundle: &[u8],
    rootfs: &[u8],
    kernel: &[u8],
    initramfs: &[u8],
) -> Vec<u8> {
    let mut s = Vec::new();
    s.extend_from_slice(&(manifest.len() as u64).to_le_bytes());
    s.extend_from_slice(manifest);
    s.extend_from_slice(&(bundle.len() as u64).to_le_bytes());
    s.extend_from_slice(bundle);
    s.extend_from_slice(rootfs);
    s.extend_from_slice(kernel);
    s.extend_from_slice(initramfs);
    s
}

/// A recorded selector call.
#[derive(Debug, PartialEq, Eq)]
enum Call {
    ActiveSlot,
    StageRootfs(Slot),
    StageBoot(Slot),
    ArmOnce(Slot),
}

struct FakeSelector {
    active: Slot,
    calls: RefCell<Vec<Call>>,
    /// Bytes actually drained per component (proves chunked draining consumed them).
    rootfs_hash: RefCell<Option<[u8; 32]>>,
}

impl FakeSelector {
    fn new(active: Slot) -> Self {
        FakeSelector {
            active,
            calls: RefCell::new(Vec::new()),
            rootfs_hash: RefCell::new(None),
        }
    }
    fn armed(&self) -> bool {
        self.calls
            .borrow()
            .iter()
            .any(|c| matches!(c, Call::ArmOnce(_)))
    }
    /// Drain the reader to EOF (for a `take`-bounded rootfs reader).
    fn drain(src: &mut dyn Read) -> (u64, [u8; 32]) {
        Self::drain_n(src, u64::MAX)
    }
    /// Read up to `limit` bytes (chunked), hashing; stop at EOF or the limit.
    fn drain_n(src: &mut dyn Read, limit: u64) -> (u64, [u8; 32]) {
        let mut hasher = Sha256::new();
        let mut n = 0u64;
        let mut buf = [0u8; 4096];
        while n < limit {
            let want = (limit - n).min(buf.len() as u64) as usize;
            let r = src.read(&mut buf[..want]).unwrap();
            if r == 0 {
                break;
            }
            hasher.update(&buf[..r]);
            n += r as u64;
        }
        (n, hasher.finalize().into())
    }
}

impl SlotSelector for FakeSelector {
    fn active_slot(&self) -> Result<Slot, SelErr> {
        self.calls.borrow_mut().push(Call::ActiveSlot);
        Ok(self.active)
    }
    fn stage_rootfs(
        &self,
        target: Slot,
        spec: &ComponentSpec,
        src: &mut dyn Read,
    ) -> Result<(), SelErr> {
        self.calls.borrow_mut().push(Call::StageRootfs(target));
        let (n, sha) = Self::drain(src);
        if n != spec.len {
            return Err(SelErr::ComponentTooShort { which: "rootfs" });
        }
        if sha != spec.sha256 {
            return Err(SelErr::HashMismatch { which: "rootfs" });
        }
        *self.rootfs_hash.borrow_mut() = Some(sha);
        Ok(())
    }
    fn stage_boot(
        &self,
        target: Slot,
        _desc: &SlotDesc,
        kernel: &ComponentSpec,
        initramfs: &ComponentSpec,
        src: &mut dyn Read,
    ) -> Result<(), SelErr> {
        self.calls.borrow_mut().push(Call::StageBoot(target));
                                                                                        
                                                                                           
        let (kn, ksha) = Self::drain_n(src, kernel.len);
        if kn != kernel.len || ksha != kernel.sha256 {
            return Err(SelErr::HashMismatch { which: "kernel" });
        }
        let (in_, isha) = Self::drain_n(src, initramfs.len);
        if in_ != initramfs.len || isha != initramfs.sha256 {
            return Err(SelErr::HashMismatch { which: "initramfs" });
        }
        Ok(())
    }
    fn arm_once(&self, target: Slot) -> Result<(), SelErr> {
        self.calls.borrow_mut().push(Call::ArmOnce(target));
        Ok(())
    }
    fn commit_default(&self, _t: Slot) -> Result<(), SelErr> {
        Ok(())
    }
    fn reclear(&self) -> Result<bool, SelErr> {
        Ok(false)
    }
}

/// A ctx with floors written to a temp dir; returns (ctx-inputs). The record path is a
/// non-existent file (no probation in flight) unless the caller creates it.
struct Fixture {
    _dir: tempfile::TempDir,
    root_pubkey: [u8; 32],
    floors_dir: std::path::PathBuf,
    update_dir: std::path::PathBuf,
}

impl Fixture {
    fn new(version_floor: u64, minctr_floor: u64, root_pubkey: [u8; 32]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let floors = dir.path().join("floors");
        let update = dir.path().join("update");
        std::fs::create_dir_all(&floors).unwrap();
        std::fs::create_dir_all(&update).unwrap();
        std::fs::write(floors.join("version-floor"), format!("{version_floor}\n")).unwrap();
        std::fs::write(floors.join("minctr-floor"), format!("{minctr_floor}\n")).unwrap();
        Fixture {
            _dir: dir,
            root_pubkey,
            floors_dir: floors,
            update_dir: update,
        }
    }
    fn ctx(&self) -> ApplyCtx<'_> {
        ApplyCtx {
            root_pubkey: &self.root_pubkey,
            now_unix: NOW,
            box_firmware: "seabios-gpt",
            floors_dir: &self.floors_dir,
            update_dir: &self.update_dir,
        }
    }
}

                           

#[test]
fn apply_ordering_happy() {
    let rootfs = component(0x11, 5 * 1024 * 1024);                                 
    let kernel = component(0x22, 1024);
    let initramfs = component(0x33, 2048);
    let m = manifest_string(9, &rootfs, &kernel, &initramfs);
    let (root, bundle) = sign_manifest(m.as_bytes(), 5_000);
    let s = stream(m.as_bytes(), &bundle, &rootfs, &kernel, &initramfs);

    let fx = Fixture::new(8, 4_000, root);
    let sel = FakeSelector::new(Slot::A);
    let target = apply(&mut s.as_slice(), &sel, &fx.ctx()).expect("happy apply");
    assert_eq!(target, Slot::B, "inactive slot is the target");

                                                                                                 
    assert_eq!(
        *sel.calls.borrow(),
        vec![
            Call::ActiveSlot,
            Call::StageRootfs(Slot::B),
            Call::StageBoot(Slot::B),
            Call::ArmOnce(Slot::B),
        ]
    );
                                                                                    
    assert!(sel.rootfs_hash.borrow().is_some());

                                                                                       
                                          
    let rec = Record::parse(&std::fs::read(fx.update_dir.join("record")).unwrap()).unwrap();
    assert_eq!(rec.slot, Slot::B);
    assert_eq!(rec.version, 9);
    assert_eq!(rec.bundle_ctr, 5_000);
    assert_eq!(rec.root_hash, "0123456789abcdef".repeat(4));
}

                                                   

/// Run apply expecting a refusal; assert it never armed + never wrote a record.
fn expect_refusal(fx: &Fixture, sel: &FakeSelector, s: &[u8]) -> ApplyError {
    let err = apply(&mut { s }, sel, &fx.ctx()).expect_err("must refuse");
    assert!(!sel.armed(), "a refusal must NOT reach the promotion point");
    assert!(
        !fx.update_dir.join("record").exists(),
        "a refusal must NOT write a probation record"
    );
    err
}

fn good_parts() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    (
        component(0x11, 4096),
        component(0x22, 1024),
        component(0x33, 2048),
    )
}

#[test]
fn refuses_bad_signature() {
    let (r, k, i) = good_parts();
    let m = manifest_string(9, &r, &k, &i);
    let (root, mut bundle) = sign_manifest(m.as_bytes(), 5_000);
    bundle[60] ^= 0xFF;                        
    let s = stream(m.as_bytes(), &bundle, &r, &k, &i);
    let fx = Fixture::new(8, 4_000, root);
    let sel = FakeSelector::new(Slot::A);
    assert!(matches!(
        expect_refusal(&fx, &sel, &s),
        ApplyError::Verify(_)
    ));
                                                                                    
    assert!(
        sel.calls.borrow().is_empty(),
        "no component work on a bad sig"
    );
}

#[test]
fn refuses_version_at_or_below_floor() {
    let (r, k, i) = good_parts();
    let m = manifest_string(8, &r, &k, &i);            
    let (root, bundle) = sign_manifest(m.as_bytes(), 5_000);
    let s = stream(m.as_bytes(), &bundle, &r, &k, &i);
    let fx = Fixture::new(8, 4_000, root);
    let sel = FakeSelector::new(Slot::A);
    assert!(matches!(
        expect_refusal(&fx, &sel, &s),
        ApplyError::VersionNotAboveFloor {
            version: 8,
            floor: 8
        }
    ));
}

#[test]
fn refuses_ctr_below_minctr_floor() {
    let (r, k, i) = good_parts();
    let m = manifest_string(9, &r, &k, &i);
    let (root, bundle) = sign_manifest(m.as_bytes(), 3_999);                
    let s = stream(m.as_bytes(), &bundle, &r, &k, &i);
    let fx = Fixture::new(8, 4_000, root);
    let sel = FakeSelector::new(Slot::A);
    assert!(matches!(
        expect_refusal(&fx, &sel, &s),
        ApplyError::Verify(_)
    ));
}

#[test]
fn refuses_absent_floor_never_reads_as_zero() {
    let (r, k, i) = good_parts();
    let m = manifest_string(9, &r, &k, &i);
    let (root, bundle) = sign_manifest(m.as_bytes(), 5_000);
    let s = stream(m.as_bytes(), &bundle, &r, &k, &i);
    let fx = Fixture::new(8, 4_000, root);
    std::fs::remove_file(fx.floors_dir.join("version-floor")).unwrap();
    let sel = FakeSelector::new(Slot::A);
    assert!(matches!(
        expect_refusal(&fx, &sel, &s),
        ApplyError::FloorUnavailable(_)
    ));
}

#[test]
fn refuses_wrong_firmware() {
    let (r, k, i) = good_parts();
    let m = manifest_string(9, &r, &k, &i).replace("seabios-gpt", "uefi");
    let (root, bundle) = sign_manifest(m.as_bytes(), 5_000);
    let s = stream(m.as_bytes(), &bundle, &r, &k, &i);
    let fx = Fixture::new(8, 4_000, root);
    let sel = FakeSelector::new(Slot::A);
    assert!(matches!(
        expect_refusal(&fx, &sel, &s),
        ApplyError::FirmwareMismatch
    ));
}

#[test]
fn refuses_oversize_rootfs() {
    let (_r, k, i) = good_parts();
                                                                                        
                                                               
    let big = fb_update::SLOT_SIZE_BYTES + 1;
    let m =
        manifest_string(9, &[], &k, &i).replace("rootfs_size = 0", &format!("rootfs_size = {big}"));
    let (root, bundle) = sign_manifest(m.as_bytes(), 5_000);
    let s = stream(m.as_bytes(), &bundle, &[], &k, &i);
    let fx = Fixture::new(8, 4_000, root);
    let sel = FakeSelector::new(Slot::A);
    assert!(matches!(
        expect_refusal(&fx, &sel, &s),
        ApplyError::SizeExceeded { .. }
    ));
}

#[test]
fn refuses_probation_in_flight() {
    let (r, k, i) = good_parts();
    let m = manifest_string(9, &r, &k, &i);
    let (root, bundle) = sign_manifest(m.as_bytes(), 5_000);
    let s = stream(m.as_bytes(), &bundle, &r, &k, &i);
    let fx = Fixture::new(8, 4_000, root);
                                                              
    let existing = Record {
        format: 1,
        slot: Slot::B,
        version: 9,
        bundle_ctr: 5_000,
        root_hash: "0123456789abcdef".repeat(4),
        deadline_secs: 300,
    };
    std::fs::write(fx.update_dir.join("record"), existing.to_bytes()).unwrap();
    let sel = FakeSelector::new(Slot::A);
    let err = apply(&mut s.as_slice(), &sel, &fx.ctx()).expect_err("must refuse");
    assert!(matches!(err, ApplyError::ProbationInFlight));
    assert!(!sel.armed());
}

#[test]
fn refuses_trailing_bytes() {
    let (r, k, i) = good_parts();
    let m = manifest_string(9, &r, &k, &i);
    let (root, bundle) = sign_manifest(m.as_bytes(), 5_000);
    let mut s = stream(m.as_bytes(), &bundle, &r, &k, &i);
    s.push(0xEE);                                     
    let fx = Fixture::new(8, 4_000, root);
    let sel = FakeSelector::new(Slot::A);
                                                                           
    let err = apply(&mut s.as_slice(), &sel, &fx.ctx()).expect_err("trailing refuse");
    assert!(matches!(err, ApplyError::BadStream(_)));
    assert!(!sel.armed(), "trailing bytes refuse before promotion");
    assert!(!fx.update_dir.join("record").exists());
}

#[test]
fn refuses_manifest_len_over_bound() {
    let mut s = Vec::new();
    s.extend_from_slice(&(fb_update::MANIFEST_MAX_LEN + 1).to_le_bytes());
    let fx = Fixture::new(8, 4_000, [0u8; 32]);
    let sel = FakeSelector::new(Slot::A);
    assert!(matches!(
        apply(&mut s.as_slice(), &sel, &fx.ctx()).unwrap_err(),
        ApplyError::BadStream(_)
    ));
    assert!(sel.calls.borrow().is_empty());
}

#[test]
fn refuses_short_rootfs_stream() {
    let (r, k, i) = good_parts();
    let m = manifest_string(9, &r, &k, &i);
    let (root, bundle) = sign_manifest(m.as_bytes(), 5_000);
                                                                             
    let mut s = stream(m.as_bytes(), &bundle, &r, &k, &i);
    s.truncate(s.len() - k.len() - i.len() - 100);
    let fx = Fixture::new(8, 4_000, root);
    let sel = FakeSelector::new(Slot::A);
    let err = apply(&mut s.as_slice(), &sel, &fx.ctx()).expect_err("short stream");
    assert!(matches!(
        err,
        ApplyError::Selector(_) | ApplyError::BadStream(_)
    ));
    assert!(!sel.armed());
}

                                                                                       
#[allow(dead_code)]
fn _types(_: UpdateManifest, _: AtomicU64) {
    let _ = Ordering::SeqCst;
}

//! The model-swap sequencer (hotswap v4 spec §5, plan Task 5): the flocked, fail-closed,
//! s6-scoped live model swap — restart, not reboot.
//!
//! Driven by `orchard deploy-model` over ssh as `fb-weights swap` with the framed push on stdin
//! (the `fb-update apply` §4c transport shape): `u64 manifest_len ‖ manifest ‖ u64 sig_len(=254) ‖
//! sig ‖ u64 image_len ‖ image bytes` — the image is STREAMED to the raw partition, never buffered
//! whole (the streaming-installer lesson).
//!
//! Failure taxonomy (spec §7, honest):
//! - [`SwapError::Refused`] — preflight (bad sig / wrong key / below-floor / expired window / bad
//!   clock / doesn't-fit / frame-vs-manifest mismatch): NOTHING on disk changed, the old model
//!   still serves. Also the stop/teardown window (pre-first-partition-byte): disk untouched, and
//!   the sequencer best-effort re-mounts + restarts the OLD stack before reporting.
//! - [`SwapError::Degraded`] — the old bytes are already overwritten (exact-fit, one partition):
//!   the box stays UP, only the engine is down + VISIBLE; the operator re-pushes. The record/floor
//!   are NOT advanced (commit is the LAST step, after the health check).
//!
//! The commit — `write_record_atomic` {new manifest, floor = the newly-verified ctr} — happens
//! ONLY after a REAL inference health check passes. A crash anywhere before it leaves the OLD
//! record current (next boot verifies old-or-new coherently, never a torn trust pointer).
//!
                
//! **Crash-safety (closed by debt-burndown Component B).** The [`run_swap`]
//! sequence handles every RETURNED `Err` from an `ops` call (Refused / abort_pre_write / Degraded).
//! A hard PROCESS death mid-step — SIGKILL / OOM / power loss, or the SIGHUP an ssh channel delivers
//! when `orchard deploy-model`'s connection drops (a network blip, laptop sleep, Ctrl-C) — skips
//! that Rust-level recovery and leaves the box in whatever raw state the interrupted syscall
//! sequence produced. That case is proven by gate leg 3 (`boot-gate-hotswap`): the four
//! [`PausePoint`]s let the gate SIGKILL the swap at pre-write / mid-write / pre-commit /
//! pre-rename and prove each postcondition + recovery on produced bytes (the graceful short-EOF
        
//! write failure stays the truncated-stream leg 2). The mechanism argument the gate confirms:
//! the commit is a single tmp+fsync+rename+dir-fsync (crash before rename ⇒ OLD record; after ⇒
//! NEW — never torn); the raw partition is only written post-teardown so a mid-write kill leaves
//! old-or-partial-new that the next boot's clock-free verify + kernel dm-verity catches (mount-EIO
//! degrade, never a brick — weights are out of the boot chain); the `flock` auto-releases on
//! process death (no wedge). The worst constructible outcome is an
//! extended-but-always-recoverable engine outage needing an operator re-push/reboot, never a
//! brick / torn floor / false-verified serving state.

use crate::stores::{
    SIG_LEN, WeightsManifest, WeightsRecord, parse_weights_manifest, read_record_strict,
    write_record_atomic_with_pause,
};
use sha2::{Digest, Sha256};
use std::io::{self, Read};
use std::path::Path;
use std::time::Duration;

/// The swap lock file inside the weights dir — `flock(LOCK_EX | LOCK_NB)`: a concurrent/retried
/// invocation REFUSES cleanly (spec §5), it never queues behind a half-done swap.
pub const SWAP_LOCK_FILE: &str = ".swap.lock";

/// Bounded teardown retry (spec §5 step 2): EBUSY on umount/dev-remove is a precondition to wait
/// out (the engine's fds close asynchronously after the supervised down), not a hard failure —
/// but only for a BOUNDED window.
pub const TEARDOWN_RETRIES: u32 = 10;
pub const TEARDOWN_RETRY_DELAY: Duration = Duration::from_millis(500);

/// How the swap failed (the §7 taxonomy). The bin maps these to distinct exit codes so the
/// operator-side `deploy-model` reports COMMITTED / REFUSED / DEGRADED faithfully.
#[derive(Debug)]
pub enum SwapError {
    /// Nothing on disk changed; the OLD model still serves (preflight, or the pre-write teardown
    /// window with the old stack best-effort restored).
    Refused(String),
    /// The old bytes are gone (or the new state is unhealthy) and the record was NOT committed:
    /// the engine is down + visible, the box otherwise serves; re-push restores.
    Degraded(String),
}

impl std::fmt::Display for SwapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SwapError::Refused(m) => write!(f, "refused (disk untouched): {m}"),
            SwapError::Degraded(m) => write!(f, "DEGRADED (engine down, re-push to restore): {m}"),
        }
    }
}

/// The framed push header (everything before the image byte stream).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapRequest {
    /// The new signed manifest bytes (the quince artifact).
    pub manifest_bytes: Vec<u8>,
    /// The detached 254-byte `Purpose::Weights` bundle.
    pub sig: [u8; SIG_LEN],
    /// The framed image length — MUST equal the (verified) manifest's `image-size`.
    pub image_len: u64,
}

/// Read the frame header from the push stream (bounded, fail-closed; the image bytes stay in
/// `src` for the streaming write). Mirrors `fb-update apply`'s §4c framing reader.
pub fn read_frame_header(src: &mut dyn Read) -> io::Result<SwapRequest> {
    let manifest_len = read_u64_le(src)?;
    if manifest_len == 0 || manifest_len > crate::stores::MANIFEST_MAX_LEN {
        return Err(io::Error::other(format!(
            "swap frame: manifest_len {manifest_len} out of bounds"
        )));
    }
    let mut manifest_bytes = vec![0u8; manifest_len as usize];
    src.read_exact(&mut manifest_bytes)
        .map_err(|e| io::Error::other(format!("swap frame: short manifest: {e}")))?;

    let sig_len = read_u64_le(src)?;
    if sig_len != SIG_LEN as u64 {
        return Err(io::Error::other(format!(
            "swap frame: sig_len {sig_len} != {SIG_LEN}"
        )));
    }
    let mut sig = [0u8; SIG_LEN];
    src.read_exact(&mut sig)
        .map_err(|e| io::Error::other(format!("swap frame: short sig: {e}")))?;

    let image_len = read_u64_le(src)?;
    Ok(SwapRequest {
        manifest_bytes,
        sig,
        image_len,
    })
}

fn read_u64_le(src: &mut dyn Read) -> io::Result<u64> {
    let mut b = [0u8; 8];
    src.read_exact(&mut b)
        .map_err(|e| io::Error::other(format!("swap frame: short length field: {e}")))?;
    Ok(u64::from_le_bytes(b))
}

/// Crash-injection pause points (spec Component B, gate leg 3). All four are
/// SWAP-PATH-ONLY — none is reachable from boot or an s6 engine restart, so even a
/// globally-set env can only stall an operator-run swap.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PausePoint {
    PreWrite,
    MidWrite,
    PreCommit,
    PreRename,
}

impl PausePoint {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreWrite => "pre-write",
            Self::MidWrite => "mid-write",
            Self::PreCommit => "pre-commit",
            Self::PreRename => "pre-rename",
        }
    }
    pub fn from_env(v: &str) -> Option<Self> {
        match v {
            "pre-write" => Some(Self::PreWrite),
            "mid-write" => Some(Self::MidWrite),
            "pre-commit" => Some(Self::PreCommit),
            "pre-rename" => Some(Self::PreRename),
            _ => None,
        }
    }
}

/// The FFI seam for [`run_swap`] — host tests drive a fake; the box runs the bin's syscall ops.
/// Every method is a single side-effect; the SEQUENCING (order, retries, failure classes, the
/// commit-last invariant) lives in [`run_swap`] where it is host-tested.
pub trait SwapOps {
    /// The weights partition's size in bytes (fit check).
    fn partition_size(&mut self) -> io::Result<u64>;
    /// `s6-svc -wD -d /run/service/<engine>` — supervised stop, wait for down.
    fn svc_stop_wait(&mut self, service: &str) -> io::Result<()>;
    /// `s6-svc -u /run/service/<engine>`.
    fn svc_start(&mut self, service: &str) -> io::Result<()>;
    /// `umount /models` (EBUSY propagates — the sequencer owns the bounded retry).
    fn umount_models(&mut self) -> io::Result<()>;
    /// `DM_DEV_REMOVE` the model verity device (EBUSY propagates likewise).
    fn dev_remove_model(&mut self) -> io::Result<()>;
    /// Stream exactly `size` bytes from `src` onto the RAW weights partition, fsync, then REREAD
    /// the written range and verify it hashes to `expected` (write-then-reread, the
    /// `stream_verified` posture). Any short stream / IO fault / hash mismatch → Err.
    fn write_image(&mut self, src: &mut dyn Read, size: u64, expected: &[u8; 32])
    -> io::Result<()>;
    /// `setup_verity_device` (EIO mode) + mount `/models` RO — the kernel-enforcement point (a
    /// root/data mismatch EIOs at the first read).
    fn setup_and_mount(&mut self, root_hash: &str, verity_offset: u64) -> io::Result<()>;
    /// A REAL inference request against the restarted engine (NOT a metadata probe — the health
            
    /// gate that makes the commit meaningful).
    fn health_check(&mut self) -> io::Result<()>;
    /// The post-ntpd wall clock (unix seconds) for the CLOCKED verify.
    fn now_unix(&mut self) -> u64;
    /// Bounded-retry sleep (injected so host tests run instantly).
    fn sleep(&mut self, d: Duration);
    /// Crash-injection pause seam (gate leg 3): DEFAULT NO-OP — `FakeOps` inherits this
    /// and can never pause, so no pause check is reachable from `cargo test` (AC-B1).
    /// The box impl consults `FB_WEIGHTS_PAUSE_AT` and, on a match, writes the marker
    /// and blocks forever (the gate SIGKILLs it). Block-or-return-unit is the seam's
    /// WHOLE observable surface (audit I-4): no value in, no value out — it cannot
    /// skip a verify, alter bytes, or branch the sequencer.
    fn pause_point(&self, _p: PausePoint) {}
}

/// The normative swap sequence (spec §5). Returns the committed (newly-verified) bundle ctr.
pub fn run_swap(
    ops: &mut dyn SwapOps,
    weights_dir: &Path,
    root_pubkey: &[u8; 32],
    engine_service: &str,
    req: &SwapRequest,
    image_src: &mut dyn Read,
) -> Result<u64, SwapError> {
                                                                                 
    let current =
        read_record_strict(weights_dir).map_err(|e| SwapError::Refused(format!("{e}")))?;

                                                                                                 
                                                                                               
                                                                                                   
                                                                                                  
                                                                                                 
                                                                                                
    let current_hash: [u8; 32] = Sha256::digest(&current.manifest_bytes).into();
    quince::verify_artifact(
        root_pubkey,
        &current.sig,
        &current_hash,
        quince::Purpose::Weights,
        current.floor_ctr,
    )
    .map_err(|e| SwapError::Refused(format!("current record verify: {e:?}")))?;

                                                                                                    
                                                                
    let artifact_hash: [u8; 32] = Sha256::digest(&req.manifest_bytes).into();
    let new_ctr = quince::verify_artifact_clocked(
        root_pubkey,
        &req.sig,
        &artifact_hash,
        quince::Purpose::Weights,
        current.floor_ctr,
        ops.now_unix(),
    )
    .map_err(|e| SwapError::Refused(format!("manifest verify: {e:?}")))?;

    let new_manifest = parse_weights_manifest(&req.manifest_bytes)
        .map_err(|e| SwapError::Refused(e.to_string()))?;

                                                                                                
                                        
    if req.image_len != new_manifest.image_size {
        return Err(SwapError::Refused(format!(
            "framed image_len {} != signed image-size {}",
            req.image_len, new_manifest.image_size
        )));
    }
                                                                       
    if new_manifest.verity_offset >= new_manifest.image_size {
        return Err(SwapError::Refused(format!(
            "verity-offset {} not inside image-size {}",
            new_manifest.verity_offset, new_manifest.image_size
        )));
    }
                                                                                                    
    let partition = ops
        .partition_size()
        .map_err(|e| SwapError::Refused(format!("partition size: {e}")))?;
    if new_manifest.image_size > partition {
        return Err(SwapError::Refused(format!(
            "image {} bytes does not fit the {partition}-byte weights partition",
            new_manifest.image_size
        )));
    }

                                                                                             
                                                                                                
                                               
    let old_manifest = parse_weights_manifest(&current.manifest_bytes)
        .map_err(|e| SwapError::Refused(format!("current record manifest: {e}")))?;

                                                                                             
    if let Err(e) = ops.svc_stop_wait(engine_service) {
        return Err(abort_pre_write(
            ops,
            engine_service,
            &old_manifest,
            format!("engine stop: {e}"),
            false,
        ));
    }
                                                                                                   
                                                                                                 
                                                                                            
                                                                                                
                                                                                           
                                                                                
    if let Err(e) = retry_teardown(ops, |o| o.umount_models(), &ALREADY_UNMOUNTED) {
        return Err(abort_pre_write(
            ops,
            engine_service,
            &old_manifest,
            format!("umount: {e}"),
            false,
        ));
    }
    if let Err(e) = retry_teardown(ops, |o| o.dev_remove_model(), &ALREADY_REMOVED) {
                                                                               
        return Err(abort_pre_write(
            ops,
            engine_service,
            &old_manifest,
            format!("dev-remove: {e}"),
            true,
        ));
    }

    ops.pause_point(PausePoint::PreWrite);

                                                                                           
    if let Err(e) = ops.write_image(
        image_src,
        new_manifest.image_size,
        &new_manifest.image_sha256,
    ) {
        return Err(SwapError::Degraded(format!("image write: {e}")));
    }

                                                                  
    if let Err(e) = ops.setup_and_mount(&new_manifest.root_hash, new_manifest.verity_offset) {
        return Err(SwapError::Degraded(format!("verity/mount: {e}")));
    }

                                   
    if let Err(e) = ops.svc_start(engine_service) {
        return Err(SwapError::Degraded(format!("engine start: {e}")));
    }
    if let Err(e) = ops.health_check() {
                                                                                               
                                                                                                     
                                                                                               
                                                                                                  
                                                                                                  
                                                                                                    
        let stop = ops.svc_stop_wait(engine_service);
        return Err(SwapError::Degraded(format!(
            "post-swap real-inference health check: {e}{}",
            match stop {
                Ok(()) => String::new(),
                Err(se) => format!("; engine stop after the failed health check also failed: {se}"),
            }
        )));
    }

    ops.pause_point(PausePoint::PreCommit);

                                                                                        
    let pause = |p| ops.pause_point(p);
    write_record_atomic_with_pause(
        weights_dir,
        &WeightsRecord {
            floor_ctr: new_ctr,
            manifest_bytes: req.manifest_bytes.clone(),
            sig: req.sig,
        },
        &pause,
    )
    .map_err(|e| SwapError::Degraded(format!("record commit: {e}")))?;
    Ok(new_ctr)
}

/// An "already satisfied" teardown-error class: the raw errnos (PRIMARY) + the strerror texts (a
/// documented FALLBACK). `fb_verity_rt::umount`/`dev_remove` now return RAW errors
                
/// (`raw_os_error()` preserved), so the `raw` match is the authoritative,
/// strerror-wording-independent classifier that fires in production AND in the unit tests. The
/// `text` fallback only catches an error that reached here already wrapped in `io::Error::other`
/// (raw lost) — it is kept as belt-and-suspenders and unit-tested directly
/// (`text_fallback_classifies_wrapped_already_done_errors`); the substrings are chosen to sit
/// inside both musl's and glibc's wording for these errnos.
struct AlreadyDone {
    raw: &'static [i32],
    text: &'static [&'static str],
}

/// `umount2` on a path with nothing mounted → EINVAL "Invalid argument": the unmounted
/// postcondition already holds.
const ALREADY_UNMOUNTED: AlreadyDone = AlreadyDone {
    raw: &[libc::EINVAL],
    text: &["Invalid argument"],
};

/// `DM_DEV_REMOVE` on an absent device → ENXIO "No such device or address" (dm-ioctl's
/// find-by-name miss; ENODEV "No such device" covered for defense): the removed postcondition
/// already holds.
const ALREADY_REMOVED: AlreadyDone = AlreadyDone {
    raw: &[libc::ENXIO, libc::ENODEV],
    text: &["No such device"],
};

/// Bounded EBUSY-tolerant teardown retry (spec §5 step 2): retry ONLY while the failure looks like
/// a busy holder draining; an `already`-class error means the step's postcondition holds (a torn
/// prior state — the §7 re-push path) and returns Ok; any other error is immediate.
fn retry_teardown(
    ops: &mut dyn SwapOps,
    mut op: impl FnMut(&mut dyn SwapOps) -> io::Result<()>,
    already: &AlreadyDone,
) -> io::Result<()> {
    let mut last = None;
    for attempt in 0..TEARDOWN_RETRIES {
        if attempt > 0 {
            ops.sleep(TEARDOWN_RETRY_DELAY);
        }
        match op(ops) {
            Ok(()) => return Ok(()),
            Err(e) => {
                let text = e.to_string();
                let busy = text.contains("Resource busy") || e.raw_os_error() == Some(libc::EBUSY);
                let done = already.raw.iter().any(|&n| e.raw_os_error() == Some(n))
                    || already.text.iter().any(|t| text.contains(t));
                if done {
                    return Ok(());
                }
                last = Some(e);
                if !busy {
                    break;
                }
            }
        }
    }
    Err(last.unwrap_or_else(|| io::Error::other("teardown retry: no attempt ran")))
}

/// The pre-write abort: disk untouched — best-effort restore of the OLD stack (re-setup + re-mount
/// when the teardown got past the umount, then restart the engine), then report `Refused` with the
/// restore outcome folded into the message (never silently half-down).
fn abort_pre_write(
    ops: &mut dyn SwapOps,
    engine_service: &str,
    old: &WeightsManifest,
    why: String,
    remount: bool,
) -> SwapError {
    let notes = why;
    if remount && let Err(e) = ops.setup_and_mount(&old.root_hash, old.verity_offset) {
        return SwapError::Degraded(format!("{notes}; old-stack remount FAILED: {e}"));
    }
    match ops.svc_start(engine_service) {
        Ok(()) => SwapError::Refused(format!("{notes}; old stack restarted")),
        Err(e) => SwapError::Degraded(format!("{notes}; old-stack restart FAILED: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stores::{render_weights_manifest, write_record_atomic};
    use dragonfruit::{Attestation, BundleFile, Delegation, sign_attestation, sign_delegation};
    use ed25519_dalek::SigningKey;

                                                                            
    const T_VALID: u64 = quince::MIN_PLAUSIBLE_CLOCK + 100;

    fn signed(manifest_bytes: &[u8], ctr: u64, nb: u64, na: u64) -> ([u8; 32], [u8; SIG_LEN]) {
        let root = SigningKey::from_bytes(&[1u8; 32]);
        let worker = SigningKey::from_bytes(&[2u8; 32]);
        let deleg = Delegation {
            worker_pubkey: worker.verifying_key().to_bytes(),
            purpose: quince::Purpose::Weights,
            not_before: nb,
            not_after: na,
            monotonic_ctr: ctr,
        };
        let root_sig = sign_delegation(&root, &deleg);
        let deleg_bytes = deleg.to_canonical();
        let delegation_id: [u8; 32] = Sha256::digest(deleg_bytes).into();
        let artifact_hash: [u8; 32] = Sha256::digest(manifest_bytes).into();
        let att = Attestation {
            artifact_hash,
            purpose: quince::Purpose::Weights,
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

    fn manifest(image_size: u64) -> WeightsManifest {
        WeightsManifest {
            root_hash: "ab".repeat(32),
            verity_offset: image_size.saturating_sub(4096),
            image_sha256: [0xCD; 32],
            image_size,
        }
    }

    /// Seed the weights dir with a CURRENT record at floor `floor` (a valid signed old manifest).
    fn seed_current(dir: &Path, floor: u64) -> [u8; 32] {
        let mb = render_weights_manifest(&manifest(1_000_000));
        let (root_pub, sig) = signed(&mb, floor, 0, u64::MAX);
        write_record_atomic(
            dir,
            &WeightsRecord {
                floor_ctr: floor,
                manifest_bytes: mb,
                sig,
            },
        )
        .expect("seed record");
        root_pub
    }

    fn request(ctr: u64, image_size: u64) -> SwapRequest {
        let mb = render_weights_manifest(&manifest(image_size));
        let (_, sig) = signed(&mb, ctr, quince::MIN_PLAUSIBLE_CLOCK, T_VALID + 1_000_000);
        SwapRequest {
            manifest_bytes: mb,
            sig,
            image_len: image_size,
        }
    }

    /// Scripted fake: records the call order; per-step failure injection.
    struct FakeOps {
        calls: Vec<String>,
        partition: u64,
        fail: Option<&'static str>,
        busy_umounts: u32,
        /// When set, `umount_models` fails EVERY time with this RAW errno — the SAME shape the real
        /// `fb_verity_rt::umount` now returns (`io::Error::last_os_error()`, `raw_os_error()`
        /// preserved). So these tests exercise the raw-errno classification branch that ACTUALLY
                        
        /// ships (fb-verity-rt no longer wraps in `io::Error::other`, so the tolerance
        /// is strerror-wording-independent). The text fallback is unit-tested separately below.
        umount_errno: Option<i32>,
        /// Likewise for `dev_remove_model` (e.g. ENXIO the DM_DEV_REMOVE find-by-name miss).
        devremove_errno: Option<i32>,
    }
    impl FakeOps {
        fn new() -> Self {
            FakeOps {
                calls: vec![],
                partition: 10_000_000,
                fail: None,
                busy_umounts: 0,
                umount_errno: None,
                devremove_errno: None,
            }
        }
        fn failing(step: &'static str) -> Self {
            FakeOps {
                fail: Some(step),
                ..FakeOps::new()
            }
        }
        fn err_if(&mut self, step: &'static str) -> io::Result<()> {
            self.calls.push(step.to_string());
            if self.fail == Some(step) {
                return Err(io::Error::other(format!("{step} injected failure")));
            }
            Ok(())
        }
    }
    impl SwapOps for FakeOps {
        fn partition_size(&mut self) -> io::Result<u64> {
            self.calls.push("partition_size".into());
            Ok(self.partition)
        }
        fn svc_stop_wait(&mut self, s: &str) -> io::Result<()> {
            assert_eq!(s, "creatine");
            self.err_if("stop")
        }
        fn svc_start(&mut self, s: &str) -> io::Result<()> {
            assert_eq!(s, "creatine");
            self.err_if("start")
        }
        fn umount_models(&mut self) -> io::Result<()> {
            self.calls.push("umount".into());
            if let Some(errno) = self.umount_errno {
                return Err(io::Error::from_raw_os_error(errno));
            }
            if self.busy_umounts > 0 {
                self.busy_umounts -= 1;
                return Err(io::Error::from_raw_os_error(libc::EBUSY));
            }
            if self.fail == Some("umount") {
                return Err(io::Error::other("umount injected failure"));
            }
            Ok(())
        }
        fn dev_remove_model(&mut self) -> io::Result<()> {
            if let Some(errno) = self.devremove_errno {
                self.calls.push("dev_remove".into());
                return Err(io::Error::from_raw_os_error(errno));
            }
            self.err_if("dev_remove")
        }
        fn write_image(
            &mut self,
            src: &mut dyn Read,
            size: u64,
            _expected: &[u8; 32],
        ) -> io::Result<()> {
                                                                                      
            let mut sink = Vec::new();
            src.take(size).read_to_end(&mut sink)?;
            self.calls.push(format!("write:{size}"));
            if self.fail == Some("write") {
                return Err(io::Error::other("write injected failure"));
            }
            Ok(())
        }
        fn setup_and_mount(&mut self, root_hash: &str, offset: u64) -> io::Result<()> {
            self.calls.push(format!("mount:{root_hash}:{offset}"));
            if self.fail == Some("mount") {
                return Err(io::Error::other("mount injected failure"));
            }
            Ok(())
        }
        fn health_check(&mut self) -> io::Result<()> {
            self.err_if("health")
        }
        fn now_unix(&mut self) -> u64 {
            T_VALID
        }
        fn sleep(&mut self, _d: Duration) {
            self.calls.push("sleep".into());
        }
    }

    fn swap(
        ops: &mut FakeOps,
        dir: &Path,
        root_pub: &[u8; 32],
        req: &SwapRequest,
    ) -> Result<u64, SwapError> {
        let mut img = io::Cursor::new(vec![0u8; req.image_len as usize]);
        run_swap(ops, dir, root_pub, "creatine", req, &mut img)
    }

    #[test]
    fn pause_env_is_structurally_inert_under_cargo_test() {
                                                                                       
                                                                                 
                                                                                       
                                                                                 
                                                                                    
                                                                                        
                                                                                     
        if std::env::var_os("FB_WEIGHTS_PAUSE_INERTNESS_CHILD").is_some() {
            assert_eq!(
                std::env::var("FB_WEIGHTS_PAUSE_AT").as_deref(),
                Ok("pre-commit"),
                "child must run with the pause env set"
            );
            let dir = tempfile::tempdir().expect("tempdir");
            let root_pub = seed_current(dir.path(), 5);
            let mut ops = FakeOps::new();
            swap(&mut ops, dir.path(), &root_pub, &request(6, 2_000_000))
                .expect("a set pause env must be inert under FakeOps");
            return;
        }
        let exe = std::env::current_exe().expect("test exe");
        let mut child = std::process::Command::new(exe)
            .args([
                "--exact",
                "swap::tests::pause_env_is_structurally_inert_under_cargo_test",
            ])
            .env("FB_WEIGHTS_PAUSE_AT", "pre-commit")
            .env("FB_WEIGHTS_PAUSE_INERTNESS_CHILD", "1")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn the child test process");
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        loop {
            match child.try_wait().expect("wait on the child") {
                Some(status) => {
                    assert!(status.success(), "child swap failed under the set env");
                    break;
                }
                None if std::time::Instant::now() > deadline => {
                    let _ = child.kill();
                    panic!("the swap HUNG under a set pause env — the seam is not inert");
                }
                None => std::thread::sleep(Duration::from_millis(50)),
            }
        }
    }

    #[test]
    fn happy_path_sequences_and_commits_last() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_pub = seed_current(dir.path(), 5);
        let mut ops = FakeOps::new();
        let req = request(6, 2_000_000);
        let ctr = swap(&mut ops, dir.path(), &root_pub, &req).expect("swap commits");
        assert_eq!(ctr, 6);
                                                                                                     
                                              
        assert_eq!(
            ops.calls,
            vec![
                "partition_size".to_string(),
                "stop".to_string(),
                "umount".to_string(),
                "dev_remove".to_string(),
                "write:2000000".to_string(),
                format!("mount:{}:{}", "ab".repeat(32), 1_995_904),
                "start".to_string(),
                "health".to_string(),
            ]
        );
                                                                                 
        let after = read_record_strict(dir.path()).expect("read");
        assert_eq!(after.floor_ctr, 6);
        assert_eq!(after.manifest_bytes, req.manifest_bytes);
    }

    #[test]
    fn below_floor_refuses_before_any_disruption() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_pub = seed_current(dir.path(), 5);
        let mut ops = FakeOps::new();
        let e = swap(&mut ops, dir.path(), &root_pub, &request(4, 2_000_000)).unwrap_err();
        assert!(matches!(e, SwapError::Refused(_)), "{e}");
        assert!(
            !ops.calls.iter().any(|c| c == "stop"),
            "the engine must never stop on a refused preflight: {:?}",
            ops.calls
        );
        assert_eq!(read_record_strict(dir.path()).expect("read").floor_ctr, 5);
    }

    #[test]
    fn expired_window_refuses_at_the_clocked_locus() {
                                                                                                 
                                                              
        let dir = tempfile::tempdir().expect("tempdir");
        let root_pub = seed_current(dir.path(), 5);
        let mb = render_weights_manifest(&manifest(2_000_000));
        let (_, sig) = signed(&mb, 6, 0, 100);                       
        let req = SwapRequest {
            manifest_bytes: mb,
            sig,
            image_len: 2_000_000,
        };
        let e = swap(&mut FakeOps::new(), dir.path(), &root_pub, &req).unwrap_err();
        assert!(matches!(e, SwapError::Refused(_)), "{e}");
        assert!(e.to_string().contains("WindowExpired"), "{e}");
    }

    #[test]
    fn doesnt_fit_refuses() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_pub = seed_current(dir.path(), 5);
        let mut ops = FakeOps::new();
        ops.partition = 1_000_000;                              
        let e = swap(&mut ops, dir.path(), &root_pub, &request(6, 2_000_000)).unwrap_err();
        assert!(matches!(e, SwapError::Refused(_)), "{e}");
        assert!(e.to_string().contains("does not fit"), "{e}");
        assert!(!ops.calls.iter().any(|c| c == "stop"));
    }

    #[test]
    fn frame_length_must_match_signed_image_size() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_pub = seed_current(dir.path(), 5);
        let mut req = request(6, 2_000_000);
        req.image_len = 1_999_999;                               
        let e = swap(&mut FakeOps::new(), dir.path(), &root_pub, &req).unwrap_err();
        assert!(matches!(e, SwapError::Refused(_)), "{e}");
        assert!(e.to_string().contains("signed image-size"), "{e}");
    }

    #[test]
    fn write_failure_is_degraded_and_never_commits() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_pub = seed_current(dir.path(), 5);
        let mut ops = FakeOps::failing("write");
        let e = swap(&mut ops, dir.path(), &root_pub, &request(6, 2_000_000)).unwrap_err();
        assert!(matches!(e, SwapError::Degraded(_)), "{e}");
                                                                              
        assert_eq!(read_record_strict(dir.path()).expect("read").floor_ctr, 5);
    }

    #[test]
    fn health_failure_is_degraded_and_floor_not_bumped_and_stops_the_engine() {
                                                                                           
        let dir = tempfile::tempdir().expect("tempdir");
        let root_pub = seed_current(dir.path(), 5);
        let mut ops = FakeOps::failing("health");
        let e = swap(&mut ops, dir.path(), &root_pub, &request(6, 2_000_000)).unwrap_err();
        assert!(matches!(e, SwapError::Degraded(_)), "{e}");
        let after = read_record_strict(dir.path()).expect("read");
        assert_eq!(
            after.floor_ctr, 5,
            "floor must NOT advance past a failed health check"
        );
                                                                                            
                                                                                               
                                                                                                    
                                                                                                     
        let tail: Vec<&str> = ops
            .calls
            .iter()
            .rev()
            .take(3)
            .rev()
            .map(String::as_str)
            .collect();
        assert_eq!(
            tail,
            vec!["start", "health", "stop"],
            "the failed health check is followed by an engine stop: {:?}",
            ops.calls
        );
    }

    #[test]
    fn stop_failure_aborts_with_old_stack_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_pub = seed_current(dir.path(), 5);
        let mut ops = FakeOps::failing("stop");
        let e = swap(&mut ops, dir.path(), &root_pub, &request(6, 2_000_000)).unwrap_err();
                                                                                        
        assert!(matches!(e, SwapError::Refused(_)), "{e}");
        assert!(e.to_string().contains("old stack restarted"), "{e}");
        assert!(!ops.calls.iter().any(|c| c.starts_with("write")));
        assert!(ops.calls.iter().any(|c| c == "start"), "restart attempted");
    }

    #[test]
    fn transient_umount_ebusy_is_retried_then_succeeds() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_pub = seed_current(dir.path(), 5);
        let mut ops = FakeOps::new();
        ops.busy_umounts = 3;                            
        swap(&mut ops, dir.path(), &root_pub, &request(6, 2_000_000)).expect("swap commits");
        assert_eq!(
            ops.calls.iter().filter(|c| *c == "umount").count(),
            4,
            "3 busy + 1 success"
        );
    }

    #[test]
    fn persistent_umount_ebusy_aborts_with_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_pub = seed_current(dir.path(), 5);
        let mut ops = FakeOps::new();
        ops.busy_umounts = u32::MAX;                
        let e = swap(&mut ops, dir.path(), &root_pub, &request(6, 2_000_000)).unwrap_err();
        assert!(matches!(e, SwapError::Refused(_)), "{e}");
        assert_eq!(
            ops.calls.iter().filter(|c| *c == "umount").count(),
            TEARDOWN_RETRIES as usize,
            "bounded retries"
        );
        assert!(!ops.calls.iter().any(|c| c.starts_with("write")));
    }

    #[test]
    fn repush_from_torn_state_tolerates_absent_mount_and_device() {
                                                                                                   
                                                                                                  
                                                                                                  
                                                                                                     
                                                                                                    
        let dir = tempfile::tempdir().expect("tempdir");
        let root_pub = seed_current(dir.path(), 5);
        let mut ops = FakeOps::new();
        ops.umount_errno = Some(libc::EINVAL);
        ops.devremove_errno = Some(libc::ENXIO);
        let req = request(6, 2_000_000);
        let ctr = swap(&mut ops, dir.path(), &root_pub, &req).expect("re-push must proceed");
        assert_eq!(ctr, 6);
        assert!(
            ops.calls.iter().any(|c| c.starts_with("write")),
            "the swap must reach the write past the already-torn-down steps: {:?}",
            ops.calls
        );
        assert_eq!(read_record_strict(dir.path()).expect("read").floor_ctr, 6);
    }

    #[test]
    fn text_fallback_classifies_wrapped_already_done_errors() {
                                                                                                   
                                                                                                 
                                                                                          
                                                                                                    
        let mut ops = FakeOps::new();
                                                                                                   
        assert!(
            retry_teardown(
                &mut ops,
                |_| Err(io::Error::other(
                    "umount /models: Invalid argument (os error 22)"
                )),
                &ALREADY_UNMOUNTED,
            )
            .is_ok(),
            "a wrapped EINVAL (not-a-mountpoint) must be tolerated via the text fallback"
        );
                                                                                                  
        assert!(
            retry_teardown(
                &mut ops,
                |_| Err(io::Error::other(
                    "DM_DEV_REMOVE (fbw-model): No such device or address (os error 6)"
                )),
                &ALREADY_REMOVED,
            )
            .is_ok(),
            "a wrapped ENXIO (already-removed) must be tolerated via the text fallback"
        );
                                                                                                     
                        
        assert!(
            retry_teardown(
                &mut ops,
                |_| Err(io::Error::other(
                    "umount /models: Operation not permitted (os error 1)"
                )),
                &ALREADY_UNMOUNTED,
            )
            .is_err(),
            "a wrapped non-already-done error must still abort"
        );
    }

    #[test]
    fn unexpected_umount_error_still_aborts() {
                                                                                                 
                                                                                               
        let dir = tempfile::tempdir().expect("tempdir");
        let root_pub = seed_current(dir.path(), 5);
        let mut ops = FakeOps::new();
        ops.umount_errno = Some(libc::EPERM);
        let e = swap(&mut ops, dir.path(), &root_pub, &request(6, 2_000_000)).unwrap_err();
        assert!(matches!(e, SwapError::Refused(_)), "{e}");
        assert!(!ops.calls.iter().any(|c| c.starts_with("write")));
        assert!(ops.calls.iter().any(|c| c == "start"), "restart attempted");
    }

    #[test]
    fn dev_remove_failure_remounts_old_before_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let root_pub = seed_current(dir.path(), 5);
        let mut ops = FakeOps::failing("dev_remove");
        let e = swap(&mut ops, dir.path(), &root_pub, &request(6, 2_000_000)).unwrap_err();
        assert!(matches!(e, SwapError::Refused(_)), "{e}");
                                                                                            
                                                         
        assert!(
            ops.calls
                .iter()
                .any(|c| c == &format!("mount:{}:{}", "ab".repeat(32), 995_904)),
            "old-stack remount: {:?}",
            ops.calls
        );
        assert!(ops.calls.iter().any(|c| c == "start"));
    }

    #[test]
    fn frame_header_round_trips_and_bounds() {
        let mb = render_weights_manifest(&manifest(2_000_000));
        let (_, sig) = signed(&mb, 6, 0, 100);
        let mut frame = Vec::new();
        frame.extend_from_slice(&(mb.len() as u64).to_le_bytes());
        frame.extend_from_slice(&mb);
        frame.extend_from_slice(&(SIG_LEN as u64).to_le_bytes());
        frame.extend_from_slice(&sig);
        frame.extend_from_slice(&2_000_000u64.to_le_bytes());
        let req = read_frame_header(&mut io::Cursor::new(&frame)).expect("frame parses");
        assert_eq!(req.manifest_bytes, mb);
        assert_eq!(req.image_len, 2_000_000);

                                          
        let mut bad = Vec::new();
        bad.extend_from_slice(&(crate::stores::MANIFEST_MAX_LEN + 1).to_le_bytes());
        assert!(read_frame_header(&mut io::Cursor::new(&bad)).is_err());
                                 
        let mut bad = Vec::new();
        bad.extend_from_slice(&(mb.len() as u64).to_le_bytes());
        bad.extend_from_slice(&mb);
        bad.extend_from_slice(&64u64.to_le_bytes());
        assert!(read_frame_header(&mut io::Cursor::new(&bad)).is_err());
    }
}

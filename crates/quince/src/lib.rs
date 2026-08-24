//! quince — the box-side artifact-verify gate (verify-only wrapper over dragonfruit's cascade).
//! The ONE shared verify path for every box applier, at BOTH clock loci:
//! - [`verify_artifact`] — clock-FREE (S1/S2: the installer's restore-from gate, pre-NTP; no window).
//! - [`verify_artifact_clocked`] — clocked (S0: `fb-update` post-ntpd-convergence; window + ctr floor).
//!
//! CRUX: verify-only. dragonfruit is taken `default-features = false`; this crate references NO sign symbol.
//! The cross-crate (feature-unification) guard is `fb-manifest`'s `shipped_crate_allowlist` (Task 6).
#![forbid(unsafe_code)]

use dragonfruit::{BundleFile, verify_bundle, verify_bundle_no_window};
pub use dragonfruit::{Purpose, VerifyError, WindowUncheckedArtifact};

                                                                                                          
                                                                                                            
                                                                                                       
                                                                                                           
                                                                                                      
                                                                                            
#[cfg(feature = "sign")]
compile_error!("quince must never enable a `sign` feature — the box only verifies, never signs");

/// Why a box-side artifact verify failed. Fail-closed: every variant aborts the caller.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The detached `.sig` is not a well-formed 254-byte bundle file.
    BadBundleFile,
    /// The cascade / artifact-hash / purpose / counter check failed.
    Verify(VerifyError),
}

/// Verify a detached artifact bundle, **clock-free**, against a pinned operator root pubkey.
/// `sig_bytes` = the 254-byte `.sig`; `artifact_hash` = the caller's SHA-256 of the artifact (the caller
/// owns the hashing strategy — in-RAM for the bounded restore tarball, streamed for a C3 `.img`).
/// Returns the sealed proof ONLY on the full cascade + both bindings + the `min_ctr` floor; fail-closed.
pub fn verify_artifact(
    root_pubkey: &[u8; 32],
    sig_bytes: &[u8],
    artifact_hash: &[u8; 32],
    expected_purpose: Purpose,
    min_ctr: u64,
) -> Result<WindowUncheckedArtifact, Error> {
    let bf = BundleFile::from_bytes(sig_bytes).map_err(|_| Error::BadBundleFile)?;
    verify_bundle_no_window(
        &bf.as_bundle(),
        root_pubkey,
        artifact_hash,
        expected_purpose,
        min_ctr,
    )
    .map_err(Error::Verify)
}

/// The S0 clocked-verify plausibility floor (unix seconds): 2026-06-24T00:00:00Z, the C1
/// quince build epoch. Any honest post-ntpd-convergence clock is past it forever; a stuck,
/// reset, or dead-RTC clock (1970 / 2000-era defaults) is far below it and must NOT be
/// allowed to evaluate a delegation window — a garbage `now` turns the expiry lever into
/// theater. Same posture as fb-acme's `EpochFloorClock` (the build-epoch floor gate).
pub const MIN_PLAUSIBLE_CLOCK: u64 = 1_782_259_200;

/// Why the S0 clocked verify failed. Fail-closed: every variant aborts the caller.
#[derive(Debug, PartialEq, Eq)]
pub enum ClockedVerifyError {
    /// The detached `.sig` is not a well-formed 254-byte bundle file.
    BadBundleFile,
    /// The cascade / window / artifact-hash / purpose check failed.
    Verify(VerifyError),
    /// The caller's clock reads before [`MIN_PLAUSIBLE_CLOCK`] — too implausible to
    /// evaluate a delegation window. Checked BEFORE the cascade, so a stuck-epoch
    /// clock never reaches (and never mis-judges) the window at all.
    ClockTooEarly { now: u64, floor: u64 },
    /// The verified delegation's `monotonic_ctr` is below the caller's floor (rollback).
    CounterBelowFloor { got: u64, min: u64 },
}

/// Verify a detached artifact bundle at the CLOCKED locus (S0): the full cascade INCLUDING
/// the delegation window (dragonfruit's 5-arg `verify_bundle` against `now_unix`), then the
/// caller's `min_ctr` floor over the verified delegation's `monotonic_ctr`. `now_unix` must
/// come from a trustworthy (post-ntpd-convergence) clock and is floor-checked against
/// [`MIN_PLAUSIBLE_CLOCK`] first. Returns the verified `monotonic_ctr` on success (the
/// applier records it as the probation `bundle_ctr`). Fail-closed on every arm.
pub fn verify_artifact_clocked(
    root_pubkey: &[u8; 32],
    sig_bytes: &[u8],
    artifact_hash: &[u8; 32],
    expected_purpose: Purpose,
    min_ctr: u64,
    now_unix: u64,
) -> Result<u64, ClockedVerifyError> {
    if now_unix < MIN_PLAUSIBLE_CLOCK {
        return Err(ClockedVerifyError::ClockTooEarly {
            now: now_unix,
            floor: MIN_PLAUSIBLE_CLOCK,
        });
    }
    let bf = BundleFile::from_bytes(sig_bytes).map_err(|_| ClockedVerifyError::BadBundleFile)?;
    let verified = verify_bundle(
        &bf.as_bundle(),
        root_pubkey,
        now_unix,
        artifact_hash,
        expected_purpose,
    )
    .map_err(ClockedVerifyError::Verify)?;
    let ctr = verified.monotonic_ctr();
    if ctr < min_ctr {
        return Err(ClockedVerifyError::CounterBelowFloor {
            got: ctr,
            min: min_ctr,
        });
    }
    Ok(ctr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dragonfruit::{
        Attestation, BundleFile as BF, Delegation, sign_attestation, sign_delegation,
    };
    use ed25519_dalek::SigningKey;
    use sha2::{Digest, Sha256};

                                                                                             
                                                                                                
                                                                
    fn signed_bundle(
        artifact: &[u8],
        purpose: Purpose,
        monotonic_ctr: u64,
        not_before: u64,
        not_after: u64,
    ) -> ([u8; 32], Vec<u8>, [u8; 32]) {
        let root = SigningKey::from_bytes(&[1u8; 32]);
        let worker = SigningKey::from_bytes(&[2u8; 32]);
        let deleg = Delegation {
            worker_pubkey: worker.verifying_key().to_bytes(),
            purpose,
            not_before,
            not_after,
            monotonic_ctr,
        };
        let root_sig = sign_delegation(&root, &deleg);
        let deleg_bytes = deleg.to_canonical();
        let delegation_id: [u8; 32] = Sha256::digest(deleg_bytes).into();
        let artifact_hash: [u8; 32] = Sha256::digest(artifact).into();
        let att = Attestation {
            artifact_hash,
            purpose,
            delegation_id,
        };
        let worker_sig = sign_attestation(&worker, &att);
        let bf = BF {
            delegation_bytes: deleg_bytes,
            root_sig,
            attestation_bytes: att.to_canonical(),
            worker_sig,
        };
        (
            root.verifying_key().to_bytes(),
            bf.to_bytes().to_vec(),
            artifact_hash,
        )
    }

                                                                                                       
    fn signed_backup(artifact: &[u8]) -> ([u8; 32], Vec<u8>, [u8; 32]) {
        signed_bundle(artifact, Purpose::Backup, 0, 0, 100)
    }

                                                                                                         
    fn signed_update(artifact: &[u8], ctr: u64) -> ([u8; 32], Vec<u8>, [u8; 32]) {
        signed_bundle(
            artifact,
            Purpose::UpdateImage,
            ctr,
            MIN_PLAUSIBLE_CLOCK,
            MIN_PLAUSIBLE_CLOCK + 1_000_000,
        )
    }

    /// A wall-clock inside both the plausibility floor and the fixture window.
    const T_VALID: u64 = MIN_PLAUSIBLE_CLOCK + 100;

    #[test]
    fn clocked_rejects_ctr_below_floor() {
        let (root_pub, sig, hash) = signed_update(b"img", 100);
        assert_eq!(
            verify_artifact_clocked(&root_pub, &sig, &hash, Purpose::UpdateImage, 200, T_VALID),
            Err(ClockedVerifyError::CounterBelowFloor { got: 100, min: 200 })
        );
    }

    #[test]
    fn clocked_rejects_early_clock() {
                                                                                           
        let (root_pub, sig, hash) = signed_update(b"img", 100);
        assert_eq!(
            verify_artifact_clocked(
                &root_pub,
                &sig,
                &hash,
                Purpose::UpdateImage,
                0,
                MIN_PLAUSIBLE_CLOCK - 1,
            ),
            Err(ClockedVerifyError::ClockTooEarly {
                now: MIN_PLAUSIBLE_CLOCK - 1,
                floor: MIN_PLAUSIBLE_CLOCK,
            })
        );
    }

    #[test]
    fn clocked_accepts_current() {
        let (root_pub, sig, hash) = signed_update(b"img", 300);
        assert_eq!(
            verify_artifact_clocked(&root_pub, &sig, &hash, Purpose::UpdateImage, 200, T_VALID),
            Ok(300)
        );
    }

    #[test]
    fn clocked_enforces_window() {
                                                                                           
        let (root_pub, sig, hash) = signed_update(b"img", 300);
        assert!(matches!(
            verify_artifact_clocked(
                &root_pub,
                &sig,
                &hash,
                Purpose::UpdateImage,
                0,
                MIN_PLAUSIBLE_CLOCK + 2_000_000,
            ),
            Err(ClockedVerifyError::Verify(VerifyError::WindowExpired))
        ));
    }

    #[test]
    fn clocked_maps_verify_error() {
        let (root_pub, mut sig, hash) = signed_update(b"img", 300);
        sig[60] ^= 0xFF;                                                                
        assert!(matches!(
            verify_artifact_clocked(&root_pub, &sig, &hash, Purpose::UpdateImage, 0, T_VALID),
            Err(ClockedVerifyError::Verify(VerifyError::BadSignature))
        ));
    }

    #[test]
    fn clocked_rejects_malformed_sig() {
        let (root_pub, _, hash) = signed_update(b"img", 300);
        assert_eq!(
            verify_artifact_clocked(
                &root_pub,
                &[0u8; 10],
                &hash,
                Purpose::UpdateImage,
                0,
                T_VALID
            ),
            Err(ClockedVerifyError::BadBundleFile)
        );
    }

    #[test]
    fn accepts_a_correctly_signed_backup_bundle() {
        let (root_pub, sig, hash) = signed_backup(b"persist-backup");
        assert!(verify_artifact(&root_pub, &sig, &hash, Purpose::Backup, 0).is_ok());
    }

    #[test]
    fn rejects_wrong_purpose() {
        let (root_pub, sig, hash) = signed_backup(b"x");
        assert!(matches!(
            verify_artifact(&root_pub, &sig, &hash, Purpose::Img, 0),
            Err(Error::Verify(VerifyError::UnexpectedPurpose { .. }))
        ));
    }

    #[test]
    fn rejects_wrong_artifact_hash() {
        let (root_pub, sig, _) = signed_backup(b"x");
        let other: [u8; 32] = Sha256::digest(b"tampered").into();
        assert!(matches!(
            verify_artifact(&root_pub, &sig, &other, Purpose::Backup, 0),
            Err(Error::Verify(VerifyError::ArtifactHashMismatch))
        ));
    }

    #[test]
    fn rejects_a_malformed_sig_length() {
        let (root_pub, _, hash) = signed_backup(b"x");
        assert_eq!(
            verify_artifact(&root_pub, &[0u8; 10], &hash, Purpose::Backup, 0),
            Err(Error::BadBundleFile)
        );
    }

    #[test]
    fn rejects_a_bad_signature() {
        let (root_pub, mut sig, hash) = signed_backup(b"x");
        sig[60] ^= 0xFF;                                                            
        assert!(matches!(
            verify_artifact(&root_pub, &sig, &hash, Purpose::Backup, 0),
            Err(Error::Verify(VerifyError::BadSignature))
        ));
    }
}

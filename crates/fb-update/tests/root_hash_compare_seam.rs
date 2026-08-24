//! T12 — the R6-1 SEAM: the byte-faithful `root_hash` compare the R6 cert's
//! convergence RESTS on. Both consumers of `record_matches_running` — the every-boot
//! reconcile's PROBATION-SKIP decision (T16) and fb-mark-good's record↔running MATCH
//! (T18) — feed it the record's `root_hash` and the running cmdline's `fb.root-hash`,
//! and the compare must fire on byte-identical pairs and MUST NOT fire on any drifted
//! pair (case, truncation, whitespace). No normalization on either side, ever:
//! the box's cmdline extraction (here `cmdline::root_hash`, mirroring the
//! initramfs-init parser's un-normalized `val.to_string()`) and the record parser
//! both carry the exact wire bytes.
//!
//! Fail-direction note (documented per the plan): a drift here is SAFE-direction —
//! a non-match means "don't skip the reconcile" and "don't commit" (both are
//! don't-touch outcomes, never an accepted downgrade) — but it would break the R5-3
//! probation freeze and the commit path, so this seam LOCKS the byte-exactness.
                            
//! Wired into the verification run via the fb-update suite (never #[ignore]d).

use fb_update::cmdline;
use fb_update::floors::record_matches_running;
use fb_update::{Record, Slot};

const H_LOWER: &str = "4a44dc15364204a80fe80e9039455cc1608281820fe2b24f1e5233ade6af1dd5";

fn probation_record(root_hash: &str) -> Record {
    Record {
        format: 1,
        slot: Slot::B,
        version: 9,
        bundle_ctr: 1000,
        root_hash: root_hash.to_string(),
        deadline_secs: 300,
    }
}

/// A realistic running cmdline (the §4d slot-b APPEND line as the kernel sees it).
fn running_cmdline(hash: &str) -> String {
    format!(
        "initrd=/slot-b/initramfs fb.root-hash={hash} fb.verity-hash-offset=000034603008 \
         fb.rootfs-dev=PARTUUID=a5dff702-a9ff-41a1-9243-30e6136aba95 fb.firmware=seabios-gpt \
         panic=10 ro quiet"
    )
}

/// Drive the compare exactly as BOTH call sites do: extract `fb.root-hash` from the
/// cmdline (un-normalized), then `record_matches_running(record, running_slot, it)`.
fn drive_compare(record: &Record, cmdline_line: &str) -> bool {
    let running_hash = cmdline::root_hash(cmdline_line).expect("cmdline carries fb.root-hash");
    let running_slot = cmdline::running_slot(cmdline_line).expect("cmdline names a slot PARTUUID");
    record_matches_running(record, running_slot, running_hash)
}

#[test]
fn faithful_pair_matches() {
                                                                                          
    let record = probation_record(H_LOWER);
    assert!(drive_compare(&record, &running_cmdline(H_LOWER)));
}

#[test]
fn case_drifted_pair_does_not_match() {
                                                                                    
                                                                                     
                                              
    let upper = H_LOWER.to_uppercase();
    let line = running_cmdline(&upper);
    assert_eq!(
        cmdline::root_hash(&line),
        Some(upper.as_str()),
        "the extractor must not normalize"
    );
    let record = probation_record(H_LOWER);
    assert!(!drive_compare(&record, &line));

                                                                       
    let record_upper = probation_record(&upper);
    assert!(!drive_compare(&record_upper, &running_cmdline(H_LOWER)));
}

#[test]
fn any_byte_drift_does_not_match() {
    let mut drifted = H_LOWER.to_string();
    drifted.replace_range(0..1, "5");
    let record = probation_record(H_LOWER);
    assert!(!drive_compare(&record, &running_cmdline(&drifted)));
}

#[test]
fn slot_mismatch_never_matches_even_with_the_same_hash() {
                                                                                    
    let record = probation_record(H_LOWER);
    let line = running_cmdline(H_LOWER).replace(
        "a5dff702-a9ff-41a1-9243-30e6136aba95",
        "04c92659-e47a-485b-b840-fe5561eaa0da",
    );
    assert!(!drive_compare(&record, &line));
}

#[test]
fn cmdline_extraction_is_last_wins_and_exact() {
                                                                                      
    let line = format!("fb.root-hash={} fb.root-hash={H_LOWER}", "ff".repeat(32));
    assert_eq!(cmdline::root_hash(&line), Some(H_LOWER));
                                                                
    assert_eq!(cmdline::root_hash("ro quiet panic=10"), None);
    assert_eq!(cmdline::running_slot("ro quiet"), None);
}

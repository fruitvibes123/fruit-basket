//! T18: the fb-mark-good decide-core (the 2026-06-22 prototype's 5 cases + the R5-3
//! slot+root_hash tightening + commit idempotency). The pure decide has no I/O; the
//! commit's floor-set + record-clear is idempotent for the row-9 crash-mid-commit rerun.

use fb_update::Record;
use fb_update::Slot;
use fb_update::floors::{MINCTR_FLOOR_FILE, VERSION_FLOOR_FILE, read_floor_strict};
use fb_update::mark_good::{Decision, commit_floors_and_clear, decide};

const RH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const DEADLINE: u64 = 300;

fn record(slot: Slot, root_hash: &str) -> Record {
    Record {
        format: 1,
        slot,
        version: 9,
        bundle_ctr: 1_752_000_500,
        root_hash: root_hash.to_string(),
        deadline_secs: DEADLINE,
    }
}

#[test]
fn no_record_idle() {
    assert_eq!(decide(None, Slot::B, RH, false, 10), Decision::Idle);
    assert_eq!(decide(None, Slot::B, RH, true, 10), Decision::Idle);
}

#[test]
fn match_healthy_commits() {
    let r = record(Slot::B, RH);
    assert_eq!(decide(Some(&r), Slot::B, RH, true, 10), Decision::Commit);
}

#[test]
fn match_unhealthy_within_deadline_probes() {
    let r = record(Slot::B, RH);
    assert_eq!(decide(Some(&r), Slot::B, RH, false, 10), Decision::Probe);
                                                          
    assert_eq!(
        decide(Some(&r), Slot::B, RH, false, DEADLINE - 1),
        Decision::Probe
    );
}

#[test]
fn match_unhealthy_past_deadline_rollbacks() {
    let r = record(Slot::B, RH);
                                                           
    assert_eq!(
        decide(Some(&r), Slot::B, RH, false, DEADLINE),
        Decision::Rollback
    );
    assert_eq!(
        decide(Some(&r), Slot::B, RH, false, DEADLINE + 100),
        Decision::Rollback
    );
}

#[test]
fn match_healthy_past_deadline_still_commits() {
                                                                                        
    let r = record(Slot::B, RH);
    assert_eq!(
        decide(Some(&r), Slot::B, RH, true, DEADLINE + 100),
        Decision::Commit
    );
}

#[test]
fn mismatch_slot_is_stale() {
                                                                                   
    let r = record(Slot::B, RH);
    assert_eq!(decide(Some(&r), Slot::A, RH, true, 10), Decision::Stale);
}

#[test]
fn mismatch_root_hash_is_stale() {
                                                                                 
                                                                                      
                                                                             
                                                   
    let r = record(Slot::B, RH);
    let other = "ff".repeat(32);
    assert_eq!(decide(Some(&r), Slot::B, &other, true, 10), Decision::Stale);
                                                                                  
    let upper = RH.to_uppercase();
    assert_eq!(decide(Some(&r), Slot::B, &upper, true, 10), Decision::Stale);
}

#[test]
fn commit_is_idempotent_on_rerun() {
                                                                                        
                                                                                       
                             
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(VERSION_FLOOR_FILE), "5\n").unwrap();
    std::fs::write(dir.path().join(MINCTR_FLOOR_FILE), "1700000000\n").unwrap();
    let r = record(Slot::B, RH);                                

    commit_floors_and_clear(dir.path(), &r).unwrap();
    assert_eq!(
        read_floor_strict(&dir.path().join(VERSION_FLOOR_FILE)),
        Ok(9)
    );
    assert_eq!(
        read_floor_strict(&dir.path().join(MINCTR_FLOOR_FILE)),
        Ok(1_752_000_500)
    );
    assert!(
        !dir.path().join("record").exists(),
        "record cleared on commit"
    );

                                                                                    
    std::fs::write(dir.path().join("record"), r.to_bytes()).unwrap();
    commit_floors_and_clear(dir.path(), &r).unwrap();
    assert_eq!(
        read_floor_strict(&dir.path().join(VERSION_FLOOR_FILE)),
        Ok(9)
    );
    assert!(!dir.path().join("record").exists());
}

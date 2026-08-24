//! T16: the probation-aware floor reconcile (spec §4f) — the anti-rollback lifecycle
//! keystone. Genesis seeds from the baked rootfs values; a normal boot maxes; a
//! PROBATION boot (record matches the running slot+root_hash) FREEZES the floors
//! (R5-3); a matching record with a vanished floor is damaged state ⇒ Rescue (R6-2);
//! an unreadable rootfs is fail-closed ⇒ Rescue.

use fb_update::Record;
use fb_update::Slot;
use fb_update::floors::{
    MINCTR_FLOOR_FILE, ReconcileError, VERSION_FLOOR_FILE, read_floor_strict, reconcile_floors,
};

const BAKED_VERSION: u64 = 7;
const BAKED_MINCTR: u64 = 1_752_000_000;
const RH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn floors(dir: &std::path::Path) -> (Option<u64>, Option<u64>) {
    let r = |f: &str| read_floor_strict(&dir.join(f)).ok();
    (r(VERSION_FLOOR_FILE), r(MINCTR_FLOOR_FILE))
}

fn write_floor(dir: &std::path::Path, f: &str, v: u64) {
    std::fs::write(dir.join(f), format!("{v}\n")).unwrap();
}

fn probation_record(dir: &std::path::Path, slot: Slot, root_hash: &str, version: u64) {
    let rec = Record {
        format: 1,
        slot,
        version,
        bundle_ctr: BAKED_MINCTR + 500,
        root_hash: root_hash.to_string(),
        deadline_secs: 300,
    };
    std::fs::write(dir.join("record"), rec.to_bytes()).unwrap();
}

#[test]
fn reconcile_seeds_genesis() {
    let dir = tempfile::tempdir().unwrap();
    reconcile_floors(dir.path(), BAKED_VERSION, BAKED_MINCTR, Some((Slot::A, RH))).unwrap();
    assert_eq!(floors(dir.path()), (Some(7), Some(1_752_000_000)));
}

#[test]
fn reconcile_maxes_on_normal_boot() {
    let dir = tempfile::tempdir().unwrap();
                                                                                 
                                                        
    write_floor(dir.path(), VERSION_FLOOR_FILE, 5);
    write_floor(dir.path(), MINCTR_FLOOR_FILE, 1_700_000_000);
    reconcile_floors(dir.path(), BAKED_VERSION, BAKED_MINCTR, Some((Slot::A, RH))).unwrap();
    assert_eq!(floors(dir.path()), (Some(7), Some(1_752_000_000)));

                                                                   
    write_floor(dir.path(), VERSION_FLOOR_FILE, 9);
    write_floor(dir.path(), MINCTR_FLOOR_FILE, 1_800_000_000);
    reconcile_floors(dir.path(), BAKED_VERSION, BAKED_MINCTR, Some((Slot::A, RH))).unwrap();
    assert_eq!(floors(dir.path()), (Some(9), Some(1_800_000_000)));
}

#[test]
fn reconcile_skips_on_matching_record() {
                                                                                          
                                                                                         
                                                                                 
    let dir = tempfile::tempdir().unwrap();
    write_floor(dir.path(), VERSION_FLOOR_FILE, 5);
    write_floor(dir.path(), MINCTR_FLOOR_FILE, 1_700_000_000);
    probation_record(dir.path(), Slot::A, RH, BAKED_VERSION);
    reconcile_floors(dir.path(), BAKED_VERSION, BAKED_MINCTR, Some((Slot::A, RH))).unwrap();
                                                                               
    assert_eq!(floors(dir.path()), (Some(5), Some(1_700_000_000)));
}

#[test]
fn reconcile_does_not_skip_on_a_stale_nonmatching_record() {
                                                                                      
                                                                                      
    let dir = tempfile::tempdir().unwrap();
    write_floor(dir.path(), VERSION_FLOOR_FILE, 5);
    write_floor(dir.path(), MINCTR_FLOOR_FILE, 1_700_000_000);
    let other_hash = "ff".repeat(32);
    probation_record(dir.path(), Slot::A, &other_hash, 6);
    reconcile_floors(dir.path(), BAKED_VERSION, BAKED_MINCTR, Some((Slot::A, RH))).unwrap();
    assert_eq!(
        floors(dir.path()),
        (Some(7), Some(1_752_000_000)),
        "maxed, not frozen"
    );
}

#[test]
fn reconcile_rescue_on_absent_floor_with_matching_record() {
                                                                                    
                                                                                       
                                                                    
    let dir = tempfile::tempdir().unwrap();
    write_floor(dir.path(), MINCTR_FLOOR_FILE, 1_700_000_000);
                           
    probation_record(dir.path(), Slot::A, RH, BAKED_VERSION);
    let err = reconcile_floors(dir.path(), BAKED_VERSION, BAKED_MINCTR, Some((Slot::A, RH)))
        .expect_err("absent floor + matching record ⇒ Rescue");
    assert!(matches!(
        err,
        ReconcileError::AbsentFloorWithMatchingRecord(_)
    ));
}

#[test]
fn reconcile_rescue_on_malformed_floor() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(VERSION_FLOOR_FILE), "garbage\n").unwrap();
    write_floor(dir.path(), MINCTR_FLOOR_FILE, 1_700_000_000);
    let err = reconcile_floors(dir.path(), BAKED_VERSION, BAKED_MINCTR, Some((Slot::A, RH)))
        .expect_err("malformed floor ⇒ fail-closed");
    assert!(matches!(err, ReconcileError::MalformedFloor(_)));
}

#[test]
fn reconcile_rescue_on_malformed_record() {
                                                                                                 
                                                                                                     
                                                                                                  
    let dir = tempfile::tempdir().unwrap();
    write_floor(dir.path(), VERSION_FLOOR_FILE, 3);
    write_floor(dir.path(), MINCTR_FLOOR_FILE, 1_700_000_000);
    std::fs::write(dir.path().join("record"), b"not a valid record\n").unwrap();
    let err = reconcile_floors(dir.path(), BAKED_VERSION, BAKED_MINCTR, Some((Slot::A, RH)))
        .expect_err("malformed record ⇒ Rescue");
    assert!(matches!(err, ReconcileError::MalformedRecord));
                                                                    
    assert_eq!(
        floors(dir.path()).0,
        Some(3),
        "floor must not advance on a damaged record"
    );
}

#[test]
fn reconcile_absent_record_is_a_normal_boot() {
                                                                                                 
    let dir = tempfile::tempdir().unwrap();
    write_floor(dir.path(), VERSION_FLOOR_FILE, 1);
    write_floor(dir.path(), MINCTR_FLOOR_FILE, 1_700_000_000);
    reconcile_floors(dir.path(), BAKED_VERSION, BAKED_MINCTR, Some((Slot::A, RH))).unwrap();
    assert_eq!(
        floors(dir.path()).0,
        Some(BAKED_VERSION),
        "absent record ⇒ normal max"
    );
}

#[test]
fn reconcile_non_ab_box_seeds_normally() {
                                                                                         
                                                                                  
                          
    let dir = tempfile::tempdir().unwrap();
    reconcile_floors(dir.path(), BAKED_VERSION, BAKED_MINCTR, None).unwrap();
    assert_eq!(floors(dir.path()), (Some(7), Some(1_752_000_000)));
}

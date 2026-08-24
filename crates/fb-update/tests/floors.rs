//! T9: the two-floor logic — apply's fail-closed read (absent/malformed ⇒ Err, NEVER
//! 0 — R4-2), the probation-aware reconcile (R5-3 skip), commit's set-not-increment,
//! and the byte-exact record↔running match (R6-1). The R6 cert's floor-monotonicity
//! invariant gets a sweep test: `reconcile_floor` NEVER returns below `stored`.

use fb_update::floors::{
    FloorError, commit_set, read_floor_strict, reconcile_floor, record_matches_running,
    write_floor_atomic,
};
use fb_update::{Record, Slot};

fn record(slot: Slot, root_hash: &str) -> Record {
    Record {
        format: 1,
        slot,
        version: 7,
        bundle_ctr: 100,
        root_hash: root_hash.to_string(),
        deadline_secs: 300,
    }
}

#[test]
fn read_strict_absent_is_err() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        read_floor_strict(&dir.path().join("version-floor")),
        Err(FloorError::Absent)
    );
}

#[test]
fn read_strict_malformed_is_err() {
    let dir = tempfile::tempdir().unwrap();
    for bad in ["", "abc", "-3", "5 ", " 5", "5\n\n", "5x\n"] {
        let p = dir.path().join("floor");
        std::fs::write(&p, bad).unwrap();
        assert_eq!(
            read_floor_strict(&p),
            Err(FloorError::Malformed),
            "content {bad:?} must be Malformed, never a value (and NEVER 0)"
        );
    }
}

#[test]
fn read_strict_reads_canonical() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("floor");
    std::fs::write(&p, "42\n").unwrap();
    assert_eq!(read_floor_strict(&p), Ok(42));
                                                                    
    std::fs::write(&p, "42").unwrap();
    assert_eq!(read_floor_strict(&p), Ok(42));
}

#[test]
fn write_then_read_roundtrips_durably() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("version-floor");
    write_floor_atomic(&p, 7).unwrap();
    assert_eq!(read_floor_strict(&p), Ok(7));
                          
    let names: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, vec!["version-floor".to_string()]);
}

#[test]
fn reconcile_no_record_maxes() {
                                                                                    
                                                                                       
    assert_eq!(reconcile_floor(Some(5), 6, false), 6);
    assert_eq!(reconcile_floor(Some(6), 5, false), 6);
    assert_eq!(reconcile_floor(None, 5, false), 5);
}

#[test]
fn reconcile_matching_record_skips() {
                                                                                    
                                                                                        
                                                                                     
    assert_eq!(reconcile_floor(Some(5), 6, true), 5);
}

#[test]
fn commit_set_advances_never_regresses() {
    assert_eq!(commit_set(5, 6), 6);
                                                                       
    assert_eq!(commit_set(6, 6), 6);
}

#[test]
fn record_matches_is_byte_exact() {
    let lower = "0123456789abcdef".repeat(4);
    let upper = "0123456789ABCDEF".repeat(4);
    let r = record(Slot::B, &lower);
    assert!(record_matches_running(&r, Slot::B, &lower));
                                           
    assert!(!record_matches_running(&r, Slot::A, &lower));
                                                                             
                                          
    assert!(!record_matches_running(&r, Slot::B, &upper));
                                         
    let mut drifted = lower.clone();
    drifted.replace_range(0..1, "f");
    assert!(!record_matches_running(&r, Slot::B, &drifted));
}

#[test]
fn reconcile_never_lowers_the_floor() {
                                                                                      
                                                                                 
                                                                                          
                                                                                  
    let grid = [0u64, 1, 2, 5, 1_000_000, u64::MAX - 1, u64::MAX];
    for &baked in &grid {
        for &stored in &grid {
            assert!(reconcile_floor(Some(stored), baked, false) >= stored);
            assert_eq!(reconcile_floor(Some(stored), baked, true), stored);
        }
                                                     
        assert_eq!(reconcile_floor(None, baked, false), baked);
    }
}

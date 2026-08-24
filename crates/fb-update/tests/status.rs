//! T15: the `fb-update status` machine-readable block (spec §4g) — every documented key
//! present, values correct, no secret material; a missing floor is REPORTED (status is a
//! read tool, distinct from apply's fail-closed refuse).

use fb_update::status::{StatusInputs, render_status};

fn base(tmp: &std::path::Path) -> StatusInputs {
    StatusInputs {
        cmdline: "ro fb.root-hash=aa fb.rootfs-dev=PARTUUID=a5dff702-a9ff-41a1-9243-30e6136aba95 \
                  fb.firmware=seabios-gpt panic=10"
            .to_string(),
        rootfs_etc: tmp.join("etc-recipes"),
        update_dir: tmp.join("update"),
        backup_dir: tmp.join("backup"),
        uptime_secs: 4242,
    }
}

/// Lay down a healthy running box: baked version/ctr on the rootfs, both floors seeded,
/// no probation, a recent backup.
fn healthy(tmp: &std::path::Path) {
    let etc = tmp.join("etc-recipes");
    std::fs::create_dir_all(&etc).unwrap();
    std::fs::write(etc.join("image-version"), "7\n").unwrap();
    std::fs::write(etc.join("min-delegation-ctr"), "1752000000\n").unwrap();
    let up = tmp.join("update");
    std::fs::create_dir_all(&up).unwrap();
    std::fs::write(up.join("version-floor"), "7\n").unwrap();
    std::fs::write(up.join("minctr-floor"), "1752000000\n").unwrap();
    let bk = tmp.join("backup");
    std::fs::create_dir_all(&bk).unwrap();
    std::fs::write(bk.join("persist-backup.tar"), b"x").unwrap();
}

fn field<'a>(block: &'a str, key: &str) -> Option<&'a str> {
    block
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{key} = ")))
}

#[test]
fn status_block_has_every_documented_key() {
    let tmp = tempfile::tempdir().unwrap();
    healthy(tmp.path());
    let block = render_status(&base(tmp.path()));

    assert_eq!(field(&block, "active_slot"), Some("slot-b"));
    assert_eq!(field(&block, "firmware"), Some("seabios-gpt"));
    assert_eq!(field(&block, "image_version"), Some("7"));
    assert_eq!(field(&block, "min_delegation_ctr"), Some("1752000000"));
    assert_eq!(field(&block, "version_floor"), Some("7"));
    assert_eq!(field(&block, "minctr_floor"), Some("1752000000"));
    assert_eq!(field(&block, "probation"), Some("none"));
    assert_eq!(field(&block, "last_failure"), Some("none"));
    assert_eq!(field(&block, "uptime_secs"), Some("4242"));
    assert_eq!(field(&block, "floor_health"), Some("ok"));
                                                            
    assert!(
        field(&block, "backup_age_secs")
            .unwrap()
            .parse::<u64>()
            .is_ok()
    );
                                                
    assert!(!block.contains("artifact-root"));
    assert!(!block.to_lowercase().contains("key"));
}

#[test]
fn status_reports_probation_when_a_record_exists() {
    let tmp = tempfile::tempdir().unwrap();
    healthy(tmp.path());
    let rec = fb_update::Record {
        format: 1,
        slot: fb_update::Slot::A,
        version: 9,
        bundle_ctr: 1752000500,
        root_hash: "cd".repeat(32),
        deadline_secs: 300,
    };
    std::fs::write(tmp.path().join("update/record"), rec.to_bytes()).unwrap();
    let block = render_status(&base(tmp.path()));
                                                                
    let p = field(&block, "probation").unwrap();
    assert!(
        p.contains("slot-a"),
        "probation shows the candidate slot: {p}"
    );
    assert!(
        p.contains('9'),
        "probation shows the candidate version: {p}"
    );
}

#[test]
fn status_reports_absent_floor_health_without_crashing() {
    let tmp = tempfile::tempdir().unwrap();
    healthy(tmp.path());
    std::fs::remove_file(tmp.path().join("update/version-floor")).unwrap();
                                                                              
    let block = render_status(&base(tmp.path()));
    assert_eq!(
        field(&block, "floor_health"),
        Some("version-floor-unavailable")
    );
    assert_eq!(field(&block, "version_floor"), Some("unavailable"));
                                                 
    assert_eq!(field(&block, "minctr_floor"), Some("1752000000"));
}

#[test]
fn status_active_slot_unknown_on_a_non_ab_box() {
                                                                                    
    let tmp = tempfile::tempdir().unwrap();
    healthy(tmp.path());
    let mut inp = base(tmp.path());
    inp.cmdline = "ro fb.rootfs-dev=/dev/vda3 fb.firmware=seabios panic=10".to_string();
    let block = render_status(&inp);
    assert_eq!(field(&block, "active_slot"), Some("unknown"));
    assert_eq!(field(&block, "firmware"), Some("seabios"));
}

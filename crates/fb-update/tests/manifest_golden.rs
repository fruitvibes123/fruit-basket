//! T8 goldens: the §4a update-manifest parser (whitelist, fail-closed — unknown/duplicate
//! keys REFUSE, all 12 fields required, values strictly typed) + the Slot/Record core
//! types (the probation-record wire shape + the tmp+rename durable write).

use fb_update::manifest::{ManifestError, parse_manifest};
use fb_update::{Record, SLOT_A_PARTUUID, SLOT_B_PARTUUID, Slot, write_record_atomic};

/// 64 lowercase hex chars built from a 2-char pattern (decodes to [byte; 32]).
fn h(pattern: &str) -> String {
    pattern.repeat(32)
}

/// The canonical §4a manifest — every key, spec order, trailing LF.
fn canonical() -> String {
    format!(
        "format = 1\n\
         firmware = seabios-gpt\n\
         version = 7\n\
         image_sha256 = {img}\n\
         root_hash = {root}\n\
         verity_hash_offset = 34603008\n\
         rootfs_sha256 = {rootfs}\n\
         rootfs_size = 33554432\n\
         kernel_sha256 = {kernel}\n\
         kernel_size = 9437184\n\
         initramfs_sha256 = {initrd}\n\
         initramfs_size = 2097152\n",
        img = h("ab"),
        root = "0123456789abcdef".repeat(4),
        rootfs = h("cd"),
        kernel = h("ef"),
        initrd = h("12"),
    )
}

#[test]
fn parses_canonical() {
    let m = parse_manifest(canonical().as_bytes()).expect("canonical manifest parses");
    assert_eq!(m.format, 1);
    assert_eq!(m.firmware, "seabios-gpt");
    assert_eq!(m.version, 7);
    assert_eq!(m.image_sha256, [0xAB; 32]);
    assert_eq!(m.root_hash, "0123456789abcdef".repeat(4));
    assert_eq!(m.verity_hash_offset, 34_603_008);
    assert_eq!(m.rootfs_sha256, [0xCD; 32]);
    assert_eq!(m.rootfs_size, 33_554_432);
    assert_eq!(m.kernel_sha256, [0xEF; 32]);
    assert_eq!(m.kernel_size, 9_437_184);
    assert_eq!(m.initramfs_sha256, [0x12; 32]);
    assert_eq!(m.initramfs_size, 2_097_152);
}

#[test]
fn rejects_unknown_key() {
    let doc = format!("{}weights_size = 5\n", canonical());
    assert_eq!(
        parse_manifest(doc.as_bytes()),
        Err(ManifestError::UnknownKey("weights_size".into()))
    );
}

#[test]
fn rejects_duplicate_key() {
    let doc = format!("{}version = 8\n", canonical());
    assert_eq!(
        parse_manifest(doc.as_bytes()),
        Err(ManifestError::DuplicateKey("version".into()))
    );
}

#[test]
fn rejects_missing_field() {
    let doc = canonical()
        .lines()
        .filter(|l| !l.starts_with("kernel_size"))
        .map(|l| format!("{l}\n"))
        .collect::<String>();
    assert_eq!(
        parse_manifest(doc.as_bytes()),
        Err(ManifestError::MissingKey("kernel_size"))
    );
}

#[test]
fn rejects_bad_version() {
    let doc = canonical().replace("version = 7", "version = seven");
    assert_eq!(
        parse_manifest(doc.as_bytes()),
        Err(ManifestError::BadValue { key: "version" })
    );
}

#[test]
fn rejects_unsupported_format() {
    let doc = canonical().replace("format = 1", "format = 2");
    assert_eq!(
        parse_manifest(doc.as_bytes()),
        Err(ManifestError::BadFormat)
    );
}

#[test]
fn root_hash_must_be_64_lowercase_hex() {
                                                                                     
                                                                                           
    let upper = canonical().replace(&"0123456789abcdef".repeat(4), &"0123456789ABCDEF".repeat(4));
    assert_eq!(
        parse_manifest(upper.as_bytes()),
        Err(ManifestError::BadValue { key: "root_hash" })
    );
    let short = canonical().replace(
        &"0123456789abcdef".repeat(4),
        &"0123456789abcdef".repeat(4)[..63],
    );
    assert_eq!(
        parse_manifest(short.as_bytes()),
        Err(ManifestError::BadValue { key: "root_hash" })
    );
}

#[test]
fn rejects_structural_garbage() {
                                                                                      
    let doc = format!("{}garbage-line\n", canonical());
    assert_eq!(
        parse_manifest(doc.as_bytes()),
        Err(ManifestError::BadFormat)
    );
    let no_lf = canonical();
    let no_lf = &no_lf.as_bytes()[..no_lf.len() - 1];
    assert_eq!(parse_manifest(no_lf), Err(ManifestError::BadFormat));
    assert_eq!(parse_manifest(b""), Err(ManifestError::BadFormat));
    assert_eq!(parse_manifest(&[0xFF, 0xFE]), Err(ManifestError::BadFormat));
}

#[test]
fn slot_constants_are_the_spec_values() {
    assert_eq!(Slot::A.as_str(), "slot-a");
    assert_eq!(Slot::B.as_str(), "slot-b");
    assert_eq!(Slot::A.partuuid(), SLOT_A_PARTUUID);
    assert_eq!(Slot::B.partuuid(), SLOT_B_PARTUUID);
    assert_eq!(SLOT_A_PARTUUID, "04c92659-e47a-485b-b840-fe5561eaa0da");
    assert_eq!(SLOT_B_PARTUUID, "a5dff702-a9ff-41a1-9243-30e6136aba95");
    assert_eq!(Slot::A.other(), Slot::B);
    assert_eq!(Slot::B.other(), Slot::A);
}

#[test]
fn record_roundtrips() {
    let r = Record {
        format: 1,
        slot: Slot::B,
        version: 7,
        bundle_ctr: 1_752_500_000,
        root_hash: "0123456789abcdef".repeat(4),
        deadline_secs: 300,
    };
    let bytes = r.to_bytes();
    let back = Record::parse(&bytes).expect("serialized record parses");
    assert_eq!(back, r);
}

#[test]
fn record_rejects_unknown_and_malformed() {
    let r = Record {
        format: 1,
        slot: Slot::A,
        version: 1,
        bundle_ctr: 2,
        root_hash: h("ab"),
        deadline_secs: 300,
    };
    let mut doc = String::from_utf8(r.to_bytes()).unwrap();
    doc.push_str("extra = 1\n");
    assert_eq!(
        Record::parse(doc.as_bytes()),
        Err(ManifestError::UnknownKey("extra".into()))
    );
                                                                                  
    let bad_slot = String::from_utf8(r.to_bytes())
        .unwrap()
        .replace("slot = slot-a", "slot = slot-c");
    assert_eq!(
        Record::parse(bad_slot.as_bytes()),
        Err(ManifestError::BadValue { key: "slot" })
    );
}

#[test]
fn write_record_atomic_leaves_only_the_record() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("record");
    let r = Record {
        format: 1,
        slot: Slot::B,
        version: 3,
        bundle_ctr: 9,
        root_hash: h("cd"),
        deadline_secs: 300,
    };
    write_record_atomic(&path, &r).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), r.to_bytes());
                                                                 
    let names: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, vec!["record".to_string()]);
}

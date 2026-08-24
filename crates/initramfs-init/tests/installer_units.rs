//! Host-runnable units for the initramfs-init installer-mode path (deploy-and-transition).
//! The full install is exercised in the QEMU install run; these cover the pure logic: the
//! install-source cmdline grammar, the partition-layout math, the 3-component `.img` `.layout.toml`
//! parse/slice/fit, the MBR serialization, and the install state-machine's invariants —
                     
//! restore-verify-before-write, mount-fail-abort-before-write, the dd-only
//! bootable-last commit ordering, and orderly fail-closed mid-commit failure.

use dragonfruit::{
    Attestation, BundleFile, Delegation, Purpose, sign_attestation, sign_delegation,
};
use ed25519_dalek::SigningKey;
use initramfs_init::install_target::DiskInfo;
use initramfs_init::installer::{
    DiskSource, Firmware, INSTALLER_DATA_PARTUUID, ImageLayout, InstallComponent, InstallOps,
    InstallParams, InstallSource, InstallSources, InstallerError, MAX_RESTORE_IMAGE_BYTES,
    MAX_RESTORE_SIG_BYTES, Partition, PartitionLayout, PartitionTable, SECTOR_SIZE,
    SLOT_A_PARTUUID, build_gpt, build_mbr_sector, check_components_fit, compute_partition_layout,
    disk_from_partition, find_partition_by_partuuid, gpt_header_crc_valid, guid_to_mixed_endian,
    installer_sources, layout_sidecar_path, parse_image_layout, parse_install_sources,
    parse_meminfo_total, restore_cap, run_install, sha2_256,
};
use initramfs_init::installer_stream::{
    ComponentDigests, ComponentSpans, INSTALL_COPY_CHUNK_BYTES, RawRegion, SourceHandle,
    check_spans_in_bounds, copy_and_verify, digest_prepass, readback_verify,
};
use initramfs_init::installer_syscall::{
    SyscallInstallOps, open_regular_nofollow, read_regular_capped,
};
use sha2::{Digest, Sha256};

#[test]
fn parses_greenfield_image_raw() {
                                                                                                
                                                                                  
    let cmdline = format!(
        "fb.mode=installer fb.root-hash=ab fb.verity-hash-offset=4096 \
         fb.image-raw={RAW_WINDOW} fb.image-layout={STD_LAYOUT_TOKEN} \
         lockdown=integrity ima_appraise=enforce"
    );
    let srcs =
        parse_install_sources(&cmdline, Firmware::Seabios).expect("valid greenfield cmdline");
    let InstallSource::RawRegion { region, layout } = &srcs.source else {
        panic!("expected the RawRegion source, got {:?}", srcs.source);
    };
    assert_eq!(
        *region,
        RawRegion {
            disk: "vda".into(),
            offset: 10_737_418_240,
            len: 1024
        }
    );
    assert_eq!(layout.firmware, Firmware::Seabios);
    assert_eq!(layout.rootfs, (512, 512));
    assert_eq!(srcs.restore_from, None);
}

#[test]
fn fb_min_ctr_parses_strict_u64_absent_is_zero_garbage_refuses() {
                                                                                             
                                                 
    let s = parse_install_sources(
        &std_cmdline("fb.restore-from=disk:vda1:/r.img fb.min-ctr=42"),
        Firmware::Seabios,
    )
    .unwrap();
    assert_eq!(s.min_ctr, 42);
                                                                   
    let s = parse_install_sources(&std_cmdline(""), Firmware::Seabios).unwrap();
    assert_eq!(s.min_ctr, 0);
                                                                                           
    let s = parse_install_sources(&std_cmdline("fb.min-ctr="), Firmware::Seabios).unwrap();
    assert_eq!(s.min_ctr, 0);
                                                                                       
                                                                                         
                            
    for bad in [
        "fb.min-ctr=-1",
        "fb.min-ctr=1x",
        "fb.min-ctr=99999999999999999999999",
    ] {
        let cmd = std_cmdline(&format!("fb.restore-from=disk:vda1:/r.img {bad}"));
        assert!(
            parse_install_sources(&cmd, Firmware::Seabios).is_err(),
            "accepted {bad}"
        );
    }
                                                                                                
                                                                                  
    assert!(parse_install_sources(&std_cmdline("fb.min-ctr=1"), Firmware::Seabios).is_err());
}

#[test]
fn parse_install_sources_yields_rawregion_variant() {
                                                                     
                                                                                                   
                                                                                            
                                                                                                 
    let p = parse_install_sources(&gpt_cmdline(""), Firmware::SeabiosGpt).unwrap();
    assert!(
        matches!(
            &p.source,
            InstallSource::RawRegion { region, layout }
                if region.disk == "vda" && layout.firmware == Firmware::SeabiosGpt
        ),
        "got {:?}",
        p.source
    );
}

#[test]
fn uefi_installer_arm_needs_no_raw_tokens() {
                                                                                                      
                                                                                                       
                                                                                                  
                                                                  
    let srcs = installer_sources(
        Firmware::Uefi,
        "fb.mode=installer fb.firmware=uefi fb.image-sha256=ab fb.root-hash=cd \
         fb.verity-hash-offset=4096",
    )
    .expect("UEFI installer arm must not require fb.image-raw");
    assert_eq!(srcs.source, InstallSource::BuiltinDataPartuuid);
    assert_eq!(srcs.restore_from, None);
}

#[test]
fn seabios_installer_arm_still_requires_image_raw() {
                                                                                                 
                                                                                                 
                                                          
    let err = installer_sources(
        Firmware::Seabios,
        "fb.mode=installer fb.root-hash=ab fb.verity-hash-offset=4096",
    )
    .unwrap_err();
    assert_eq!(err, InstallerError::MissingImageRaw);
                                                                                                 
    let err = installer_sources(
        Firmware::Seabios,
        &format!("fb.mode=installer fb.image-raw={RAW_WINDOW}"),
    )
    .unwrap_err();
    assert_eq!(err, InstallerError::MissingImageLayout);
                                                                                                
    let err = installer_sources(Firmware::SeabiosGpt, &std_cmdline("")).unwrap_err();
    assert!(
        matches!(err, InstallerError::FirmwareTokenMismatch { .. }),
        "got {err:?}"
    );
}

#[test]
fn uefi_prepare_reads_box_img_from_builtin_data_partuuid() {
                                                                                  
                                                                                            
                                                                                                     
                                                                                                 
    let sources = installer_sources(Firmware::Uefi, "").expect("uefi sources");
    let mut fake = FakeInstallOps::new_uefi();
                                                                                                      
    let params = InstallParams {
        sources: &sources,
        operator_root_pubkey_hex: b"",
        image_sha256: Some(sha2_256(&staged_image())),
        install_to: None,
    };
    run_install(&mut fake, &params).expect("uefi builtin-source install runs over the fake");
    assert!(
        fake.ops.contains(&OpKind::ResolvePartuuid(
            INSTALLER_DATA_PARTUUID.to_string()
        )),
        "expected ResolvePartuuid(INSTALLER_DATA_PARTUUID), ops: {:?}",
        fake.ops
    );
                                                                                                       
                                                               
    assert!(fake.ops.contains(&OpKind::MountDataPartition));
    assert!(!fake.ops.contains(&OpKind::MountOldRoot));
                                                                                               
                                                                                         
    assert!(
        fake.ops
            .contains(&OpKind::ReadFile("/box.layout.toml".to_string()))
    );
    assert!(
        !fake.ops.contains(&OpKind::ReadFile("/box.img".to_string())),
        "the .img must never pass through the whole-file read: {:?}",
        fake.ops
    );
    assert!(fake.ops.contains(&OpKind::ReadSourceChunk));
}

#[test]
fn uefi_prepare_halts_on_image_digest_mismatch_before_any_write() {
                                                                                               
                                                                                                   
                                                                                             
    let sources = installer_sources(Firmware::Uefi, "").unwrap();
    let mut fake = FakeInstallOps::new_uefi();
    let params = InstallParams {
        sources: &sources,
        operator_root_pubkey_hex: b"",
        image_sha256: Some([0xAB; 32]),                                               
        install_to: None,
    };
    let err = run_install(&mut fake, &params).unwrap_err();
    assert!(
        matches!(err, InstallerError::StagedImageDigestMismatch { .. }),
        "expected a digest-mismatch halt, got {err:?}"
    );
    assert!(
        !fake.did_destructive(),
        "no destructive write may precede the digest check; ops: {:?}",
        fake.ops
    );
}

#[test]
fn uefi_prepare_proceeds_on_image_digest_match() {
                                                                                                   
    let sources = installer_sources(Firmware::Uefi, "").unwrap();
    let mut fake = FakeInstallOps::new_uefi();
    let params = InstallParams {
        sources: &sources,
        operator_root_pubkey_hex: b"",
        image_sha256: Some(sha2_256(&staged_image())),                      
        install_to: None,
    };
    run_install(&mut fake, &params).expect("digest match → install proceeds");
    assert!(fake.ops.contains(&OpKind::WritePartitionTable));
}

#[test]
fn uefi_run_install_selects_independent_target_then_commits() {
                                                                                                      
                                                                                                        
    let sources = installer_sources(Firmware::Uefi, "").unwrap();
    let mut fake = FakeInstallOps::new_uefi();                                                                 
    let params = InstallParams {
        sources: &sources,
        operator_root_pubkey_hex: b"",
        image_sha256: Some(sha2_256(&staged_image())),
        install_to: None,
    };
    run_install(&mut fake, &params).expect("uefi install proceeds");
    assert!(fake.ops.contains(&OpKind::EnumerateDisks));
    assert_eq!(
        fake.target_disk.as_deref(),
        Some("nvme0n1"),
        "destructive target must be the independent fixed disk, never the source (sda)"
    );
    assert!(
        fake.ops
            .contains(&OpKind::SetTargetDisk("nvme0n1".to_string()))
    );
}

#[test]
fn uefi_run_install_halts_on_ambiguous_target_before_any_write() {
                                                                                                
    let sources = installer_sources(Firmware::Uefi, "").unwrap();
    let mut fake = FakeInstallOps::new_uefi();
    fake.enumerated_disks = vec![
        DiskInfo {
            name: "sda".into(),
            class_ok: true,
            removable: true,
        },              
        DiskInfo {
            name: "nvme0n1".into(),
            class_ok: true,
            removable: false,
        },
        DiskInfo {
            name: "nvme1n1".into(),
            class_ok: true,
            removable: false,
        },
    ];
    let params = InstallParams {
        sources: &sources,
        operator_root_pubkey_hex: b"",
        image_sha256: Some(sha2_256(&staged_image())),
        install_to: None,
    };
    let err = run_install(&mut fake, &params).unwrap_err();
    assert!(
        matches!(err, InstallerError::OpFailed { op, .. } if op == "select-target"),
        "expected a select-target halt, got {err:?}"
    );
    assert!(
        !fake.did_destructive(),
        "an ambiguous target must halt before any write; ops: {:?}",
        fake.ops
    );
    assert_eq!(fake.target_disk, None, "no target set on an ambiguous halt");
}

#[test]
fn uefi_prepare_halts_on_layout_firmware_mismatch_before_any_write() {
                                                                                                 
                                                                                                         
                                                                                                          
                                                                                                           
                                                                                         
    let sources = installer_sources(Firmware::Uefi, "").unwrap();                       
    let mut fake = FakeInstallOps::new();
    fake.layout_toml = FAKE_LAYOUT_TOML_UEFI.replace("\"uefi\"", "\"seabios\"");
    let params = InstallParams {
        sources: &sources,
        operator_root_pubkey_hex: b"",
        image_sha256: Some(sha2_256(&staged_image())),                                               
        install_to: None,
    };
    let err = run_install(&mut fake, &params).unwrap_err();
    assert!(
        matches!(err, InstallerError::OpFailed { op, .. } if op == "verify-image-firmware"),
        "expected a layout-firmware-mismatch halt, got {err:?}"
    );
    assert!(
        !fake.did_destructive(),
        "a layout/firmware mismatch must abort before any write; ops: {:?}",
        fake.ops
    );
}

#[test]
fn uefi_prepare_halts_on_seabios_gpt_layout_before_any_write() {
                                                                                                            
                                                                                    
                                                                                                            
                                                                                                              
                                                                                           
                                           
    let sources = installer_sources(Firmware::Uefi, "").unwrap();                       
    let mut fake = FakeInstallOps::new();
    fake.layout_toml = FAKE_LAYOUT_TOML_UEFI.replace("\"uefi\"", "\"seabios-gpt\"");
    let params = InstallParams {
        sources: &sources,
        operator_root_pubkey_hex: b"",
        image_sha256: Some(sha2_256(&staged_image())),                                               
        install_to: None,
    };
    let err = run_install(&mut fake, &params).unwrap_err();
    assert!(
        matches!(err, InstallerError::OpFailed { op, .. } if op == "verify-image-firmware"),
        "a seabios-gpt layout on the UEFI arm must halt at verify-image-firmware, got {err:?}"
    );
    assert!(
        !fake.did_destructive(),
        "a (BuiltinDataPartuuid, SeabiosGpt) mismatch must abort before any write; ops: {:?}",
        fake.ops
    );
}

#[test]
fn uefi_prepare_halts_on_absent_image_digest_before_any_write() {
                                                                                                       
                                                                                                         
                                                                                                     
                                                                          
    let sources = installer_sources(Firmware::Uefi, "").unwrap();
    let mut fake = FakeInstallOps::new_uefi();
    let params = InstallParams {
        sources: &sources,
        operator_root_pubkey_hex: b"",
        image_sha256: None,                                                      
        install_to: None,
    };
    let err = run_install(&mut fake, &params).unwrap_err();
    assert!(
        matches!(err, InstallerError::OpFailed { op, .. } if op == "verify-image-digest"),
        "expected an absent-digest halt, got {err:?}"
    );
    assert!(
        !fake.did_destructive(),
        "an absent fb.image-sha256 must abort before any write; ops: {:?}",
        fake.ops
    );
}

#[test]
fn uefi_prepare_halts_when_both_digest_and_firmware_mismatch_before_any_write() {
                                                                                                     
                                                                                                    
                                                                                              
                                    
    let sources = installer_sources(Firmware::Uefi, "").unwrap();                       
    let mut fake = FakeInstallOps::new();
    fake.layout_toml = FAKE_LAYOUT_TOML_UEFI.replace("\"uefi\"", "\"seabios\"");                         
    let params = InstallParams {
        sources: &sources,
        operator_root_pubkey_hex: b"",
        image_sha256: Some([0xAB; 32]),                                                         
        install_to: None,
    };
    let err = run_install(&mut fake, &params).unwrap_err();
    assert!(
        matches!(err, InstallerError::StagedImageDigestMismatch { .. })
            || matches!(err, InstallerError::OpFailed { op, .. } if op == "verify-image-firmware"),
        "expected a fail-closed prepare halt, got {err:?}"
    );
    assert!(
        !fake.did_destructive(),
        "both-wrong must abort before any write; ops: {:?}",
        fake.ops
    );
}

#[test]
fn installer_data_partuuid_is_the_canonical_literal() {
                                                                                               
                                                                                                          
                                                                                                        
                                                                                                             
                                                                                                         
    assert_eq!(
        initramfs_init::installer::INSTALLER_DATA_PARTUUID,
        "988794b1-f4c5-49a3-aebe-12b2dd91e58d"
    );
}

#[test]
fn parses_restore_from_alongside_image_raw() {
                                                                                                
                                                                                              
    let cmdline = std_cmdline("fb.restore-from=disk:vda1:/tmp/backup-20260601.tar.zst");
    let srcs =
        parse_install_sources(&cmdline, Firmware::Seabios).expect("valid restore-from cmdline");
    assert!(matches!(&srcs.source, InstallSource::RawRegion { .. }));
    assert_eq!(
        srcs.restore_from,
        Some(DiskSource {
            device: "vda1".into(),
            path: "/tmp/backup-20260601.tar.zst".into()
        })
    );
}

#[test]
fn missing_image_raw_is_an_error() {
                                                                                               
                                                          
    let err =
        parse_install_sources("fb.mode=installer fb.root-hash=ab", Firmware::Seabios).unwrap_err();
    assert_eq!(err, InstallerError::MissingImageRaw);

                                                                                            
    let err = parse_install_sources("fb.image-raw=", Firmware::Seabios).unwrap_err();
    assert_eq!(err, InstallerError::MissingImageRaw);
}

#[test]
fn malformed_raw_tokens_are_typed_errors() {
                                                                                                   
                                                                                            
    for bad in [
        "fb.image-raw=vda:8388608",                               
        "fb.image-raw=/dev/vda:8388608:1024",                
        "fb.image-raw=vda1:8388608:1024",                                   
        "fb.image-raw=vda:512:1024",                              
        "fb.image-raw=vda:8388608:0",                        
    ] {
        let cmdline = format!("{bad} fb.image-layout={STD_LAYOUT_TOKEN}");
        let err = parse_install_sources(&cmdline, Firmware::Seabios).unwrap_err();
        assert!(
            matches!(err, InstallerError::BadStreamToken(_)),
            "expected BadStreamToken for {bad:?}, got {err:?}"
        );
    }
                                                                                           
                                                
    let cmdline = format!(
        "fb.image-raw={RAW_WINDOW} fb.image-layout=fw:seabios,boot:0:512,skel:256:256,rootfs:512:512"
    );
    let err = parse_install_sources(&cmdline, Firmware::Seabios).unwrap_err();
    assert!(
        matches!(err, InstallerError::BadStreamToken(_)),
        "got {err:?}"
    );
}

#[test]
fn restore_device_must_be_a_bare_partition_name() {
                                                                                                
                                                                                            
    for bad_dev in ["mapper/evil", "../vda1", "vda1/x", "VDA1", ""] {
        let cmdline = std_cmdline(&format!("fb.restore-from=disk:{bad_dev}:/tmp/b.tar.zst"));
        let err = parse_install_sources(&cmdline, Firmware::Seabios).unwrap_err();
        assert!(
            matches!(err, InstallerError::InvalidSourceDevice { .. })
                                                                                            
                || matches!(err, InstallerError::MalformedSource { .. }),
            "expected device {bad_dev:?} rejected, got {err:?}"
        );
    }
                                                              
    let cmdline = std_cmdline("fb.restore-from=disk:vda2:/tmp/b.tar.zst");
    let srcs = parse_install_sources(&cmdline, Firmware::Seabios).expect("valid device");
    assert_eq!(srcs.restore_from.unwrap().device, "vda2");
}

#[test]
fn restore_path_must_be_absolute_and_traversal_free() {
                                                                                                   
    for bad_path in ["relative/path", "/tmp/../etc/shadow", "../escape", ""] {
        let cmdline = std_cmdline(&format!("fb.restore-from=disk:vda1:{bad_path}"));
        let err = parse_install_sources(&cmdline, Firmware::Seabios).unwrap_err();
        assert!(
            matches!(err, InstallerError::InvalidSourcePath { .. }),
            "expected path {bad_path:?} rejected, got {err:?}"
        );
    }
}

#[test]
fn restore_device_must_be_a_partition_of_the_window_disk() {
                                                                                             
                                                                                                 
                                                                                               
                                                           
    let err = parse_install_sources(
        &std_cmdline("fb.restore-from=disk:vdb1:/tmp/b.tar.zst"),
        Firmware::Seabios,
    )
    .unwrap_err();
    assert_eq!(
        err,
        InstallerError::SourceDeviceMismatch {
            image: "vda".into(),
            restore: "vdb1".into()
        }
    );
                                                                                               
                                                                                             
    for bare in ["vda", "nvme0n1", "mmcblk0", "loop0"] {
        let cmdline = std_cmdline(&format!("fb.restore-from=disk:{bare}:/tmp/b.tar.zst"));
        let err = parse_install_sources(&cmdline, Firmware::Seabios).unwrap_err();
        assert!(
            matches!(err, InstallerError::InvalidSourceDevice { .. }),
            "bare disk {bare:?} must be rejected as a restore device, got {err:?}"
        );
    }
}

#[test]
fn partition_layout_for_a_typical_disk() {
                                                                                                     
                                                                                                       
    let disk = 20 * 1024 * 1024 * 1024u64;
    let layout = compute_partition_layout(disk, Firmware::Seabios, None)
        .expect("20 GiB disk is large enough");

                                                                                                  
    assert_eq!(
        layout.boot,
        Partition {
            number: 1,
            start_lba: 2048,
            sector_count: 262_144,
            part_type: 0x83,
            bootable: true
        }
    );
                                                                         
    assert_eq!(
        layout.slot_a,
        Partition {
            number: 2,
            start_lba: 264_192,
            sector_count: 131_072,
            part_type: 0x83,
            bootable: false
        }
    );
                                                 
    assert_eq!(
        layout.slot_b,
        Partition {
            number: 3,
            start_lba: 395_264,
            sector_count: 131_072,
            part_type: 0x83,
            bootable: false
        }
    );
                                                          
    let disk_sectors = disk / SECTOR_SIZE;
    assert_eq!(
        layout.persist,
        Partition {
            number: 4,
            start_lba: 526_336,
            sector_count: disk_sectors - 526_336,
            part_type: 0x83,
            bootable: false,
        }
    );
}

#[test]
fn disk_too_small_aborts_before_any_write() {
                                                                                                  
                                                                                             
    let tiny = 100 * 1024 * 1024u64;                                              
    let err = compute_partition_layout(tiny, Firmware::Seabios, None).unwrap_err();
    assert!(
        matches!(err, InstallerError::DiskTooSmall { .. }),
        "expected DiskTooSmall, got {err:?}"
    );
}

#[test]
fn compute_layout_shared_geometry_uefi_reserves_gpt_backup() {
                                                                                                   
                                                                                                    
                                                                                                    
                                                                                                      
                                                                                                     
    let disk = 20 * 1024 * 1024 * 1024u64;
    let sb = compute_partition_layout(disk, Firmware::Seabios, None).expect("seabios layout");
    let uefi = compute_partition_layout(disk, Firmware::Uefi, None).expect("uefi layout");
    assert_eq!(sb.boot, uefi.boot);
    assert_eq!(sb.slot_a, uefi.slot_a);
    assert_eq!(sb.slot_b, uefi.slot_b);
    assert_eq!(sb.persist.start_lba, uefi.persist.start_lba);
    assert_eq!(sb.persist.sector_count - uefi.persist.sector_count, 33);
}

#[test]
fn compute_layout_2tib_guard_is_seabios_scoped() {
                                                                                                       
                                                                                         
    let huge = 3 * 1024 * 1024 * 1024 * 1024u64;
    assert!(matches!(
        compute_partition_layout(huge, Firmware::Seabios, None),
        Err(InstallerError::DiskTooLargeForMbr { .. })
    ));
    assert!(compute_partition_layout(huge, Firmware::Uefi, None).is_ok());
}

#[test]
fn uefi_layout_places_esp_then_slots_then_persist() {
                                                                                                  
                                                                                                 
                                                      
    let disk = 8 * 1024 * 1024 * 1024u64;
    let disk_sectors = disk / SECTOR_SIZE;
    let l = compute_partition_layout(disk, Firmware::Uefi, None).expect("8 GiB UEFI layout");
    assert_eq!(l.boot.start_lba, 2048);                                                      
    assert_eq!(l.boot.sector_count, 262_144);                 
    assert!(l.slot_a.start_lba > l.boot.start_lba);
    assert!(l.slot_b.start_lba > l.slot_a.start_lba);
    assert_eq!(
        l.persist.start_lba + l.persist.sector_count,
        disk_sectors - 33
    );
}

#[test]
fn partitions_are_aligned_and_non_overlapping() {
    let layout = compute_partition_layout(20 * 1024 * 1024 * 1024, Firmware::Seabios, None)
        .expect("large enough");
    let align = (1024 * 1024) / SECTOR_SIZE;                        
    for p in [
        &layout.boot,
        &layout.slot_a,
        &layout.slot_b,
        &layout.persist,
    ] {
        assert_eq!(
            p.start_lba % align,
            0,
            "partition {} start {} not 1 MiB-aligned",
            p.number,
            p.start_lba
        );
        assert!(p.sector_count > 0, "partition {} is empty", p.number);
    }
                                                                               
    assert!(layout.slot_a.start_lba >= layout.boot.start_lba + layout.boot.sector_count);
    assert!(layout.slot_b.start_lba >= layout.slot_a.start_lba + layout.slot_a.sector_count);
    assert!(layout.persist.start_lba >= layout.slot_b.start_lba + layout.slot_b.sector_count);
                                                                                              
    let bootable = [
        &layout.boot,
        &layout.slot_a,
        &layout.slot_b,
        &layout.persist,
    ]
    .iter()
    .filter(|p| p.bootable)
    .count();
    assert_eq!(
        bootable, 1,
        "exactly one partition must carry the boot flag"
    );
}

                                                                                         

/// Every effect [`run_install`] performs, in call order, as recorded by [`FakeInstallOps`].
#[derive(Debug, Clone, PartialEq, Eq)]
enum OpKind {
                                                    
    MountOldRoot,
    ResolvePartuuid(String),                                                            
    MountDataPartition,                                                                            
    ReadFile(String),
    OldRootFileSize,
    VerifyRestoreImage(u64),                                                                           
    UnmountOldRoot,
    EnumerateDisks,                                                                      
    SetTargetDisk(String),                                                       
                                                
    DiskSize,                          
    WritePartitionTable,
    DdComponent(InstallComponent),
    ZeroSlotB,
    WriteMbrBootcode,
    WriteGptmbrBootcode,
    FinalizeAndReboot,
                                          
    ReadSourceChunk,                                                               
    WriteChunk(InstallComponent),                                     
    FsyncPartition(InstallComponent),                                                        
    ReadbackChunk(InstallComponent),                                          
}

impl OpKind {
    /// The disk-mutating ops — NONE may run before the 7.pre read/verify phase completes
                         
    /// (verify-before-write; mount-fail-aborts-before-write).
    fn is_destructive(&self) -> bool {
        matches!(
            self,
            OpKind::WritePartitionTable
                | OpKind::DdComponent(_)
                | OpKind::ZeroSlotB
                | OpKind::WriteMbrBootcode
                | OpKind::WriteGptmbrBootcode
                | OpKind::FinalizeAndReboot
                | OpKind::WriteChunk(_)
        )
    }
}

/// The staged raw-window "image" (streaming redesign): 1024 bytes carved as boot `[0,256)`,
/// persist-skeleton `[256,512)`, rootfs `[512,1024)` — a 512-aligned total per the `fb.image-raw`
/// grammar. On the raw arm this is the WINDOW content (`FakeInstallOps.staged`); on the UEFI arm
/// the same bytes serve as the mounted `box.img` file.
fn staged_image() -> Vec<u8> {
    (0..1024u32).map(|i| (i % 251) as u8).collect()
}

/// The dha variant: + a weights component `[1024,1536)`.
fn staged_dha_image() -> Vec<u8> {
    (0..1536u32).map(|i| (i % 251) as u8).collect()
}

/// The staging window on the fake's 20 GiB disk: chunk-aligned at 10 GiB — far clear of every
/// written extent (persist starts at 257 MiB; the skeleton prefix is tiny).
const RAW_WINDOW: &str = "vda:10737418240:1024";
const RAW_WINDOW_DHA: &str = "vda:10737418240:1536";
const STD_LAYOUT_TOKEN: &str = "fw:seabios,boot:0:256,skel:256:256,rootfs:512:512";
const GPT_LAYOUT_TOKEN: &str = "fw:seabios-gpt,boot:0:256,skel:256:256,rootfs:512:512";
const DHA_LAYOUT_TOKEN: &str =
    "fw:seabios-gpt,boot:0:256,skel:256:256,rootfs:512:512,weights:1024:512";

/// A plain-seabios raw-arm installer cmdline (greenfield unless `extra` adds restore tokens).
fn std_cmdline(extra: &str) -> String {
    format!("fb.image-raw={RAW_WINDOW} fb.image-layout={STD_LAYOUT_TOKEN} {extra}")
}

/// The seabios-gpt twin of [`std_cmdline`].
fn gpt_cmdline(extra: &str) -> String {
    format!("fb.image-raw={RAW_WINDOW} fb.image-layout={GPT_LAYOUT_TOKEN} {extra}")
}

/// A dha (weights) seabios-gpt raw-arm cmdline.
fn dha_cmdline(extra: &str) -> String {
    format!("fb.image-raw={RAW_WINDOW_DHA} fb.image-layout={DHA_LAYOUT_TOKEN} {extra}")
}

/// The UEFI arm's sidecar (STILL a file on the USB data partition — spec D10), carving
/// [`staged_image`] with the same offsets the raw tokens declare. Includes the build's
/// still-emitted `rootfs_verity_hash_offset` (build-owned) to confirm the parser IGNORES it.
const FAKE_LAYOUT_TOML_UEFI: &str = "[layout]\n\
     boot_offset = 0\n\
     boot_size = 256\n\
     persist_skeleton_offset = 256\n\
     persist_skeleton_size = 256\n\
     rootfs_offset = 512\n\
     rootfs_size = 512\n\
     rootfs_verity_hash_offset = 24\n\
     firmware = \"uefi\"\n";

/// Records the op sequence (and captures the bytes each dd op writes) and can inject a failure at a
/// chosen op (to test fail-closed aborts + bootable-last).
struct FakeInstallOps {
    ops: Vec<OpKind>,
    fail_on: Option<OpKind>,
    disk_size: u64,
    /// Size `old_root_file_size` reports for the restore image (the cap is checked against this BEFORE
    /// the read). Default = the fake image length, well under the cap; the over-cap test sets it high.
    restore_image_size: u64,
    /// Size `old_root_file_size` reports for the restore `.sig` (the `.sig` cap is checked against this).
                       
    /// Default = a valid bundle's 254 bytes; the over-cap `.sig` test sets it high.
    restore_sig_size: u64,
    /// What `mem_total_bytes` reports (Task 4.3 RAM-aware cap). Default None = /proc/meminfo
    /// unreadable ⇒ restore_cap falls back to the static ceiling (the no-regression direction).
    mem_total: Option<u64>,
    /// Restore-image CONTENT `read_old_root_file` returns for paths ending `.persist.img` (the
    /// Task 4.3 identity pre-checks read real superblock bytes). None ⇒ the fake image bytes.
    restore_bytes: Option<Vec<u8>>,
    image_bytes: Vec<u8>,
    layout_toml: String,
    /// §9.5: the bare partition name the UEFI `resolve_partuuid` arm returns (the source data partition).
    data_partition_dev: String,
    /// §9.5: the disks `enumerate_disks` reports (default: the source USB + one fixed internal target).
    enumerated_disks: Vec<DiskInfo>,
    /// §9.5: the destructive target `set_target_disk` bound (None until selection runs).
    target_disk: Option<String>,
                                                                                           
    written_table_primary: Option<Vec<u8>>,
    dd_boot: Option<Vec<u8>>,
    dd_rootfs: Option<Vec<u8>>,
    dd_persist_skeleton: Option<Vec<u8>>,
    /// dha Component E: the bytes dd'd to the weights partition (`None` until/unless a dha `.img` commits).
    dd_weights: Option<Vec<u8>>,
                                                                          
    /// The staged raw-window CONTENT (region-relative — `read_source_chunk(Raw)` indexes it by the
    /// source-relative offset, exactly as the real impl preads `region.offset + offset`).
    staged: Vec<u8>,
    /// Per-component partition contents materialized by `write_partition_chunk` (offset-addressed;
    /// the readback + the byte-for-byte asserts read these).
    chunk_boot: Vec<u8>,
    chunk_rootfs: Vec<u8>,
    chunk_persist: Vec<u8>,
    chunk_weights: Vec<u8>,
    /// Chunk-layer fault injection (readback flip / truncated source).
    fault: Option<Fault>,
}

/// Chunk-layer fault injection for the streaming engine tests (spec D7's failure paths).
enum Fault {
    /// Flip the first byte served by `read_partition_chunk` for this component (readback-mismatch:
    /// the media "returned" different bytes than were written).
    FlipReadback(InstallComponent),
    /// The source reports EOF at this source-relative offset (truncated staging region).
    TruncateSource { at: u64 },
}

impl FakeInstallOps {
    fn new() -> Self {
        Self {
            ops: Vec::new(),
            fail_on: None,
            disk_size: 20 * 1024 * 1024 * 1024,
            restore_image_size: staged_image().len() as u64,
            restore_sig_size: 254,
            mem_total: None,
            restore_bytes: None,
            image_bytes: staged_image(),
            layout_toml: FAKE_LAYOUT_TOML_UEFI.to_string(),
            data_partition_dev: "sda2".to_string(),
            enumerated_disks: vec![
                                                                                   
                DiskInfo {
                    name: "sda".into(),
                    class_ok: true,
                    removable: true,
                },
                                                 
                DiskInfo {
                    name: "nvme0n1".into(),
                    class_ok: true,
                    removable: false,
                },
            ],
            target_disk: None,
            written_table_primary: None,
            dd_boot: None,
            dd_rootfs: None,
            dd_persist_skeleton: None,
            dd_weights: None,
            staged: staged_image(),
            chunk_boot: Vec::new(),
            chunk_rootfs: Vec::new(),
            chunk_persist: Vec::new(),
            chunk_weights: Vec::new(),
            fault: None,
        }
    }
    fn failing_on(kind: OpKind) -> Self {
        Self {
            fail_on: Some(kind),
            ..Self::new()
        }
    }
    /// The UEFI arm's fake: same staged bytes, served as the mounted `box.img` FILE + the sidecar
    /// (`FAKE_LAYOUT_TOML_UEFI` is already the default `layout_toml`).
    fn new_uefi() -> Self {
        Self::new()
    }
    /// A dha staged image (SeabiosGpt + the 5th weights component): drives the weights commit path
    /// via [`dha_cmdline`]'s tokens (the raw arm reads no sidecar).
    fn new_dha() -> Self {
        Self {
            staged: staged_dha_image(),
            ..Self::new()
        }
    }
    fn step(&mut self, kind: OpKind) -> Result<(), InstallerError> {
        let fail = self.fail_on.as_ref() == Some(&kind);
        self.ops.push(kind.clone());
        if fail {
            Err(InstallerError::OpFailed {
                op: "fake",
                reason: format!("injected at {kind:?}"),
            })
        } else {
            Ok(())
        }
    }
    fn did_destructive(&self) -> bool {
        self.ops.iter().any(OpKind::is_destructive)
    }
}

impl InstallOps for FakeInstallOps {
    fn mount_old_root(&mut self, _device: &str) -> Result<(), InstallerError> {
        self.step(OpKind::MountOldRoot)
    }
    fn resolve_partuuid(&mut self, partuuid: &str) -> Result<String, InstallerError> {
        self.step(OpKind::ResolvePartuuid(partuuid.to_string()))?;
        Ok(self.data_partition_dev.clone())
    }
    fn mount_data_partition(&mut self, _device: &str) -> Result<(), InstallerError> {
        self.step(OpKind::MountDataPartition)
    }
    fn enumerate_disks(&mut self) -> Result<Vec<DiskInfo>, InstallerError> {
        self.step(OpKind::EnumerateDisks)?;
        Ok(self.enumerated_disks.clone())
    }
    fn set_target_disk(&mut self, disk: &str) {
                                                                                                       
        self.ops.push(OpKind::SetTargetDisk(disk.to_string()));
        self.target_disk = Some(disk.to_string());
    }
    fn read_old_root_file(&mut self, path: &str) -> Result<Vec<u8>, InstallerError> {
        self.step(OpKind::ReadFile(path.to_string()))?;
                                                                                             
                                                                                                  
                                                                                                 
                                  
        if path.ends_with(".layout.toml") {
            Ok(self.layout_toml.clone().into_bytes())
        } else if path.ends_with(".persist.img") {
            Ok(self
                .restore_bytes
                .clone()
                .unwrap_or_else(|| self.image_bytes.clone()))
        } else {
            Ok(self.image_bytes.clone())
        }
    }
    fn old_root_file_size(&mut self, path: &str) -> Result<u64, InstallerError> {
        self.step(OpKind::OldRootFileSize)?;
                                                                                                  
                                                                                                 
                                                   
        if path.ends_with(".sig") {
            Ok(self.restore_sig_size)
        } else if path.ends_with(".layout.toml") {
            Ok(self.layout_toml.len() as u64)
        } else if path == "/box.img" {
            Ok(self.image_bytes.len() as u64)
        } else {
            Ok(self.restore_image_size)
        }
    }
    fn verify_restore_image(
        &mut self,
        _image: &[u8],
        _sig: &[u8],
        _anchor: &[u8],
        min_ctr: u64,
    ) -> Result<(), InstallerError> {
                                                                                                 
                                                                      
        self.step(OpKind::VerifyRestoreImage(min_ctr))
    }
    fn mem_total_bytes(&mut self) -> Option<u64> {
        self.mem_total
    }
    fn unmount_old_root(&mut self) -> Result<(), InstallerError> {
        self.step(OpKind::UnmountOldRoot)
    }
    fn disk_size_bytes(&mut self) -> Result<u64, InstallerError> {
        self.step(OpKind::DiskSize)?;
        Ok(self.disk_size)
    }
    fn write_partition_table(&mut self, table: PartitionTable) -> Result<(), InstallerError> {
        self.written_table_primary = Some(match table {
            PartitionTable::Mbr(b) => b.to_vec(),
            PartitionTable::Gpt { primary, .. } => primary.to_vec(),
        });
        self.step(OpKind::WritePartitionTable)
    }
    fn dd_component(
        &mut self,
        which: InstallComponent,
        bytes: &[u8],
    ) -> Result<(), InstallerError> {
        self.step(OpKind::DdComponent(which))?;
        let captured = Some(bytes.to_vec());
        match which {
            InstallComponent::Boot => self.dd_boot = captured,
            InstallComponent::Rootfs => self.dd_rootfs = captured,
            InstallComponent::PersistSkeleton => self.dd_persist_skeleton = captured,
            InstallComponent::Weights => self.dd_weights = captured,
        }
        Ok(())
    }
    fn read_source_chunk(
        &mut self,
        src: &SourceHandle,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, InstallerError> {
        self.step(OpKind::ReadSourceChunk)?;
                                                                                              
                                                                               
        let data: &[u8] = match src {
            SourceHandle::Raw(_) => &self.staged,
            SourceHandle::OldRootFile(path) => {
                if path.ends_with(".layout.toml") {
                    self.layout_toml.as_bytes()
                } else {
                    &self.image_bytes
                }
            }
        };
                                                                                        
        let effective_len = match self.fault {
            Some(Fault::TruncateSource { at }) => (data.len() as u64).min(at),
            _ => data.len() as u64,
        };
        if offset >= effective_len {
            return Ok(0);
        }
        let n = buf.len().min((effective_len - offset) as usize);
        buf[..n].copy_from_slice(&data[offset as usize..offset as usize + n]);
        Ok(n)
    }

    fn write_partition_chunk(
        &mut self,
        which: InstallComponent,
        offset: u64,
        buf: &[u8],
    ) -> Result<(), InstallerError> {
        self.step(OpKind::WriteChunk(which))?;
        let dest = match which {
            InstallComponent::Boot => &mut self.chunk_boot,
            InstallComponent::Rootfs => &mut self.chunk_rootfs,
            InstallComponent::PersistSkeleton => &mut self.chunk_persist,
            InstallComponent::Weights => &mut self.chunk_weights,
        };
        let end = offset as usize + buf.len();
        if dest.len() < end {
            dest.resize(end, 0);
        }
        dest[offset as usize..end].copy_from_slice(buf);
        Ok(())
    }

    fn read_partition_chunk(
        &mut self,
        which: InstallComponent,
        offset: u64,
        buf: &mut [u8],
    ) -> Result<usize, InstallerError> {
        self.step(OpKind::ReadbackChunk(which))?;
                                                                                            
                                                        
        let data: &[u8] = match which {
            InstallComponent::Boot if !self.chunk_boot.is_empty() => &self.chunk_boot,
            InstallComponent::Rootfs if !self.chunk_rootfs.is_empty() => &self.chunk_rootfs,
            InstallComponent::PersistSkeleton if !self.chunk_persist.is_empty() => {
                &self.chunk_persist
            }
            InstallComponent::Weights if !self.chunk_weights.is_empty() => &self.chunk_weights,
            InstallComponent::Boot => self.dd_boot.as_deref().unwrap_or(&[]),
            InstallComponent::Rootfs => self.dd_rootfs.as_deref().unwrap_or(&[]),
            InstallComponent::PersistSkeleton => self.dd_persist_skeleton.as_deref().unwrap_or(&[]),
            InstallComponent::Weights => self.dd_weights.as_deref().unwrap_or(&[]),
        };
        if offset >= data.len() as u64 {
            return Ok(0);
        }
        let n = buf.len().min(data.len() - offset as usize);
        buf[..n].copy_from_slice(&data[offset as usize..offset as usize + n]);
                                                                                                
        if offset == 0 && n > 0 && matches!(self.fault, Some(Fault::FlipReadback(f)) if f == which)
        {
            buf[0] ^= 0xff;
        }
        Ok(n)
    }

    fn fsync_partition(&mut self, which: InstallComponent) -> Result<(), InstallerError> {
        self.step(OpKind::FsyncPartition(which))
    }

    fn zero_slot_b(&mut self, _l: &PartitionLayout) -> Result<(), InstallerError> {
        self.step(OpKind::ZeroSlotB)
    }
    fn write_mbr_bootcode(&mut self) -> Result<(), InstallerError> {
        self.step(OpKind::WriteMbrBootcode)
    }
    fn write_gptmbr_bootcode(&mut self) -> Result<(), InstallerError> {
        self.step(OpKind::WriteGptmbrBootcode)
    }
    fn finalize_and_reboot(&mut self) -> Result<(), InstallerError> {
        self.step(OpKind::FinalizeAndReboot)
    }
}

fn params(sources: &InstallSources) -> InstallParams<'_> {
    params_for(sources, &staged_image())
}

/// [`params`] for a non-default staged image (the dha fixture): the raw arm's `fb.image-sha256`
/// is MANDATORY (spec D4), so every flow test threads the matching digest.
fn params_for<'a>(sources: &'a InstallSources, staged: &[u8]) -> InstallParams<'a> {
    InstallParams {
        sources,
                                                                                                
                                                                                        
        operator_root_pubkey_hex: b"",
        image_sha256: Some(sha32(staged)),
        install_to: None,
    }
}

#[test]
fn restore_from_verifies_tarball_before_writing_partition_table() {
                                                                                              
                                               
    let sources = parse_install_sources(
        &std_cmdline("fb.restore-from=disk:vda1:/r.persist.img"),
        Firmware::Seabios,
    )
    .unwrap();
    let mut fake = FakeInstallOps::new();
    fake.restore_bytes = Some(restore_image_fixture(true, false));                        
    run_install(&mut fake, &params(&sources)).expect("install succeeds");

    let verify = fake
        .ops
        .iter()
        .position(|o| *o == OpKind::VerifyRestoreImage(0))
        .expect("restore image verified");
    let write = fake
        .ops
        .iter()
        .position(|o| *o == OpKind::WritePartitionTable)
        .expect("partition table written");
    assert!(
        verify < write,
                    
        "verify ({verify}) must precede partition write ({write})"
    );
}

#[test]
fn mount_failure_aborts_before_any_write() {
                                                                                                 
                                                                                                 
                                    
    let sources = parse_install_sources(
        &std_cmdline("fb.restore-from=disk:vda1:/r.persist.img"),
        Firmware::Seabios,
    )
    .unwrap();
    let mut fake = FakeInstallOps::failing_on(OpKind::MountOldRoot);
    let err = run_install(&mut fake, &params(&sources)).unwrap_err();
    assert!(
        matches!(err, InstallerError::OpFailed { .. }),
        "got {err:?}"
    );
    assert!(
        !fake.did_destructive(),
        "no destructive op may run after a mount failure: {:?}",
        fake.ops
    );
}

#[test]
fn tarball_verify_failure_aborts_before_any_write() {
                                                                                   
    let sources = parse_install_sources(
        &std_cmdline("fb.restore-from=disk:vda1:/tmp/b.tar.zst"),
        Firmware::Seabios,
    )
    .unwrap();
    let mut fake = FakeInstallOps::failing_on(OpKind::VerifyRestoreImage(0));
    let err = run_install(&mut fake, &params(&sources)).unwrap_err();
    assert!(
        matches!(err, InstallerError::OpFailed { .. }),
        "got {err:?}"
    );
    assert!(
        fake.ops.contains(&OpKind::VerifyRestoreImage(0)),
        "verify must be attempted"
    );
    assert!(
        !fake.did_destructive(),
        "no destructive op after verify failure: {:?}",
        fake.ops
    );
}

#[test]
fn restore_image_over_cap_aborts_before_the_read() {
                                                                                                     
                                                                                                    
                                                                                              
    let sources = parse_install_sources(
        &std_cmdline("fb.restore-from=disk:vda1:/tmp/b.tar.zst"),
        Firmware::Seabios,
    )
    .unwrap();
    let mut fake = FakeInstallOps::new();
    fake.restore_image_size = MAX_RESTORE_IMAGE_BYTES + 1;
    let err = run_install(&mut fake, &params(&sources)).unwrap_err();
    assert!(
        matches!(
            &err,
            InstallerError::OpFailed {
                op: "restore-size-cap",
                ..
            }
        ),
        "expected a restore-size-cap abort, got {err:?}"
    );
                                                                                                
    assert!(
        fake.ops.contains(&OpKind::OldRootFileSize),
        "the size cap must be checked: {:?}",
        fake.ops
    );
    assert!(
        !fake
            .ops
            .contains(&OpKind::ReadFile("/tmp/b.tar.zst".into())),
        "the over-cap image must not be read into RAM: {:?}",
        fake.ops
    );
    assert!(
        !fake.did_destructive(),
        "no destructive op after an over-cap abort: {:?}",
        fake.ops
    );
}

                                                                                                             

#[test]
fn open_regular_nofollow_rejects_symlink_device_accepts_regular() {
                                                                                           
                                                                                                            
                                                                                             
    let dir = std::env::temp_dir().join(format!("c1_fatk1_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let reg = dir.join("backup.tar.zst");
    std::fs::write(&reg, b"hello world").unwrap();
    let (_f, len) =
        open_regular_nofollow(reg.to_str().unwrap()).expect("a regular file is accepted");
    assert_eq!(len, 11, "a regular file reports its true length");

                                                                                    
    assert!(
        open_regular_nofollow("/dev/zero").is_err(),
                   
        "a char device must be rejected (not a regular file)"
    );

                                                                                                              
    let link = dir.join("evil.tar.zst");
    if std::os::unix::fs::symlink("/dev/zero", &link).is_ok() {
        assert!(
            open_regular_nofollow(link.to_str().unwrap()).is_err(),
                       
            "a symlink-to-device must be rejected by O_NOFOLLOW"
        );
        assert!(
            read_regular_capped(link.to_str().unwrap(), 1024).is_err(),
                       
            "the capped read of a symlink-to-device is also refused"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn open_regular_nofollow_rejects_a_writerless_fifo_without_hanging() {
                                                                                                     
                                                                                                          
                                                                                                    
                                                                                                      
                                                                           
    let dir = std::env::temp_dir().join(format!("c1_fatk_fifo_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let fifo = dir.join("backup.tar.zst");
    let made = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !made {
        eprintln!("SKIP: mkfifo unavailable in this env");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    let path = fifo.to_str().unwrap().to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(open_regular_nofollow(&path).is_err());
    });
    match rx.recv_timeout(std::time::Duration::from_secs(5)) {
        Ok(rejected) => assert!(
            rejected,
                      
            "a writerless FIFO must be REJECTED (is_file fails)"
        ),
        Err(_) => {
            panic!(
                          
                "REGRESSION: open_regular_nofollow HUNG on a writerless FIFO — O_NONBLOCK dropped?"
            )
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn restore_sig_over_cap_aborts_before_the_read() {
                                                                                                      
                                                                                                            
    let sources = parse_install_sources(
        &std_cmdline("fb.restore-from=disk:vda1:/tmp/b.tar.zst"),
        Firmware::Seabios,
    )
    .unwrap();
    let mut fake = FakeInstallOps::new();
    fake.restore_sig_size = MAX_RESTORE_SIG_BYTES + 1;
    let err = run_install(&mut fake, &params(&sources)).unwrap_err();
    assert!(
        matches!(
            &err,
            InstallerError::OpFailed {
                op: "restore-sig-cap",
                ..
            }
        ),
        "expected a restore-sig-cap abort, got {err:?}"
    );
                                                                                                       
    assert!(
        !fake
            .ops
            .contains(&OpKind::ReadFile("/tmp/b.tar.zst.sig".into())),
        "the over-cap .sig must not be read into RAM: {:?}",
        fake.ops
    );
    assert!(
        !fake.did_destructive(),
        "no destructive op after a .sig-cap abort: {:?}",
        fake.ops
    );
}

                                                                                              

#[test]
fn restore_cap_pins_both_failure_directions() {
    const G2: u64 = 2 * 1024 * 1024 * 1024;
                                                                        
    assert_eq!(restore_cap(None), G2, "meminfo failure ⇒ static ceiling");
                                                                                           
                                                                                                  
                                                                                              
    assert_eq!(restore_cap(Some(1536 << 20)), (1536u64 << 20) - (256 << 20));
                                                                                                    
                                                                                             
                                                                                    
    assert_eq!(restore_cap(Some(64 << 30)), G2);
                                                                                
    assert_eq!(restore_cap(Some(128 << 20)), 0);
}

#[test]
fn parse_meminfo_total_handles_the_real_shape_and_garbage() {
    assert_eq!(
        parse_meminfo_total("MemTotal:       16309564 kB\nMemFree: 1 kB\n"),
        Some(16309564 * 1024)
    );
    assert_eq!(parse_meminfo_total(""), None);
    assert_eq!(parse_meminfo_total("MemTotal: lots kB"), None);
}

/// A minimal restore-image byte buffer with the §4b identity facts CONTROLLABLE: ext4 magic at
/// 1024+56, the journal COMPAT bit at 1024+0x5C.
fn restore_image_fixture(magic_ok: bool, journal: bool) -> Vec<u8> {
    let mut img = vec![0u8; 8192];
    if magic_ok {
        img[1024 + 56] = 0x53;
        img[1024 + 57] = 0xEF;
    }
    if journal {
        img[1024 + 0x5C] |= 0x04;
    }
    img
}

fn restore_sources(min_ctr: &str) -> InstallSources {
    let cmd = std_cmdline(&format!(
        "fb.restore-from=disk:vda1:/r.persist.img{min_ctr}"
    ));
    parse_install_sources(&cmd, Firmware::Seabios).unwrap()
}

#[test]
fn ram_derived_cap_refuses_before_the_read() {
                                                                                                  
                                                                         
    let sources = restore_sources("");
    let mut fake = FakeInstallOps::new();
    fake.mem_total = Some(300 << 20);                                                            
    fake.restore_image_size = 50 << 20;
    let err = run_install(&mut fake, &params(&sources)).unwrap_err();
    assert!(
        matches!(
            &err,
            InstallerError::OpFailed {
                op: "restore-size-cap",
                ..
            }
        ),
        "expected a restore-size-cap abort, got {err:?}"
    );
                                                                                        
    assert!(fake.ops.contains(&OpKind::OldRootFileSize));
    assert!(
        !fake
            .ops
            .iter()
            .any(|o| matches!(o, OpKind::ReadFile(p) if p.ends_with(".persist.img"))),
        "the over-RAM-cap image must never be read: {:?}",
        fake.ops
    );
    assert!(!fake.did_destructive());
}

#[test]
fn verified_non_ext4_restore_refuses_after_verify_before_unmount() {
                                                                                                    
                                                                                                   
                                                                     
    let sources = restore_sources("");
    let mut fake = FakeInstallOps::new();
    fake.restore_bytes = Some(b"not-an-ext4-image-just-a-signed-tarball".to_vec());
    let err = run_install(&mut fake, &params(&sources)).unwrap_err();
    assert!(
        matches!(
            &err,
            InstallerError::OpFailed {
                op: "restore-ext4-magic",
                ..
            }
        ),
        "expected a restore-ext4-magic abort, got {err:?}"
    );
    let verify_pos = fake
        .ops
        .iter()
        .position(|o| matches!(o, OpKind::VerifyRestoreImage(_)))
        .expect("the signature verify ran (the check is post-verify)");
    assert!(
        !fake.ops.contains(&OpKind::UnmountOldRoot),
        "the identity refusal fires before unmount: {:?}",
        fake.ops
    );
    assert!(verify_pos < fake.ops.len());
    assert!(!fake.did_destructive());
}

#[test]
fn journal_bearing_restore_refuses() {
                                                                                                     
                                                                                      
    let sources = restore_sources("");
    let mut fake = FakeInstallOps::new();
    fake.restore_bytes = Some(restore_image_fixture(true, true));
    let err = run_install(&mut fake, &params(&sources)).unwrap_err();
    assert!(
        matches!(
            &err,
            InstallerError::OpFailed {
                op: "restore-journal-present",
                ..
            }
        ),
        "expected a restore-journal-present abort, got {err:?}"
    );
    assert!(!fake.did_destructive());
}

#[test]
fn min_ctr_threads_the_parsed_floor_into_the_verify() {
                                                                                                
                                                                               
    let sources = restore_sources(" fb.min-ctr=42");
    let mut fake = FakeInstallOps::new();
    fake.restore_bytes = Some(restore_image_fixture(true, false));
                                                                                         
    let _ = run_install(&mut fake, &params(&sources));
    assert!(
        fake.ops.contains(&OpKind::VerifyRestoreImage(42)),
        "the parsed fb.min-ctr floor must reach the verify: {:?}",
        fake.ops
    );
}

                                                                                                  

#[test]
fn commit_dds_the_restore_image_in_place_of_the_skeleton() {
                                                                                                
                                                                                          
                                                                                                 
                                                  
    let sources = restore_sources("");
    let mut fake = FakeInstallOps::new();
    let restore = restore_image_fixture(true, false);
    fake.restore_bytes = Some(restore.clone());
    run_install(&mut fake, &params(&sources)).expect("restore install succeeds");
    assert_eq!(
        fake.dd_persist_skeleton.as_deref(),
        Some(&restore[..]),
        "the persist dd carries the RESTORE image, not the skeleton subrange"
    );
    assert!(
        !fake
            .ops
            .contains(&OpKind::WriteChunk(InstallComponent::PersistSkeleton)),
        "restore persist arrives via the dd swap, never the chunk copy: {:?}",
        fake.ops
    );
    assert!(
        fake.ops
            .contains(&OpKind::ReadbackChunk(InstallComponent::PersistSkeleton)),
        "the restore dd is read back too (D7/L8): {:?}",
        fake.ops
    );
                                                                                
    let gsources = parse_install_sources(&std_cmdline(""), Firmware::Seabios).unwrap();
    let mut green = FakeInstallOps::new();
    run_install(&mut green, &params(&gsources)).expect("greenfield install succeeds");
    assert_eq!(fake.chunk_boot, green.chunk_boot, "boot payload unchanged");
    assert_eq!(
        fake.chunk_rootfs, green.chunk_rootfs,
        "rootfs payload unchanged"
    );
    assert_eq!(
        fake.written_table_primary, green.written_table_primary,
        "partition table unchanged"
    );
                                                                                        
    let persist_step = |o: &OpKind| {
        matches!(
            o,
            OpKind::DdComponent(InstallComponent::PersistSkeleton)
                | OpKind::ReadSourceChunk
                | OpKind::WriteChunk(InstallComponent::PersistSkeleton)
                | OpKind::FsyncPartition(InstallComponent::PersistSkeleton)
                | OpKind::ReadbackChunk(InstallComponent::PersistSkeleton)
        )
    };
    let from_table = |ops: &[OpKind]| {
        let i = ops
            .iter()
            .position(|o| *o == OpKind::WritePartitionTable)
            .expect("table written");
        ops[i..]
            .iter()
            .filter(|o| !persist_step(o))
            .cloned()
            .collect::<Vec<_>>()
    };
    assert_eq!(
        from_table(&fake.ops),
        from_table(&green.ops),
        "the non-persist commit-phase op sequence is identical to greenfield"
    );
}

#[test]
fn greenfield_commit_writes_the_skeleton_subrange_to_persist() {
                                                                                               
                                                                                      
    let gsources = parse_install_sources(&std_cmdline(""), Firmware::Seabios).unwrap();
    let mut green = FakeInstallOps::new();
    run_install(&mut green, &params(&gsources)).expect("greenfield install succeeds");
    let img = staged_image();
    assert_eq!(
        green.chunk_persist,
        &img[256..512],
        "greenfield persist content = the staged image's pre-baked skeleton subrange"
    );
}

#[test]
fn oversize_restore_image_refuses_before_the_partition_table_write() {
                                                                                                    
                                                                                                   
                                                                                             
                                                                                             
                                                                                    
                                                                                                
                                                                   
    let cmd = format!(
        "fb.image-raw=vda:285212672:1024 fb.image-layout={STD_LAYOUT_TOKEN} \
         fb.restore-from=disk:vda1:/r.persist.img"
    );
    let sources = parse_install_sources(&cmd, Firmware::Seabios).unwrap();
    let mut fake = FakeInstallOps::new();
    fake.disk_size = 300 * 1024 * 1024;                                                                      
    let mut big = restore_image_fixture(true, false);
    big.resize(64 * 1024 * 1024, 0);                                                        
    fake.restore_image_size = big.len() as u64;                                         
    fake.restore_bytes = Some(big);
    let err = run_install(&mut fake, &params(&sources)).unwrap_err();
    assert!(
        matches!(
            &err,
            InstallerError::StagingOverlapsInstall {
                hit: "persist-prefix",
                ..
            }
        ),
        "expected the probed-length persist-prefix geometry refusal, got {err:?}"
    );
    assert!(
        !fake.did_destructive(),
        "disk untouched on the fit refusal: {:?}",
        fake.ops
    );
    assert!(
        !fake
            .ops
            .contains(&OpKind::ReadFile("/r.persist.img".into())),
        "the oversized image must never be read into RAM: {:?}",
        fake.ops
    );
}

                                                                                                                    
  
                                                                                                         
                                                                                                           
                                                                                                        
                                                                                                       
                                                                                             

/// Mint a real operator-signed bundle over `tarball` for `purpose`. Returns (root_pubkey_hex, sig_bytes).
fn signed_bundle(tarball: &[u8], purpose: Purpose) -> (Vec<u8>, Vec<u8>) {
    signed_bundle_with_ctr(tarball, purpose, 0)
}

/// Like [`signed_bundle`] but with an explicit delegation `monotonic_ctr` — the fb.min-ctr floor
/// tests pin quince's below-floor rejection + at-floor acceptance against REAL bundles.
fn signed_bundle_with_ctr(tarball: &[u8], purpose: Purpose, ctr: u64) -> (Vec<u8>, Vec<u8>) {
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
    let artifact_hash: [u8; 32] = Sha256::digest(tarball).into();
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
    (
        hex::encode(root.verifying_key().to_bytes()).into_bytes(),
        bf.to_bytes().to_vec(),
    )
}

/// A correctly-signed Backup bundle (the happy path).
fn signed_backup(tarball: &[u8]) -> (Vec<u8>, Vec<u8>) {
    signed_bundle(tarball, Purpose::Backup)
}

#[test]
fn verify_restore_image_accepts_a_correctly_signed_backup() {
    let tarball = b"persist-backup-2026";
    let (root_hex, sig) = signed_backup(tarball);
    let mut ops = SyscallInstallOps::new();
    assert!(
        ops.verify_restore_image(tarball, &sig, &root_hex, 0)
            .is_ok(),
        "a correctly operator-signed Backup tarball must verify"
    );
}

#[test]
fn verify_restore_image_enforces_the_min_ctr_floor_below_refuses_at_floor_proceeds() {
                                                                                                
                                                                                                     
                                                                                                  
                                                    
    let image = b"floored-restore-image";
    let (root_hex, sig) = signed_bundle_with_ctr(image, Purpose::Backup, 5);
    let mut ops = SyscallInstallOps::new();
    assert!(
        ops.verify_restore_image(image, &sig, &root_hex, 5).is_ok(),
        "at-floor (ctr == min_ctr) must proceed"
    );
    let err = ops
        .verify_restore_image(image, &sig, &root_hex, 6)
        .unwrap_err();
    assert!(
        matches!(
            &err,
            InstallerError::OpFailed {
                op: "verify-restore-image",
                ..
            }
        ),
        "below-floor must refuse at the verify op, got {err:?}"
    );
}

#[test]
fn verify_restore_image_rejects_a_forged_signature() {
    let tarball = b"persist-backup-2026";
    let (root_hex, mut sig) = signed_backup(tarball);
    sig[60] ^= 0xFF;                                                               
    let mut ops = SyscallInstallOps::new();
    let err = ops
        .verify_restore_image(tarball, &sig, &root_hex, 0)
        .unwrap_err();
    let InstallerError::OpFailed { op, reason } = &err else {
        panic!("expected OpFailed, got {err:?}");
    };
    assert_eq!(*op, "verify-restore-image");
                                                                                                              
    assert!(
        reason.contains("BadSignature"),
        "reason must name BadSignature: {reason}"
    );
}

#[test]
fn verify_restore_image_rejects_a_tampered_tarball() {
                                                                                                         
    let (root_hex, sig) = signed_backup(b"original-backup");
    let mut ops = SyscallInstallOps::new();
    let err = ops
        .verify_restore_image(b"tampered-backup", &sig, &root_hex, 0)
        .unwrap_err();
    let InstallerError::OpFailed { op, reason } = &err else {
        panic!("expected OpFailed, got {err:?}");
    };
    assert_eq!(*op, "verify-restore-image");
    assert!(
        reason.contains("ArtifactHashMismatch"),
        "reason must name ArtifactHashMismatch: {reason}"
    );
}

#[test]
fn verify_restore_image_rejects_a_wrong_purpose_bundle() {
                                                                                                      
    let tarball = b"persist-backup-2026";
    let (root_hex, sig) = signed_bundle(tarball, Purpose::Img);
    let mut ops = SyscallInstallOps::new();
    let err = ops
        .verify_restore_image(tarball, &sig, &root_hex, 0)
        .unwrap_err();
    let InstallerError::OpFailed { op, reason } = &err else {
        panic!("expected OpFailed, got {err:?}");
    };
    assert_eq!(*op, "verify-restore-image");
    assert!(
        reason.contains("UnexpectedPurpose"),
        "reason must name UnexpectedPurpose: {reason}"
    );
}

#[test]
fn verify_restore_image_rejects_a_malformed_bundle() {
                                                                                                
    let (root_hex, _sig) = signed_backup(b"x");
    let mut ops = SyscallInstallOps::new();
    let err = ops
        .verify_restore_image(b"x", &[0u8; 10], &root_hex, 0)
        .unwrap_err();
    let InstallerError::OpFailed { reason, .. } = &err else {
        panic!("expected OpFailed, got {err:?}");
    };
    assert!(
        reason.contains("BadBundleFile"),
        "reason must name BadBundleFile: {reason}"
    );
}

#[test]
fn verify_restore_image_rejects_an_absent_or_malformed_pubkey() {
                                                                                                       
                                                             
    let tarball = b"persist-backup-2026";
    let (_root_hex, sig) = signed_backup(tarball);
    let mut ops = SyscallInstallOps::new();
                             
    assert!(matches!(
        ops.verify_restore_image(tarball, &sig, b"", 0),
        Err(InstallerError::OpFailed {
            op: "verify-restore-image",
            ..
        })
    ));
                            
    assert!(
        ops.verify_restore_image(tarball, &sig, &[b'z'; 64], 0)
            .is_err()
    );
                                     
    assert!(
        ops.verify_restore_image(tarball, &sig, b"deadbeef", 0)
            .is_err()
    );
}

#[test]
fn verify_restore_image_tolerates_a_crlf_terminated_anchor() {
                                                                                                          
                                                                                                    
    let tarball = b"persist-backup-2026";
    let (mut root_hex, sig) = signed_backup(tarball);
    root_hex.extend_from_slice(b"\r\n");
    let mut ops = SyscallInstallOps::new();
    assert!(
        ops.verify_restore_image(tarball, &sig, &root_hex, 0)
            .is_ok(),
        "a CRLF-terminated anchor (trimmed) must still verify"
    );
}

#[test]
fn greenfield_install_has_no_verify_and_mounts_nothing() {
                                                                                                       
                                                                                                
                                                     
    let sources = parse_install_sources(&std_cmdline(""), Firmware::Seabios).unwrap();
    let mut fake = FakeInstallOps::new();
    run_install(&mut fake, &params(&sources)).expect("greenfield install succeeds");
    assert!(
        !fake
            .ops
            .iter()
            .any(|o| matches!(o, OpKind::VerifyRestoreImage(_))),
        "greenfield has no restore image to verify (any floor value)"
    );
    assert!(
        !fake.ops.contains(&OpKind::MountOldRoot),
        "greenfield mounts NOTHING on the raw arm: {:?}",
        fake.ops
    );
    assert!(
        fake.ops.contains(&OpKind::SetTargetDisk("vda".to_string())),
        "the target binds from the fb.image-raw token: {:?}",
        fake.ops
    );
    assert!(
        fake.ops
            .contains(&OpKind::WriteChunk(InstallComponent::PersistSkeleton)),
        "greenfield streams the pre-baked persist-skeleton subrange: {:?}",
        fake.ops
    );
    let read = fake
        .ops
        .iter()
        .position(|o| *o == OpKind::ReadSourceChunk)
        .expect("staged region read (digest pre-pass)");
    let write = fake
        .ops
        .iter()
        .position(|o| *o == OpKind::WritePartitionTable)
        .expect("partition written");
    assert!(
        read < write,
        "the staged region is digested before the first write"
    );
}

#[test]
fn restore_from_runs_steps_7pre_through_7h_in_order() {
                                                                                             
                                                                                                   
                                                                                                
                                                                                                      
    let sources = parse_install_sources(
        &std_cmdline("fb.restore-from=disk:vda1:/r.persist.img"),
        Firmware::Seabios,
    )
    .unwrap();
    let mut fake = FakeInstallOps::new();
    fake.restore_bytes = Some(restore_image_fixture(true, false));                        
    run_install(&mut fake, &params(&sources)).expect("install succeeds");
    let expected = [
        OpKind::SetTargetDisk("vda".to_string()),                                        
        OpKind::DiskSize,                                                                    
        OpKind::MountOldRoot,                                                        
        OpKind::OldRootFileSize,                                                          
        OpKind::ReadFile("/r.persist.img".into()),                     
        OpKind::OldRootFileSize,                                        
        OpKind::ReadFile("/r.persist.img.sig".into()),                    
        OpKind::VerifyRestoreImage(0),                                  
        OpKind::UnmountOldRoot,                                                              
        OpKind::ReadSourceChunk,                                                             
        OpKind::WritePartitionTable,                                        
        OpKind::ReadSourceChunk,                                   
        OpKind::WriteChunk(InstallComponent::Rootfs),
        OpKind::FsyncPartition(InstallComponent::Rootfs),
        OpKind::ReadbackChunk(InstallComponent::Rootfs),                                     
        OpKind::DdComponent(InstallComponent::PersistSkeleton),                                 
        OpKind::ReadbackChunk(InstallComponent::PersistSkeleton),                                  
        OpKind::ZeroSlotB,                                    
        OpKind::ReadSourceChunk,                                     
        OpKind::WriteChunk(InstallComponent::Boot),
        OpKind::FsyncPartition(InstallComponent::Boot),
        OpKind::ReadbackChunk(InstallComponent::Boot),
        OpKind::WriteMbrBootcode,                                          
        OpKind::FinalizeAndReboot,      
    ];
    assert_eq!(fake.ops, expected);
}

#[test]
fn uefi_commit_writes_gpt_skips_mbr_bootcode_with_esp_last() {
                                                                                                         
                                                                                        
                                                                                                       
                                                                                                     
                                                              
    let sources = installer_sources(Firmware::Uefi, "").unwrap();
    let mut fake = FakeInstallOps::new_uefi();
    let params = InstallParams {
        sources: &sources,
        operator_root_pubkey_hex: b"",
        image_sha256: Some(sha2_256(&staged_image())),
        install_to: None,
    };
    run_install(&mut fake, &params).expect("uefi install succeeds");
                                   
    assert!(
        !fake.ops.contains(&OpKind::WriteMbrBootcode),
        "no MBR stage-1 on UEFI (D6): {:?}",
        fake.ops
    );
                                                                                                
                                                                             
    let pos = |k: &OpKind| fake.ops.iter().position(|o| o == k);
    let table = pos(&OpKind::WritePartitionTable).expect("7a wrote a partition table");
    let rootfs = pos(&OpKind::WriteChunk(InstallComponent::Rootfs)).expect("rootfs copy");
    let persist =
        pos(&OpKind::WriteChunk(InstallComponent::PersistSkeleton)).expect("persist copy");
    let boot = pos(&OpKind::WriteChunk(InstallComponent::Boot)).expect("ESP copy");
    let reboot = pos(&OpKind::FinalizeAndReboot).expect("reboot");
    assert!(
        table < rootfs && rootfs < boot && persist < boot && boot < reboot,
        "GPT(7a) → rootfs/persist copy → ESP copy (bootable-last) → reboot: {:?}",
        fake.ops
    );
                                                                                                        
    let table_bytes = fake
        .written_table_primary
        .as_ref()
        .expect("a partition table was written");
    assert_eq!(
        &table_bytes[512..520],
        b"EFI PART",
        "7a wrote a GPT, not an MBR"
    );
}

#[test]
fn seabios_prepare_halts_on_uefi_layout_firmware_mismatch_before_any_write() {
                                                                                                       
                                                                                                   
                                                                                                         
                                                                                                      
                                                                                           
                                                                                                 
                                                                                              
                                                                    
    let err = installer_sources(Firmware::Seabios, &gpt_cmdline("")).unwrap_err();
    assert!(
        matches!(err, InstallerError::FirmwareTokenMismatch { .. }),
        "expected the two-token firmware refusal on the SeaBIOS arm, got {err:?}"
    );
    let uefi_layout_cmdline = format!(
        "fb.image-raw={RAW_WINDOW} fb.image-layout=fw:uefi,boot:0:256,skel:256:256,rootfs:512:512"
    );
    let err = installer_sources(Firmware::Seabios, &uefi_layout_cmdline).unwrap_err();
    assert!(
        matches!(err, InstallerError::BadStreamToken(_)),
        "fw:uefi is unrepresentable on the raw arm, got {err:?}"
    );
}

#[test]
fn seabios_gpt_commit_writes_gpt_then_gptmbr_bootcode_last() {
                                                                                                 
                                                                                             
                                                                                                
                                                          
    let sources = parse_install_sources(&gpt_cmdline(""), Firmware::SeabiosGpt).unwrap();
    let mut fake = FakeInstallOps::new();
    run_install(&mut fake, &params(&sources)).expect("seabios-gpt install succeeds");
    let expected = [
        OpKind::SetTargetDisk("vda".to_string()),
        OpKind::DiskSize,
        OpKind::ReadSourceChunk,                       
        OpKind::WritePartitionTable,                                     
        OpKind::ReadSourceChunk,
        OpKind::WriteChunk(InstallComponent::Rootfs),              
        OpKind::FsyncPartition(InstallComponent::Rootfs),
        OpKind::ReadbackChunk(InstallComponent::Rootfs),
        OpKind::ReadSourceChunk,
        OpKind::WriteChunk(InstallComponent::PersistSkeleton),               
        OpKind::FsyncPartition(InstallComponent::PersistSkeleton),
        OpKind::ReadbackChunk(InstallComponent::PersistSkeleton),
        OpKind::ZeroSlotB,
        OpKind::ReadSourceChunk,
        OpKind::WriteChunk(InstallComponent::Boot),                        
        OpKind::FsyncPartition(InstallComponent::Boot),
        OpKind::ReadbackChunk(InstallComponent::Boot),
        OpKind::WriteGptmbrBootcode,                                                     
        OpKind::FinalizeAndReboot,
    ];
    assert_eq!(fake.ops, expected);
    assert!(
        !fake.ops.contains(&OpKind::WriteMbrBootcode),
        "SeabiosGpt uses gptmbr.bin, not the MBR stage-1: {:?}",
        fake.ops
    );
    let table = fake
        .written_table_primary
        .as_ref()
        .expect("a partition table was written");
    assert_eq!(&table[512..520], b"EFI PART", "7a wrote a GPT, not an MBR");
           
    assert_eq!(
        table[446], 0x80,
        "the SeabiosGpt protective MBR is 0x80-active"
    );
}

#[test]
fn dha_commit_streams_the_weights_component_to_the_fifth_partition() {
                                                                                           
                                                                                         
                                                                                                  
                                                                                       
    let sources = parse_install_sources(&dha_cmdline(""), Firmware::SeabiosGpt).unwrap();
    let staged = staged_dha_image();
    let mut fake = FakeInstallOps::new_dha();
    run_install(&mut fake, &params_for(&sources, &staged)).expect("dha install succeeds");
    let pos = |k: &OpKind| fake.ops.iter().position(|o| o == k);
    let zero = pos(&OpKind::ZeroSlotB).expect("slot B zeroed");
    let weights = pos(&OpKind::WriteChunk(InstallComponent::Weights)).expect("weights copy");
    let weights_rb = pos(&OpKind::ReadbackChunk(InstallComponent::Weights)).expect("weights rb");
    let boot = pos(&OpKind::WriteChunk(InstallComponent::Boot)).expect("boot copy");
    let stage1 = pos(&OpKind::WriteGptmbrBootcode).expect("gptmbr stage-1");
    assert!(
        zero < weights && weights < weights_rb && weights_rb < boot && boot < stage1,
        "zero B → weights copy+readback → boot copy → stage-1: {:?}",
        fake.ops
    );
                                                                               
    assert_eq!(fake.chunk_weights, &staged[1024..1536]);
}

#[test]
fn commit_step_failure_is_orderly_not_panic() {
                                                                                                      
                                                                                                       
                                                                                            
    let sources = parse_install_sources(&std_cmdline(""), Firmware::Seabios).unwrap();
    let mut fake = FakeInstallOps::failing_on(OpKind::WriteChunk(InstallComponent::Rootfs));
    let err = run_install(&mut fake, &params(&sources)).unwrap_err();
    assert!(
        matches!(err, InstallerError::OpFailed { .. }),
        "got {err:?}"
    );
                                                                                                      
                                                                                           
    assert!(fake.ops.contains(&OpKind::WritePartitionTable));
    assert!(!fake.ops.contains(&OpKind::WriteMbrBootcode));
    assert!(!fake.ops.contains(&OpKind::FinalizeAndReboot));
}

#[test]
fn boot_dd_failure_leaves_mbr_bootcode_unwritten() {
                                                                                            
                                                                                                   
                                                                                       
                                    
    let sources = parse_install_sources(&std_cmdline(""), Firmware::Seabios).unwrap();
    let mut fake = FakeInstallOps::failing_on(OpKind::WriteChunk(InstallComponent::Boot));
    let err = run_install(&mut fake, &params(&sources)).unwrap_err();
    assert!(
        matches!(err, InstallerError::OpFailed { .. }),
        "got {err:?}"
    );
                                                                                                     
    assert!(
        fake.ops
            .contains(&OpKind::WriteChunk(InstallComponent::Boot))
    );
    assert!(
        !fake.ops.contains(&OpKind::WriteMbrBootcode),
        "the MBR stage-1 must NOT be written if the boot copy failed: {:?}",
        fake.ops
    );
    assert!(!fake.ops.contains(&OpKind::FinalizeAndReboot));
}

                                                                                    

#[test]
fn layout_sidecar_path_swaps_img_for_layout_toml() {
                                                                                                      
                                                                                            
    assert_eq!(
        layout_sidecar_path("/tmp/recipes-image-abc123.img").unwrap(),
        "/tmp/recipes-image-abc123.layout.toml"
    );
    assert_eq!(
        layout_sidecar_path("/tmp/img.img").unwrap(),
        "/tmp/img.layout.toml"
    );
}

#[test]
fn parse_image_layout_reads_all_fields() {
                                                                                                   
                                                                                                    
                           
    let toml = "# build sidecar\n[layout]\nboot_offset = 0\nboot_size = 100\n\
                persist_skeleton_offset = 100\npersist_skeleton_size = 50\nrootfs_offset = 150\n\
                rootfs_size = 900\nrootfs_verity_hash_offset = 700\nfuture_key = 42\n\
                firmware = \"seabios\"\n";
    assert_eq!(
        parse_image_layout(toml).unwrap(),
        ImageLayout {
            boot_offset: 0,
            boot_size: 100,
            persist_skeleton_offset: 100,
            persist_skeleton_size: 50,
            rootfs_offset: 150,
            rootfs_size: 900,
            weights_offset: None,
            weights_size: None,
            firmware: Firmware::Seabios,
        }
    );
}

#[test]
fn parse_image_layout_rejects_malformed() {
    for bad in [
                                              
        "[layout]\nboot_offset = 0\nfirmware = \"seabios\"\n",
                         
        "[layout]\nboot_offset = 0\nboot_size = -1\npersist_skeleton_offset = 1\n\
         persist_skeleton_size = 1\nrootfs_offset = 2\nrootfs_size = 2\nfirmware = \"seabios\"\n",
                            
        "[layout]\nboot_offset = nope\nboot_size = 1\npersist_skeleton_offset = 1\n\
         persist_skeleton_size = 1\nrootfs_offset = 2\nrootfs_size = 2\nfirmware = \"seabios\"\n",
                        
        "[layout]\nboot_offset = 0\nboot_offset = 0\nboot_size = 1\npersist_skeleton_offset = 1\n\
         persist_skeleton_size = 1\nrootfs_offset = 2\nrootfs_size = 2\nfirmware = \"seabios\"\n",
                          
        "[layout]\ngarbage-without-equals\n",
                                                                            
        "[layout]\nboot_offset = 0\nboot_size = 1\npersist_skeleton_offset = 1\n\
         persist_skeleton_size = 1\nrootfs_offset = 2\nrootfs_size = 2\nfirmware = \"bootleg\"\n",
                           
        "[layout]\nboot_offset = 0\nboot_size = 1\npersist_skeleton_offset = 1\n\
         persist_skeleton_size = 1\nrootfs_offset = 2\nrootfs_size = 2\n",
    ] {
        let err = parse_image_layout(bad).unwrap_err();
        assert!(
            matches!(err, InstallerError::MalformedImageLayout { .. }),
            "expected MalformedImageLayout for {bad:?}, got {err:?}"
        );
    }
}

#[test]
fn parse_image_layout_reads_weights_all_or_nothing() {
                                                                                                        
                                                                                                   
                                                                                                 
    let dha = "[layout]\nboot_offset = 0\nboot_size = 16\npersist_skeleton_offset = 16\n\
               persist_skeleton_size = 16\nrootfs_offset = 32\nrootfs_size = 32\n\
               weights_offset = 64\nweights_size = 16\nweights_verity_hash_offset = 12\n\
               firmware = \"seabios-gpt\"\n";
    let layout = parse_image_layout(dha).unwrap();
    assert_eq!(layout.weights_offset, Some(64));
    assert_eq!(layout.weights_size, Some(16));

                                                          
    let plain = parse_image_layout(FAKE_LAYOUT_TOML_UEFI).unwrap();
    assert_eq!(plain.weights_offset, None);
    assert_eq!(plain.weights_size, None);

                                                                                                          
                                                                                                  
    let partial = "[layout]\nboot_offset = 0\nboot_size = 16\npersist_skeleton_offset = 16\n\
                   persist_skeleton_size = 16\nrootfs_offset = 32\nrootfs_size = 32\n\
                   weights_offset = 64\nfirmware = \"seabios-gpt\"\n";
    assert!(matches!(
        parse_image_layout(partial).unwrap_err(),
        InstallerError::MalformedImageLayout { .. }
    ));
}

#[test]
fn spans_in_bounds_accepts_an_exact_carve() {
                                                                                              
                                                                                                  
    let spans = ComponentSpans {
        firmware: Firmware::Seabios,
        boot: (0, 16),
        skel: (16, 16),
        rootfs: (32, 32),
        weights: None,
    };
    assert_eq!(check_spans_in_bounds(&spans, 64), Ok(()));
}

#[test]
fn spans_in_bounds_rejects_out_of_bounds_and_overflow() {
                                           
    let past_end = ComponentSpans {
        firmware: Firmware::Seabios,
        boot: (0, 16),
        skel: (16, 16),
        rootfs: (32, 999),
        weights: None,
    };
    assert!(matches!(
        check_spans_in_bounds(&past_end, 64).unwrap_err(),
        InstallerError::ImageLayoutOutOfBounds {
            component: "rootfs",
            ..
        }
    ));
                                                                                                        
    let overflow = ComponentSpans {
        firmware: Firmware::Seabios,
        boot: (u64::MAX, 1),
        skel: (0, 1),
        rootfs: (0, 1),
        weights: None,
    };
    assert!(matches!(
        check_spans_in_bounds(&overflow, 64).unwrap_err(),
        InstallerError::ImageLayoutOutOfBounds {
            component: "boot",
            ..
        }
    ));
                                                                    
    let weights_past = ComponentSpans {
        firmware: Firmware::SeabiosGpt,
        boot: (0, 16),
        skel: (16, 16),
        rootfs: (32, 16),
        weights: Some((48, 999)),
    };
    assert!(matches!(
        check_spans_in_bounds(&weights_past, 64).unwrap_err(),
        InstallerError::ImageLayoutOutOfBounds {
            component: "weights",
            ..
        }
    ));
}

/// A PartitionLayout with chosen boot / slot-A / persist capacities (in sectors) for the fit check.
fn layout_with_capacities(
    boot_sectors: u64,
    slot_a_sectors: u64,
    persist_sectors: u64,
) -> PartitionLayout {
    let part = |number, sector_count, bootable| Partition {
        number,
        start_lba: 2048,
        sector_count,
        part_type: 0x83,
        bootable,
    };
    PartitionLayout {
        boot: part(1, boot_sectors, true),
        slot_a: part(2, slot_a_sectors, false),
        slot_b: part(3, slot_a_sectors, false),
        weights: None,
        persist: part(4, persist_sectors, false),
    }
}

/// [`ComponentSpans`] with chosen component LENGTHS (offsets irrelevant to the fit check).
fn spans_with_lens(boot: u64, skel: u64, rootfs: u64, weights: Option<u64>) -> ComponentSpans {
    ComponentSpans {
        firmware: Firmware::Seabios,
        boot: (0, boot),
        skel: (boot, skel),
        rootfs: (boot + skel, rootfs),
        weights: weights.map(|w| (boot + skel + rootfs, w)),
    }
}

#[test]
fn check_components_fit_rejects_oversized_components() {
                                                                      
    let small = 100;
    let big = 1000;                          

                                                                                 
    assert!(matches!(
        check_components_fit(
            &layout_with_capacities(1, 1024, 1024),
            &spans_with_lens(big, small, small, None)
        )
        .unwrap_err(),
        InstallerError::ComponentTooLargeForPartition {
            component: "boot",
            ..
        }
    ));

                                 
    assert!(matches!(
        check_components_fit(
            &layout_with_capacities(1024, 1, 1024),
            &spans_with_lens(small, small, big, None)
        )
        .unwrap_err(),
        InstallerError::ComponentTooLargeForPartition {
            component: "rootfs",
            ..
        }
    ));

                                                          
    assert!(matches!(
        check_components_fit(
            &layout_with_capacities(1024, 1024, 1),
            &spans_with_lens(small, big, small, None)
        )
        .unwrap_err(),
        InstallerError::ComponentTooLargeForPartition {
            component: "persist-skeleton",
            ..
        }
    ));

                                           
    assert!(
        check_components_fit(
            &layout_with_capacities(4096, 4096, 4096),
            &spans_with_lens(small, small, big, None)
        )
        .is_ok()
    );
}

#[test]
fn check_components_fit_rejects_an_oversized_weights_component() {
                                                                                                 
                                                                                             
                                                                       
    let part = |number, sector_count| Partition {
        number,
        start_lba: 2048,
        sector_count,
        part_type: 0x83,
        bootable: false,
    };
    let layout = PartitionLayout {
        boot: part(1, 1024),
        slot_a: part(2, 1024),
        slot_b: part(3, 1024),
        weights: Some(part(5, 1)),                                           
        persist: part(4, 1024),
    };
    assert!(matches!(
        check_components_fit(&layout, &spans_with_lens(100, 100, 100, Some(1000))).unwrap_err(),
        InstallerError::ComponentTooLargeForPartition {
            component: "weights",
            ..
        }
    ));
                                            
    assert!(check_components_fit(&layout, &spans_with_lens(100, 100, 100, Some(100))).is_ok());
}

#[test]
fn disk_from_partition_strips_the_partition_suffix() {
    for (partition, disk) in [
        ("sda1", "sda"),
        ("vda2", "vda"),
        ("sdb10", "sdb"),
        ("xvda1", "xvda"),
        ("nvme0n1p1", "nvme0n1"),
        ("mmcblk0p2", "mmcblk0"),
        ("loop0p1", "loop0"),
    ] {
        assert_eq!(disk_from_partition(partition).unwrap(), disk);
    }
                                                                                                   
                                                                                                          
                                                                                               
    for bare in ["sda", "nvme0n1", "mmcblk0", "loop0"] {
        assert!(
            matches!(
                disk_from_partition(bare).unwrap_err(),
                InstallerError::InvalidSourceDevice { .. }
            ),
            "bare disk {bare:?} must be rejected, not mis-derived"
        );
    }
}

                                                                

#[test]
fn build_mbr_sector_serializes_the_partition_table() {
    let layout =
        compute_partition_layout(20 * 1024 * 1024 * 1024, Firmware::Seabios, None).unwrap();
    let mbr = build_mbr_sector(&layout).unwrap();

                                                                                                    
    assert!(
        mbr[0..440].iter().all(|&b| b == 0),
        "boot code area must be zero"
    );
                      
    assert_eq!(mbr[510], 0x55);
    assert_eq!(mbr[511], 0xAA);

    let entry = |i: usize| &mbr[446 + i * 16..446 + i * 16 + 16];
    let parts = [
        &layout.boot,
        &layout.slot_a,
        &layout.slot_b,
        &layout.persist,
    ];
    for (i, p) in parts.iter().enumerate() {
        let e = entry(i);
        assert_eq!(
            e[0],
            if p.bootable { 0x80 } else { 0x00 },
            "entry {i} active flag"
        );
        assert_eq!(
            &e[1..4],
            &[0xFE, 0xFF, 0xFF],
            "entry {i} start-CHS sentinel"
        );
        assert_eq!(e[4], 0x83, "entry {i} Linux type");
        assert_eq!(&e[5..8], &[0xFE, 0xFF, 0xFF], "entry {i} end-CHS sentinel");
        assert_eq!(
            u32::from_le_bytes(e[8..12].try_into().unwrap()) as u64,
            p.start_lba,
            "entry {i} LBA start"
        );
        assert_eq!(
            u32::from_le_bytes(e[12..16].try_into().unwrap()) as u64,
            p.sector_count,
            "entry {i} sector count"
        );
    }
                                           
    let active = (0..4).filter(|&i| entry(i)[0] == 0x80).count();
    assert_eq!(active, 1, "exactly one active partition");
}

#[test]
fn build_mbr_sector_rejects_un_addressable_partition() {
                                                                                                     
    let mut layout =
        compute_partition_layout(20 * 1024 * 1024 * 1024, Firmware::Seabios, None).unwrap();
    layout.persist.sector_count = u64::from(u32::MAX) + 1;
    assert!(matches!(
        build_mbr_sector(&layout).unwrap_err(),
        InstallerError::DiskTooLargeForMbr { .. }
    ));
}

#[test]
fn out_of_bounds_layout_aborts_before_any_destructive_op() {
                                                                                               
                                                                                                   
                                                                 
    let cmdline = format!(
        "fb.image-raw={RAW_WINDOW} fb.image-layout=fw:seabios,boot:0:256,skel:256:256,rootfs:512:9984"
    );
    let sources = parse_install_sources(&cmdline, Firmware::Seabios).unwrap();
    let mut fake = FakeInstallOps::new();
    let err = run_install(&mut fake, &params(&sources)).unwrap_err();
    assert!(
        matches!(
            err,
            InstallerError::ImageLayoutOutOfBounds {
                component: "rootfs",
                ..
            }
        ),
        "got {err:?}"
    );
    assert!(
        !fake.did_destructive(),
        "no write after a bad layout: {:?}",
        fake.ops
    );
    assert!(
        !fake.ops.contains(&OpKind::ReadSourceChunk),
        "bounds are validated before the digest pre-pass reads anything: {:?}",
        fake.ops
    );
}

#[test]
fn greenfield_wires_staged_subranges_to_the_partitions() {
                                                                                                
                                                                                                  
                                                                                         
                                                           
    let sources = parse_install_sources(&std_cmdline(""), Firmware::Seabios).unwrap();
    let mut fake = FakeInstallOps::new();
    run_install(&mut fake, &params(&sources)).expect("greenfield install succeeds");

    let image = staged_image();
    assert_eq!(fake.chunk_boot, &image[0..256]);
    assert_eq!(fake.chunk_persist, &image[256..512]);
    assert_eq!(fake.chunk_rootfs, &image[512..1024]);
}

                                                               

#[test]
fn guid_mixed_endian_matches_the_known_esp_type_bytes() {
                                                                                                
                                                                                       
    let bytes = guid_to_mixed_endian("C12A7328-F81F-11D2-BA4B-00A0C93EC93B").unwrap();
    assert_eq!(
        bytes,
        [
            0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E,
            0xC9, 0x3B
        ]
    );
}

#[test]
fn guid_mixed_endian_rejects_malformed() {
                                                                                                        
    assert!(guid_to_mixed_endian("not-a-guid").is_none());
    assert!(guid_to_mixed_endian("C12A7328F81F11D2BA4B00A0C93EC93B").is_none());             
    assert!(guid_to_mixed_endian("C12A7328-F81F-11D2-BA4B-00A0C93EC93").is_none());                    
    assert!(guid_to_mixed_endian("g12a7328-f81f-11d2-ba4b-00a0c93ec93b").is_none());               
}

#[test]
fn slot_a_partuuid_is_a_well_formed_canonical_guid() {
                                                                                      
    assert!(guid_to_mixed_endian(SLOT_A_PARTUUID).is_some());
    assert_eq!(SLOT_A_PARTUUID.len(), 36);              
}

                                                                                                
                                                                                     
const ESP_TYPE: &str = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
const LINUX_FS_TYPE: &str = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";

#[test]
fn gpt_protective_mbr_and_primary_header_are_well_formed() {
    let disk = 8 * 1024 * 1024 * 1024u64;
    let disk_sectors = disk / SECTOR_SIZE;
    let layout = compute_partition_layout(disk, Firmware::Uefi, None).unwrap();
    let gpt = build_gpt(&layout, disk_sectors, Firmware::Uefi).unwrap();
    let p = &gpt.primary;
                                                                                            
    assert_eq!(p[450], 0xEE, "protective MBR partition type");
    assert_eq!(&p[510..512], &[0x55, 0xAA], "MBR boot signature");
                                            
    let h = |off: usize, len: usize| &p[512 + off..512 + off + len];
    assert_eq!(&p[512..520], b"EFI PART", "GPT signature");
    assert_eq!(
        u32::from_le_bytes(h(12, 4).try_into().unwrap()),
        92,
        "header size"
    );
    assert_eq!(
        u64::from_le_bytes(h(24, 8).try_into().unwrap()),
        1,
        "my_lba"
    );
    assert_eq!(
        u64::from_le_bytes(h(32, 8).try_into().unwrap()),
        disk_sectors - 1,
        "alt_lba (backup header at last LBA)"
    );
    assert_eq!(
        u64::from_le_bytes(h(40, 8).try_into().unwrap()),
        34,
        "first usable LBA"
    );
    assert_eq!(
        u64::from_le_bytes(h(48, 8).try_into().unwrap()),
        disk_sectors - 34,
        "last usable LBA"
    );
    assert_eq!(
        u32::from_le_bytes(h(80, 4).try_into().unwrap()),
        128,
        "num entries"
    );
    assert_eq!(
        u32::from_le_bytes(h(84, 4).try_into().unwrap()),
        128,
        "entry size"
    );
                                                                                               
    assert!(
        gpt_header_crc_valid(&p[512..512 + 92]),
        "primary header CRC"
    );
}

#[test]
fn gpt_entries_carry_canonical_guids_and_lbas() {
    let disk = 8 * 1024 * 1024 * 1024u64;
    let disk_sectors = disk / SECTOR_SIZE;
    let layout = compute_partition_layout(disk, Firmware::Uefi, None).unwrap();
    let gpt = build_gpt(&layout, disk_sectors, Firmware::Uefi).unwrap();
    let p = &gpt.primary;
                                                                                                
    let slot_a = &p[1024 + 128..1024 + 256];
    assert_eq!(
        &slot_a[0..16],
        &guid_to_mixed_endian(LINUX_FS_TYPE).unwrap(),
        "slot-A type GUID = Linux filesystem data"
    );
    assert_eq!(
        &slot_a[16..32],
        &guid_to_mixed_endian(SLOT_A_PARTUUID).unwrap(),
        "slot-A unique GUID = the canonical PARTUUID"
    );
    assert_eq!(
        u64::from_le_bytes(slot_a[32..40].try_into().unwrap()),
        layout.slot_a.start_lba,
        "slot-A first LBA"
    );
    assert_eq!(
        u64::from_le_bytes(slot_a[40..48].try_into().unwrap()),
        layout.slot_a.start_lba + layout.slot_a.sector_count - 1,
        "slot-A last LBA (inclusive)"
    );
                                                              
    assert_eq!(
        &p[1024..1024 + 16],
        &guid_to_mixed_endian(ESP_TYPE).unwrap(),
        "boot partition carries the ESP type GUID"
    );
}

#[test]
fn gpt_backup_mirrors_primary_with_swapped_lbas() {
    let disk = 8 * 1024 * 1024 * 1024u64;
    let disk_sectors = disk / SECTOR_SIZE;
    let layout = compute_partition_layout(disk, Firmware::Uefi, None).unwrap();
    let gpt = build_gpt(&layout, disk_sectors, Firmware::Uefi).unwrap();
                                                                                                
    assert_eq!(gpt.backup_lba, disk_sectors - 33);
    assert_eq!(gpt.backup.len(), 33 * 512);
                                                                                                     
                                                              
    let bh = &gpt.backup[32 * 512..32 * 512 + 92];
    assert_eq!(&bh[0..8], b"EFI PART");
    assert_eq!(
        u64::from_le_bytes(bh[24..32].try_into().unwrap()),
        disk_sectors - 1,
        "backup my_lba"
    );
    assert_eq!(
        u64::from_le_bytes(bh[32..40].try_into().unwrap()),
        1,
        "backup alt_lba"
    );
    assert_eq!(
        u64::from_le_bytes(bh[72..80].try_into().unwrap()),
        disk_sectors - 33,
        "backup entry-array LBA"
    );
    assert!(gpt_header_crc_valid(bh), "backup header CRC");
                                                                                               
    assert_eq!(&gpt.backup[0..16384], &gpt.primary[1024..1024 + 16384]);
}

#[test]
fn find_partition_by_partuuid_locates_slot_a() {
    let disk = 8 * 1024 * 1024 * 1024u64;
    let layout = compute_partition_layout(disk, Firmware::Uefi, None).unwrap();
    let gpt = build_gpt(&layout, disk / SECTOR_SIZE, Firmware::Uefi).unwrap();
                                                                                                          
    assert_eq!(
        find_partition_by_partuuid(&gpt.primary, SLOT_A_PARTUUID).unwrap(),
        Some(2)
    );
                                                                                 
    assert_eq!(
        find_partition_by_partuuid(&gpt.primary, "00000000-0000-4000-8000-000000000000").unwrap(),
        None
    );
}

#[test]
fn find_partition_by_partuuid_rejects_a_non_gpt_blob() {
                                                                                       
    let zeros = vec![0u8; 34 * 512];
    assert!(find_partition_by_partuuid(&zeros, SLOT_A_PARTUUID).is_err());
                                                        
    assert!(find_partition_by_partuuid(&[0u8; 100], SLOT_A_PARTUUID).is_err());
                                                                                             
    assert!(find_partition_by_partuuid(&zeros, "not-a-guid").is_err());
}

#[test]
fn find_partition_by_partuuid_rejects_a_bad_header_crc() {
                                                                                                       
                                                                                                       
    let disk = 8 * 1024 * 1024 * 1024u64;
    let layout = compute_partition_layout(disk, Firmware::Uefi, None).unwrap();
    let mut gpt = build_gpt(&layout, disk / SECTOR_SIZE, Firmware::Uefi).unwrap();
                                                                                                         
                                                                                                           
    gpt.primary[512 + 56] ^= 0xFF;
    assert!(find_partition_by_partuuid(&gpt.primary, SLOT_A_PARTUUID).is_err());
}

                                                                                         

/// SHA-256 of a byte slice, as the raw 32-byte array the engine compares.
fn sha32(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// A 1024-byte staged "image": boot [0,256), skel [256,512), rootfs [512,1024) — 512-aligned
/// total (the fb.image-raw len grammar), distinct byte patterns per component.
fn staged_1024() -> Vec<u8> {
    (0..1024u32).map(|i| (i % 251) as u8).collect()
}

fn spans_1024(firmware: Firmware) -> ComponentSpans {
    ComponentSpans {
        firmware,
        boot: (0, 256),
        skel: (256, 256),
        rootfs: (512, 512),
        weights: None,
    }
}

fn raw_src() -> SourceHandle {
    SourceHandle::Raw(RawRegion {
        disk: "vda".to_string(),
        offset: INSTALL_COPY_CHUNK_BYTES,
        len: 1024,
    })
}

#[test]
fn digest_prepass_splits_components_and_verifies_whole() {
                                                                                                
                                                                                           
    let staged = staged_1024();
    let mut fake = FakeInstallOps::new();
    fake.staged = staged.clone();
    let digests = digest_prepass(
        &mut fake,
        &raw_src(),
        &spans_1024(Firmware::Seabios),
        &sha32(&staged),
    )
    .expect("matching digest must pass");
    assert_eq!(
        digests,
        ComponentDigests {
            whole: sha32(&staged),
            boot: sha32(&staged[0..256]),
            skel: sha32(&staged[256..512]),
            rootfs: sha32(&staged[512..1024]),
            weights: None,
        }
    );
    assert!(!fake.did_destructive(), "pre-pass must write nothing");
}

#[test]
fn digest_prepass_mismatch_refuses_with_nothing_written() {
    let staged = staged_1024();
    let mut fake = FakeInstallOps::new();
    fake.staged = staged.clone();
    let mut wrong = sha32(&staged);
    wrong[0] ^= 0xff;
    let err = digest_prepass(
        &mut fake,
        &raw_src(),
        &spans_1024(Firmware::Seabios),
        &wrong,
    )
    .expect_err("flipped expected digest must refuse");
    assert!(
        matches!(err, InstallerError::StagedImageDigestMismatch { .. }),
        "got {err:?}"
    );
    assert!(!fake.did_destructive());
}

#[test]
fn digest_prepass_truncated_source_is_a_typed_short_read() {
                                                                                              
    let mut fake = FakeInstallOps::new();
    fake.staged = staged_1024();
    fake.fault = Some(Fault::TruncateSource { at: 512 });
    let err = digest_prepass(
        &mut fake,
        &raw_src(),
        &spans_1024(Firmware::Seabios),
        &sha32(&staged_1024()),
    )
    .expect_err("truncated source must refuse");
    assert!(
        matches!(err, InstallerError::SourceShortRead { .. }),
        "got {err:?}"
    );
}

#[test]
fn digest_prepass_old_root_file_arm_matches_raw() {
                                                                                                  
                                                                      
    let staged = staged_1024();
    let mut raw_fake = FakeInstallOps::new();
    raw_fake.staged = staged.clone();
    let via_raw = digest_prepass(
        &mut raw_fake,
        &raw_src(),
        &spans_1024(Firmware::Seabios),
        &sha32(&staged),
    )
    .unwrap();
    let mut file_fake = FakeInstallOps::new();
    file_fake.image_bytes = staged.clone();
    file_fake.restore_image_size = staged.len() as u64;                                          
    let via_file = digest_prepass(
        &mut file_fake,
        &SourceHandle::OldRootFile("/data/box.img".to_string()),
        &spans_1024(Firmware::Seabios),
        &sha32(&staged),
    )
    .unwrap();
    assert_eq!(via_raw, via_file);
}

#[test]
fn copy_and_verify_copies_fsyncs_then_reads_back_byte_exact() {
                                                                                                   
                                                        
    let staged = staged_1024();
    let mut fake = FakeInstallOps::new();
    fake.staged = staged.clone();
    copy_and_verify(
        &mut fake,
        &raw_src(),
        512,
        512,
        InstallComponent::Rootfs,
        &sha32(&staged[512..1024]),
    )
    .expect("clean copy must verify");
    assert_eq!(fake.chunk_rootfs, &staged[512..1024]);
    let write_idx = fake
        .ops
        .iter()
        .position(|o| *o == OpKind::WriteChunk(InstallComponent::Rootfs))
        .expect("write recorded");
    let fsync_idx = fake
        .ops
        .iter()
        .position(|o| *o == OpKind::FsyncPartition(InstallComponent::Rootfs))
        .expect("fsync recorded");
    let readback_idx = fake
        .ops
        .iter()
        .position(|o| *o == OpKind::ReadbackChunk(InstallComponent::Rootfs))
        .expect("readback recorded");
    assert!(
        write_idx < fsync_idx && fsync_idx < readback_idx,
        "order must be write < fsync < readback: {:?}",
        fake.ops
    );
}

#[test]
fn copy_and_verify_flipped_readback_is_a_component_mismatch() {
    let staged = staged_1024();
    let mut fake = FakeInstallOps::new();
    fake.staged = staged.clone();
    fake.fault = Some(Fault::FlipReadback(InstallComponent::Rootfs));
    let err = copy_and_verify(
        &mut fake,
        &raw_src(),
        512,
        512,
        InstallComponent::Rootfs,
        &sha32(&staged[512..1024]),
    )
    .expect_err("media flip must fail the readback");
    assert_eq!(
        err,
        InstallerError::ComponentReadbackMismatch {
            component: "rootfs"
        }
    );
}

#[test]
fn copy_and_verify_short_source_read_aborts_typed() {
    let mut fake = FakeInstallOps::new();
    fake.staged = staged_1024();
    fake.fault = Some(Fault::TruncateSource { at: 700 });
    let err = copy_and_verify(
        &mut fake,
        &raw_src(),
        512,
        512,
        InstallComponent::Rootfs,
        &sha32(&staged_1024()[512..1024]),
    )
    .expect_err("truncated source mid-copy must abort");
    assert!(
        matches!(err, InstallerError::SourceShortRead { .. }),
        "got {err:?}"
    );
}

#[test]
fn readback_verify_covers_the_restore_dd_path() {
                                                                                              
                                                                            
    let restore: Vec<u8> = (0..2048u32).map(|i| (i % 199) as u8).collect();
    let mut fake = FakeInstallOps::new();
    fake.dd_component(InstallComponent::PersistSkeleton, &restore)
        .unwrap();
    readback_verify(
        &mut fake,
        InstallComponent::PersistSkeleton,
        restore.len() as u64,
        &sha32(&restore),
    )
    .expect("clean dd must read back");
    let mut fake2 = FakeInstallOps::new();
    fake2
        .dd_component(InstallComponent::PersistSkeleton, &restore)
        .unwrap();
    fake2.fault = Some(Fault::FlipReadback(InstallComponent::PersistSkeleton));
    let err = readback_verify(
        &mut fake2,
        InstallComponent::PersistSkeleton,
        restore.len() as u64,
        &sha32(&restore),
    )
    .expect_err("flipped restore readback must fail");
    assert_eq!(
        err,
        InstallerError::ComponentReadbackMismatch {
            component: "persist-skeleton"
        }
    );
}

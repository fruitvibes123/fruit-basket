//! Host-runnable units for the initramfs-init runtime boot path.
//! The full boot is exercised in the QEMU smoke; these cover the pure cmdline/offset logic.

use initramfs_init::cmdline::{BootMode, CmdlineError, WeightsConfig, parse_cmdline};
use initramfs_init::installer::Firmware;

#[test]
fn parses_a_full_runtime_cmdline() {
                                                                                            
                                                                                                
                                          
    let cmdline = "ro fb.root-hash=deadbeefcafe fb.verity-hash-offset=8388608 \
                   fb.rootfs-dev=/dev/vda2 \
                   lockdown=integrity ima_appraise=enforce sysctl.kernel.yama.ptrace_scope=2";
    let cfg = parse_cmdline(cmdline).expect("valid runtime cmdline");
    assert_eq!(cfg.mode, BootMode::Runtime);                                           
    assert_eq!(cfg.root_hash, "deadbeefcafe");
    assert_eq!(cfg.verity_hash_offset, 8_388_608);
    assert_eq!(cfg.rootfs_dev.as_deref(), Some("/dev/vda2"));
}

#[test]
fn recognizes_installer_mode() {
                                                                                    
    let cfg = parse_cmdline("fb.root-hash=ab fb.verity-hash-offset=4096 fb.mode=installer")
        .expect("valid installer cmdline");
    assert_eq!(cfg.mode, BootMode::Installer);
    assert_eq!(cfg.rootfs_dev, None);
}

#[test]
fn parses_fb_image_sha256_as_32_bytes() {
                                                                                                       
                                                                                                     
    let cmd = format!(
        "fb.mode=installer fb.firmware=uefi fb.root-hash=ab fb.verity-hash-offset=4096 \
         fb.image-sha256={}",
        "a".repeat(64)
    );
    let cfg = parse_cmdline(&cmd).expect("valid installer cmdline with image-sha256");
    assert_eq!(cfg.image_sha256, Some([0xaa; 32]));
                                                          
    let rt = parse_cmdline("fb.root-hash=ab fb.verity-hash-offset=4096 fb.rootfs-dev=/dev/vda2")
        .expect("valid runtime cmdline");
    assert_eq!(rt.image_sha256, None);
}

#[test]
fn rejects_malformed_fb_image_sha256() {
                                                                                                      
    for bad in [
        "abc",                                       
        &"a".repeat(63),                            
        &"a".repeat(65),                            
        &"A".repeat(64),                                      
        &format!("{}g", "a".repeat(63)),                 
    ] {
        let cmd = format!(
            "fb.mode=installer fb.root-hash=ab fb.verity-hash-offset=4096 fb.image-sha256={bad}"
        );
        assert!(
            matches!(
                parse_cmdline(&cmd),
                Err(CmdlineError::InvalidImageSha256(_))
            ),
            "expected InvalidImageSha256 for {bad:?}"
        );
    }
}

#[test]
fn parses_fb_install_to_whole_disk() {
                                                                                                    
    let cfg = parse_cmdline(
        "fb.mode=installer fb.firmware=uefi fb.root-hash=ab fb.verity-hash-offset=4096 \
         fb.install-to=nvme0n1",
    )
    .expect("valid fb.install-to");
    assert_eq!(cfg.install_to.as_deref(), Some("nvme0n1"));
                                             
    let none = parse_cmdline("fb.root-hash=ab fb.verity-hash-offset=4096 fb.mode=installer")
        .expect("no install-to");
    assert_eq!(none.install_to, None);
}

#[test]
fn rejects_fb_install_to_that_is_not_a_whole_disk() {
                                                                                                 
                                                                       
    for bad in ["nvme0n1p1", "sda1", "foo", "SDA", "/dev/sda", ""] {
        let cmd = format!(
            "fb.mode=installer fb.root-hash=ab fb.verity-hash-offset=4096 fb.install-to={bad}"
        );
                                                                                                           
        if bad.is_empty() {
            assert_eq!(parse_cmdline(&cmd).unwrap().install_to, None);
        } else {
            assert!(
                matches!(parse_cmdline(&cmd), Err(CmdlineError::InvalidInstallTo(_))),
                "expected InvalidInstallTo for {bad:?}"
            );
        }
    }
}

#[test]
fn installer_mode_accepts_stray_rootfs_dev() {
                                                                                       
                                                                                                
                                                                                                            
    let cfg = parse_cmdline(
        "fb.root-hash=ab fb.verity-hash-offset=4096 fb.mode=installer fb.rootfs-dev=/dev/sda2",
    )
    .expect("installer cmdline with a stray rootfs-dev must parse, not error");
    assert_eq!(cfg.mode, BootMode::Installer);
}

#[test]
fn explicit_runtime_mode_is_accepted() {
    let cfg = parse_cmdline(
        "fb.root-hash=ab fb.verity-hash-offset=4096 fb.rootfs-dev=/dev/sda2 \
         fb.mode=runtime",
    )
    .expect("valid explicit-runtime cmdline");
    assert_eq!(cfg.mode, BootMode::Runtime);
    assert_eq!(cfg.rootfs_dev.as_deref(), Some("/dev/sda2"));
}

#[test]
fn missing_root_hash_is_an_error() {
    let err = parse_cmdline("fb.verity-hash-offset=4096").unwrap_err();
    assert_eq!(err, CmdlineError::MissingRootHash);
}

#[test]
fn empty_root_hash_is_treated_as_missing() {
                                                         
    let err = parse_cmdline("fb.root-hash= fb.verity-hash-offset=4096").unwrap_err();
    assert_eq!(err, CmdlineError::MissingRootHash);
}

#[test]
fn missing_verity_offset_is_an_error() {
                                                                                      
    let err = parse_cmdline("fb.root-hash=deadbeef").unwrap_err();
    assert_eq!(err, CmdlineError::MissingVerityOffset);
}

#[test]
fn non_integer_verity_offset_is_an_error() {
    let err = parse_cmdline("fb.root-hash=ab fb.verity-hash-offset=notanum").unwrap_err();
    assert_eq!(err, CmdlineError::InvalidVerityOffset("notanum".into()));
}

#[test]
fn missing_rootfs_dev_on_runtime_is_an_error() {
                                                                                                 
                                                                                                      
    let err = parse_cmdline("fb.root-hash=ab fb.verity-hash-offset=4096").unwrap_err();
    assert_eq!(err, CmdlineError::MissingRootfsDev);
}

#[test]
fn empty_rootfs_dev_on_runtime_is_treated_as_missing() {
    let err =
        parse_cmdline("fb.root-hash=ab fb.verity-hash-offset=4096 fb.rootfs-dev=").unwrap_err();
    assert_eq!(err, CmdlineError::MissingRootfsDev);
}

#[test]
fn rootfs_dev_accepts_real_device_forms() {
                                                                         
    for dev in ["/dev/sda2", "/dev/vda3", "/dev/nvme0n1p2"] {
        let cmdline = format!("fb.root-hash=ab fb.verity-hash-offset=4096 fb.rootfs-dev={dev}");
        let cfg = parse_cmdline(&cmdline).expect("valid rootfs-dev");
        assert_eq!(cfg.rootfs_dev.as_deref(), Some(dev));
    }
}

#[test]
fn rootfs_dev_rejects_paths_with_slashes_and_traversal() {
                                                                                    
    for bad in [
        "/dev/mapper/evil",
        "/dev/../etc/shadow",
        "/etc/passwd",
        "vda2",
        "/dev/SDA2",
    ] {
        let cmdline = format!("fb.root-hash=ab fb.verity-hash-offset=4096 fb.rootfs-dev={bad}");
        let err = parse_cmdline(&cmdline).unwrap_err();
        assert_eq!(
            err,
            CmdlineError::InvalidRootfsDev(bad.to_string()),
            "expected {bad:?} rejected by the device whitelist"
        );
    }
}

#[test]
fn unknown_mode_is_an_error() {
    let err =
        parse_cmdline("fb.root-hash=ab fb.verity-hash-offset=4096 fb.mode=bogus").unwrap_err();
    assert_eq!(err, CmdlineError::UnknownMode("bogus".into()));
}

                                                                                                 
                                                                                 
                                                                                                 
                                                                         

                                                                                        
                                                                                       
                                                                                         
                                                               

#[test]
fn seabios_is_the_default_firmware_and_still_requires_root_hash() {
                                                                                                 
    assert_eq!(
        parse_cmdline("fb.rootfs-dev=/dev/vda2 ro").unwrap_err(),
        CmdlineError::MissingRootHash
    );
                                                                                       
    let c = parse_cmdline(
        "fb.firmware=seabios fb.root-hash=ab fb.verity-hash-offset=4096 \
         fb.rootfs-dev=/dev/vda2",
    )
    .expect("explicit seabios cmdline");
    assert_eq!(c.firmware, Firmware::Seabios);
}

#[test]
fn unknown_firmware_token_fails_closed() {
                                                                                                   
    assert!(matches!(
        parse_cmdline("fb.firmware=bios fb.rootfs-dev=/dev/vda2 ro"),
        Err(CmdlineError::UnknownFirmware(_))
    ));
}

#[test]
fn rootfs_dev_accepts_canonical_partuuid_and_dev_paths() {
    assert!(
        parse_cmdline(
            "fb.firmware=uefi fb.root-hash=ab fb.verity-hash-offset=4096 \
             fb.rootfs-dev=PARTUUID=04c92659-e47a-485b-b840-fe5561eaa0da ro"
        )
        .is_ok()
    );
    assert!(
        parse_cmdline("fb.root-hash=ab fb.verity-hash-offset=4096 fb.rootfs-dev=/dev/vda2").is_ok()
    );
}

#[test]
fn rootfs_dev_rejects_malformed_partuuid() {
    for bad in [
        "PARTUUID=NOTAGUID",
        "PARTUUID=04C92659-E47A-485B-B840-FE5561EAA0DA",                                              
        "PARTUUID=../etc",
        "PARTUUID=04c92659e47a485bb840fe5561eaa0da",             
    ] {
        let cmdline = format!(
            "fb.firmware=uefi fb.root-hash=ab fb.verity-hash-offset=4096 \
             fb.rootfs-dev={bad} ro"
        );
        let err = parse_cmdline(&cmdline).unwrap_err();
        assert_eq!(
            err,
            CmdlineError::InvalidRootfsDev(bad.to_string()),
            "expected malformed PARTUUID {bad:?} rejected by the whitelist"
        );
    }
}

#[test]
fn seabios_rejects_a_partuuid_rootfs_dev() {
                                                                                                       
                                                                                                      
    let cmdline = format!(
        "fb.root-hash={} fb.verity-hash-offset=4096 \
         fb.rootfs-dev=PARTUUID=04c92659-e47a-485b-b840-fe5561eaa0da",
        "ab".repeat(32)
    );
    let err = parse_cmdline(&cmdline).unwrap_err();
    assert_eq!(
        err,
        CmdlineError::InvalidRootfsDev("PARTUUID=04c92659-e47a-485b-b840-fe5561eaa0da".to_string())
    );
}

                                                                                                 

#[test]
fn seabios_gpt_accepts_a_partuuid_rootfs_dev() {
                                                                                                       
                                                                                                     
    let c = parse_cmdline(
        "fb.firmware=seabios-gpt fb.root-hash=ab fb.verity-hash-offset=4096 \
         fb.rootfs-dev=PARTUUID=04c92659-e47a-485b-b840-fe5561eaa0da ro",
    )
    .expect("SeabiosGpt + a canonical PARTUUID must parse");
    assert_eq!(c.firmware, Firmware::SeabiosGpt);
    assert_eq!(
        c.rootfs_dev.as_deref(),
        Some("PARTUUID=04c92659-e47a-485b-b840-fe5561eaa0da")
    );
}

#[test]
fn seabios_gpt_rejects_a_bare_dev_node() {
                                                                                                       
                                                                                      
    let err = parse_cmdline(
        "fb.firmware=seabios-gpt fb.root-hash=ab fb.verity-hash-offset=4096 \
         fb.rootfs-dev=/dev/sda2 ro",
    )
    .unwrap_err();
    assert_eq!(err, CmdlineError::InvalidRootfsDev("/dev/sda2".to_string()));
}

#[test]
fn adding_seabios_gpt_leaves_the_seabios_and_uefi_rootfs_shapes_unchanged() {
                                                                                                
                                      
    assert_eq!(
        parse_cmdline(
            "fb.firmware=seabios fb.root-hash=ab fb.verity-hash-offset=4096 \
             fb.rootfs-dev=PARTUUID=04c92659-e47a-485b-b840-fe5561eaa0da"
        )
        .unwrap_err(),
        CmdlineError::InvalidRootfsDev("PARTUUID=04c92659-e47a-485b-b840-fe5561eaa0da".to_string())
    );
                                         
    assert!(
        parse_cmdline(
            "fb.firmware=seabios fb.root-hash=ab fb.verity-hash-offset=4096 fb.rootfs-dev=/dev/vda2"
        )
        .is_ok()
    );
                                                                                                      
    assert!(
        parse_cmdline(
            "fb.firmware=uefi fb.root-hash=ab fb.verity-hash-offset=4096 fb.rootfs-dev=/dev/vda2"
        )
        .is_ok()
    );
}

                                                                      

#[test]
fn uefi_cmdline_now_parses_verity_from_the_cmdline() {
                                                                                 
                                                                                    
                                                                  
    let hex = "ab".repeat(32);
    let c = parse_cmdline(&format!(
        "fb.firmware=uefi fb.root-hash={hex} fb.verity-hash-offset=8192 \
         fb.rootfs-dev=PARTUUID=52a3f1c0-0000-4a00-a000-0000000051a7 ro"
    ))
    .expect("uefi runtime cmdline with the verity pair parses");
    assert_eq!(c.firmware, Firmware::Uefi);
    assert_eq!(c.root_hash, hex);                                               
    assert_eq!(c.verity_hash_offset, 8192);
}

#[test]
fn uefi_cmdline_without_the_pair_fails_closed_like_seabios() {
                                                                                   
                                                                                   
                                                                                   
                                                        
    let err = parse_cmdline(
        "fb.firmware=uefi \
         fb.rootfs-dev=PARTUUID=52a3f1c0-0000-4a00-a000-0000000051a7 ro",
    )
    .unwrap_err();
    assert_eq!(err, CmdlineError::MissingRootHash);
}

                                                                                   
                                                                                      
                                                                               

                                                                              
                                                                                                      
                                                                                                         
                                                                                                      
                                                                                                    
                                          

#[test]
fn parses_a_dha_weights_triple() {
    let c = parse_cmdline(
        "fb.firmware=seabios-gpt fb.root-hash=ab fb.verity-hash-offset=4096 \
         fb.rootfs-dev=PARTUUID=04c92659-e47a-485b-b840-fe5561eaa0da \
         fb.weights-dev=PARTUUID=7d3b9f24-6a1c-4e58-b0d9-2c4f8a6e1b35 \
         fb.weights-hash=cafef00d fb.weights-offset=2097152 ro",
    )
    .expect("a dha weights triple must parse");
    assert_eq!(
        c.weights,
        Some(WeightsConfig {
            dev: "PARTUUID=7d3b9f24-6a1c-4e58-b0d9-2c4f8a6e1b35".to_string(),
            hash: "cafef00d".to_string(),
            offset: 2_097_152,
        })
    );
}

#[test]
fn non_dha_cmdline_has_no_weights() {
                                                                                                        
    let c =
        parse_cmdline("fb.root-hash=deadbeef fb.verity-hash-offset=8192 fb.rootfs-dev=/dev/vda2")
            .expect("non-dha runtime cmdline");
    assert_eq!(c.weights, None);
    assert_eq!(c.rootfs_dev.as_deref(), Some("/dev/vda2"));
}

#[test]
fn empty_weights_tokens_are_treated_as_absent() {
                                                                                    
    let c = parse_cmdline(
        "fb.firmware=seabios-gpt fb.root-hash=ab fb.verity-hash-offset=4096 \
         fb.rootfs-dev=PARTUUID=04c92659-e47a-485b-b840-fe5561eaa0da \
         fb.weights-dev= fb.weights-hash= fb.weights-offset=",
    )
    .expect("all-empty weights tokens are absent, not an error");
    assert_eq!(c.weights, None);
}

#[test]
fn partial_weights_triple_fails_closed() {
                                                                                                  
                                                                                          
    let base = "fb.firmware=seabios-gpt fb.root-hash=ab fb.verity-hash-offset=4096 \
                fb.rootfs-dev=PARTUUID=04c92659-e47a-485b-b840-fe5561eaa0da";
    let dev = "fb.weights-dev=PARTUUID=7d3b9f24-6a1c-4e58-b0d9-2c4f8a6e1b35";
    let hash = "fb.weights-hash=cafef00d";
    let off = "fb.weights-offset=2097152";
    for partial in [
        format!("{base} {dev}"),
        format!("{base} {hash}"),
        format!("{base} {off}"),
        format!("{base} {dev} {hash}"),                  
        format!("{base} {dev} {off}"),                        
        format!("{base} {hash} {off}"),               
    ] {
        assert_eq!(
            parse_cmdline(&partial).unwrap_err(),
            CmdlineError::IncompleteWeights,
            "a partial weights triple must fail closed: {partial:?}"
        );
    }
}

#[test]
fn weights_dev_rejects_non_partuuid_or_malformed_guid() {
                                                                                                         
                                                                                                           
    let base = "fb.firmware=seabios-gpt fb.root-hash=ab fb.verity-hash-offset=4096 \
                fb.rootfs-dev=PARTUUID=04c92659-e47a-485b-b840-fe5561eaa0da \
                fb.weights-hash=cafef00d fb.weights-offset=2097152";
    for bad in [
        "/dev/vda3",
        "/dev/mapper/weights",
        "PARTUUID=7D3B9F24-6A1C-4E58-B0D9-2C4F8A6E1B35",                      
        "PARTUUID=NOTAGUID",
        "7d3b9f24-6a1c-4e58-b0d9-2c4f8a6e1b35",                            
    ] {
        let cmd = format!("{base} fb.weights-dev={bad}");
        assert_eq!(
            parse_cmdline(&cmd).unwrap_err(),
            CmdlineError::InvalidWeightsDev(bad.to_string()),
            "expected InvalidWeightsDev for {bad:?}"
        );
    }
}

#[test]
fn weights_partuuid_rejected_on_seabios_mbr() {
                                                                                                         
                                                                                                   
    let cmd = "fb.firmware=seabios fb.root-hash=ab fb.verity-hash-offset=4096 fb.rootfs-dev=/dev/vda2 \
               fb.weights-dev=PARTUUID=7d3b9f24-6a1c-4e58-b0d9-2c4f8a6e1b35 \
               fb.weights-hash=cafef00d fb.weights-offset=2097152";
    assert_eq!(
        parse_cmdline(cmd).unwrap_err(),
        CmdlineError::InvalidWeightsDev(
            "PARTUUID=7d3b9f24-6a1c-4e58-b0d9-2c4f8a6e1b35".to_string()
        )
    );
}

#[test]
fn weights_offset_must_be_a_u64() {
    let cmd = "fb.firmware=seabios-gpt fb.root-hash=ab fb.verity-hash-offset=4096 \
               fb.rootfs-dev=PARTUUID=04c92659-e47a-485b-b840-fe5561eaa0da \
               fb.weights-dev=PARTUUID=7d3b9f24-6a1c-4e58-b0d9-2c4f8a6e1b35 \
               fb.weights-hash=cafef00d fb.weights-offset=notanum";
    assert_eq!(
        parse_cmdline(cmd).unwrap_err(),
        CmdlineError::InvalidWeightsOffset("notanum".to_string())
    );
}

#[test]
fn uefi_also_carries_the_weights_triple() {
                                                                                   
    let c = parse_cmdline(
        "fb.firmware=uefi fb.root-hash=ab fb.verity-hash-offset=4096 \
         fb.rootfs-dev=PARTUUID=04c92659-e47a-485b-b840-fe5561eaa0da \
         fb.weights-dev=PARTUUID=7d3b9f24-6a1c-4e58-b0d9-2c4f8a6e1b35 \
         fb.weights-hash=cafef00d fb.weights-offset=2097152",
    )
    .expect("uefi weights triple parses");
    assert!(c.weights.is_some());
}

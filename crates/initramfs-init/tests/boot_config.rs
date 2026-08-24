//! Host-runnable units for the firmware-agnostic boot-config accessor (SB-loader plan Task 2.3).
//! ONE source on both firmwares: the kernel cmdline (SeaBIOS = extlinux APPEND; UEFI = the signed
//! rambutan loader's baked cmdline via LoadOptions). The impure `/proc/cmdline` wiring in `main` is
//! proven by the Phase-5 OVMF gate.

use initramfs_init::boot_config::read_boot_config_from;
use initramfs_init::cmdline::CmdlineError;
use initramfs_init::installer::Firmware;

#[test]
fn accessor_sources_the_verity_pair_from_the_cmdline_on_both_firmwares() {
                                                                         
    let sb = read_boot_config_from(
        "fb.root-hash=abcd fb.verity-hash-offset=8192 fb.rootfs-dev=/dev/vda2 ro",
    )
    .expect("seabios boot config");
    assert_eq!(sb.firmware, Firmware::Seabios);
    assert_eq!(sb.root_hash, "abcd");
    assert_eq!(sb.verity_hash_offset, 8192);

                                                                                    
                                                                                  
    let uefi = read_boot_config_from(
        "fb.firmware=uefi fb.root-hash=cdef fb.verity-hash-offset=4096 \
         fb.rootfs-dev=PARTUUID=04c92659-e47a-485b-b840-fe5561eaa0da ro",
    )
    .expect("uefi boot config");
    assert_eq!(uefi.firmware, Firmware::Uefi);
    assert_eq!(uefi.root_hash, "cdef");                                     
    assert_eq!(uefi.verity_hash_offset, 4096);
    assert_eq!(
        uefi.rootfs_dev.as_deref(),
        Some("PARTUUID=04c92659-e47a-485b-b840-fe5561eaa0da")
    );
}

#[test]
fn accessor_fails_closed_when_the_uefi_cmdline_lacks_the_pair() {
                                                                               
                                                                                     
                                                                            
    let err = read_boot_config_from(
        "fb.firmware=uefi \
         fb.rootfs-dev=PARTUUID=04c92659-e47a-485b-b840-fe5561eaa0da ro",
    )
    .unwrap_err();
    assert_eq!(err, CmdlineError::MissingRootHash);
}

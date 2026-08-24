//! initramfs-init — the box PID-1 init library.
//!
//! The boot logic splits into host-testable pure units + the FFI-heavy syscall path. The pure units
//! (cmdline parsing + verity byte→block math, the dm-verity ioctl-buffer marshalling + target-table
//! string + dev_t decode, the IMA policy-load success determination, the pseudo-mount table) are
//! unit-tested on the host without root or a kernel. The syscall sequences they feed (dm-verity
//! device-mapper ioctls, mount, securityfs policy write, `switch_root`) are exercised by the
                
//! QEMU boot-test (the Task 1.6 plan). Every kernel-mechanism constant is verified
                                    
//! against the pinned linux-6.18.33 source, not asserted.

                                                                                                   
                                                                                                    
                                                                                                 
                                                                                                        
                                                                                                       
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

pub mod boot_config;
pub mod cmdline;
pub mod ima_policy;
pub mod install_target;
pub mod installer;
pub mod installer_stream;
pub mod installer_syscall;
pub mod mount;
pub mod verity;

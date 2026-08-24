                                          
//! Option-C IMA appraise-policy load (Task 1.6 inc-2, spec init-flow step 4a).
//! After mounting the verity rootfs and BEFORE `switch_root`, the init loads the
//! operator-signed appraise ruleset so every post-`switch_root` exec is IMA-appraised. FAIL-CLOSED:
//! a load that does not take is a kernel panic — never a silent layer-6-absent boot.
//!
//! **Mechanism verified against the pinned kernel** (`security/integrity/ima/ima_fs.c::ima_write_policy`,
                                    
//! linux-6.18.33):
//!  - We write the **absolute path** `/sysroot/etc/ima/policy` (the `data[0] == '/'` branch →
//!    `kernel_read_file_from_path(.., READING_POLICY)`). Under `CONFIG_IMA_APPRAISE_REQUIRE_POLICY_SIGS=y`
//!    that read appraises the policy file's OWN `security.ima` signature — so an unsigned/forged
//!    policy is refused. Writing the rules inline instead would hit the `-EACCES` "signed policy
//!    file (absolute pathname) required" path.
//!  - **One `write()` only**: the handler rejects `*ppos != 0` with `-EINVAL` (no partial writes),
//!    and truncates at `PAGE_SIZE`. The path is tiny, so a single `libc::write` is correct.
//!  - **Success signal**: on the path branch the handler returns `pathlen` (the bytes we wrote);
//!    on any failure (bad signature, missing file, parse error) it returns a negative errno. So
//!    `write_ret == bytes_written` ⇔ the rules were parsed, appraised, and applied.

use std::io;
use std::os::unix::io::AsRawFd;

/// The signed appraise policy on the (now-mounted) verity rootfs. Written as an absolute PATH so the
/// kernel reads + signature-checks the file itself (see module doc).
pub const POLICY_PATH: &str = "/sysroot/etc/ima/policy";

/// The securityfs policy sink. securityfs must already be mounted at /sys/kernel/security.
pub const SECURITYFS_POLICY: &str = "/sys/kernel/security/ima/policy";

/// Why a policy load is treated as failed (each → kernel panic in the PID-1 caller).
#[derive(Debug, PartialEq, Eq)]
pub enum PolicyError {
    /// The kernel returned a negative errno (rejected: bad/absent signature, missing file, or a
    /// rule the kernel won't parse).
    KernelRejected(i64),
    /// The write returned a byte count that does not match what we wrote — the load did not fully
    /// take. Fail closed rather than assume success.
    ShortWrite { wrote: usize, returned: i64 },
}

impl std::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KernelRejected(e) => {
                write!(
                    f,
                    "kernel rejected IMA policy load (errno {e}) — signature/parse failure"
                )
            }
            Self::ShortWrite { wrote, returned } => {
                write!(
                    f,
                    "IMA policy load short write: wrote {wrote} bytes, kernel returned {returned}"
                )
            }
        }
    }
}

impl std::error::Error for PolicyError {}

/// Decide whether a policy `write()` took, from its return value + the bytes written. Pure so the
/// fail-closed contract is host-tested without securityfs. Success ⇔ the kernel returned exactly the
/// path length (the `ima_write_policy` path-branch return); anything else fails closed.
pub fn load_outcome(write_ret: i64, bytes_written: usize) -> Result<(), PolicyError> {
    if write_ret < 0 {
        return Err(PolicyError::KernelRejected(write_ret));
    }
    if write_ret as usize != bytes_written {
        return Err(PolicyError::ShortWrite {
            wrote: bytes_written,
            returned: write_ret,
        });
    }
    Ok(())
}

/// Load the signed IMA appraise policy via securityfs (FFI; exercised by the QEMU boot-test).
/// Opens the policy sink **write-only** (the handler `-EACCES`es a non-`O_WRONLY` open), writes the
/// policy file path in a single `write()`, and validates the return fail-closed. Returns `Err` on any
/// failure — the caller panics, which is the layer-6 fail-closed guarantee.
pub fn load_policy() -> Result<(), Box<dyn std::error::Error>> {
    use std::fs::OpenOptions;
                                                                                                      
    let file = OpenOptions::new().write(true).open(SECURITYFS_POLICY)?;
    let bytes = POLICY_PATH.as_bytes();
                                                                                          
                                                                            
    let ret = unsafe { libc::write(file.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
    if ret < 0 {
                                                                                             
        return Err(Box::new(io::Error::last_os_error()));
    }
    load_outcome(ret as i64, bytes.len())?;
                                                                                                    
                                                                                                      
                                                                                                      
                                                                                                       
                                                                                                      
                                                                                                
                                            
    drop(file);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_an_absolute_path_so_the_kernel_appraises_the_policy_file() {
                                                                                             
                                                                                              
        assert!(POLICY_PATH.starts_with('/'));
        assert_eq!(POLICY_PATH, "/sysroot/etc/ima/policy");
    }

    #[test]
    fn full_write_is_success() {
        assert_eq!(load_outcome(23, 23), Ok(()));
    }

    #[test]
    fn negative_return_fails_closed() {
                                                                                      
        assert_eq!(load_outcome(-13, 23), Err(PolicyError::KernelRejected(-13)));
    }

    #[test]
    fn short_write_fails_closed() {
                                                                        
        assert_eq!(
            load_outcome(10, 23),
            Err(PolicyError::ShortWrite {
                wrote: 23,
                returned: 10
            })
        );
    }

    #[test]
    fn zero_return_fails_closed() {
        assert_eq!(
            load_outcome(0, 23),
            Err(PolicyError::ShortWrite {
                wrote: 23,
                returned: 0
            })
        );
    }
}

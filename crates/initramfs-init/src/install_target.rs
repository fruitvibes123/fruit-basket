                       
//! UEFI installer target-disk selection — the pure, host-tested eligibility logic.
//!
//! The destructive-write target is selected INDEPENDENTLY of the boot/source USB: fail-closed when
//! zero or multiple internal disks are eligible, or via an explicit `fb.install-to` whole-disk
//! override. The `/sys/block` enumeration FFI ([`crate::installer_syscall`], Task 2.4) feeds these
//! pure predicates; this module touches no real device, so the safety matrix is host-unit-tested.

/// The installable whole-disk classes (mirrors `installer::disk_from_partition`'s families; rules
/// out loop/dm/ram/etc.) — moved VERBATIM to `fb_verity_rt::discover` (hotswap v4 §9/R3-I7), where
/// the runtime PARTUUID scan shares it; re-exported so [`valid_install_to_dev`] and the
/// `/sys/block` enumeration's `class_ok` keep their `crate::install_target::` path.
pub use fb_verity_rt::is_candidate_disk_class;

/// A block disk as seen by target selection. `class_ok` = an installable disk class;
                  
/// `removable` = `/sys/block/<name>/removable == 1`. **`removable` is ADVISORY**: a
/// boot USB is *typically* removable, but the LOAD-BEARING exclusion of the source/boot disk is
/// `!= source` in [`select_target`] — NOT this flag. Under QEMU `usb-storage` the stick reads
/// `removable=0`, so the OVMF gate exercises the `!= source` path, NOT the removable filter (the §12-2
/// "removable reads 1 for the stick" obligation is UNDISCHARGED by the gate; the `!= source` fallback is
/// what holds). `removable` only adds AUTO-select exclusion of *other* removable media. The FFI
/// enumeration (Task 2.4) builds these; the struct is pure data so [`select_target`] is host-tested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskInfo {
    pub name: String,
    pub class_ok: bool,
    pub removable: bool,
}

/// Why target selection halted (fail-closed BEFORE any write). Each maps to a printed-reason kernel
/// halt in the installer (`console=tty0/ttyS0` makes the reason operator-visible).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetError {
    /// Auto-select found NO eligible internal disk (`class_ok ∧ !removable ∧ != source`).
    NoneEligible,
    /// Auto-select found MORE THAN ONE — refuse to guess which to wipe (carries the names).
    Ambiguous(Vec<String>),
    /// `fb.install-to` names the source disk — refuse to wipe the boot USB.
    InstallToIsSource,
    /// `fb.install-to` is not a valid whole-disk device name (fails [`valid_install_to_dev`]).
    InstallToInvalid,
    /// `fb.install-to` names a disk not present in the enumerated set.
    InstallToMissing,
}

impl core::fmt::Display for TargetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoneEligible => write!(
                f,
                "no eligible internal target disk (need exactly one fixed, non-source disk; set fb.install-to=<dev>)"
            ),
            Self::Ambiguous(names) => write!(
                f,
                "ambiguous target: {} eligible internal disks {names:?} — set fb.install-to=<dev>",
                names.len()
            ),
            Self::InstallToIsSource => {
                write!(
                    f,
                    "fb.install-to names the source/boot disk — refusing to wipe it"
                )
            }
            Self::InstallToInvalid => {
                write!(f, "fb.install-to is not a valid whole-disk device name")
            }
            Self::InstallToMissing => {
                write!(f, "fb.install-to names a disk not present on this machine")
            }
        }
    }
}

/// Is `s` a WHOLE-disk device name (not a partition) of an installable class? A precise per-class
                  
/// grammar — deliberately NOT `disk_from_partition`'s lenient inverse, which admits
/// bare class prefixes (`sd`, `nvme`, `nvme0`) and odd forms (`sda1b`) as "not a partition". Accepts
/// exactly the real whole-disk shapes; `select_target`'s candidate-set membership check remains the
/// load-bearing gate (only a real `/sys/block` entry is ever written) — this is the syntactic belt.
fn is_whole_disk_name(s: &str) -> bool {
                                                                                                        
    if let Some(rest) = s.strip_prefix("nvme") {
        return match rest.split_once('n') {
            Some((ctrl, ns)) => {
                !ctrl.is_empty()
                    && ctrl.bytes().all(|b| b.is_ascii_digit())
                    && !ns.is_empty()
                    && ns.bytes().all(|b| b.is_ascii_digit())
            }
            None => false,
        };
    }
                                                                    
    if let Some(rest) = s.strip_prefix("mmcblk") {
        return !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit());
    }
                                                                                                   
    ["xvd", "sd", "vd", "hd"].into_iter().any(|class| {
        s.strip_prefix(class)
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_lowercase()))
    })
}

/// Validate an `fb.install-to=<dev>` value: a bare `[a-z0-9]+` token that is a WHOLE disk of an
                           
/// installable class ([`is_whole_disk_name`]). DISTINCT from
/// `installer::is_valid_source_device` (which validates a *partition*). Rejects partitions
/// (`sda1`/`nvme0n1p1`), bare class prefixes (`sd`/`nvme`/`nvme0`), and uppercase / slashes / empty.
pub fn valid_install_to_dev(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && is_whole_disk_name(s)
}

/// Select the destructive-write target disk INDEPENDENTLY of the source (§6 H-1). With `install_to`:
/// that exact whole disk (must be valid, `!=` source, and present in `candidates`). Without it: the
/// EXACTLY-ONE disk that is an installable class, non-removable, and `!=` source — `0` or `>1` fail
/// closed. NEVER returns the source disk. Pure; the caller (Task 2.4) writes only the returned name.
pub fn select_target(
    candidates: &[DiskInfo],
    install_to: Option<&str>,
    source_disk: &str,
) -> Result<String, TargetError> {
    if let Some(dev) = install_to {
                                                                
        if dev == source_disk {
            return Err(TargetError::InstallToIsSource);
        }
        if !valid_install_to_dev(dev) {
            return Err(TargetError::InstallToInvalid);
        }
        if !candidates.iter().any(|d| d.name == dev) {
            return Err(TargetError::InstallToMissing);
        }
        return Ok(dev.to_string());
    }
                                                                                                
    let eligible: Vec<&str> = candidates
        .iter()
        .filter(|d| d.class_ok && !d.removable && d.name != source_disk)
        .map(|d| d.name.as_str())
        .collect();
    match eligible.as_slice() {
        [] => Err(TargetError::NoneEligible),
        [one] => Ok((*one).to_string()),
        many => Err(TargetError::Ambiguous(
            many.iter().map(|s| s.to_string()).collect(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn di(name: &str, class_ok: bool, removable: bool) -> DiskInfo {
        DiskInfo {
            name: name.to_string(),
            class_ok,
            removable,
        }
    }

    #[test]
    fn auto_selects_single_fixed_nonsource() {
                                                                                                     
                                        
        let c = vec![di("sda", true, true), di("nvme0n1", true, false)];
        assert_eq!(select_target(&c, None, "sda").unwrap(), "nvme0n1");
    }

    #[test]
    fn auto_halts_on_two_eligible() {
                                                                                                      
        let c = vec![
            di("sda", true, true),
            di("nvme0n1", true, false),
            di("nvme1n1", true, false),
        ];
        assert!(matches!(
            select_target(&c, None, "sda"),
            Err(TargetError::Ambiguous(_))
        ));
    }

    #[test]
    fn auto_halts_on_zero_eligible() {
                                                                                                 
        let c = vec![di("sda", true, true)];
        assert!(matches!(
            select_target(&c, None, "sda"),
            Err(TargetError::NoneEligible)
        ));
    }

    #[test]
    fn auto_excludes_source_even_if_misflagged_nonremovable() {
                                                                                               
                                                                                             
        let c = vec![di("sda", true, false)];
        assert!(matches!(
            select_target(&c, None, "sda"),
            Err(TargetError::NoneEligible)
        ));
    }

    #[test]
    fn auto_skips_removable_and_wrong_class() {
                                                                              
        let c = vec![
            di("sda", true, true),                  
            di("sdb", true, true),                                                      
            di("loop0", false, false),                            
            di("nvme0n1", true, false),
        ];
        assert_eq!(select_target(&c, None, "sda").unwrap(), "nvme0n1");
    }

    #[test]
    fn install_to_selects_the_named_disk() {
        let c = vec![di("sda", true, true), di("nvme0n1", true, false)];
        assert_eq!(
            select_target(&c, Some("nvme0n1"), "sda").unwrap(),
            "nvme0n1"
        );
    }

    #[test]
    fn install_to_must_not_be_source() {
        let c = vec![di("sda", true, true), di("nvme0n1", true, false)];
        assert!(matches!(
            select_target(&c, Some("sda"), "sda"),
            Err(TargetError::InstallToIsSource)
        ));
    }

    #[test]
    fn install_to_rejects_a_partition_or_garbage() {
        let c = vec![di("sda", true, true), di("nvme0n1", true, false)];
                                               
        assert!(matches!(
            select_target(&c, Some("nvme0n1p1"), "sda"),
            Err(TargetError::InstallToInvalid)
        ));
        assert!(matches!(
            select_target(&c, Some("garbage"), "sda"),
            Err(TargetError::InstallToInvalid)
        ));
    }

    #[test]
    fn install_to_must_exist_in_the_candidate_set() {
        let c = vec![di("sda", true, true), di("nvme0n1", true, false)];
        assert!(matches!(
            select_target(&c, Some("nvme1n1"), "sda"),
            Err(TargetError::InstallToMissing)
        ));
    }

    #[test]
    fn valid_install_to_dev_accepts_whole_disks() {
        for ok in ["sda", "vdb", "nvme0n1", "mmcblk0", "xvda"] {
            assert!(
                valid_install_to_dev(ok),
                "{ok:?} should be a valid whole disk"
            );
        }
    }

    #[test]
    fn valid_install_to_dev_rejects_partitions_and_garbage() {
        for bad in [
            "sda1",                              
            "nvme0n1p1",                        
            "mmcblk0p2",                        
            "",                  
            "SDA",                   
            "foo",                       
            "/dev/sda",            
            "sda/x",               
        ] {
            assert!(
                !valid_install_to_dev(bad),
                "{bad:?} should be rejected as an install-to target"
            );
        }
    }

    #[test]
    fn valid_install_to_dev_rejects_bare_class_prefixes_and_partial_names() {
                                                                                                        
                                                                                                          
                                                                                                         
                                               
        for phantom in [
            "sd", "vd", "hd", "xvd", "nvme", "mmcblk",                       
            "nvme0", "nvme0n", "nvmexn1",                            
            "sda1b",                                                                        
        ] {
            assert!(
                !valid_install_to_dev(phantom),
                "{phantom:?} is not a whole disk and must be rejected"
            );
        }
    }
}

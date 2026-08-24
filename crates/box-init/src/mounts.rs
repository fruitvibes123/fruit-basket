//! Early-boot mounts box-init applies post-`switch_root`.
//!
//! box-init mounts the runtime tmpfs (`/run`, `/tmp`; plus a tmpfs `/persist` on the bench host, see
//! [`early_mounts`]). `/proc`, `/sys`, `/dev` are already
//! mounted: `initramfs-init`'s `switch_root` `MS_MOVE`s them into the new root
//! (`crates/initramfs-init/src/mount.rs:91-102`), so re-mounting them here would stack a second
//! mount over each. Both tmpfs carry the FSTAB hardening (`config.rs` FSTAB) — `nosuid,nodev,noexec`.
             
//! The `/run noexec` is the *retained backstop*: legitimate execs resolve through the
//! scan-directory symlinks onto the signed verity rootfs (the kernel checks the *resolved* mount),
//! so noexec never fires on them — it only fail-closes an accidental tmpfs-resident exec target.

use rustix::mount::MountFlags;

/// One `mount(2)` the early boot performs. `source`/`fstype`/`data` are the classic mount args;
/// `flags` is the typed `MountFlags` bitset.
pub struct MountSpec {
    pub source: &'static str,
    pub target: &'static str,
    pub fstype: &'static str,
    pub flags: MountFlags,
    pub data: &'static str,
}

/// The tmpfs box-init mounts after `switch_root`, in order. `/run` + `/tmp` always — see the module
/// doc for why `/proc`/`/sys`/`/dev` are excluded (inherited via `MS_MOVE`). All `nosuid,nodev,noexec`,
/// matching `config.rs` FSTAB lines 257-258.
///
/// On the **bench host** (`bench == true`, signalled by the signed `/etc/box-bench` marker) it ALSO
/// mounts a tmpfs `/persist`. The bench has no persist partition, so without it box-init's Rescue-classed
/// persist oneshots (`prepare-persist`/`mount-persist`/`-check`/`setup-dirs`) fail → the box diverts to a
/// dead no-network rescue and never reaches its services. With the tmpfs in place their
/// `mountpoint -q /persist` guards short-circuit and `setup-dirs` mkdir/chowns on it. The server boot
/// (`bench == false`) is byte-unchanged.
pub fn early_mounts(bench: bool) -> Vec<MountSpec> {
    let hardened = MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC;
    let mut mounts = vec![
        MountSpec {
            source: "tmpfs",
            target: "/run",
            fstype: "tmpfs",
            flags: hardened,
            data: "mode=0755",
        },
        MountSpec {
            source: "tmpfs",
            target: "/tmp",
            fstype: "tmpfs",
            flags: hardened,
            data: "mode=1777",
        },
    ];
    if bench {
                                                                                                      
                                                                                                           
                                                                                                          
                                                                                   
        mounts.push(MountSpec {
            source: "tmpfs",
            target: "/persist",
            fstype: "tmpfs",
            flags: hardened,
            data: "mode=0755",
        });
    }
    mounts
}

impl MountSpec {
    /// Create the mountpoint (harmless if the rootfs already baked it) then perform the mount.
    pub fn apply(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(self.target)?;
                                                                                                  
                                                                                               
        rustix::mount::mount(
            cstr(self.source)?.as_c_str(),
            cstr(self.target)?.as_c_str(),
            cstr(self.fstype)?.as_c_str(),
            self.flags,
            cstr(self.data)?.as_c_str(),
        )?;
        Ok(())
    }
}

/// `&str` → `CString` for the `mount(2)` FFI (mirrors `initramfs-init`'s `cstr`).
fn cstr(s: &str) -> std::io::Result<std::ffi::CString> {
    std::ffi::CString::new(s).map_err(|_| std::io::Error::other("interior NUL in mount arg"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn early_mounts_are_run_and_tmp_tmpfs() {
        let m = early_mounts(false);
        assert_eq!(
            m.iter().map(|s| s.target).collect::<Vec<_>>(),
            ["/run", "/tmp"],
            "the server boot mounts only the runtime tmpfs; /proc,/sys,/dev are MS_MOVE'd by initramfs-init"
        );
        for s in &m {
            assert_eq!(s.fstype, "tmpfs");
            assert!(
                s.flags
                    .contains(MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC),
                             
                "{} must be nosuid,nodev,noexec (FSTAB hardening; /run noexec backstop)",
                s.target
            );
        }
        assert_eq!(m[0].data, "mode=0755", "/run mode");
        assert_eq!(m[1].data, "mode=1777", "/tmp mode");
    }

    #[test]
    fn early_mounts_bench_adds_a_tmpfs_persist() {
                                                                                                        
                                                                                                           
                                                                                                           
                                                                                                               
        let m = early_mounts(true);
        assert_eq!(
            m.iter().map(|s| s.target).collect::<Vec<_>>(),
            ["/run", "/tmp", "/persist"],
            "the bench host adds a tmpfs /persist after /run + /tmp"
        );
        let persist = m
            .iter()
            .find(|s| s.target == "/persist")
            .expect("the bench /persist mount");
        assert_eq!(persist.fstype, "tmpfs");
        assert!(
            persist
                .flags
                .contains(MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC),
            "the bench /persist tmpfs must be nosuid,nodev,noexec (matches the prod /persist fstab)"
        );
                                                                                 
        assert_eq!(
            early_mounts(false)
                .iter()
                .map(|s| s.target)
                .collect::<Vec<_>>(),
            ["/run", "/tmp"],
            "bench=false must NOT add /persist (the prod boot is unchanged)"
        );
    }
}

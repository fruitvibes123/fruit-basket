//! Mount + sysctl + `switch_root` syscalls for the runtime boot path (the
//! init-flow steps 1/1a/4/5/6). All FFI — exercised by the QEMU boot-test; the PID-1 caller
                 
//! turns any `Err` into a kernel panic (fail-closed). The only host-testable unit is
//! the pseudo-filesystem mount table.

use std::ffi::CString;
use std::io;
use std::os::unix::io::AsRawFd;
use std::path::Path;

/// The pseudo-filesystems the init mounts at step 1, in order. securityfs is mounted last because it
/// lives under `/sys` (the IMA policy sink at /sys/kernel/security/ima/policy needs it — step 4a).
/// `(fstype, mountpoint, flags)` — source is the fstype name (conventional for virtual filesystems).
///
              
/// Hardening: `/proc`, `/sys`, and securityfs carry `nosuid,nodev,noexec`; `/dev`
/// (devtmpfs) carries `nosuid` ONLY — NOT `nodev` (it MUST interpret device nodes) and NOT `noexec`
/// (kept exec-permissive). These flags survive the later `switch_root` `MS_MOVE` (MS_MOVE relocates a
/// mount carrying its existing flags), so no runtime re-mount is needed — box-init re-mounts only
/// `/run`+`/tmp` (`box-init/src/mounts.rs`). This brings the inherited pseudo-mounts up to the
/// systemd/CIS baseline the tmpfs already meet.
pub fn pseudo_mounts() -> [(&'static str, &'static str, libc::c_ulong); 4] {
    const HARDENED: libc::c_ulong = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
    [
        ("proc", "/proc", HARDENED),
        ("sysfs", "/sys", HARDENED),
        ("devtmpfs", "/dev", libc::MS_NOSUID),
        ("securityfs", "/sys/kernel/security", HARDENED),
    ]
}

fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::other("interior NUL in path"))
}

/// `mount(2)` wrapper. `fstype`/`data` are passed only when `Some` (NULL otherwise — required for
/// MS_MOVE, which takes neither).
fn do_mount(
    source: &str,
    target: &str,
    fstype: Option<&str>,
    flags: libc::c_ulong,
) -> io::Result<()> {
    let source = cstr(source)?;
    let target = cstr(target)?;
    let fstype = fstype.map(cstr).transpose()?;
    let fstype_ptr = fstype.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
                                                                                                   
                                  
    let rc = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fstype_ptr,
            flags,
            std::ptr::null(),
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Step 1: mount /proc, /sys, /dev (devtmpfs), and securityfs. Mountpoints are created if absent
/// (a minimal initramfs cpio may not carry every dir).
pub fn mount_pseudo_filesystems() -> io::Result<()> {
    for (fstype, mountpoint, flags) in pseudo_mounts() {
                                                                                                  
        let _ = std::fs::create_dir_all(mountpoint);
        do_mount(fstype, mountpoint, Some(fstype), flags)?;
    }
    Ok(())
}

/// Steps 1a + 5: write a bare sysctl value (`7` to printk, `2` to ptrace_scope). The kernel sysctl
           
/// files take the bare value, NOT a `key=value` form.
pub fn write_sysctl(path: &str, value: &str) -> io::Result<()> {
    std::fs::write(path, value)
}

/// The dha weights dm-verity volume's RO mount point INSIDE the rootfs (Component E; operator-pinned
/// 2026-06-30). A baked-EMPTY directory in the RO rootfs squashfs — `initramfs-init` mounts the weights
/// squashfs here RO after the rootfs verity, before `switch_root`, so it rides the `/sysroot → /` MS_MOVE
/// (the real mount target is `SYSROOT` + this, i.e. `/sysroot/models`). This is the MOUNT DIRECTORY, NOT
/// the model FILE: dha's `creatine` reads the GGUF at `$CREATINE_MODEL_PATH=/models/model.gguf` (the
/// canonical in-volume name keeps that env constant across model swaps). MUST byte-match the dir the
/// orchard bake creates EMPTY in the dha rootfs (a cross-crate convention constant, D3). No runtime mkdir
/// on the RO rootfs (Info-1) — the dir pre-exists in the squashfs; the weights mount does NOT create it.
pub const WEIGHTS_MOUNT_DIR: &str = "/models";

/// Step 4: mount the verity block device (read-only squashfs) at /sysroot.
pub fn mount_verity_rootfs(dev: &Path, target: &str) -> io::Result<()> {
    std::fs::create_dir_all(target)?;
    let dev = dev
        .to_str()
        .ok_or_else(|| io::Error::other("non-utf8 device path"))?;
    do_mount(dev, target, Some("squashfs"), libc::MS_RDONLY)
}

/// dha Component E: the weights RO mount target = `SYSROOT` + [`WEIGHTS_MOUNT_DIR`] (e.g.
/// `/sysroot/models`). Mounting there (a baked-empty dir INSIDE the RO rootfs) makes the weights mount a
/// submount of `/sysroot`, so it rides the `/sysroot → /` `MS_MOVE` in [`switch_root`] and lands at
/// `/models` — where box-init/`creatine` read it (`CREATINE_MODEL_PATH=/models/model.gguf`).
pub fn weights_mount_target(sysroot: &str) -> String {
    format!("{sysroot}{WEIGHTS_MOUNT_DIR}")
}

/// Step 4b (dha Component E): mount the weights dm-verity squashfs READ-ONLY at
/// [`weights_mount_target`]. Unlike [`mount_verity_rootfs`] it does NOT create the mountpoint — the dir
/// is baked EMPTY into the RO rootfs squashfs by the orchard bake (Info-1: no runtime mkdir on a RO
/// filesystem). A missing dir fails CLOSED with a clear diagnostic before the opaque `mount(2)` ENOENT,
/// never a silent runtime create. Called after the rootfs mount (so the dir exists) and before
/// `switch_root` (so the mount rides the `MS_MOVE`).
pub fn mount_weights_verity(dev: &Path, sysroot: &str) -> io::Result<()> {
    let target = weights_mount_target(sysroot);
    if !Path::new(&target).is_dir() {
        return Err(io::Error::other(format!(
            "weights mount dir {target} absent — it MUST be baked EMPTY into the RO rootfs (no runtime mkdir, Info-1)"
        )));
    }
    let dev = dev
        .to_str()
        .ok_or_else(|| io::Error::other("non-utf8 weights device path"))?;
    do_mount(dev, &target, Some("squashfs"), libc::MS_RDONLY)
}

/// Step 6 (runtime): the canonical `switch_root` into `newroot`, then `execv` `init`. Moves the API
/// filesystems into the new root, `MS_MOVE`s the new root onto `/`, `chroot`s, reopens the console,
/// and execs. On success this NEVER returns (the process image is replaced); it returns `Err` only
/// when a step fails (→ kernel panic in the caller). `newroot`/`init` are build-time constants.
pub fn switch_root(newroot: &str, init: &str) -> io::Result<std::convert::Infallible> {
                                                                                              
    let init_on_newroot = format!("{newroot}{init}");
    if !Path::new(&init_on_newroot).exists() {
        return Err(io::Error::other(format!("no init at {init_on_newroot}")));
    }

                                                                                                   
                                                      
    for (_fstype, mountpoint, _flags) in pseudo_mounts() {
                                                                                                    
                                                                                                        
                                                                                                  
                                 
        if mountpoint == "/sys/kernel/security" {
            continue;
        }
        let dst = format!("{newroot}{mountpoint}");
        let _ = std::fs::create_dir_all(&dst);
        do_mount(mountpoint, &dst, None, libc::MS_MOVE)?;
    }

    chdir(newroot)?;
                                                                            
    do_mount(".", "/", None, libc::MS_MOVE)?;
    chroot(".")?;
    chdir("/")?;
    reopen_console();

    let init_c = cstr(init)?;
    let argv = [init_c.as_ptr(), std::ptr::null()];
                                                                              
    unsafe {
        libc::execv(init_c.as_ptr(), argv.as_ptr());
    }
                                     
    Err(io::Error::last_os_error())
}

fn chdir(path: &str) -> io::Result<()> {
    let p = cstr(path)?;
                                         
    if unsafe { libc::chdir(p.as_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn chroot(path: &str) -> io::Result<()> {
    let p = cstr(path)?;
                                         
    if unsafe { libc::chroot(p.as_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Reopen /dev/console onto stdin/stdout/stderr after the root switch (best-effort — failure here is
/// not fatal; the panic path writes /dev/kmsg directly).
fn reopen_console() {
    if let Ok(f) = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/console")
    {
        let fd = f.as_raw_fd();
                                                                                           
        unsafe {
            libc::dup2(fd, 0);
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn securityfs_is_mounted_after_sysfs() {
                                                                                                 
        let mounts = pseudo_mounts();
        let sys = mounts.iter().position(|(_, m, _)| *m == "/sys").unwrap();
        let sec = mounts
            .iter()
            .position(|(_, m, _)| *m == "/sys/kernel/security")
            .unwrap();
        assert!(sys < sec, "securityfs must mount after sysfs");
    }

    #[test]
    fn dev_is_devtmpfs() {
                                                                                                  
        let mounts = pseudo_mounts();
        assert!(
            mounts
                .iter()
                .any(|(fs, m, _)| *fs == "devtmpfs" && *m == "/dev")
        );
    }

    #[test]
    fn pseudo_mounts_carry_hardening_flags() {
                                                                                                    
                                                                                            
        let mounts = pseudo_mounts();
        let flags = |mp: &str| {
            mounts
                .iter()
                .find(|(_, p, _)| *p == mp)
                .map(|(_, _, f)| *f)
                .unwrap()
        };
        let full = libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC;
        assert_eq!(flags("/proc"), full, "/proc must be nosuid,nodev,noexec");
        assert_eq!(flags("/sys"), full, "/sys must be nosuid,nodev,noexec");
        assert_eq!(
            flags("/sys/kernel/security"),
            full,
            "securityfs must be nosuid,nodev,noexec"
        );
                                                                                                        
        assert_eq!(
            flags("/dev"),
            libc::MS_NOSUID,
            "/dev devtmpfs = nosuid only (needs device nodes; kept exec-permissive)"
        );
        assert_eq!(
            flags("/dev") & libc::MS_NODEV,
            0,
            "/dev must NOT carry nodev — it would break device-node interpretation"
        );
    }

    #[test]
    fn weights_mount_target_is_sysroot_plus_models() {
                                                                                                   
                                                                                                           
                                                                                               
        assert_eq!(weights_mount_target("/sysroot"), "/sysroot/models");
    }

    #[test]
    fn mount_weights_verity_fails_closed_on_a_missing_baked_dir() {
                                                                                                          
                                                                                                         
                                                                                                           
                                                  
        let err = mount_weights_verity(
            Path::new("/dev/irrelevant"),
            "/nonexistent-sysroot-for-the-weights-mount-test",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("baked"),
            "a missing weights mount dir must fail closed with the baked-dir diagnostic, got: {err}"
        );
    }

    #[test]
    fn weights_mount_dir_is_the_canonical_contract_path() {
                                                                                                    
                                                                                                         
                                                                                                          
                                                                                                    
        assert_eq!(WEIGHTS_MOUNT_DIR, "/models");
        assert!(WEIGHTS_MOUNT_DIR.starts_with('/'));
        assert!(!WEIGHTS_MOUNT_DIR.ends_with('/'));
        assert!(!WEIGHTS_MOUNT_DIR.contains(char::is_whitespace));
    }
}

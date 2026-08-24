//! Build the tmpfs scan directory box-init hands to `s6-svscan`.
//!
//! The signed-exec invariant (spec §3): everything `s6-svscan`/`s6-supervise` `execve` resolves onto
//! the signed dm-verity rootfs; tmpfs holds only never-executed control state. The scandir (tmpfs,
//! `/run/service`) contains:
//!   - per active service, a WRITABLE tmpfs servicedir `<name>/` whose `run` is a symlink to the
//!     signed rootfs run script: `<name>/run` -> `<box_svc>/<name>/run`. s6-supervise CREATES
//!     `supervise/` + `event/` inside `<name>/` (they must be writable — servicedir.html), so the
//!     servicedir lives on tmpfs; only `run` (+ an OPTIONAL `finish`, wired the same way) rides the RO rootfs. On exec, `./run` resolves through
//!     the symlink onto the rootfs mount → IMA appraises the signed inode and `/run noexec` doesn't
//!     fire (the resolved mount is the rootfs, not the tmpfs scandir). This is the documented RO-root
//!     pattern (a writable tmpfs servicedir over a RO run image), with `run` symlinked-not-copied so
//!     it stays signed. (The earlier whole-servicedir-symlink + supervise/event-symlink layout failed:
//!     s6-supervise `mkdir`s `event` and a symlink there is always EEXIST → fatal — boot-gate finding.)
//!   - `.s6-svscan/<handler>` symlinks -> `<box_svc>/.s6-svscan/<handler>` with **absolute** targets.
//!     `s6-svscan` execs `finish`/`SIGxxx` by a RELATIVE path from this tmpfs CWD with NO chdir, so
             
//!     only an absolute symlink-into-the-rootfs keeps the executed inode signed — a plain
//!     tmpfs handler would be unsigned + on the `noexec` mount → EACCES → PID-1-exit panic.
//!
//! CONTRACT with `service_tree.rs` (image-builder, build-time): it emits `<box_svc>/<name>/run` (the
//! signed run script), an OPTIONAL `<box_svc>/<name>/finish` (the signed s6-permafailon restart-cap,
//! D2 — present only for a capped service), + `<box_svc>/.s6-svscan/` handler scripts; box-init
//! discovers + wires them here. The set agreement is verified by the boot-gate — a name with no
            
//! servicedir would dangle, and a `finish` left unwired would silently void the restart-cap.

use std::io;
use std::path::Path;

/// The `s6-svscan` control dir (skipped by service discovery; svscan also writes its `control` FIFO
/// + `lock` here at startup, tolerating our pre-created dir).
const SVSCAN_CTRL: &str = ".s6-svscan";

/// The `finish` + shutdown-signal handlers box-init symlinks into the scandir's `.s6-svscan`,
/// targeting the signed rootfs copies. `finish` = the teardown; `SIGTERM`/`SIGUSR1`/`SIGUSR2` =
/// reboot/halt/poweroff (spec §4). MUST match the set `service_tree.rs` emits.
pub const HANDLERS: [&str; 4] = ["finish", "SIGTERM", "SIGUSR1", "SIGUSR2"];

/// Rescue servicedirs carry this name prefix; everything else is a normal (services-bundle) service.
const RESCUE_PREFIX: &str = "rescue-";

/// Discover the servicedirs under `box_svc`, partitioned `(services, rescue)`. A servicedir is a
/// subdirectory containing a regular `run` file; the `.s6-svscan` control dir + any other dotfile is
/// skipped, as is any non-directory or a directory without a `run`. `rescue-*` → rescue, the rest →
/// services. Both byte-lexicographically sorted (== `LC_ALL=C` for the ASCII service names — a
/// deterministic scandir for the reproducibility gate).
pub fn discover_servicedirs(box_svc: &Path) -> io::Result<(Vec<String>, Vec<String>)> {
    let mut services = Vec::new();
    let mut rescue = Vec::new();
    for entry in std::fs::read_dir(box_svc)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') {
            continue;                                                       
        }
        if !entry.file_type()?.is_dir() {
            continue;                                   
        }
                                                                                                          
                                                                                                      
                                                                                                     
                                                                                                  
        let run = entry.path().join("run");
        if !run.symlink_metadata().map(|m| m.is_file()).unwrap_or(false) {
            continue;                                                 
        }
        if name.starts_with(RESCUE_PREFIX) {
            rescue.push(name);
        } else {
            services.push(name);
        }
    }
    services.sort();
    rescue.sort();
    Ok((services, rescue))
}

/// Build the tmpfs scandir at `<run>/service` for `members`, wiring every entry onto the signed
/// rootfs. `box_svc` MUST be absolute (e.g. `/etc/box-svc`) so the `.s6-svscan` handler symlinks get
             
/// absolute targets; a relative `box_svc` is rejected fail-closed.
pub fn build_scandir(run: &Path, box_svc: &Path, members: &[String]) -> io::Result<()> {
    if !box_svc.is_absolute() {
        return Err(io::Error::other(
                         
            "box_svc must be absolute so .s6-svscan handler symlinks resolve onto the rootfs",
        ));
    }
    let scandir = run.join("service");
    std::fs::create_dir_all(&scandir)?;

    for name in members {
                                                                                                      
                                                                                                       
                                                                                                       
                                                                                                    
        let sd = scandir.join(name);
        std::fs::create_dir_all(&sd)?;
        force_symlink(&box_svc.join(name).join("run"), &sd.join("run"))?;
                                                                                                
                                                                                                        
                                                                                                         
                                                                                                    
                                                                                                       
                                                                                                        
                                                                                                          
                                                                                            
        let rootfs_finish = box_svc.join(name).join("finish");
        if rootfs_finish
            .symlink_metadata()
            .map(|m| m.is_file())
            .unwrap_or(false)
        {
            force_symlink(&rootfs_finish, &sd.join("finish"))?;
        }
    }

                                                                                              
                                                                                                      
    let ctrl = scandir.join(SVSCAN_CTRL);
    std::fs::create_dir_all(&ctrl)?;
    let rootfs_ctrl = box_svc.join(SVSCAN_CTRL);
    for h in HANDLERS {
        force_symlink(&rootfs_ctrl.join(h), &ctrl.join(h))?;
    }
    Ok(())
}

/// Create `link -> target`, replacing any pre-existing entry. The only caller is `build_scandir`, run
/// ONCE during the single PID-1 startup on a FRESH boot tmpfs (no pre-existing entry, no re-run path) —
                              
/// so the remove-then-create, though not atomic, never races (the prior
/// "idempotent across a re-run" wording over-promised; box-init has no re-run).
fn force_symlink(target: &Path, link: &Path) -> io::Result<()> {
    if link.is_symlink() || link.exists() {
        std::fs::remove_file(link)?;
    }
    std::os::unix::fs::symlink(target, link)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn touch_servicedir(box_svc: &Path, name: &str) {
        let d = box_svc.join(name);
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("run"), "#!/bin/sh\n").unwrap();
    }

    #[test]
    fn discover_partitions_by_rescue_prefix() {
        let tmp = tempfile::tempdir().unwrap();
        let box_svc = tmp.path();
        touch_servicedir(box_svc, "recipes");
        touch_servicedir(box_svc, "dropbear");
        touch_servicedir(box_svc, "rescue-dropbear");
                                                                               
        fs::create_dir_all(box_svc.join(".s6-svscan")).unwrap();
        fs::write(box_svc.join("notes.txt"), "x").unwrap();
        fs::create_dir_all(box_svc.join("emptydir")).unwrap();

        let (services, rescue) = discover_servicedirs(box_svc).unwrap();
        assert_eq!(services, ["dropbear", "recipes"]);                                    
        assert_eq!(rescue, ["rescue-dropbear"]);
    }

    #[test]
    fn discover_rejects_a_symlink_run() {
                                                                                                           
                                                                                                  
        let tmp = tempfile::tempdir().unwrap();
        let box_svc = tmp.path();
        touch_servicedir(box_svc, "recipes");                                
        let sneaky = box_svc.join("sneaky");
        fs::create_dir_all(&sneaky).unwrap();
                                                                                   
        std::os::unix::fs::symlink(box_svc.join("recipes").join("run"), sneaky.join("run"))
            .unwrap();
        let (services, rescue) = discover_servicedirs(box_svc).unwrap();
        assert_eq!(
            services,
            ["recipes"],
            "a symlink `run` servicedir must be rejected (unsigned)"
        );
        assert!(rescue.is_empty());
    }

    #[test]
    fn scandir_entry_is_a_writable_dir_with_a_run_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let box_svc = tmp.path().join("etc/box-svc");
        let run = tmp.path().join("run");
        fs::create_dir_all(&box_svc).unwrap();
        let members = vec!["recipes".to_string(), "dropbear".to_string()];
        build_scandir(&run, &box_svc, &members).unwrap();
        for name in &members {
                                                                                                      
                                                   
            let sd = run.join("service").join(name);
            assert!(
                sd.is_dir() && !sd.is_symlink(),
                "{name} servicedir must be a writable dir"
            );
                                                                    
            let runlink = sd.join("run");
            assert!(runlink.is_symlink(), "{name}/run must be a symlink");
            assert_eq!(
                fs::read_link(&runlink).unwrap(),
                box_svc.join(name).join("run")
            );
        }
    }

    #[test]
    fn scandir_wires_a_per_service_finish_symlink() {
                                                                                                    
                                                                                                      
                                                                                                   
                                                                                                      
        let tmp = tempfile::tempdir().unwrap();
        let box_svc = tmp.path().join("etc/box-svc");
        let run = tmp.path().join("run");
        fs::create_dir_all(&box_svc).unwrap();
        touch_servicedir(&box_svc, "dha-creatine");                                 
        fs::write(
            box_svc.join("dha-creatine").join("finish"),
            "#!/bin/sh\nexec s6-permafailon 3600 5 1-255 true\n",
        )
        .unwrap();
        touch_servicedir(&box_svc, "dropbear");                          
        let members = vec!["dha-creatine".to_string(), "dropbear".to_string()];
        build_scandir(&run, &box_svc, &members).unwrap();

                                                                                                  
        let capped_finish = run.join("service").join("dha-creatine").join("finish");
        assert!(
            capped_finish.is_symlink(),
            "a capped service must get a finish symlink into the live servicedir"
        );
        assert_eq!(
            fs::read_link(&capped_finish).unwrap(),
            box_svc.join("dha-creatine").join("finish")
        );
                                                                     
        let uncapped_finish = run.join("service").join("dropbear").join("finish");
        assert!(
            !uncapped_finish.exists() && !uncapped_finish.is_symlink(),
            "an uncapped service must not get a finish symlink"
        );
    }

    #[test]
    fn handler_symlinks_are_absolute_rootfs_targets() {
        let tmp = tempfile::tempdir().unwrap();
        let box_svc = tmp.path().join("etc/box-svc");                                  
        let run = tmp.path().join("run");
        fs::create_dir_all(&box_svc).unwrap();
        build_scandir(&run, &box_svc, &[]).unwrap();
        for h in HANDLERS {
            let link = run.join("service").join(".s6-svscan").join(h);
            assert!(link.is_symlink(), "{h} handler must be a symlink");
            let target = fs::read_link(&link).unwrap();
            assert!(
                target.is_absolute(),
                             
                "{h} handler target must be ABSOLUTE so it resolves onto the rootfs"
            );
            assert_eq!(target, box_svc.join(".s6-svscan").join(h));
        }
    }

    #[test]
    fn build_scandir_rejects_relative_box_svc() {
        let tmp = tempfile::tempdir().unwrap();
        let run = tmp.path().join("run");
        let err = build_scandir(&run, &PathBuf::from("etc/box-svc"), &[]).unwrap_err();
        assert!(
            err.to_string().contains("absolute"),
            "must reject a relative box_svc"
        );
    }
}

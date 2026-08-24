//! box-init — the box PID-1 (post-`switch_root` `/sbin/init`) library.
//!
//! The orchestration lives here (testable as lib API); `main.rs` is the thin bin entry. box-init
//! mounts the runtime tmpfs, builds a tmpfs scan directory of symlinks into the signed-rootfs
//! servicedirs (so every `execve` resolves onto the dm-verity rootfs), runs the bootstrap oneshots,
//! branches services-vs-rescue, then `execve`s `s6-svscan` (which becomes PID-1 and supervises).
                                                                                    

#![cfg_attr(not(test), deny(clippy::unwrap_used))]

pub mod cgroup;
pub mod mounts;
pub mod net;
pub mod oneshots;
pub mod scandir;

use oneshots::{OnFailure, Oneshot};
use std::io;
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

/// The signed-rootfs servicedir tree box-init discovers + symlinks into the scandir.
const BOX_SVC: &str = "/etc/box-svc";
/// The signed-rootfs topology file (the tenant's app-domain boot-hooks; baked by image-builder BEFORE
/// the IMA/verity signer). Parsed fail-closed at boot — a parse failure → rescue (firewall-first).
const BOX_TOPOLOGY: &str = "/etc/box-topology.toml";
/// The signed marker that switches box-init to BENCH mode — baked into the bench-host rootfs ONLY
/// (dm-verity+IMA-covered like the rest of `/etc`; the unsigned cmdline is never trusted for this).
/// Present → the net-new `(Branch::Services, no-network)` outcome (tmpfs `/persist`, eth0 down). The
/// prod box has no marker → the unchanged server boot. (Bench-host USB plan, 2026-06-16.)
const BOX_BENCH: &str = "/etc/box-bench";
/// The tmpfs scan directory `s6-svscan` supervises.
const SCANDIR: &str = "/run/service";
/// `PATH` for the oneshots + the s6 run scripts (bare tool names: `s6-envdir`, `s6-setuidgid`,
/// busybox applets). Matches the old `s6-linux-init-maker -p` set; `s6-svscan` inherits it via exec.
const PATH_ENV: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// Which scandir box-init builds + hands to `s6-svscan`.
#[derive(Debug, PartialEq, Eq)]
pub enum Branch {
    /// bootstrap fully succeeded → the normal services.
    Services,
                 
    /// a bootstrap oneshot failed → the recovery-only rescue surface (fail-closed).
    Rescue,
}

/// The result of running bootstrap + wiring the scandir: either box-init should `exec` s6-svscan on a
/// built scandir ([`Outcome::Supervise`]), or a *critical* bootstrap precondition failed and box-init
              
/// must reboot fail-closed without exposing anything ([`Outcome::Reboot`]; NO scandir is
/// built on that path, so nothing is supervised/exposed before the reboot).
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Supervise(Branch),
    Reboot,
}

/// What the bring-up closure should do (so `wire_scandir` stays testable — no real `ip`).
pub enum BringUp<'a> {
    /// Apply the parsed config (services bring-up + the C5(a) rescue re-apply). `Ok(false)` → rescue.
    Apply(&'a net::NetConfig),
    /// Best-effort `lo`+`eth0` up only (the no-parse / unsupported-config rescue path, C5(b)).
    LinkOnly,
}

/// The boot decision + scandir wiring, parameterized for testing (no real mounts, no exec, no reboot, no
/// real `ip`). Runs the bootstrap oneshots via `runner`; on success runs the Rust-native `network-up` via
/// `bring_up` at the pinned slot (after ALL bootstrap oneshots — i.e. after `nftables-load` +
/// `mount-persist*`; spec §4.4). On the BENCH host (`bench`, the `/etc/box-bench` marker), after
/// bootstrap-ok + a parsed topology, box-init enters `Branch::Services` with NO network bring-up — the
/// net-new `(Services, no-network)` outcome, skipping the `net` block below; the server boot
/// (`bench == false`) is unchanged. Three paths reach rescue: a `Rescue`-classed bootstrap oneshot failed,
/// the services `network-up` failed (R2-1), or the cmdline did not parse (`net == None`). On rescue it runs
/// the rescue oneshots + the rescue networking (`Apply` for a parsed `Static`, else `LinkOnly`). A
              
/// `Reboot`-classed oneshot (the firewall) → [`Outcome::Reboot`] with NO scandir. Testable: it
/// never reboots itself — `run` maps `Outcome::Reboot` to [`fatal`].
pub fn wire_scandir<F, G>(
    run_dir: &Path,
    box_svc: &Path,
    net: Option<&net::NetConfig>,
    topology: Option<&fb_manifest::topology::Topology>,
    bench: bool,
    mut runner: F,
    mut bring_up: G,
) -> io::Result<Outcome>
where
    F: FnMut(&Oneshot) -> io::Result<bool>,
    G: FnMut(BringUp) -> io::Result<bool>,
{
    let (services, rescue_set) = scandir::discover_servicedirs(box_svc)?;
    let mut go_rescue = false;
    let bootstrap = oneshots::bootstrap(topology);
    for o in &bootstrap {
        if runner(o)? {
            continue;
        }
        match o.on_failure {
            OnFailure::Reboot => {
                eprintln!(
                    "box-init: critical bootstrap oneshot '{}' failed → reboot",
                    o.name
                );
                return Ok(Outcome::Reboot);
            }
            OnFailure::Rescue => {
                eprintln!("box-init: bootstrap oneshot '{}' failed → rescue", o.name);
                go_rescue = true;
                break;
            }
        }
    }
                                                                                                  
                                                                                                         
                                                                                                         
    if topology.is_none() && !go_rescue {
        eprintln!("box-init: topology parse failed → rescue (firewall + persist are up)");
        go_rescue = true;
    }
                                                                                                    
                                                                                                          
                                                                                                             
                                                                                                        
                                                                                                          
                                                      
    if bench && !go_rescue {
        scandir::build_scandir(run_dir, box_svc, &services)?;
        return Ok(Outcome::Supervise(Branch::Services));
    }
                                                                                                             
                                                                            
    if !go_rescue {
        match net {
                                                                                                         
                                                                                                                
                                                                                                                 
                                                                                         
            Some(cfg) => match bring_up(BringUp::Apply(cfg)) {
                Ok(true) => {
                    scandir::build_scandir(run_dir, box_svc, &services)?;
                    return Ok(Outcome::Supervise(Branch::Services));
                }
                Ok(false) => eprintln!("box-init: network-up failed → rescue"),
                Err(e) => eprintln!("box-init: network-up errored ({e}) → rescue"),
            },
            None => eprintln!("box-init: fb.net= did not parse → rescue (link-only)"),
        }
    }
                                                                                                        
                                                                                                           
                                                                                  
    for r in oneshots::rescue() {
        let _ = runner(&r);
    }
    let _ = match net {
        Some(cfg @ net::NetConfig::Static { .. }) => bring_up(BringUp::Apply(cfg)),
        _ => bring_up(BringUp::LinkOnly),
    };
    scandir::build_scandir(run_dir, box_svc, &rescue_set)?;
    Ok(Outcome::Supervise(Branch::Rescue))
}

/// The PID-1 entry: set `PATH`, mount the runtime tmpfs, run the bootstrap→services|rescue wiring, then
/// `exec` `s6-svscan` (which becomes PID-1 + supervises). A critical-precondition failure reboots
/// fail-closed via [`fatal`] (never returns). Returns `Err` ONLY on a mount/wiring/exec failure → the
/// caller (`main`) also routes that through [`fatal`], so box-init reboots ITSELF rather than relying on
              
/// the kernel "init died" panic (which only reboots with a `panic=` cmdline token).
pub fn run() -> io::Result<std::convert::Infallible> {
                                                                                                    
                                                                                                   
                                                                                                    
    unsafe { std::env::set_var("PATH", PATH_ENV) };

                                                                                                      
                                                                                                  
                                                                                                          
                                                                                                                 
    let bench = Path::new(BOX_BENCH).exists();

    for m in mounts::early_mounts(bench) {
        m.apply()?;
    }

                                                                                                              
                                                                                                        
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let net = match net::parse_net(&cmdline) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            eprintln!("box-init: fb.net= parse error: {e}");
            None
        }
    };

                                                                                                       
                                                                                                            
                                                                                                   
    let topology = match std::fs::read_to_string(BOX_TOPOLOGY)
        .map_err(|e| e.to_string())
        .and_then(|s| fb_manifest::topology::parse_topology(&s).map_err(|e| e.to_string()))
    {
        Ok(t) => Some(t),
        Err(e) => {
            eprintln!("box-init: {BOX_TOPOLOGY} parse failed ({e}) → rescue");
            None
        }
    };

    let outcome = wire_scandir(
        Path::new("/run"),
        Path::new(BOX_SVC),
        net.as_ref(),
        topology.as_ref(),
        bench,
        |o| Ok(oneshots::run(o)?.success()),
        |b| match b {
            BringUp::Apply(cfg) => net::apply(cfg),
            BringUp::LinkOnly => net::link_only(),
        },
    )?;

                                                                                                       
                                                                                                         
                                                                                                      
                                                                                                    
    if let Some(rd) = cgroup::should_setup_cgroups(&outcome, topology.as_ref())
        && matches!(
            cgroup::setup_dha_cgroups(rd, cgroup::read_mem_total()),
            Outcome::Reboot
        )
    {
        fatal("dha cgroup setup failed → reboot");
    }

    match outcome {
        Outcome::Supervise(branch) => {
            eprintln!("box-init: {branch:?}; exec s6-svscan {SCANDIR}");
                                                                                                      
                                                                                      
            Err(Command::new("s6-svscan").arg(SCANDIR).exec())
        }
                                                                                                         
        Outcome::Reboot => fatal("critical bootstrap oneshot failed (firewall load) → reboot"),
    }
}

/// The PID-1 fatal path: best-effort KERN_EMERG log to `/dev/kmsg`, then `reboot(2)`. Never returns.
/// Mirrors `initramfs-init`'s `fatal` so box-init's fail-closed is SELF-CONTAINED — it reboots itself
/// instead of `exit(1)`-ing and depending on the kernel "init died" panic + a `panic=` cmdline token
              
/// that does not yet exist. MUST NOT be called from unit tests — it reboots the machine
/// (the testable core, `wire_scandir`, never calls it; only `run`/`main` do, on the real PID-1 path).
pub fn fatal(msg: &str) -> ! {
    log_kmsg(0, &format!("box-init FATAL: {msg}"));
                                                                                                    
                                                                                                     
                                                                                                    
                                                                                           
                                                       
    let ts = libc::timespec {
        tv_sec: 20,
        tv_nsec: 0,
    };
                                                                                                    
    unsafe { libc::nanosleep(&ts, std::ptr::null_mut()) };
                                                                                                        
    unsafe { libc::reboot(libc::RB_AUTOBOOT) };
                                                                                              
    loop {
                                                                         
        unsafe { libc::pause() };
    }
}

/// Best-effort write to `/dev/kmsg` (operator-readable via the substrate console / `dmesg`). `level` is
/// the syslog level: 0 = EMERG (always reaches the console). Failure is ignored. Mirrors initramfs-init.
fn log_kmsg(level: u8, msg: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open("/dev/kmsg") {
        let _ = writeln!(f, "<{level}>{msg}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn fake_box_svc(root: &Path) -> PathBuf {
        let box_svc = root.join("etc/box-svc");
        for n in ["recipes", "dropbear", "rescue-dropbear"] {
            let d = box_svc.join(n);
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("run"), "#!/bin/sh\n").unwrap();
        }
        box_svc
    }

    fn static_cfg() -> net::NetConfig {
        net::NetConfig::Static {
            ip: "192.0.2.10".into(),
            prefix: 24,
            gw: "192.0.2.1".into(),
            dns: vec!["1.1.1.1".into()],
        }
    }

    /// A minimal valid topology (no app-domain hooks) for the ROUTING tests — bootstrap's app-domain
    /// interleave is tested in oneshots.rs; here we exercise the bootstrap→services/rescue routing.
    fn topo() -> fb_manifest::topology::Topology {
        fb_manifest::topology::parse_topology("schema_version = 1\nboot_hooks = []\npersist = []\n")
            .expect("empty topology parses")
    }

    #[test]
    fn all_bootstrap_ok_selects_services() {
        let tmp = tempfile::tempdir().unwrap();
        let box_svc = fake_box_svc(tmp.path());
        let run = tmp.path().join("run");
        let cfg = static_cfg();
        let mut calls = Vec::new();
        let mut brought_up = 0;
        let outcome = wire_scandir(
            &run,
            &box_svc,
            Some(&cfg),
            Some(&topo()),
            false,
            |o| {
                calls.push(o.name.clone());
                Ok(true)
            },
            |_| {
                brought_up += 1;
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(outcome, Outcome::Supervise(Branch::Services));
        assert_eq!(brought_up, 1, "network-up runs once on the services path");
                                                                                               
                                         
        assert!(run.join("service/recipes").is_dir());
        assert!(run.join("service/recipes/run").is_symlink());
        assert!(run.join("service/dropbear/run").is_symlink());
        assert!(!run.join("service/rescue-dropbear").exists());
                                                
        let expected: Vec<_> = oneshots::bootstrap(Some(&topo()))
            .iter()
            .map(|o| o.name.clone())
            .collect();
        assert_eq!(calls, expected);
    }

    #[test]
    fn noncritical_bootstrap_fail_selects_rescue() {
        let tmp = tempfile::tempdir().unwrap();
        let box_svc = fake_box_svc(tmp.path());
        let run = tmp.path().join("run");
        let cfg = static_cfg();
        let mut applied = 0;
                                                                                                     
        let outcome = wire_scandir(
            &run,
            &box_svc,
            Some(&cfg),
            Some(&topo()),
            false,
            |o| Ok(o.name != "setup-dirs"),
            |b| {
                if matches!(b, BringUp::Apply(_)) {
                    applied += 1;
                }
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(outcome, Outcome::Supervise(Branch::Rescue));
        assert_eq!(applied, 1, "rescue re-applies the parsed Static (C5a)");
                                                                                                  
                                   
        assert!(run.join("service/rescue-dropbear/run").is_symlink());
        assert!(!run.join("service/recipes").exists());
    }

    #[test]
    fn critical_bootstrap_fail_reboots_and_builds_no_scandir() {
                                                                                                
                                                                                    
        let tmp = tempfile::tempdir().unwrap();
        let box_svc = fake_box_svc(tmp.path());
        let run = tmp.path().join("run");
        let cfg = static_cfg();
        let outcome = wire_scandir(
            &run,
            &box_svc,
            Some(&cfg),
            Some(&topo()),
            false,
            |o| Ok(o.name != "nftables-load"),
            |_| Ok(true),
        )
        .unwrap();
        assert_eq!(outcome, Outcome::Reboot);
                                                        
        assert!(!run.join("service").exists());
    }

    #[test]
    fn no_parse_selects_rescue_with_link_only() {
        let tmp = tempfile::tempdir().unwrap();
        let box_svc = fake_box_svc(tmp.path());
        let run = tmp.path().join("run");
        let mut link_only = 0;
                                                                                  
        let outcome = wire_scandir(
            &run,
            &box_svc,
            None,
            Some(&topo()),
            false,
            |_| Ok(true),
            |b| {
                if matches!(b, BringUp::LinkOnly) {
                    link_only += 1;
                }
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(outcome, Outcome::Supervise(Branch::Rescue));
        assert_eq!(link_only, 1, "no-parse rescue does link-only (C5b)");
        assert!(run.join("service/rescue-dropbear/run").is_symlink());
        assert!(!run.join("service/recipes").exists());
    }

    #[test]
    fn topology_parse_fail_diverts_to_rescue_after_firewall() {
                                                                                                       
                                                                                                           
                                                                                                        
                                                                                                        
                              
        let tmp = tempfile::tempdir().unwrap();
        let box_svc = fake_box_svc(tmp.path());
        let run = tmp.path().join("run");
        let cfg = static_cfg();
        let mut saw_nft = false;
        let outcome = wire_scandir(
            &run,
            &box_svc,
            Some(&cfg),
            None,                                
            false,
            |o| {
                if o.name == "nftables-load" {
                    saw_nft = true;
                }
                Ok(true)
            },
            |_| Ok(true),
        )
        .unwrap();
        assert_eq!(
            outcome,
            Outcome::Supervise(Branch::Rescue),
            "a None topology must divert to rescue (don't start services without app-domain setup)"
        );
        assert!(
            saw_nft,
                          
            "the firewall (nftables-load) must STILL run before the rescue divert"
        );
        assert!(run.join("service/rescue-dropbear/run").is_symlink());
        assert!(!run.join("service/recipes").exists());
    }

    #[test]
    fn services_network_up_failure_diverts_to_rescue() {
        let tmp = tempfile::tempdir().unwrap();
        let box_svc = fake_box_svc(tmp.path());
        let run = tmp.path().join("run");
        let cfg = static_cfg();
                                                                                                 
        let mut n = 0;
        let outcome = wire_scandir(
            &run,
            &box_svc,
            Some(&cfg),
            Some(&topo()),
            false,
            |_| Ok(true),
            |_| {
                n += 1;
                Ok(n != 1)                                                                   
            },
        )
        .unwrap();
        assert_eq!(
            outcome,
            Outcome::Supervise(Branch::Rescue),
            "a services network-up failure → rescue (R2-1)"
        );
        assert_eq!(
            n, 2,
            "network-up tried on services, then re-applied on rescue"
        );
        assert!(!run.join("service/recipes").exists());
    }

    #[test]
    fn services_network_up_error_diverts_to_rescue_not_reboot() {
                                                                                                        
                                                                                                             
                                                                                                           
        let tmp = tempfile::tempdir().unwrap();
        let box_svc = fake_box_svc(tmp.path());
        let run = tmp.path().join("run");
        let cfg = static_cfg();
        let mut n = 0;
        let outcome = wire_scandir(
            &run,
            &box_svc,
            Some(&cfg),
            Some(&topo()),
            false,
            |_| Ok(true),
            |_| {
                n += 1;
                if n == 1 {
                    Err(io::Error::other("ip failed to spawn"))                            
                } else {
                    Ok(true)                            
                }
            },
        )
        .unwrap();
        assert_eq!(
            outcome,
            Outcome::Supervise(Branch::Rescue),
            "a services bring-up Err → rescue, not reboot"
        );
        assert!(run.join("service/rescue-dropbear/run").is_symlink());
    }

    #[test]
    fn bench_no_persist_no_net_selects_services() {
                                                                                                       
                                                                                                          
                                                                                                       
                                                                                                           
        let tmp = tempfile::tempdir().unwrap();
        let box_svc = fake_box_svc(tmp.path());
        let run = tmp.path().join("run");
        let mut brought_up = 0;
        let outcome = wire_scandir(
            &run,
            &box_svc,
            None,
            Some(&topo()),
            true,         
            |_| Ok(true),
            |_| {
                brought_up += 1;
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(outcome, Outcome::Supervise(Branch::Services));
        assert_eq!(
            brought_up, 0,
            "the bench enters Services with NO network bring-up (eth0 stays down)"
        );
                                                                               
        assert!(run.join("service/recipes/run").is_symlink());
        assert!(!run.join("service/rescue-dropbear").exists());
    }

    #[test]
    fn bench_ignores_net_and_does_not_bring_up() {
                                                                                                           
                                                                                                       
                                                                                                          
        let tmp = tempfile::tempdir().unwrap();
        let box_svc = fake_box_svc(tmp.path());
        let run = tmp.path().join("run");
        let cfg = static_cfg();
        let mut brought_up = 0;
        let outcome = wire_scandir(
            &run,
            &box_svc,
            Some(&cfg),
            Some(&topo()),
            true,         
            |_| Ok(true),
            |_| {
                brought_up += 1;
                Ok(true)
            },
        )
        .unwrap();
        assert_eq!(outcome, Outcome::Supervise(Branch::Services));
        assert_eq!(
            brought_up, 0,
            "the bench NEVER brings up the network, even with a parsed Static"
        );
        assert!(run.join("service/recipes/run").is_symlink());
    }

    #[test]
    fn bench_bootstrap_failure_still_diverts_to_rescue() {
                                                                                                     
                                                                                                         
                                                                                  
        let tmp = tempfile::tempdir().unwrap();
        let box_svc = fake_box_svc(tmp.path());
        let run = tmp.path().join("run");
        let outcome = wire_scandir(
            &run,
            &box_svc,
            None,
            Some(&topo()),
            true,                                   
            |o| Ok(o.name != "setup-dirs"),                                  
            |_| Ok(true),
        )
        .unwrap();
        assert_eq!(
            outcome,
            Outcome::Supervise(Branch::Rescue),
            "a bench with a failed bootstrap oneshot must still fail-closed to rescue"
        );
        assert!(!run.join("service/recipes").exists());
    }

    #[test]
    fn bench_with_unparsed_topology_still_diverts_to_rescue() {
                                                                                                 
                                                                                                          
                                                                                   
        let tmp = tempfile::tempdir().unwrap();
        let box_svc = fake_box_svc(tmp.path());
        let run = tmp.path().join("run");
        let outcome = wire_scandir(
            &run,
            &box_svc,
            None,
            None,                            
            true,         
            |_| Ok(true),
            |_| Ok(true),
        )
        .unwrap();
        assert_eq!(
            outcome,
            Outcome::Supervise(Branch::Rescue),
            "a bench with an unparseable topology must divert to rescue (a parsed topology is required)"
        );
        assert!(!run.join("service/recipes").exists());
    }
}

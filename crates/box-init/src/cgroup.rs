//! The dha tenant cgroup-v2 setup (spec §4.2) — box-init builds a minimal-root cgroup tree under a
//! freshly-mounted unified hierarchy: a root-owned `dha/` Σ ceiling, the `dha/creatine` engine leaf, and
//! the delegated `dha/work` subtree. Every step is fail-closed Reboot-class (M-R4-1): a half-built tree
//! must NEVER reach `exec s6-svscan`. The whole block is gated (in `run`) on a `ResourceDomain` present on
//! the SIGNED topology, and is skipped on a non-dha box + the rescue/parse-fail path (§4.2 / C3).
//!
//! Split for review (the plan's C1/C2/C3): C1 = the fail-closed PRECONDITIONS ([`check_preconditions`] —
//! the memory controller is present + subtree-enabled, and Σ fits under MemTotal − reserve); C2 = the
//! root-owned tree + the precise `work/` delegation; C3 = the `run` gate.

use crate::{Branch, Outcome};
use fb_manifest::manifest::ResourceDomain;
use rustix::mount::MountFlags;
use std::io;
use std::path::Path;

/// Where box-init mounts the unified cgroup-v2 hierarchy (§4.2 step 1).
const CGROUP_ROOT: &str = "/sys/fs/cgroup";

/// The box's own-footprint reserve, held back from MemTotal before the tenant Σ is admitted (§4.2 step 2).
/// v1 is BEST-EFFORT (spec §7 / R1-M2): the box does NOT cgroup its OWN services, so this bounds only the
/// dha contribution — a box-service spike + dha-at-Σ can still trip the GLOBAL killer. The residual fix is
/// (a) this reserve, sized against the MEASURED box-own peak, + (b) `oom_score_adj` on box-critical tasks.
/// 512 MiB is a CONSERVATIVE v1 PLACEHOLDER pending the O2 measurement (recipes + haproxy + s6 + ntpd +
/// dropbear + fb-* + page cache); tune it to the measured peak. Cgroup-ing the box's own services is the
/// hard fix, promoted to a sizing requirement (§7) — not done here.
const BOX_RESERVE_BYTES: u64 = 512 * 1024 * 1024;

/// Set up the dha tenant cgroup tree (§4.2). Mounts the unified cgroup-v2 hierarchy, then builds the
/// minimal-root tree under it. Returns [`Outcome::Reboot`] on ANY failure — every step is Reboot-class
/// (M-R4-1): a botched step must not `exec s6-svscan` with a half-built tree. On full success returns
/// [`Outcome::Supervise`]`(`[`Branch::Services`]`)` — the "proceed to s6-svscan" signal (`run` only
/// distinguishes `Reboot` from not-`Reboot`). Called by `run` ONLY on the Services + `Some(ResourceDomain)`
/// path (C3); a non-dha box + the rescue/parse-fail path never reach here.
pub fn setup_dha_cgroups(rd: &ResourceDomain, mem_total: u64) -> Outcome {
                                                                                                         
                                                                                                       
    if let Err(e) = mount_cgroup2(Path::new(CGROUP_ROOT)) {
        eprintln!("box-init: cgroup2 mount failed ({e}) → reboot");
        return Outcome::Reboot;
    }
    if let Err(e) = check_preconditions(Path::new(CGROUP_ROOT), rd, mem_total) {
        eprintln!("box-init: dha cgroup preconditions failed ({e}) → reboot");
        return Outcome::Reboot;
    }
                                                                                                              
    if let Err(e) = build_tree(&mut RealOps, Path::new(CGROUP_ROOT), Path::new("/run"), rd) {
        eprintln!("box-init: dha cgroup tree build failed ({e}) → reboot");
        return Outcome::Reboot;
    }
    Outcome::Supervise(Branch::Services)
}

/// Mount the unified cgroup-v2 hierarchy at `root` (nosuid,nodev,noexec — a pseudo-fs with no exec/suid/
/// device targets; the hardening matches the box's other mounts). Mirrors `crate::mounts::MountSpec`.
/// INVARIANT (R1-I1): nothing else mounts cgroup2 on this box — `crate::mounts::early_mounts` mounts only
/// `/run`,`/tmp` (+ bench `/persist`) and initramfs-init mounts only sysfs/securityfs — so this
/// unconditional mount finds an empty sysfs dir. A future earlier cgroup2 mount would make this EBUSY →
/// reboot (fail-closed, not silent); if that ever changes, probe `cgroup.controllers` for an existing
/// mount first.
fn mount_cgroup2(root: &Path) -> io::Result<()> {
    std::fs::create_dir_all(root)?;
    let target = root
        .to_str()
        .ok_or_else(|| io::Error::other("non-UTF-8 cgroup root"))?;
    rustix::mount::mount(
        cstr("cgroup2")?.as_c_str(),
        cstr(target)?.as_c_str(),
        cstr("cgroup2")?.as_c_str(),
        MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC,
        cstr("")?.as_c_str(),
    )?;
    Ok(())
}

/// `&str` → `CString` for the `mount(2)` FFI (mirrors `crate::mounts::cstr`).
fn cstr(s: &str) -> io::Result<std::ffi::CString> {
    std::ffi::CString::new(s).map_err(|_| io::Error::other("interior NUL in mount arg"))
}

/// The fail-closed preconditions (C1), testable on a tmpfs `root` (the post-mount cgroup-v2 root). Each
/// failure is an `Err` → the caller reboots. ALL checks run BEFORE the one mutation (audit R1-L1):
/// 1. the cgroup-v2 MEMORY **and** PIDS controllers are present in `cgroup.controllers` (the A1 kernel pins
///    CONFIG_MEMCG + CONFIG_CGROUP_PIDS) — absent memory, the Σ ceiling cannot be set and the whole defense
///    is gone; absent pids, the per-job fork-bomb backstop (`job_pids_max`) is silently inert (R2-M1);
/// 2. `Σ + BOX_RESERVE ≤ MemTotal` (else the cgroup OOM is not deterministically scoped — best-effort v1);
/// 3. only then enable `+memory +pids` in the root `cgroup.subtree_control` (so `dha/` + children get
///    `memory.*` and the delegated `work/<id>` can carry `pids.max`).
fn check_preconditions(root: &Path, rd: &ResourceDomain, mem_total: u64) -> io::Result<()> {
                                                                                                           
                                                                                                         
                                                                                                                 
    let controllers = std::fs::read_to_string(root.join("cgroup.controllers"))?;
    let present = |c: &str| controllers.split_whitespace().any(|t| t == c);
    if !present("memory") {
        return Err(io::Error::other(
            "cgroup memory controller absent (kernel CONFIG_MEMCG missing?)",
        ));
    }
    if !present("pids") {
        return Err(io::Error::other(
            "cgroup pids controller absent (kernel CONFIG_CGROUP_PIDS missing?)",
        ));
    }
                                                                                                            
                                                                                                        
                                                                                                               
                                                       
    let need = rd
        .memory_max
        .0
        .checked_add(BOX_RESERVE_BYTES)
        .ok_or_else(|| io::Error::other("Σ + reserve overflows u64"))?;
    if need > mem_total {
        return Err(io::Error::other(format!(
            "Σ ({}) + reserve ({BOX_RESERVE_BYTES}) exceeds MemTotal ({mem_total})",
            rd.memory_max.0
        )));
    }
                                                                                                             
    std::fs::write(root.join("cgroup.subtree_control"), "+memory +pids")?;
    Ok(())
}

/// The filesystem operations the tree-builder performs, abstracted so the unit test can RECORD them
/// without root: the **chown file-set is the load-bearing security property** (the tenant-unliftable
/// delegation boundary), and a real `chown(2)` needs root. [`RealOps`] performs the real syscalls; the
/// test records every call and asserts the exact delegated set.
trait CgroupOps {
    fn mkdir(&mut self, path: &Path, mode: u32) -> io::Result<()>;
    fn write(&mut self, path: &Path, content: &str) -> io::Result<()>;
    fn chown(&mut self, path: &Path, uid: u32, gid: u32) -> io::Result<()>;
}

/// The real syscalls (prod). Not unit-tested — the tree it builds is proven on produced bytes by the
/// boot-gate (F2/F3/F5); the unit test drives [`build_tree`] through a recording [`CgroupOps`].
struct RealOps;

impl CgroupOps for RealOps {
    fn mkdir(&mut self, path: &Path, mode: u32) -> io::Result<()> {
        use std::os::unix::fs::DirBuilderExt;
                                                                                                        
                                                                                                        
        std::fs::DirBuilder::new().mode(mode).create(path)
    }
    fn write(&mut self, path: &Path, content: &str) -> io::Result<()> {
        std::fs::write(path, content)
    }
    fn chown(&mut self, path: &Path, uid: u32, gid: u32) -> io::Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::other("interior NUL in chown path"))?;
                                                                                                    
        let rc = unsafe { libc::chown(c.as_ptr(), uid as libc::uid_t, gid as libc::gid_t) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

/// Build the root-owned dha cgroup tree under `cg` (the mounted cgroup-v2 root) + pre-create the creatine
/// uds dir under `run`, then DELEGATE only `work/`'s structural files to `delegate_uid`. Minimal-root
/// topology (§2 D4 / §4.2 steps 3-8):
/// - `dha/` — Σ ceiling, `oom.group=0` (the merged-Σ OOM scans by badness, not whole-tree group-kill),
///   `+memory`;
/// - `dha/creatine` — engine cap + optional `memory.min`, `oom.group=1` (clean whole-engine kill),
///   `swap.max=0` (the swapless belt);
/// - `dha/work` — `+memory +pids` + the root-owned `cgroup.max.{descendants,depth}` + the AGGREGATE
///   `pids.max` fork-bomb backstop, all set BEFORE delegation so the tenant cannot raise them (H2 + R3-H1);
/// - `dha/work/orch` — root-owned optional `memory.min`, NOT delegated.
///
/// The delegation chowns EXACTLY the cgroup-v2 containment set — the `work/` dir + `cgroup.procs` +
/// `cgroup.threads` + `cgroup.subtree_control` — and NOTHING else: not the limit files, not
/// `cgroup.max.*`, not `work/orch`. A recursive chown would make the H2 caps tenant-liftable (the R4
/// reread bug). Every step is an `io::Result`; the caller maps `Err` → `Outcome::Reboot`.
fn build_tree<O: CgroupOps>(
    ops: &mut O,
    cg: &Path,
    run: &Path,
    rd: &ResourceDomain,
) -> io::Result<()> {
    let uid = rd.delegate_uid.0;

                                                                                                         
                                                                                       
    let dha = cg.join(&rd.name);
    ops.mkdir(&dha, 0o755)?;
    ops.write(&dha.join("memory.max"), &rd.memory_max.0.to_string())?;
    ops.write(&dha.join("memory.oom.group"), "0")?;
    ops.write(&dha.join("cgroup.subtree_control"), "+memory +pids")?;

                                                                                                        
                                                                                               
    if let Some(engine) = &rd.engine {
        let creatine = dha.join("creatine");
        ops.mkdir(&creatine, 0o755)?;
        ops.write(
            &creatine.join("memory.max"),
            &engine.memory_max.0.to_string(),
        )?;
        if let Some(min) = engine.memory_min {
            ops.write(&creatine.join("memory.min"), &min.0.to_string())?;
        }
        ops.write(
            &creatine.join("memory.oom.group"),
            if engine.oom_group { "1" } else { "0" },
        )?;
        ops.write(&creatine.join("memory.swap.max"), "0")?;
    }

                                                                                                          
                                                                                                           
    let work = dha.join("work");
    ops.mkdir(&work, 0o755)?;
    ops.write(&work.join("cgroup.subtree_control"), "+memory +pids")?;
    ops.write(
        &work.join("cgroup.max.descendants"),
        &rd.work.max_descendants.to_string(),
    )?;
    ops.write(
        &work.join("cgroup.max.depth"),
        &rd.work.max_depth.to_string(),
    )?;
                                                                                                     
                                                                                                    
                                                                                                     
    ops.write(&work.join("pids.max"), &rd.work.work_pids_max.to_string())?;

                                                                                              
    let orch = work.join("orch");
    ops.mkdir(&orch, 0o755)?;
    if let Some(min) = rd.work.orch_memory_min {
        ops.write(&orch.join("memory.min"), &min.0.to_string())?;
    }

                                                                                                         
                                                                                                  
                                                                                                        
    ops.chown(&work, uid, uid)?;
    ops.chown(&work.join("cgroup.procs"), uid, uid)?;
    ops.chown(&work.join("cgroup.threads"), uid, uid)?;
    ops.chown(&work.join("cgroup.subtree_control"), uid, uid)?;

                                                                                                           
                                                                                 
    let creatine_run = run.join("creatine");
    ops.mkdir(&creatine_run, 0o700)?;
    ops.chown(&creatine_run, uid, uid)?;

                                                                                                           
                                                                                                       
                                                                                                    
                                                                                             
    let dha_run = run.join("dha");
    ops.mkdir(&dha_run, 0o700)?;
    ops.chown(&dha_run, uid, uid)?;

                                                                                                     
                                                                                                  
                                                                                                           
                                                                                                     
                                                                                                       
                                                                                                 
    let dha_secrets = run.join("dha-secrets");
    ops.mkdir(&dha_secrets, 0o700)?;
    ops.chown(&dha_secrets, uid, uid)?;

    Ok(())
}

/// The C3 gate (testable): the dha cgroup tree is built ONLY on the success Services path WITH a
/// `ResourceDomain` present on the signed topology. `Some(rd)` → `run` builds the tree (a `Reboot` from
/// [`setup_dha_cgroups`] then propagates to `fatal`); `None` → SKIP — a non-dha box (no `resource_domain`),
               
/// the rescue branch, or a parse-fail-`None` topology. So the cgroup block is unreachable off
/// the Services-with-dha path by construction.
pub fn should_setup_cgroups<'a>(
    outcome: &Outcome,
    topology: Option<&'a fb_manifest::topology::Topology>,
) -> Option<&'a ResourceDomain> {
    match outcome {
        Outcome::Supervise(Branch::Services) => topology.and_then(|t| t.resource_domain.as_ref()),
        _ => None,
    }
}

/// Read `MemTotal` from `/proc/meminfo` as BYTES (the file reports kB). Fail-closed: an unreadable /
/// unparseable meminfo returns 0, so the Σ-validation rejects ANY Σ → reboot (never run uncapped).
pub fn read_mem_total() -> u64 {
    match std::fs::read_to_string("/proc/meminfo") {
        Ok(s) => parse_mem_total(&s).unwrap_or(0),
        Err(_) => 0,
    }
}

/// Parse `MemTotal: <N> kB` from /proc/meminfo into BYTES (`N * 1024`). `None` if the line is absent or
/// malformed (the caller treats that as 0 = fail-closed).
fn parse_mem_total(meminfo: &str) -> Option<u64> {
    let line = meminfo.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    kb.checked_mul(1024)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fb_manifest::manifest::{ByteSize, EngineLeaf, ResourceDomain, Uid, WorkSubtree};

    const GIB: u64 = 1024 * 1024 * 1024;

    fn rd(sigma: u64) -> ResourceDomain {
        ResourceDomain {
            name: "dha".into(),
            memory_max: ByteSize(sigma),
            delegate_uid: Uid(110),
            engine: Some(EngineLeaf {
                service: "dha-creatine".into(),
                memory_max: ByteSize(sigma / 2),
                memory_min: None,
                oom_group: true,
            }),
            work: WorkSubtree {
                orchestrator: "dha-orchestrator".into(),
                orch_memory_min: None,
                job_memory_max: ByteSize(sigma / 4),
                job_pids_max: Some(64),
                max_descendants: 16,
                max_depth: 2,
                work_pids_max: 256,
            },
        }
    }

    /// A fake post-mount cgroup-v2 root: a `cgroup.controllers` (caller-chosen) + an empty
    /// `cgroup.subtree_control` (the kernel exposes both at the unified-hierarchy root).
    fn fake_root(controllers: &str) -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("cgroup.controllers"), controllers).unwrap();
        std::fs::write(tmp.path().join("cgroup.subtree_control"), "").unwrap();
        tmp
    }

    #[test]
    fn memory_controller_absent_fails_closed() {
                                                                                                             
        let root = fake_root("cpuset cpu io pids");
        assert!(check_preconditions(root.path(), &rd(6 * GIB), 8 * GIB).is_err());
    }

    #[test]
    fn sigma_plus_reserve_over_memtotal_fails_closed() {
                                                                                                     
        let root = fake_root("memory pids");
        assert!(check_preconditions(root.path(), &rd(8 * GIB), 8 * GIB).is_err());
    }

    #[test]
    fn happy_path_enables_memory_for_the_subtree() {
        let root = fake_root("cpuset cpu io memory pids");
        check_preconditions(root.path(), &rd(6 * GIB), 8 * GIB).expect("preconditions hold");
                                                                                                             
        let sc = std::fs::read_to_string(root.path().join("cgroup.subtree_control")).unwrap();
        assert_eq!(sc, "+memory +pids");
    }

    #[test]
    fn pids_controller_absent_fails_closed() {
                                                                                                           
                                                         
        let root = fake_root("cpuset cpu io memory");
        assert!(check_preconditions(root.path(), &rd(6 * GIB), 8 * GIB).is_err());
    }

    #[test]
    fn sigma_exactly_fitting_is_allowed() {
                                                                      
        let root = fake_root("memory pids");
        let sigma = 8 * GIB - BOX_RESERVE_BYTES;
        check_preconditions(root.path(), &rd(sigma), 8 * GIB).expect("exact fit is allowed");
    }

                                                                 

    /// A recording [`CgroupOps`]: logs every op IN ORDER without touching the filesystem, so the chown
    /// file-set (the tenant-unliftable property) is asserted without root.
    #[derive(Default)]
    struct Rec {
        ops: Vec<Op>,
    }
    #[derive(Debug, Clone, PartialEq)]
    enum Op {
        Mkdir(std::path::PathBuf, u32),
        Write(std::path::PathBuf, String),
        Chown(std::path::PathBuf, u32, u32),
    }
    impl CgroupOps for Rec {
        fn mkdir(&mut self, path: &Path, mode: u32) -> io::Result<()> {
            self.ops.push(Op::Mkdir(path.to_path_buf(), mode));
            Ok(())
        }
        fn write(&mut self, path: &Path, content: &str) -> io::Result<()> {
            self.ops
                .push(Op::Write(path.to_path_buf(), content.to_string()));
            Ok(())
        }
        fn chown(&mut self, path: &Path, uid: u32, gid: u32) -> io::Result<()> {
            self.ops.push(Op::Chown(path.to_path_buf(), uid, gid));
            Ok(())
        }
    }

    #[test]
    fn build_tree_delegates_exactly_the_structural_files_and_no_caps() {
        use std::collections::BTreeSet;
        use std::path::PathBuf;
        let cg = Path::new("/sys/fs/cgroup");
        let run = Path::new("/run");
        let mut rec = Rec::default();
        build_tree(&mut rec, cg, run, &rd(6 * GIB)).expect("tree builds");
        let work = cg.join("dha/work");

                                                                                                                   
        let chowned: BTreeSet<PathBuf> = rec
            .ops
            .iter()
            .filter_map(|o| match o {
                Op::Chown(p, 110, 110) => Some(p.clone()),
                _ => None,
            })
            .collect();
        let expected: BTreeSet<PathBuf> = [
            work.clone(),
            work.join("cgroup.procs"),
            work.join("cgroup.threads"),
            work.join("cgroup.subtree_control"),
            run.join("creatine"),
            run.join("dha"),                                                            
            run.join("dha-secrets"),                                                                       
        ]
        .into_iter()
        .collect();
        assert_eq!(
            chowned, expected,
            "ONLY work/'s structural files + the tenant runtime dirs (/run/creatine, /run/dha, /run/dha-secrets) are delegated to the tenant"
        );

                                                                                                       
        for root_owned in [
            work.join("cgroup.max.descendants"),
            work.join("cgroup.max.depth"),
            work.join("orch"),
            work.join("memory.max"),
            work.join("pids.max"),
            cg.join("dha"),
            cg.join("dha/memory.max"),
            cg.join("dha/creatine"),
        ] {
            assert!(
                !chowned.contains(&root_owned),
                "{root_owned:?} MUST stay root-owned (a recursive chown would lift the caps — R4)"
            );
        }

                                                          
        let w = |p: &Path| {
            rec.ops.iter().find_map(|o| match o {
                Op::Write(wp, v) if wp == p => Some(v.clone()),
                _ => None,
            })
        };
        assert_eq!(w(&cg.join("dha/memory.max")), Some((6 * GIB).to_string()));
        assert_eq!(w(&cg.join("dha/memory.oom.group")), Some("0".to_string()));
        assert_eq!(
            w(&cg.join("dha/creatine/memory.oom.group")),
            Some("1".to_string())
        );
        assert_eq!(
            w(&cg.join("dha/creatine/memory.swap.max")),
            Some("0".to_string())
        );
        assert_eq!(
            w(&work.join("cgroup.max.descendants")),
            Some("16".to_string())
        );
        assert_eq!(w(&work.join("cgroup.max.depth")), Some("2".to_string()));
                                                                                                
        assert_eq!(w(&work.join("pids.max")), Some("256".to_string()));
                                                                                                            
        assert_eq!(
            w(&cg.join("dha/cgroup.subtree_control")),
            Some("+memory +pids".to_string())
        );
        assert_eq!(
            w(&work.join("cgroup.subtree_control")),
            Some("+memory +pids".to_string())
        );

                                                                                                             
        let cap_pos = rec
            .ops
            .iter()
            .position(|o| matches!(o, Op::Write(p, _) if *p == work.join("cgroup.max.descendants")))
            .expect("the cap write happened");
        let chown_pos = rec
            .ops
            .iter()
            .position(|o| matches!(o, Op::Chown(p, ..) if *p == work))
            .expect("the work/ delegation happened");
        assert!(
            cap_pos < chown_pos,
            "caps are set before the work/ delegation"
        );

                                                                                                             
                                                                                                             
                                                                                            
        for dir in ["creatine", "dha", "dha-secrets"] {
            let mode = rec.ops.iter().find_map(|o| match o {
                Op::Mkdir(p, m) if *p == run.join(dir) => Some(*m),
                _ => None,
            });
            assert_eq!(mode, Some(0o700), "/run/{dir} is mkdir'd 0700");
        }
    }

    #[test]
    fn engine_oom_group_drives_the_written_value() {
                                                                                                         
        let mut r = rd(6 * GIB);
        r.engine.as_mut().unwrap().oom_group = false;
        let mut rec = Rec::default();
        build_tree(&mut rec, Path::new("/sys/fs/cgroup"), Path::new("/run"), &r).expect("builds");
        let target = Path::new("/sys/fs/cgroup/dha/creatine/memory.oom.group");
        let v = rec.ops.iter().find_map(|o| match o {
            Op::Write(p, v) if p == target => Some(v.clone()),
            _ => None,
        });
        assert_eq!(
            v,
            Some("0".to_string()),
            "engine.oom_group=false → memory.oom.group 0"
        );
    }

                                                                                          

    fn topo_with(rd: Option<ResourceDomain>) -> fb_manifest::topology::Topology {
        fb_manifest::topology::Topology {
            schema_version: 1,
            boot_hooks: vec![],
            persist: vec![],
            resource_domain: rd,
        }
    }

    #[test]
    fn gate_skips_a_non_dha_box_no_resource_domain() {
        let topo = topo_with(None);
        assert!(
            should_setup_cgroups(&Outcome::Supervise(Branch::Services), Some(&topo)).is_none(),
                          
            "a manifest without a resource_domain skips the cgroup block"
        );
    }

    #[test]
    fn gate_skips_the_rescue_branch() {
        let topo = topo_with(Some(rd(6 * GIB)));
        assert!(
            should_setup_cgroups(&Outcome::Supervise(Branch::Rescue), Some(&topo)).is_none(),
            "the rescue surface never builds the cgroup tree"
        );
    }

    #[test]
    fn gate_skips_a_parse_fail_none_topology() {
        assert!(
            should_setup_cgroups(&Outcome::Supervise(Branch::Services), None).is_none(),
            "a parse-fail-None topology (→ rescue) skips the cgroup block"
        );
    }

    #[test]
    fn gate_skips_on_reboot() {
        let topo = topo_with(Some(rd(6 * GIB)));
        assert!(should_setup_cgroups(&Outcome::Reboot, Some(&topo)).is_none());
    }

    #[test]
    fn gate_fires_on_the_services_path_with_a_resource_domain() {
        let topo = topo_with(Some(rd(6 * GIB)));
        let got = should_setup_cgroups(&Outcome::Supervise(Branch::Services), Some(&topo));
        assert_eq!(
            got.map(|r| r.name.as_str()),
            Some("dha"),
            "the success-with-ResourceDomain path builds the tree"
        );
    }

    #[test]
    fn mem_total_parses_kb_to_bytes() {
        let meminfo = "MemTotal:       16384000 kB\nMemFree:        100 kB\n";
        assert_eq!(parse_mem_total(meminfo), Some(16384000u64 * 1024));
    }

    #[test]
    fn mem_total_malformed_is_none() {
        assert_eq!(
            parse_mem_total("MemFree: 100 kB\n"),
            None,
            "no MemTotal line"
        );
        assert_eq!(
            parse_mem_total("MemTotal: notanumber kB\n"),
            None,
            "non-numeric"
        );
    }
}

//! The bootstrap + rescue oneshots box-init runs before starting supervision.
//!
//! These are one-time setup steps (mounts, firewall, dir ownership, CA/cert bootstrap) that the old
//! design ran as s6-rc `oneshot` services. Under the redesign box-init runs them directly, BEFORE
//! `exec`ing `s6-svscan` — so by the time any longrun starts, every bootstrap step has completed
//! (which is exactly what satisfies the security-critical oneshot→longrun edges: firewall before any
//! bind, dir-chown before the privilege-dropping services, CA/cert before recipes/haproxy).
//!
//! Each oneshot runs as `execve("/bin/sh", ["sh", "-c", body])`: `/bin/sh` (busybox) is the signed
//! rootfs `execve` target; `body` is argv DATA, never a file — so it is NOT appraised and, critically,
//! is NEVER materialized as a script on tmpfs (which would be unsigned + on the `noexec` mount →
             
//! EACCES — the keystone bug this redesign fixes). The bodies are plain `sh`, not execline.
//! They use bare tool names (`s6-envdir`, `s6-setuidgid`, busybox applets) that resolve via the `PATH`
//! box-init sets before running them (see the orchestration in `lib`/`main`). The domain is read at
//! runtime from the signed `/etc/box-domain` (`$(cat ...)`) so box-init carries no compiled-in domain.

use std::io;
use std::process::{Command, ExitStatus};
use std::time::{Duration, Instant};

use fb_manifest::PlaceholderCtx;
use fb_manifest::topology::Topology;

/// What box-init does when a *bootstrap* oneshot fails (or times out). Consulted only on the bootstrap
/// path (`lib::wire_scandir`); rescue oneshots are always best-effort (a rescue failure never diverts —
/// box-init is already on the rescue surface).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum OnFailure {
    /// Divert to the rescue surface (operator SSH via rescue-dropbear). The default for bootstrap steps
    /// whose failure leaves the box safe-but-degraded (a disk that won't mount, a CA that won't gen).
    Rescue,
    /// Reboot the box, fail-closed. Reserved for preconditions that MUST hold before ANY exposure:
    /// the firewall load (`nftables-load`). A box with no firewall must not expose even rescue — a
    /// flushed/never-loaded ruleset is the kernel default-ACCEPT, so rescue-with-no-firewall is worse
                  
    /// than a reboot for a publicly-exposed sacrificial bastion.
    Reboot,
}

/// One bootstrap/rescue step. Each runs as `sh -c body` under a wall-clock `timeout_secs`: a hung step
/// is SIGKILLed and treated as a failure, so box-init always reaches EITHER a running svscan OR a
              
/// reboot in bounded time — it never blocks PID-1 forever on a stuck child (the boot-gate
/// hit this exact hang via `udhcpc` on a down link). `on_failure` governs the bootstrap path only.
///
/// Bodies MUST be synchronous + non-daemonizing: box-init installs no SIGCHLD reaper during its brief
/// PID-1 window — `run` reaps only each oneshot's OWN direct child, and s6-svscan owns reaping after the
/// `exec`. A body that backgrounds a long-lived helper would leak it (or escape `run`'s wait) until
              
/// svscan takes over. All current bodies are synchronous mount/nft/chown/fb-oneshots/recipes-admin
/// invocations, so this holds; a future body that daemonizes would violate it.
pub struct Oneshot {
    pub name: String,
    pub body: String,
    pub timeout_secs: u64,
    pub on_failure: OnFailure,
}

/// Wall-clock bound for the fast oneshots (mounts, nft, chown, hostname, rescue staging). No legit
/// oneshot runs anywhere near this; it is the hang backstop, not a tuned latency budget.
pub(crate) const FAST_TIMEOUT_SECS: u64 = 30;
                                                                                                          
                                                                                                         
                                                                                                       
/// Bound for the OFFLINE persist prep (`prepare-persist`): `e2fsck` + `resize2fs` (+ the Layer-2
/// journal-add) on a possibly multi-GB fs is size-dependent, so this is a generous hang backstop — NOT a
/// tuned budget. Only the first boot's real grow/fsck takes meaningful time (subsequent boots are a
/// sub-second no-op + a clean fsck); a SIGKILL'd prep leaves the fs dirty → next boot retries → fail-safe.
              
/// CAVEAT: this is a FIXED wall-clock — it does NOT scale with `/persist` size. At plausible
/// sizes (the ~GiB Infomaniak persist; the gate's ~1.25 GiB) a cold fsck is sub-second, so 300s is huge
/// headroom. If `/persist` ever grows to where a cold `e2fsck` legitimately approaches minutes, EVERY boot
/// would SIGKILL prepare-persist mid-scan → rescue every boot (a soft loop-to-rescue — fail-safe, never a
/// corrupt mount, but revisit the bound then; consider scaling it to the partition size).
const GROW_TIMEOUT_SECS: u64 = 300;

/// Crash-recovery + first-boot persist prep (persist-crash-recovery component). Runs OFFLINE on the
/// UNMOUNTED `LABEL=persist` device, ORDERED BEFORE `mount-persist` (shape (b)) — so every fs-touching
/// op provably never touches a mounted fs (audit F-5).
///
/// `/persist` is baked `-O ^has_journal` for byte-reproducibility, so an UNCLEAN stop (power-loss,
/// panic, OOM, host force-stop, the box's own fatal reboot) leaves a dirty no-journal ext4 that `mount`
/// rejects → the box would divert to rescue on EVERY unclean stop. `e2fsck -p` (preen, non-interactive —
/// cannot prompt/hang) auto-fixes exactly the post-crash inconsistencies. Its exit code is an OR'd
/// BITMASK (FSCK_*): proceed iff NO error bit is set — `(rc & 0xFC) == 0` covers rc 0 (clean), 1 (errors
/// CORRECTED — the COMMON dirty-fs outcome), 2 (reboot-rec), 3 (1|2); any of {4,8,16,32,128} → `exit 1`
/// → rescue (preen bailed on something unsafe to auto-fix — the intended fail-safe). The naive
/// `e2fsck -p … && mount` is WRONG: `&&` proceeds only on rc=0, false-diverting the rc=1 common recovery
/// to rescue (audit F-4).
///
/// `findfs LABEL=persist` (busybox applet) resolves the device; empty → `exit 1` → rescue (never run
/// e2fsck on a garbage arg, audit F-11). `e2fsck` is `/sbin/e2fsck` (base `e2fsprogs`; busybox has no
/// e2fsck applet, so the bare name PATH-resolves there) — presence-guarded `config::REQUIRED_COMPONENT_PATHS`.
/// On failure → rescue (a dirty/corrupt `/persist` is degraded, never an exposure); bounded by
/// `GROW_TIMEOUT_SECS` (an fsck of a multi-GB persist can exceed `FAST_TIMEOUT_SECS`; a SIGKILL'd scan
/// leaves the fs dirty → next boot retries → still fail-safe).
///
/// The grow + journal-add are FIRST-BOOT PROVISIONING, GATED on journal-absence (`if ! tune2fs -l |
/// grep -q has_journal`). This gate is load-bearing, found by the QEMU crash-sim gate: offline
/// `resize2fs` REFUSES ("run e2fsck -f first") after a journal REPLAY, because `e2fsck -p` only replays
/// the journal — it does not do the full check `resize2fs` demands. Running `resize2fs` every boot would
/// therefore divert EVERY post-crash boot to rescue (`resize2fs … || exit 1`). So `resize2fs` runs ONLY
/// on the first boot, when the skeleton is clean + has NO journal (where it provably grows-to-fill); once
/// the journal lands, the fs is already grown and every later boot skips the branch → straight to mount.
/// (Trade vs the spec's "self-healing every-boot resize": auto-regrow after a manual partition-enlarge is
/// no longer automatic — a rare operator action that can resize2fs by hand; correctness wins.) Inside the
/// branch: `resize2fs … || exit 1` (a real first-boot grow failure → rescue, a too-small persist is
/// degraded), then `tune2fs -O has_journal … || true` (Layer-2 enhancement; a failure must NOT rescue —
/// Layer 1 already made the fs mountable, audit F-7). The add is OFFLINE (the only supported form). After
/// the journal lands, an unclean stop replays it on the next `e2fsck -p` (fast); Layer 1 stays the belt
/// for the journal-insufficient case + the first-boot window before the journal exists. `tune2fs` is
/// e2fsprogs-extra (`REQUIRED_PATH_COMMANDS`); `grep` is busybox (`REQUIRED_BUSYBOX_APPLETS`). The
/// reproducible `-O ^has_journal` BAKE is unchanged — the journal is a runtime mutation of the installed
/// disk, never a hashed artifact (acceptance #4).
const PREPARE_PERSIST: &str = r#"mountpoint -q /persist && exit 0
dev="$(findfs LABEL=persist)"; [ -n "$dev" ] || exit 1
e2fsck -p "$dev"; rc=$?
[ $(( rc & 0xFC )) -eq 0 ] || exit 1
if ! tune2fs -l "$dev" | grep -q has_journal; then
resize2fs "$dev" || exit 1
tune2fs -O has_journal "$dev" || true
fi"#;

/// Own the data + runtime dirs to the service uids before the privilege-dropping services run.
/// Single `&&`-chain (fail-fast). The TENANT persist dirs (mkdir + chown to the declared uid) are
                 
/// MANIFEST-DERIVED: box-init renders them from the baked topology's `persist` instead
/// of hardcoding `recipes` — a non-recipes tenant otherwise hit `chown: unknown user/group
/// recipes:recipes` → setup-dirs FAIL → rescue divert (the produced-bytes finding). The acme/log/etc
/// dirs + the fb-acme runtime stay OS-invariant (§5.2). chown is by the validated UID (non-zero,
/// OS-disjoint) so it needs no passwd-name lookup; for the reference `chown 100:100` ≡ the prior `chown
/// recipes:recipes` (recipes IS uid 100) — functionally identical, byte-different (a runtime command,
/// not a hashed artifact; the boot-gate re-verifies). Empty persist (the None→rescue path) renders the
/// OS-invariant dirs only — no dangling `&&`.
fn setup_dirs_body(persist: &[fb_manifest::manifest::PersistDir]) -> String {
    let tenant_paths: String = persist
        .iter()
        .map(|d| format!(" /persist/{}", d.path))
        .collect();
                                                                                                        
                                                                                                     
                                                                                                      
                                                                                                  
    let tenant_setup: String = persist
        .iter()
        .map(|d| {
            format!(
                "chown {uid}:{uid} /persist/{path} && chmod {mode:04o} /persist/{path} && ",
                uid = d.uid,
                path = d.path,
                mode = d.mode,
            )
        })
        .collect();
    format!(
        "mkdir -p{tenant_paths} /persist/acme /persist/log /persist/etc && \
         {tenant_setup}chown fb-acme:fb-acme /persist/acme && chmod 0700 /persist/acme && \
         mkdir -p /run/fb-acme/challenges && chown -R fb-acme:fb-acme /run/fb-acme"
    )
}

/// Rescue key staging: a MODE-0700 tmpfs `/root/.ssh` (shadowing the dangling rootfs symlink — 0700
/// so dropbear's `checkpubkeyperms` accepts it; a DEFAULT tmpfs is 1777/world-writable, which dropbear
/// rejects → the recovery key would never authenticate, locking the operator out of rescue), the baked
/// recovery pubkey, the 0700 host-key dir, and the HKDF-derived rescue dropbear host key.
const RESCUE_KEYS: &str = "mkdir -p /run/dropbear-rescue && chmod 0700 /run/dropbear-rescue && mount -t tmpfs -o mode=0700 tmpfs /root/.ssh && cp /etc/ssh/recovery_authorized_keys /root/.ssh/authorized_keys && fb-oneshots derive-rescue-host-keys";

/// Services SSH host-key staging (BOOT-1 fix): derive the box's ed25519 dropbear host key to the
/// WRITABLE tmpfs path the services dropbear reads (`config::DROPBEAR_HOST_KEY = /run/dropbear/...`),
/// because that dropbear's `-R` regenerates at the RO `/etc/dropbear/` regardless of `-r` (→ the
/// running box was SSH-inaccessible). Reuses the SAME HKDF derivation as rescue (seed + verity root
/// hash → one operator-precomputable host identity; no dependency on a `dropbearkey` applet in the
/// rootfs). Runs in BOOTSTRAP (services branch) so it completes before the dropbear longrun starts.
const SERVICES_KEYS: &str = "mkdir -p /run/dropbear && chmod 0700 /run/dropbear && fb-oneshots derive-rescue-host-keys --out /run/dropbear/dropbear_ed25519_host_key";

/// box-init fills the topology's `Domain` placeholder with this runtime source-of-truth — the signed
/// `/etc/box-domain` read at boot via `$(cat …)`, a whole quoted shell word (box-init carries NO
/// compiled-in domain). With this fill, `render_boot_hook_body` reproduces the OS-invariant boot-hook
/// bodies byte-for-byte (pinned by the fb-manifest `render_boot_hook_body_reproduces_*` test).
const DOMAIN_REPR: &str = "\"$(cat /etc/box-domain)\"";

/// The `order` of the OS-infra `services-keys-stage` hook — AFTER the app-domain hooks (max 30) so the
/// interleave reproduces today's sequence (it stages the services SSH host key last, BOOT-1).
const OS_KEYS_STAGE_ORDER: u32 = 40;

/// Map a topology `OnFailure` (the manifest's externally-tagged enum) to box-init's bootstrap `OnFailure`.
fn map_on_failure(f: fb_manifest::manifest::OnFailure) -> OnFailure {
    match f {
        fb_manifest::manifest::OnFailure::Rescue {} => OnFailure::Rescue,
        fb_manifest::manifest::OnFailure::Reboot {} => OnFailure::Reboot,
    }
}

/// The bootstrap oneshots, in dependency order. The OS-INFRA hooks (firewall / persist crash-recovery /
/// mount / dir-ownership / host-key staging) are ALWAYS present + compiled-in here (the §5.2 partition —
/// they are audited OS controls, not tenant data); the tenant's APP-DOMAIN hooks (set-hostname /
/// bootstrap-ca / bootstrap-acme-cert) come from the baked, signed `Topology` (`Some`) and render to
/// identical bodies via `render_boot_hook_body`. The two sets interleave by an explicit `order`
/// (app-domain orders are manifest-declared; the OS-infra orders here reproduce today's EXACT sequence:
/// nft<prepare<mount<mount-check<setup-dirs(4) < set-hostname(10)<ca(20)<acme(30) < keys-stage(40)).
///
             
/// `set-hostname` needs only `mount-persist-check` (NOT `setup-dirs`); with order 10 > 4 it
/// still lands after setup-dirs (today's sequence preserved). `nftables-load` failure → REBOOT (the
              
/// exposure precondition); every other failure → rescue.
///
/// **`None` topology** (the signed `etc/box-topology.toml` failed to parse — a should-never-happen below
/// the dm-verity+IMA layer; this parse is the fail-closed backstop): yields the OS-INFRA hooks ONLY, so
/// the FIREWALL + persist still come up, then `wire_scandir` diverts to rescue (the app-domain setup is
/// absent → don't start the services). So a topology-parse-fail is fail-closed to rescue WITH the
              
/// firewall already loaded — satisfying BOTH §5.1e (unparseable → Rescue) AND the rule (never expose
/// even rescue without the firewall).
pub fn bootstrap(topology: Option<&Topology>) -> Vec<Oneshot> {
    let os = |order: u32, name: &str, body: &str, timeout_secs: u64, on_failure: OnFailure| {
        (
            order,
            Oneshot {
                name: name.to_string(),
                body: body.to_string(),
                timeout_secs,
                on_failure,
            },
        )
    };
                                                                                                      
                                                                                  
    let setup_dirs = setup_dirs_body(topology.map(|t| t.persist.as_slice()).unwrap_or(&[]));
    let mut ordered: Vec<(u32, Oneshot)> = vec![
        os(
            0,
            "nftables-load",
            "/usr/sbin/nft -f /etc/nftables.conf",
            FAST_TIMEOUT_SECS,
            OnFailure::Reboot,
        ),
                                                                                                     
                                                                                                      
        os(
            1,
            "prepare-persist",
            PREPARE_PERSIST,
            GROW_TIMEOUT_SECS,
            OnFailure::Rescue,
        ),
        os(
            2,
            "mount-persist",
            "mountpoint -q /persist || mount /persist",
            FAST_TIMEOUT_SECS,
            OnFailure::Rescue,
        ),
        os(
            3,
            "mount-persist-check",
            "mountpoint -q /persist",
            FAST_TIMEOUT_SECS,
            OnFailure::Rescue,
        ),
        os(
            4,
            "setup-dirs",
            &setup_dirs,
            FAST_TIMEOUT_SECS,
            OnFailure::Rescue,
        ),
                                                                                        
                                                                                         
                                                                                        
                                                                                        
                                                                                    
                                                                                        
                                                                                      
                                                                                         
        os(
            5,
            "seed-update-floors",
            "fb-update reconcile-floors",
            FAST_TIMEOUT_SECS,
            OnFailure::Rescue,
        ),
                                                                                                     
                                                                                                          
                                                                                                         
        os(
            OS_KEYS_STAGE_ORDER,
            "services-keys-stage",
            SERVICES_KEYS,
            FAST_TIMEOUT_SECS,
            OnFailure::Rescue,
        ),
    ];
                                                                                                           
    if let Some(t) = topology {
        let ctx = PlaceholderCtx {
            domain: DOMAIN_REPR.to_string(),
            source_date_epoch: 0,
        };
        for hook in &t.boot_hooks {
            ordered.push((
                hook.order,
                Oneshot {
                    name: hook.name.clone(),
                    body: fb_manifest::render_boot_hook_body(hook, &ctx),
                    timeout_secs: hook.timeout_secs,
                    on_failure: map_on_failure(hook.on_failure),
                },
            ));
        }
    }
                                                                                                        
    ordered.sort_by_key(|(order, _)| *order);
    ordered.into_iter().map(|(_, o)| o).collect()
}

/// The rescue oneshots (run only when bootstrap fails), in order. Networking is NO LONGER a oneshot here
/// (box-init runs `net::apply`/`net::link_only` on the rescue branch — spec §4.4); this stages the rescue
/// SSH keys. `on_failure` is unused on the rescue path (best-effort); `timeout_secs` is the hang backstop.
pub fn rescue() -> Vec<Oneshot> {
    vec![Oneshot {
        name: "rescue-keys-stage".to_string(),
        body: RESCUE_KEYS.to_string(),
        timeout_secs: FAST_TIMEOUT_SECS,
        on_failure: OnFailure::Rescue,
    }]
}

/// Run a oneshot as `sh -c body`, bounded by `o.timeout_secs` (delegates to [`run_bounded`]). `/bin/sh` is
             
/// the signed rootfs `execve` target; `body` is argv data — NEVER written to a file. Inherits
/// box-init's environment (incl. the `PATH` it sets).
pub fn run(o: &Oneshot) -> io::Result<ExitStatus> {
    let child = Command::new("/bin/sh")
        .args(["-c", o.body.as_str()])
        .spawn()?;
    run_bounded(child, &o.name, o.timeout_secs)
}

/// Wall-clock-bound an already-spawned `child`: poll `try_wait` to the deadline, then SIGKILL + reap. A
/// killed child reports `!success`, so the caller treats a hang identically to a non-zero exit (→
              
/// rescue/reboot) rather than blocking PID-1 forever. Polls with `try_wait` (no timer thread)
/// — box-init MUST stay single-threaded for the `set_var(PATH)` in `lib::run`. Shared by [`run`] (sh -c
/// oneshots) AND the Rust-native `ip` bring-up (`net::apply`), so both have one liveness guard (R2-3).
pub fn run_bounded(
    mut child: std::process::Child,
    name: &str,
    timeout_secs: u64,
) -> io::Result<ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            eprintln!("box-init: '{name}' exceeded {timeout_secs}s → SIGKILL");
                                                                                                      
                                                                                                       
                                                                                               
            let _ = child.kill();
            return child.wait();
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reference app-domain topology (the 3 boot-hooks box-init interleaves) — mirrors the baked
    /// `etc/box-topology.toml` (image-builder golden s15) so the order + body tests run against the real
    /// shape: set-hostname(10,root,30s) / bootstrap-ca(20,setuid,60s) / bootstrap-acme-cert(30,setuid,60s).
    fn ref_topology() -> Topology {
        fb_manifest::topology::parse_topology(
            r#"
schema_version = 1
[[boot_hooks]]
name = "set-hostname"
binary = "/usr/bin/fb-oneshots"
argv = [ { literal = { value = "set-hostname" } }, { literal = { value = "--fallback" } }, { placeholder = { name = "domain" } } ]
priv = { root = {} }
order = 10
timeout_secs = 30
on_failure = { rescue = {} }
[[boot_hooks]]
name = "bootstrap-ca"
binary = "/usr/bin/recipes-admin"
argv = [ { literal = { value = "bootstrap-ca" } } ]
priv = { setuidgid = { user = "recipes", envdir = "/etc/recipes/env" } }
order = 20
timeout_secs = 60
on_failure = { rescue = {} }
[[boot_hooks]]
name = "bootstrap-acme-cert"
binary = "/usr/bin/fb-oneshots"
argv = [ { literal = { value = "selfsign-acme-cert" } }, { literal = { value = "--domain" } }, { placeholder = { name = "domain" } } ]
priv = { setuidgid = { user = "fb-acme" } }
order = 30
timeout_secs = 60
on_failure = { rescue = {} }
[[persist]]
path = "recipes"
uid = 100
mode = 0o700
"#,
        )
        .expect("the reference app-domain topology parses")
    }

    fn pos(set: &[Oneshot], name: &str) -> usize {
        set.iter()
            .position(|o| o.name == name)
            .expect("oneshot present")
    }

    #[test]
    fn bootstrap_interleaves_app_domain_in_the_canonical_order() {
                                                                                                   
                                                                                                       
                                                                                                         
                                                                                     
        let b = bootstrap(Some(&ref_topology()));
        let names: Vec<&str> = b.iter().map(|o| o.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "nftables-load",
                "prepare-persist",
                "mount-persist",
                "mount-persist-check",
                "setup-dirs",
                                                                                  
                                                                    
                "seed-update-floors",
                "set-hostname",
                "bootstrap-ca",
                "bootstrap-acme-cert",
                "services-keys-stage",
            ]
        );
        let by = |name: &str| b.iter().find(|o| o.name == name).expect("hook present");
                                                                                                    
                                                                                                        
        assert_eq!(
            by("set-hostname").body,
            "'/usr/bin/fb-oneshots' 'set-hostname' '--fallback' \"$(cat /etc/box-domain)\""
        );
        assert_eq!(by("set-hostname").timeout_secs, 30);
        assert_eq!(
            by("bootstrap-ca").body,
            "s6-envdir '/etc/recipes/env' s6-setuidgid 'recipes' '/usr/bin/recipes-admin' 'bootstrap-ca'"
        );
        assert_eq!(
            by("bootstrap-ca").timeout_secs,
            60,
            "keygen margin from the manifest"
        );
        assert_eq!(
            by("bootstrap-acme-cert").body,
            "s6-setuidgid 'fb-acme' '/usr/bin/fb-oneshots' 'selfsign-acme-cert' '--domain' \"$(cat /etc/box-domain)\""
        );
    }

    #[test]
    fn setup_dirs_applies_the_declared_persist_mode() {
                                                                                                   
                                                                                                     
                                                                                                            
                                                                      
        let b = bootstrap(Some(
            &fb_manifest::topology::parse_topology(
                "schema_version = 1\nboot_hooks = []\n\
                 [[persist]]\npath = \"recipes\"\nuid = 100\nmode = 0o700\n\
                 [[persist]]\npath = \"widget\"\nuid = 200\nmode = 0o755\n",
            )
            .expect("the 2-persist topology parses"),
        ));
        let body = &b
            .iter()
            .find(|o| o.name == "setup-dirs")
            .expect("setup-dirs oneshot")
            .body;
        assert!(
            body.contains("chown 100:100 /persist/recipes && chmod 0700 /persist/recipes"),
            "the secrets dir must be chmod 0700 (the declared, now-applied mode): {body}"
        );
        assert!(
            body.contains("chown 200:200 /persist/widget && chmod 0755 /persist/widget"),
            "a second persist dir gets its OWN declared mode (0755), proving per-dir octal: {body}"
        );
    }

    #[test]
    fn bootstrap_without_topology_is_os_infra_only() {
                                                                                                          
                                                                                                       
                                                                                           
        let b = bootstrap(None);
        assert!(
            b.iter().any(|o| o.name == "nftables-load"),
                          
            "the firewall must still load on a topology-parse-fail"
        );
        assert!(b.iter().any(|o| o.name == "setup-dirs"));
        for app in ["set-hostname", "bootstrap-ca", "bootstrap-acme-cert"] {
            assert!(
                b.iter().all(|o| o.name != app),
                "app-domain hook {app} must be ABSENT without a topology"
            );
        }
    }

    #[test]
    fn bootstrap_order_honors_edges() {
        let b = bootstrap(Some(&ref_topology()));
        let b: &[Oneshot] = &b;
        assert!(pos(b, "mount-persist") < pos(b, "mount-persist-check"));
        assert!(pos(b, "mount-persist-check") < pos(b, "setup-dirs"));
                                                                                       
        assert!(pos(b, "mount-persist-check") < pos(b, "set-hostname"));
        assert!(pos(b, "setup-dirs") < pos(b, "bootstrap-ca"));
        assert!(pos(b, "setup-dirs") < pos(b, "bootstrap-acme-cert"));
        assert!(
            b.iter().any(|o| o.name == "nftables-load"),
            "firewall load is a bootstrap oneshot"
        );
    }

    #[test]
    fn seed_update_floors_is_pre_services_and_rescue() {
                                                                                        
                                                                                  
                                                                                       
        let b = bootstrap(Some(&ref_topology()));
        let b: &[Oneshot] = &b;
        assert!(pos(b, "mount-persist-check") < pos(b, "seed-update-floors"));
        assert!(pos(b, "seed-update-floors") < pos(b, "set-hostname"));
        let o = b
            .iter()
            .find(|o| o.name == "seed-update-floors")
            .expect("seed-update-floors oneshot present");
        assert_eq!(o.body, "fb-update reconcile-floors");
                                                                               
                                                                              
                                                                    
        assert_eq!(o.on_failure, OnFailure::Rescue);
        assert_eq!(o.timeout_secs, FAST_TIMEOUT_SECS);
    }

    #[test]
    fn prepare_persist_grows_offline_by_label() {
                                                                                                            
                                                                                                       
                                                                                              
        let b = bootstrap(Some(&ref_topology()));
        let b: &[Oneshot] = &b;
        assert!(pos(b, "prepare-persist") < pos(b, "mount-persist"));
                                                                        
        assert!(
            b.iter().all(|o| o.name != "grow-persist"),
            "grow-persist must be removed (folded into prepare-persist)"
        );
        let p = b
            .iter()
            .find(|o| o.name == "prepare-persist")
            .expect("prepare-persist oneshot");
                                                                                       
        assert!(p.body.contains("findfs LABEL=persist"));
                                                                                                         
                                                                                                        
                                                                                                         
                                                                                                          
                                                                                                             
                                                                                                          
        assert!(
            p.body
                .contains("if ! tune2fs -l \"$dev\" | grep -q has_journal; then"),
            "the grow MUST be journal-gated to the first boot"
        );
        assert!(p.body.contains("resize2fs \"$dev\" || exit 1"));
                                                                                                            
                                                                                                      
                                                                                                           
                                                                                       
        let lines: Vec<&str> = p.body.lines().collect();
        let gate_idx = lines
            .iter()
            .position(|l| l.contains("if ! tune2fs -l") && l.contains("has_journal"))
            .expect("the journal-gate line");
        let resize_idxs: Vec<usize> = lines
            .iter()
            .enumerate()
            .filter(|(_, l)| l.contains("resize2fs"))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(
            resize_idxs.len(),
            1,
            "exactly one resize2fs (a second, un-gated one would resize every boot)"
        );
        assert!(
            resize_idxs[0] > gate_idx,
            "resize2fs must be INSIDE the journal-gate (after the `if`), not an always-run line"
        );
        assert_eq!(p.on_failure, OnFailure::Rescue);
    }

    #[test]
    fn prepare_persist_recovers_offline_before_mount() {
        let b = bootstrap(Some(&ref_topology()));
        let b: &[Oneshot] = &b;
                                                                                                       
                                                                         
        assert!(pos(b, "prepare-persist") < pos(b, "mount-persist"));
        let p = b
            .iter()
            .find(|o| o.name == "prepare-persist")
            .expect("prepare-persist oneshot");
                                                                      
        assert!(p.body.contains("mountpoint -q /persist && exit 0"));
                                                                                                          
                                                          
        assert!(p.body.contains("findfs LABEL=persist"));
        assert!(p.body.contains("[ -n \"$dev\" ] || exit 1"));
                                                                                                           
                                                                             
        assert!(p.body.contains("e2fsck -p"));
        assert!(p.body.contains("rc & 0xFC"));
                                                                                                     
                                                                                                         
                                                                                                      
                                                                                                    
                                                                                                           
        assert!(
            p.body
                .contains("if ! tune2fs -l \"$dev\" | grep -q has_journal; then")
        );
        assert!(p.body.contains("tune2fs -O has_journal \"$dev\" || true"));
                                                                                                         
        assert_eq!(p.on_failure, OnFailure::Rescue);
                                                                                                       
        assert_eq!(p.timeout_secs, GROW_TIMEOUT_SECS);
    }

    #[test]
    fn prepare_persist_rc_gate_proceeds_0_to_3_diverts_on_error_bits() {
                                                                                                             
                                                                                                          
                                                                                                       
                                                                                                               
                                                                                    
                                                                                                            
                                                                                                          
                                                                                                        
        let gate = PREPARE_PERSIST
            .lines()
            .find(|l| l.contains("rc & 0xFC"))
            .expect("the rc-bitmask gate line in PREPARE_PERSIST");
        for (rc, proceed) in [
            (0, true),
            (1, true),
            (2, true),
            (3, true),
            (4, false),
            (8, false),
            (16, false),
            (32, false),
            (128, false),
        ] {
            let st = Command::new("/bin/sh")
                .args(["-c", &format!("rc={rc}; {gate}")])
                .status()
                .expect("spawn sh");
            assert_eq!(st.success(), proceed, "rc={rc} gate proceed={proceed}");
        }
    }

    #[test]
    fn nftables_load_is_the_only_critical_oneshot() {
                                                                                                    
                                                                                                  
        for o in bootstrap(Some(&ref_topology())) {
            let expected = if o.name == "nftables-load" {
                OnFailure::Reboot
            } else {
                OnFailure::Rescue
            };
            assert_eq!(o.on_failure, expected, "{} on_failure", o.name);
        }
    }

    #[test]
    fn all_bodies_are_valid_sh_not_execline() {
                                                                                                      
                                                                                                           
                                                                                                           
                                                                                                           
                                               
        let b = bootstrap(Some(&ref_topology()));
        let r = rescue();
                                                                                                        
                                                                                                     
                                                                                                              
        let none = bootstrap(None);
        let multi = bootstrap(Some(
            &fb_manifest::topology::parse_topology(
                "schema_version = 1\nboot_hooks = []\n\
                 [[persist]]\npath = \"a\"\nuid = 200\nmode = 0o700\n\
                 [[persist]]\npath = \"b\"\nuid = 201\nmode = 0o755\n",
            )
            .expect("the 2-persist topology parses"),
        ));
        for o in b
            .iter()
            .chain(r.iter())
            .chain(none.iter())
            .chain(multi.iter())
        {
            let st = Command::new("/bin/sh")
                .args(["-n", "-c", o.body.as_str()])
                .status()
                .expect("spawn sh -n");
            assert!(
                st.success(),
                "oneshot {} body is not valid sh: {}",
                o.name,
                o.body
            );
        }
    }

    #[test]
    fn rescue_keys_mounts_root_ssh_mode_0700_not_world_writable() {
                                                                                                       
                                                                                                          
                                                                                                        
                                                        
        let r = rescue();
        let body = &r
            .iter()
            .find(|o| o.name == "rescue-keys-stage")
            .expect("rescue-keys-stage oneshot")
            .body;
        assert!(
            body.contains("mount -t tmpfs -o mode=0700 tmpfs /root/.ssh"),
            "RESCUE_KEYS must mount /root/.ssh as a mode-0700 tmpfs (a default 1777 tmpfs locks the \
             operator out of rescue); got: {body}"
        );
    }

    #[test]
    fn run_executes_body_via_sh_c_never_a_tmpfs_script() {
                                                                                                  
                                                                                                     
                                                                                           
        let probe = |body: &str| Oneshot {
            name: "probe".to_string(),
            body: body.to_string(),
            timeout_secs: FAST_TIMEOUT_SECS,
            on_failure: OnFailure::Rescue,
        };
        assert!(run(&probe("true ; true")).unwrap().success());
        assert!(!run(&probe("false")).unwrap().success());
    }

    #[test]
    fn run_completes_a_fast_oneshot_within_its_timeout() {
        let o = Oneshot {
            name: "ok".to_string(),
            body: "true".to_string(),
            timeout_secs: FAST_TIMEOUT_SECS,
            on_failure: OnFailure::Rescue,
        };
        assert!(run(&o).unwrap().success());
    }

    #[test]
    fn run_kills_a_oneshot_that_exceeds_its_timeout() {
                                                                                                  
                                                                                            
        let o = Oneshot {
            name: "hang".to_string(),
            body: "sleep 30".to_string(),
            timeout_secs: 1,
            on_failure: OnFailure::Rescue,
        };
        let start = Instant::now();
        let status = run(&o).unwrap();
        assert!(
            !status.success(),
            "a killed oneshot must report failure (!success)"
        );
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "run() must return ~at the 1s deadline, not wait out `sleep 30`"
        );
    }

    #[test]
    fn run_bounded_kills_an_arbitrary_command_past_its_deadline() {
                                                                                                           
                                                                
        let child = Command::new("/bin/sh")
            .args(["-c", "sleep 30"])
            .spawn()
            .unwrap();
        let start = Instant::now();
        let status = run_bounded(child, "probe", 1).unwrap();
        assert!(!status.success(), "a killed child must report failure");
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "must return ~at the 1s deadline"
        );
    }

    #[test]
    fn run_bounded_returns_a_fast_commands_status() {
        let child = Command::new("/bin/sh")
            .args(["-c", "true"])
            .spawn()
            .unwrap();
        assert!(
            run_bounded(child, "ok", FAST_TIMEOUT_SECS)
                .unwrap()
                .success()
        );
    }
}

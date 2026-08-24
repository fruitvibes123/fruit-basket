//! initramfs-init — the box PID-1 init binary (runtime-mode path).
//!
                      
//! ## PID-1 contract
//! All errors are FATAL — `main` never returns to a shell. Any error (or panic) runs [`fatal`]:
//! writes `<0>` (KERN_EMERG) to `/dev/kmsg`, then `reboot(RB_AUTOBOOT)`. `panic = "abort"`, sync
//! code only (no async runtime). A box that cannot complete the verified-boot sequence MUST reboot,
//! never drop to an unverified running state.
//!
//! ## Boot path (runtime mode — spec "Initramfs as compiled Rust binary" steps 1..6)
//! - Step 1: mount `/proc` + `/sys` + `/dev` (devtmpfs) + securityfs ([`mount::mount_pseudo_filesystems`]).
//! - Step 1a: write `7` to `/proc/sys/kernel/printk` (operator-visible panics at every level).
//! - Step 2: read the boot config ([`boot_config::read_boot_config_from`]) — `/proc/cmdline` on BOTH
//!   firmwares, verity pair included (SB-loader plan L4: SeaBIOS bakes it into the extlinux APPEND;
//!   UEFI bakes it into the signed rambutan loader's cmdline const, delivered via LoadOptions).
//!   `fb.rootfs-dev` names the rootfs block device: a `/dev` path on SeaBIOS (operator-side
//!   detection bakes it into the APPEND), or a `PARTUUID=<uuid>` on UEFI (resolved against the
//!   on-disk GPT in step 3 — GUID-keyed, like the kernel's `root=PARTUUID=`).
//! - Step 3: on UEFI, resolve the PARTUUID → `/dev` node ([`installer_syscall::resolve_partuuid`]);
//!   then dm-verity setup with `restart_on_corruption`, fb.root-hash + byte→block offset
//!   ([`verity::setup_verity`], vendored DM ioctls verified against `dm-ioctl.h`).
//! - Step 4: mount the verity-wrapped squashfs read-only at `/sysroot` ([`mount::mount_verity_rootfs`]).
              
//! - Step 4a: **load the signed IMA policy FAIL-CLOSED** (Option C;
//!   [`ima_policy::load_policy`]) — write `/sysroot/etc/ima/policy` (absolute path → kernel appraises
//!   its own signature under `REQUIRE_POLICY_SIGS=y`) to `/sys/kernel/security/ima/policy`, verify
//!   the load took, PANIC otherwise. A silent failed load is a fail-OPEN layer-6 bypass, so it MUST
//!   be fatal BEFORE `switch_root`. The `.ima`/`.evm` leaf certs are kernel-loaded from the
//!   initramfs `/etc/keys/x509_{ima,evm}.der` before PID 1 runs.
//! - Step 5: write `2` to `/proc/sys/kernel/yama/ptrace_scope`.
//! - Step 6: dispatch — runtime ⇒ `switch_root` into `/sysroot` + exec `/sbin/init` (the box-init PID-1);
//!   installer ⇒ [`run_installer`] (the deploy-and-transition installer path, spec deploy-prod steps
//!   7.pre–7h: partition + write slot A from the scp'd `.img` + stage /persist + reboot).
//!
//! Steps 3/4/4a/6 are FFI (mount + dm device-mapper ioctls + securityfs + `switch_root` /
//! [`installer_syscall`] raw block I/O); they are written against verified kernel source
                                    
//! and exercised by the QEMU smoke (runtime and installer
//! runs). The host-testable units live in the library modules.

                                                                                                  
                                                                     
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

use initramfs_init::cmdline::{BootConfig, BootMode};
use initramfs_init::{boot_config, ima_policy, installer, installer_syscall, mount, verity};
use std::convert::Infallible;
use std::error::Error;
use std::io::Write;

const SYSROOT: &str = "/sysroot";
const RUNTIME_INIT: &str = "/sbin/init";

/// Initramfs-resident operator ed25519 ROOT pubkey, raw 64-char hex — the restore-image trust anchor
/// (spec §6d, C1). Only consumed by the restore-from verify; greenfield installs don't require it.
/// (image-signing.crt stays baked for the build-side rescue-seed IKM, but is no longer the restore anchor.)
const ARTIFACT_ROOT_PUB: &str = "/etc/recipes/artifact-root.pub";

fn main() {
                                                                                          
                                                                               
                                                                               
                                                                                     
                                                                                          
                                                                                          
                                                                                  
                                                             
      
                                                                                            
                                                                                             
                                                                                               
                                                                                      
      
                                                                                 
                                                                                     
                                                                                  
                                                                    
      
                                                                                         
                                                                                                
                                                                                               
                                                                                              
                                                                           
    unsafe {
        let mut fd = libc::open(c"/dev/kmsg".as_ptr().cast(), libc::O_WRONLY);
        if fd < 0 {
            fd = libc::open(c"/dev/null".as_ptr().cast(), libc::O_RDWR);
        }
        if fd >= 0 {
            libc::dup2(fd, 1);
            libc::dup2(fd, 2);
            if fd > 2 {
                libc::close(fd);
            }
        }
    }

                                                                                                    
                                                                                                 
                              
    std::panic::set_hook(Box::new(|info| fatal(&format!("panic: {info}"))));

    match run() {
                                                                                                 
                                                                                      
        Ok(never) => match never {},
        Err(e) => fatal(&format!("{e}")),
    }
}

fn run() -> Result<Infallible, Box<dyn Error>> {
                   
    mount::mount_pseudo_filesystems()?;
    mount::write_sysctl("/proc/sys/kernel/printk", "7")?;

                                                                                          
                                             
    let raw = std::fs::read_to_string("/proc/cmdline")?;
    let cfg = boot_config::read_boot_config_from(&raw).map_err(|e| e.to_string())?;

    match cfg.mode {
        BootMode::Runtime => run_runtime(&cfg),
        BootMode::Installer => run_installer(&cfg, &raw),
    }
}

/// Installer-mode dispatch (spec deploy-prod step 7): resolve the install sources for the boot firmware
/// ([`installer::installer_sources`] — SeaBIOS/kexec parses `fb.image-raw`+`fb.image-layout`; UEFI uses the built-in
/// `INSTALLER_DATA_PARTUUID`, §9.5), read the best-effort operator root pubkey (the restore-from trust
/// anchor, C1), and run the install
/// state machine over the real [`installer_syscall::SyscallInstallOps`]. The runtime kernel cmdline +
/// the operator pubkey are baked into the pre-baked components build-side (the boot-fs `extlinux.conf`
/// APPEND + the persist-skeleton), so the installer reads neither here. On success `run_install`
/// reboots into the runtime and NEVER returns; it returns only on failure, which propagates to
/// [`fatal`] (kmsg + reboot) — the box never drops to an unverified running state.
fn run_installer(cfg: &BootConfig, raw: &str) -> Result<Infallible, Box<dyn Error>> {
                                                                                                              
                                                                                              
    let sources = installer::installer_sources(cfg.firmware, raw).map_err(|e| e.to_string())?;
                                                                                                 
                                                                                                              
                                                                                             
    let operator_root_pubkey_hex = std::fs::read(ARTIFACT_ROOT_PUB).unwrap_or_default();

    let params = installer::InstallParams {
        sources: &sources,
        operator_root_pubkey_hex: &operator_root_pubkey_hex,
                                                                                                         
        image_sha256: cfg.image_sha256,
                                                                                                  
        install_to: cfg.install_to.as_deref(),
    };
    let mut ops = installer_syscall::SyscallInstallOps::new();
    installer::run_install(&mut ops, &params).map_err(|e| e.to_string())?;
                                                                                               
                                                                                                  
    Err("installer-mode run_install returned without rebooting the box".into())
}

/// Whether the runtime must resolve a `fb.rootfs-dev=PARTUUID=<uuid>` token against the on-disk GPT
/// before verity. True for the GPT firmwares (UEFI + SeabiosGpt) — both boot a GPT disk and carry a
/// baked PARTUUID (the kernel/GPT select the rootfs by GUID). False for SeaBIOS, whose APPEND carries a
               
/// `/dev` node directly (and whose parser rejects PARTUUID anyway).
fn resolves_partuuid(firmware: installer::Firmware) -> bool {
    matches!(
        firmware,
        installer::Firmware::Uefi | installer::Firmware::SeabiosGpt
    )
}

/// Resolve a device token to a `/dev` node: on the GPT firmwares (UEFI, SeabiosGpt) a `PARTUUID=<uuid>`
/// is resolved against the on-disk GPT; a bare `/dev` path — or any token on legacy SeaBIOS — passes
/// through unchanged. Shared by the rootfs and the dha weights device (both are baked as PARTUUIDs under
/// GPT and resolved identically; the weights token is ALWAYS a PARTUUID — the volume is a 5th GPT partition).
fn resolve_dev(dev: String, firmware: installer::Firmware) -> Result<String, Box<dyn Error>> {
    if resolves_partuuid(firmware)
        && let Some(partuuid) = dev.strip_prefix("PARTUUID=")
    {
        let node = installer_syscall::resolve_partuuid(partuuid).map_err(|e| e.to_string())?;
        log_kmsg(
            6,
            &format!("fb-init: resolved PARTUUID={partuuid} -> {node}"),
        );
        return Ok(node);
    }
    Ok(dev)
}

/// Steps 3 → 6 of the runtime boot path. Returns `Ok(Infallible)` only via the `execv` in
/// `switch_root` (which replaces the process image); every fallible step propagates to [`fatal`].
fn run_runtime(cfg: &BootConfig) -> Result<Infallible, Box<dyn Error>> {
                                                                                                        
                                                                                                     
                                                                                                         
                                                                                                         
                                                      
    let mut cfg = cfg.clone();
    if let Some(rootfs_dev) = cfg.rootfs_dev.take() {
        cfg.rootfs_dev = Some(resolve_dev(rootfs_dev, cfg.firmware)?);
    }

                                                
    log_kmsg(
        6,
        &format!(
            "fb-init: setup_verity dev={}",
            cfg.rootfs_dev.as_deref().unwrap_or("??")
        ),
    );
    let verity_node = verity::setup_verity(&cfg)?;
    log_kmsg(
        6,
        &format!("fb-init: verity node={}", verity_node.display()),
    );

                                                               
    mount::mount_verity_rootfs(&verity_node, SYSROOT)?;
    log_kmsg(6, "fb-init: verity rootfs mounted");

                                                                                                           
                                                                                                          
                                                                                                   
                                                                                                        
                                                                                                          
                                                                                                             
                                                                                        
    if let Some(weights) = cfg.weights.as_ref() {
        let weights_dev = resolve_dev(weights.dev.clone(), cfg.firmware)?;
        log_kmsg(
            6,
            &format!("fb-init: setup_weights_verity dev={weights_dev}"),
        );
        let weights_node =
            verity::setup_weights_verity(&weights_dev, &weights.hash, weights.offset)?;
        mount::mount_weights_verity(&weights_node, SYSROOT)?;
        log_kmsg(6, "fb-init: weights volume mounted RO at /sysroot/models");
    }

                                                                                                
                                                                                      
    log_kmsg(6, "fb-init: load_policy");
    ima_policy::load_policy()?;

                                                      
    mount::write_sysctl("/proc/sys/kernel/yama/ptrace_scope", "2")?;

                                                                                                  
    log_kmsg(
        6,
        &format!(
            "fb-init: mode=runtime verity-root-hash={} switch_root={SYSROOT}{RUNTIME_INIT}",
            cfg.root_hash
        ),
    );
    Ok(mount::switch_root(SYSROOT, RUNTIME_INIT)?)
}

/// The PID-1 fatal path: best-effort KERN_EMERG log to `/dev/kmsg`, then reboot. Never returns.
fn fatal(msg: &str) -> ! {
    log_kmsg(0, &format!("fb-init FATAL: {msg}"));
                                                                                                   
                                                                                                     
                                                                                                 
                                                                                               
                                                                                             
                                                                                          
    let ts = libc::timespec {
        tv_sec: 20,
        tv_nsec: 0,
    };
                                                                                                    
    unsafe {
        libc::nanosleep(&ts, std::ptr::null_mut());
    }
                                                                                                      
    unsafe {
        libc::reboot(libc::RB_AUTOBOOT);
    }
                                                                                                        
    loop {
                                                          
        unsafe {
            libc::pause();
        }
    }
}

/// Best-effort write to `/dev/kmsg` (the kernel ring buffer; operator-readable via the VPS console /
/// `dmesg`). `level` is the syslog level: 0 = EMERG (always reaches the console), 6 = INFO. Failure
/// is ignored — early in boot (before /dev is mounted) the node may not exist yet.
fn log_kmsg(level: u8, msg: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open("/dev/kmsg") {
        let _ = writeln!(f, "<{level}>{msg}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use installer::Firmware;

    #[test]
    fn partuuid_resolution_runs_for_the_gpt_firmwares_only() {
                                                                                                     
                                                                                    
        assert!(resolves_partuuid(Firmware::Uefi));
        assert!(resolves_partuuid(Firmware::SeabiosGpt));
        assert!(!resolves_partuuid(Firmware::Seabios));
    }
}

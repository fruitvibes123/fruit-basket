//! fb-oneshots: the box's in-image runtime oneshots, invoked by box-init's bootstrap/rescue
//! sequence at boot (the signed-exec init layer). They run in the minimal musl image and
              
//! need NO database. Lifted from `recipes`' `box_oneshots` (the OS extraction).
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

use std::path::PathBuf;

use clap::{Parser, Subcommand};

mod cert_reload;
mod hostname;
mod rescue_keys;
mod selfsign;

#[derive(Parser)]
#[command(
    name = "fb-oneshots",
    version,
    about = "Box in-image bootstrap/rescue oneshots"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Set the kernel hostname from `/persist/etc/hostname` (operator-set; survives image swaps),
    /// falling back to the image default. Bootstrap oneshot invoked by box-init.
    SetHostname {
        #[arg(long, default_value = "/persist/etc/hostname")]
        persist_hostname: PathBuf,
        #[arg(long, default_value = "recipes-box")]
        fallback: String,
    },
    /// Self-sign a temporary ACME bootstrap cert into `<persist-dir>/<domain>/full.pem` if absent,
    /// so haproxy can `bind :443` before fb-acme issues the real cert. Idempotent.
    SelfsignAcmeCert {
        #[arg(long)]
        domain: String,
        #[arg(long, default_value = "/persist/acme")]
        persist_dir: PathBuf,
    },
    /// One cert-reload watcher cycle (the `fb-cert-reload` OS service body): content-hash
    /// `<persist-dir>/<domain>/full.pem` with the hardened reader and `s6-svc -2` HAProxy when it
    /// changed since the last signalled hash (`/run/fb-cert-reload.marker`). Reload-on-Init;
    /// fail-closed marker.
    CertReloadCheck {
        #[arg(long)]
        domain: String,
        #[arg(long, default_value = "/persist/acme")]
        persist_dir: PathBuf,
    },
    /// Derive the rescue dropbear ed25519 host key from the baked seed + the dm-verity root hash on
    /// the kernel cmdline, and write it to the rescue tmpfs. Invoked by box-init's keys-stage oneshots.
    DeriveRescueHostKeys {
        #[arg(long, default_value = "/etc/dropbear/rescue-host-key-seed")]
        seed: PathBuf,
        #[arg(long, default_value = "/proc/cmdline")]
        cmdline: PathBuf,
        #[arg(long, default_value = "/run/dropbear-rescue/dropbear_ed25519_host_key")]
        out: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Cmd::SetHostname {
            persist_hostname,
            fallback,
        } => hostname::set_hostname(&persist_hostname, &fallback),
        Cmd::SelfsignAcmeCert {
            domain,
            persist_dir,
        } => selfsign::selfsign_acme_cert(&persist_dir, &domain),
        Cmd::CertReloadCheck {
            domain,
            persist_dir,
        } => cert_reload::cert_reload_check(&persist_dir, &domain),
        Cmd::DeriveRescueHostKeys { seed, cmdline, out } => {
            rescue_keys::derive_rescue_host_keys(&seed, &cmdline, &out)
        }
    }
}

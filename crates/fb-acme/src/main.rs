//! fb-acme: merged ACME HTTP-01 challenge server (`serve`) + scheduled
//! renewal client (`renew`) for the immutable box image. Edge TLS is
//! terminated by HAProxy; this binary serves loopback challenges and renews
                                       
//! the cert HAProxy binds. The `serve` path descends from the
//! recorded Axum pilot.

mod acme;
mod due;
mod instant_client;
mod renew;
mod serve;

use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

use instant_client::{EpochFloorClock, InstantAcmeClient};
use renew::{AcmeMode, RenewConfig, TokioSleeper};

#[derive(Parser)]
#[command(
    name = "fb-acme",
    version,
    about = "ACME HTTP-01 challenge server + renewal client"
)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve HTTP-01 challenge files on loopback :8081 (long-running; HAProxy
    /// proxies `:80/.well-known/acme-challenge/*` here). Reads ACME_CHALLENGE_DIR.
    Serve,
    /// Obtain or renew the TLS certificate for `--domain` and persist it to
    /// `<persist-dir>/<domain>/full.pem` (mode 0600). Gated on the build-epoch
    /// clock floor (`--min-epoch`).
    Renew {
        /// FQDN to issue the certificate for.
        #[arg(long)]
        domain: String,
        /// Root holding per-domain ACME state (`<root>/<domain>/...`).
        #[arg(long, default_value = "/persist/acme")]
        persist_dir: PathBuf,
        /// Challenge files are written here for `serve` to publish. L-2: reads `ACME_CHALLENGE_DIR`
        /// (the same `/etc/recipes/env` envdir `serve` reads, via the run script's `s6-envdir` prefix)
        /// so the writer (renew) and the server (serve) share ONE source of truth — not a coincidental
        /// clap-default match. Falls back to the default when the env is unset (operator one-shot).
        #[arg(
            long,
            env = "ACME_CHALLENGE_DIR",
            default_value = "/run/fb-acme/challenges"
        )]
        challenge_dir: PathBuf,
        /// ACME directory to target (production burns real rate limits).
        #[arg(long, value_enum, default_value_t = ModeArg::Production)]
        acme_mode: ModeArg,
        /// Optional `mailto:` contact for the ACME account.
        #[arg(long)]
        contact_email: Option<String>,
        /// Build-epoch floor (Unix seconds): defer issuance until the system clock
        /// advances strictly past this, so a not-yet-stepped first-boot clock can't
        /// mint a cert with a bogus validity window. The s6 run script bakes the
        /// image's build epoch here; pass `0` to disable the floor on a known-good clock.
        #[arg(long)]
        min_epoch: u64,
        /// Run a single attempt (no backoff loop) — operator-driven one-shot.
        #[arg(long)]
        once: bool,
    },
}

#[derive(Copy, Clone, ValueEnum)]
enum ModeArg {
    Production,
    Staging,
}

impl From<ModeArg> for AcmeMode {
    fn from(m: ModeArg) -> Self {
        match m {
            ModeArg::Production => AcmeMode::Production,
            ModeArg::Staging => AcmeMode::Staging,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    match Cli::parse().command {
        Cmd::Serve => serve::run().await,
        Cmd::Renew {
            domain,
            persist_dir,
            challenge_dir,
            acme_mode,
            contact_email,
            min_epoch,
            once,
        } => {
            let mode: AcmeMode = acme_mode.into();
            let cfg = RenewConfig {
                domain: domain.clone(),
                persist_dir: persist_dir.clone(),
            };
            let client = InstantAcmeClient {
                directory_url: mode.directory_url().to_string(),
                challenge_dir,
                account_path: persist_dir.join(&domain).join("account.json"),
                contact_email,
            };
            let clock = EpochFloorClock::new(min_epoch);
            let outcome = if once {
                                                                          
                                                                                 
                Some(renew::renew_once(&client, &cfg, &clock).await?)
            } else {
                                                                          
                                                                              
                                                                              
                                                                         
                let now_unix = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                renew::renew_scheduled(
                    &due::FileCertInspector,
                    &client,
                    &cfg,
                    &clock,
                    now_unix,
                    &TokioSleeper,
                )
                .await?
            };
            if let Some(path) = outcome {
                println!("fb-acme renew: wrote {}", path.display());
            }
            Ok(())
        }
    }
}

//! `fb-weights` — the hotswappable-model box binary (hotswap v4 §3/§5).
//!
//! Subcommands:
//! - `setup` — the boot-time weights-verity-setup, invoked from the engine leaf's s6 `run` script
//!   as `/usr/bin/fb-weights setup || exit 1` (root, pre-uid-drop). Verifies the persisted signed
//!   weights record CLOCK-FREE (Rider 1), sets up runtime dm-verity, mounts `/models` RO. Every
//!   failure → non-zero exit → the run dies → the engine's restart-cap downs ONLY that service.
//! - `swap` — the flocked model-swap sequencer (invoked by `orchard deploy-model` over ssh as
//!   root; the framed push on stdin). Exit codes: 0 COMMITTED, 3 REFUSED (disk untouched),
//!   4 DEGRADED (engine down + visible; re-push restores), 19 lock/context unavailable.
//!
//! One binary, two verbs (the `fb-update` shape) — one pinned supply-chain artifact.

use std::path::Path;
use std::process::ExitCode;

use fb_weights::boxops::{
    BoxSwapOps, WEIGHTS_ENGINE_FILE, WEIGHTS_HEALTH_FILE, parse_health_cfg, read_engine_service,
};
use fb_weights::setup::{
    ARTIFACT_ROOT_PUB, SyscallSetupOps, WEIGHTS_PARTUUID, read_root_pubkey, run_setup,
};
use fb_weights::stores::WEIGHTS_DIR;
use fb_weights::swap::{SWAP_LOCK_FILE, SwapError, read_frame_header, run_swap};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("setup") => run_setup_cmd(),
        Some("swap") => run_swap_cmd(),
        _ => {
            eprintln!("usage: fb-weights <setup|swap>");
            ExitCode::from(2)
        }
    }
}

/// `fb-weights swap`: hold the NON-BLOCKING swap flock (a concurrent swap refuses, spec §5),
/// assemble the box context (all preflight — nothing stops before every input is in hand), then
/// run the sequencer with stdin as the framed push.
fn run_swap_cmd() -> ExitCode {
    let weights_dir = Path::new(WEIGHTS_DIR);
    let _lock = match fb_verity_rt::lock_exclusive_nonblocking(&weights_dir.join(SWAP_LOCK_FILE)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "fb-weights swap: refused: cannot take the swap lock (concurrent swap?): {e}"
            );
            return ExitCode::from(19);
        }
    };
    let root_pubkey = match read_root_pubkey(Path::new(ARTIFACT_ROOT_PUB)) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("fb-weights swap: {e}");
            return ExitCode::from(19);
        }
    };
    let engine = match read_engine_service(Path::new(WEIGHTS_ENGINE_FILE)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("fb-weights swap: {e}");
            return ExitCode::from(19);
        }
    };
    let health = match std::fs::read_to_string(WEIGHTS_HEALTH_FILE)
        .map_err(|e| std::io::Error::other(format!("weights-health {WEIGHTS_HEALTH_FILE}: {e}")))
        .and_then(|s| parse_health_cfg(&s))
    {
        Ok(h) => h,
        Err(e) => {
            eprintln!("fb-weights swap: {e}");
            return ExitCode::from(19);
        }
    };
                                                                                               
    let weights_dev = match fb_verity_rt::resolve_partuuid(WEIGHTS_PARTUUID) {
        Ok(d) => std::path::PathBuf::from(d),
        Err(e) => {
            eprintln!("fb-weights swap: refused: weights partition: {e}");
            return ExitCode::from(3);
        }
    };

    let mut stdin = std::io::stdin().lock();
    let req = match read_frame_header(&mut stdin) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("fb-weights swap: refused: {e}");
            return ExitCode::from(3);
        }
    };

    let mut ops = BoxSwapOps {
        weights_dev,
        health,
    };
    match run_swap(
        &mut ops,
        weights_dir,
        &root_pubkey,
        &engine,
        &req,
        &mut stdin,
    ) {
        Ok(ctr) => {
            eprintln!("fb-weights swap: COMMITTED (ctr {ctr})");
            ExitCode::SUCCESS
        }
        Err(e @ SwapError::Refused(_)) => {
            eprintln!("fb-weights swap: {e}");
            ExitCode::from(3)
        }
        Err(e @ SwapError::Degraded(_)) => {
            eprintln!("fb-weights swap: {e}");
            ExitCode::from(4)
        }
    }
}

/// `fb-weights setup`: fail-closed; the s6 run script's `|| exit 1` consumes the exit code.
fn run_setup_cmd() -> ExitCode {
    let root_pubkey = match read_root_pubkey(Path::new(ARTIFACT_ROOT_PUB)) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("fb-weights setup: {e}");
            return ExitCode::from(19);
        }
    };
    match run_setup(&mut SyscallSetupOps, Path::new(WEIGHTS_DIR), &root_pubkey) {
        Ok(()) => {
            eprintln!("fb-weights setup: model volume verified + mounted");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("fb-weights setup: {e}");
            ExitCode::from(1)
        }
    }
}

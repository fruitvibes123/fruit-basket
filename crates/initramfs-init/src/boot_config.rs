               
//! The firmware-agnostic boot-config accessor (SB-loader plan Task 2.3 / spec §5.3).
//!
//! Both firmwares produce the SAME [`crate::cmdline::BootConfig`] from the SAME source: the kernel
//! cmdline. SeaBIOS bakes the dm-verity fb.root-hash + byte-offset into the extlinux APPEND; UEFI bakes
//! them into the cmdline const inside the SIGNED rambutan loader (delivered via `LoadOptions` — the
//! kernel-stub-era `/recipes-verity-params` file is gone). This accessor is the ONE chokepoint that
//! turns `/proc/cmdline` into a `BootConfig`.
//!
               
//! **The root hash is HEX on both firmwares** — the seam the signer's Thread-2
//! verity-bound host key consumes; never change that representation without re-running the
//! signer↔UEFI seam check.

use crate::cmdline::{BootConfig, CmdlineError, parse_cmdline};

/// Build the unified [`BootConfig`] from the kernel cmdline — the single source on both firmwares.
/// Kept as the named accessor seam (rather than callers invoking `parse_cmdline` directly) so a
               
/// future second source would have exactly one place to join, and the hex contract has
/// one documented anchor.
pub fn read_boot_config_from(cmdline: &str) -> Result<BootConfig, CmdlineError> {
    parse_cmdline(cmdline)
}

//! Loader PE byte-reproducibility gate (plan Task 1.8; spec §8/§9.4).
//!
//! Builds the loader twice from IDENTICAL inputs (fixed RECIPES_LOADER_* + fixed
//! SOURCE_DATE_EPOCH, ambient RECIPES_LOADER_DEV stripped) into two CLEAN target
//! dirs and asserts the two PEs are byte-identical. The signed artifact contract
//! (spec §8) is unsigned-PE byte-equivalence — a nondeterministic PE field (e.g.
//! a TimeDateStamp) would break repro AND the signature story; if one ever appears,
//! the pinned fallback is a deterministic post-link normalization documented HERE,
//! never an ad-hoc byte-patch in the build.
//!
                                        
//! `#[ignore]`d: two clean release builds are too slow for every verification run. RUN by
//! the UEFI boot gate (`cargo test --manifest-path crates/rambutan/Cargo.toml -- --ignored`,
                   
//! wired there as a fast-fail before the KVM battery — the audit found it previously
//! unreachable by any make target). M-α note: this gate needs NO external env — it fixes its own
//! inputs — so unlike the .img gates it cannot false-green on missing env; it asserts real bytes
//! every run (no KVM/docker required, pure cargo).

use std::path::PathBuf;
use std::process::Command;

#[test]
#[ignore = "two clean release builds; run via make boot-gate-uefi (--ignored)"]
fn loader_double_build_is_byte_identical() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let base = std::env::temp_dir().join(format!("rambutan-repro-{}", std::process::id()));
    let mut pes: Vec<Vec<u8>> = Vec::new();

    for i in 0..2 {
        let target_dir = base.join(format!("build-{i}"));
        std::fs::create_dir_all(&target_dir).expect("create clean target dir");
        let status = Command::new("cargo")
            .args([
                "build",
                "--release",
                "--target",
                "x86_64-unknown-uefi",
                "--locked",
            ])
            .current_dir(&manifest_dir)
            .env("CARGO_TARGET_DIR", &target_dir)
            .env_remove("RECIPES_LOADER_DEV")
            .env("RECIPES_LOADER_CMDLINE", "ro repro-gate-fixed-cmdline")
            .env("RECIPES_LOADER_INITRD_SHA256", "ab".repeat(32))
            .env("RECIPES_LOADER_SB_REQUIRED", "1")
            .env("SOURCE_DATE_EPOCH", "1700000000")
            .status()
            .expect("cargo build runs");
        assert!(status.success(), "build {i} failed");
        let pe = target_dir.join("x86_64-unknown-uefi/release/rambutan.efi");
        pes.push(std::fs::read(&pe).expect("read built PE"));
    }

    let identical = pes[0] == pes[1];
                                                                                   
    if identical {
        let _ = std::fs::remove_dir_all(&base);
    }
    assert!(
        identical,
        "double-build PEs differ ({} vs {} bytes) — inspect {} (kept); if a \
         nondeterministic PE field appeared, pin the documented post-link \
         normalization, do NOT ad-hoc patch",
        pes[0].len(),
        pes[1].len(),
        base.display()
    );
}

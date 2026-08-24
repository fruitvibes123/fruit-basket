//! CRUX-style dependency tree lock (plan Task 1.7 step 3; the dragonfruit precedent).
//!
//! The loader's §3 contract pins the dependency tree to `core` + the RustCrypto sha2
//! stack ONLY — no std/alloc creep, no new crates, into the un-appraised boot window.
//! This lock asserts the EXACT crate set for the uefi target; any addition (or a
                       
//! surprise transitive) fails the verification run loudly and forces a deliberate decision.
//! Each listed crate is no_std-clean under `default-features = false` (verified at
//! adoption); the lock keeps the set closed, the audit re-verifies members. NOTE
                    
//! — `cpufeatures` additionally runs CPUID at runtime to pick the
//! SHA-NI vs portable SHA-256 path — sound in the boot window (CPUID is a bare
//! instruction, no OS surface; both paths are RustCrypto-audited), so the digest is
//! not a single fixed code path but branches on the CPU. That is why a "pure compute"
//! hash legitimately pulls a CPU-detection crate.

use std::process::Command;

#[test]
fn dependency_tree_is_exactly_the_sha2_stack() {
    let out = Command::new("cargo")
        .args([
            "tree",
            "--target",
            "x86_64-unknown-uefi",
            "--edges",
            "normal",
            "--prefix",
            "none",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo tree runs");
    assert!(out.status.success(), "cargo tree failed: {:?}", out);
    let tree = String::from_utf8(out.stdout).expect("utf8");
    let mut crates: Vec<String> = tree
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            l.split_whitespace()
                .next()
                .expect("crate name column")
                .to_string()
        })
        .collect();
    crates.sort();
    crates.dedup();
    assert_eq!(
        crates,
        [
            "block-buffer",
            "cfg-if",
            "cpufeatures",
            "crypto-common",
            "digest",
            "generic-array",
            "rambutan",
            "sha2",
            "typenum",
        ],
        "the rambutan dependency tree changed — every addition into the boot-trust \
         window is a deliberate, audited decision (spec §3); update this lock ONLY \
         alongside that audit"
    );
}

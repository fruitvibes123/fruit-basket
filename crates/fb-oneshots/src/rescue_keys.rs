//! `fb-oneshots derive-rescue-host-keys` (runtime mode) — invoked by box-init's
//! `rescue-keys-stage` oneshot at rescue boot (spec §"Rescue host-key derivation",
//! L1145). Reads the baked rescue seed + the dm-verity root hash off the kernel
//! cmdline, derives the deterministic ed25519 dropbear host key via the
//! `grape` crate (host-key derivation), and writes it to the rescue tmpfs. The seed
//! is build-time-only-secret; the runtime derivation reads ONLY seed + verity root
//! hash (never the operator master.key — load-bearing for the threat model).
//!
//! The offline `--image` squashfs-parse mode (operator-side TOFU known_hosts
//! precompute) lives in the operator-host `orchard` CLI (`orchard derive-rescue-offline`).

use std::path::Path;

/// Parse the dm-verity root hash (the runtime HKDF nonce) from a kernel cmdline:
/// the `fb.root-hash=<64-hex>` token the bootloader's APPEND directive carries
/// (SHA-256 → 32 bytes). Spec L1190: a cmdline without it is operator-actionable.
pub fn parse_root_hash(cmdline: &str) -> Result<[u8; 32], String> {
    let hex = cmdline
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("fb.root-hash="))
        .ok_or_else(|| {
            "verity root hash not on cmdline; cannot derive rescue host keys".to_string()
        })?;
    decode_hex_32(hex)
        .ok_or_else(|| format!("fb.root-hash on cmdline is not 32 bytes of hex: {hex:?}"))
}

/// Decode exactly 32 bytes from 64 lowercase/uppercase hex chars; `None` on any
/// non-hex char or wrong length.
fn decode_hex_32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

/// Runtime entry point: derive the rescue dropbear ed25519 host key and write it to
/// `out` (mode 0600). `cmdline_path` is read for the verity-root-hash nonce; the
/// `rescue-keys-stage` oneshot pre-creates `out`'s parent (`/run/dropbear-rescue/`) at
/// 0700 root:root before calling this. Error text mirrors the spec's operator-actionable
/// diagnostics (L1188-1192).
pub fn derive_rescue_host_keys(
    seed: &Path,
    cmdline_path: &Path,
    out: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let cmdline = std::fs::read_to_string(cmdline_path).map_err(|e| {
        boxed(format!(
            "cannot read kernel cmdline {}: {e}",
            cmdline_path.display()
        ))
    })?;
    let nonce = parse_root_hash(&cmdline).map_err(boxed)?;

    let key = grape::derive_host_key(seed, &nonce).map_err(|e| {
        use grape::DeriveError;
        boxed(match e {
            DeriveError::FileRead(_) => {
                "rescue host-key seed not found or invalid size; image build may be corrupted"
                    .into()
            }
            DeriveError::Hkdf(d) => {
                format!("HKDF derivation failed: {d}; check hkdf crate version")
            }
            other => other.to_string(),
        })
    })?;

    write_key_0600(out, key.as_ref()).map_err(|e| {
        boxed(format!(
            "cannot write rescue host key: {e}; ensure {} exists at mode 0700 root:root",
            out.parent()
                .map(Path::to_path_buf)
                .unwrap_or_default()
                .display()
        ))
    })?;
    println!(
        "fb-oneshots derive-rescue-host-keys: wrote rescue dropbear host key to {}",
        out.display()
    );
    Ok(())
}

fn boxed(msg: String) -> Box<dyn std::error::Error> {
    Box::new(std::io::Error::other(msg))
}

/// Write `bytes` to `out` at mode 0600, refusing to follow a symlink (`O_NOFOLLOW`).
/// Overwrites (the derivation is deterministic — re-running yields identical bytes).
fn write_key_0600(out: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let mut f = opts.open(out)?;
    f.write_all(bytes)?;
    f.sync_all()
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_root_hash_finds_token_among_others() {
        let hex = "ab".repeat(32);
        let cmdline = format!("ro fb.root-hash={hex} fb.verity-hash-offset=4096 console=ttyS0");
        let parsed = parse_root_hash(&cmdline).unwrap();
        assert_eq!(parsed, [0xabu8; 32]);
    }

    #[test]
    fn parse_root_hash_errors_when_absent() {
        let err = parse_root_hash("ro console=ttyS0 quiet").unwrap_err();
        assert!(err.contains("verity root hash not on cmdline"));
    }

    #[test]
    fn parse_root_hash_rejects_wrong_length() {
        assert!(parse_root_hash("fb.root-hash=deadbeef").is_err());
    }

    #[test]
    fn decode_hex_32_round_trips_and_rejects_garbage() {
        assert_eq!(decode_hex_32(&"00".repeat(32)), Some([0u8; 32]));
        assert_eq!(decode_hex_32(&"ff".repeat(32)), Some([0xffu8; 32]));
        assert_eq!(decode_hex_32("zz"), None);
        assert_eq!(decode_hex_32(&"ab".repeat(31)), None);            
    }

    #[cfg(unix)]
    #[test]
    fn runtime_derivation_matches_crate_core_and_is_0600() {
        use std::os::unix::fs::PermissionsExt as _;
        let tmp = tempfile::tempdir().unwrap();
                                                                                        
                                                                              
        let seed = [7u8; 32];
        let nonce_byte = 0x5au8;
        let seed_path = tmp.path().join("rescue-host-key-seed");
        std::fs::write(&seed_path, seed).unwrap();
        let cmdline_path = tmp.path().join("cmdline");
        let hex = format!("{nonce_byte:02x}").repeat(32);
        std::fs::write(
            &cmdline_path,
            format!("ro fb.root-hash={hex} console=ttyS0"),
        )
        .unwrap();
        let out = tmp.path().join("dropbear_ed25519_host_key");

        derive_rescue_host_keys(&seed_path, &cmdline_path, &out).unwrap();

        let expected = grape::host_key_from_seed(&seed, &[nonce_byte; 32]).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), expected.as_ref());
        let mode = std::fs::metadata(&out).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn missing_seed_gives_operator_actionable_error() {
        let tmp = tempfile::tempdir().unwrap();
        let cmdline_path = tmp.path().join("cmdline");
        std::fs::write(&cmdline_path, format!("fb.root-hash={}", "00".repeat(32))).unwrap();
        let err = derive_rescue_host_keys(
            &tmp.path().join("does-not-exist-seed"),
            &cmdline_path,
            &tmp.path().join("out"),
        )
        .unwrap_err();
        assert!(err.to_string().contains("seed not found or invalid size"));
    }
}

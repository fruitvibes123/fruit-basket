//! The persisted weights store (hotswap v4 spec §6, plan Task 3): ONE atomically-written record at
//! `/persist/weights/current` holding {the co-located anti-rollback floor, the current signed
//! weights-manifest bytes, the 254-byte `Purpose::Weights` signature bundle}.
//!
//! **Why co-located (Rider 2):** the swap's commit (§5 step 7) must persist "the new manifest is
//! current" AND "the floor is bumped" with no torn intermediate — two files would need a commit
//! ordering; one record file behind one tmp+fsync+rename+dir-fsync write has none. The record's
//! `floor_ctr` IS the dedicated weights floor: it is never read or written by fb-update's rootfs
//! `reconcile_floors` (which touches only `/persist/update/{version,minctr}-floor` — the
//! disjointness guard below pins that against fb-update's REAL constants).
//!
//! **Trust ordering (mirrors `fb-update::apply`):** [`read_record_strict`] is a dumb, bounded,
//! fail-closed parser — it verifies NOTHING. The consumer (the boot-time setup helper / the swap
//! preflight) hands `manifest_bytes` + `sig` to `quince` (`Purpose::Weights`, `min_ctr =
//! floor_ctr`) and only THEN parses the manifest view via [`parse_weights_manifest`]. Nothing from
//! the record is acted on pre-verification.
//!
//! **Cross-repo wire contract:** orchard's bake (initial record into the persist skeleton) and
//! `deploy-model` (the swap push) produce these exact bytes — the record layout + the manifest
//! line grammar below are the contract; both sides pin them with golden tests.
//!
//! Record file layout (all integers little-endian; ANY deviation — short read, bad magic, length
//! out of bounds, trailing bytes — is a fail-closed `Err`, never a default):
//!
//! ```text
//! magic      [u8; 4]  = b"FBW1"
//! floor_ctr  u64 LE          — the co-located anti-rollback floor
//! manifest_len u64 LE        — 1..=MANIFEST_MAX_LEN
//! manifest   [u8; manifest_len]  — the SIGNED artifact bytes (sha256'd for the quince verify)
//! sig        [u8; 254]       — the dragonfruit BundleFile (delegation‖root_sig‖attestation‖worker_sig)
//! ```

use std::io::{self, Read, Write};
use std::path::Path;

/// The DEDICATED weights store dir — disjoint from fb-update's `/persist/update` by construction
/// (the guard test pins this against fb-update's real constants).
pub const WEIGHTS_DIR: &str = "/persist/weights";

/// The record file name inside [`WEIGHTS_DIR`].
pub const CURRENT_FILE: &str = "current";

/// Record magic — version 1 of the layout.
const MAGIC: [u8; 4] = *b"FBW1";

/// The serialized dragonfruit `BundleFile` length (delegation 59 ‖ root_sig 64 ‖ attestation 67 ‖
/// worker_sig 64). Pinned here because the record layout embeds it; cross-checked against
/// `dragonfruit::BUNDLE_FILE_LEN` where the consumer verifies (quince rejects any other length).
pub const SIG_LEN: usize = 254;

/// Weights manifests are tiny (two lines); anything bigger is malformed by construction.
pub const MANIFEST_MAX_LEN: u64 = 4096;

/// The persisted record: the co-located floor + the byte-exact signed manifest + its bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightsRecord {
    /// The co-located anti-rollback floor. The boot verify runs quince with `min_ctr = floor_ctr`;
    /// the swap commit bumps it to the newly-verified bundle ctr. [`write_record_atomic`] refuses
    /// to lower it.
    pub floor_ctr: u64,
    /// The signed artifact, byte-exact (the quince verify hashes exactly these bytes).
    pub manifest_bytes: Vec<u8>,
    /// The detached 254-byte `Purpose::Weights` bundle over `sha256(manifest_bytes)`.
    pub sig: [u8; SIG_LEN],
}

/// The PARSED manifest view — only meaningful AFTER the quince verify succeeded on the raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WeightsManifest {
    /// The dm-verity root hash of the weights volume (64 lowercase hex).
    pub root_hash: String,
    /// Byte offset where the verity hash tree begins on the partition (4096-aligned; the
    /// squashfs data occupies `[0, verity_offset)`).
    pub verity_offset: u64,
    /// SHA-256 of the WHOLE image (squashfs data ‖ verity hash tree) — the swap's
    /// write-then-reread check (the `stream_verified` pattern; fail-fast on a torn write BEFORE
    /// the mount-time verity enforcement).
    pub image_sha256: [u8; 32],
    /// Total image byte length (data + hash tree) — the swap's fit check against the partition
    /// and the exact stream/reread length.
    pub image_size: u64,
}

/// Read + strictly parse the record at `dir/current`. Fail-closed on EVERY deviation — absent,
/// short, bad magic, oversized manifest length, trailing bytes — mirroring `read_floor_strict`'s
/// never-defaults discipline: an unreadable trust pointer aborts the caller (creatine stays down /
/// the swap refuses); recovery is an operator action (re-push / restore-from), never a silent
/// zero-floor default.
pub fn read_record_strict(dir: &Path) -> io::Result<WeightsRecord> {
    let path = dir.join(CURRENT_FILE);
    let mut f = std::fs::File::open(&path)
        .map_err(|e| io::Error::other(format!("weights record {}: {e}", path.display())))?;

    let mut magic = [0u8; 4];
    f.read_exact(&mut magic)
        .map_err(|e| io::Error::other(format!("weights record: short magic: {e}")))?;
    if magic != MAGIC {
        return Err(io::Error::other(format!(
            "weights record: bad magic {magic:02x?} (want {MAGIC:02x?})"
        )));
    }

    let mut u64buf = [0u8; 8];
    f.read_exact(&mut u64buf)
        .map_err(|e| io::Error::other(format!("weights record: short floor_ctr: {e}")))?;
    let floor_ctr = u64::from_le_bytes(u64buf);

    f.read_exact(&mut u64buf)
        .map_err(|e| io::Error::other(format!("weights record: short manifest_len: {e}")))?;
    let manifest_len = u64::from_le_bytes(u64buf);
    if manifest_len == 0 || manifest_len > MANIFEST_MAX_LEN {
        return Err(io::Error::other(format!(
            "weights record: manifest_len {manifest_len} out of bounds (1..={MANIFEST_MAX_LEN})"
        )));
    }

    let mut manifest_bytes = vec![0u8; manifest_len as usize];
    f.read_exact(&mut manifest_bytes)
        .map_err(|e| io::Error::other(format!("weights record: short manifest: {e}")))?;

    let mut sig = [0u8; SIG_LEN];
    f.read_exact(&mut sig)
        .map_err(|e| io::Error::other(format!("weights record: short sig: {e}")))?;

                                                                               
    let mut trailing = [0u8; 1];
    match f.read(&mut trailing) {
        Ok(0) => {}
        Ok(_) => {
            return Err(io::Error::other(
                "weights record: trailing bytes after the sig (malformed layout)",
            ));
        }
        Err(e) => return Err(io::Error::other(format!("weights record: EOF probe: {e}"))),
    }

    Ok(WeightsRecord {
        floor_ctr,
        manifest_bytes,
        sig,
    })
}

/// Serialize + durably write the record to `dir/current` (tmp+fsync+rename+dir-fsync — the
/// `write_floor_atomic` pattern, `floors.rs:224`; the record is anti-rollback state, so a write
/// that evaporates on power loss would re-open the downgrade window).
///
/// **Monotonic floor:** a well-formed existing record with `floor_ctr` ABOVE the new one refuses
/// the write (the writer never lowers; equality is allowed — quince's floor check is `≥`, and a
/// same-ctr re-push of the identical manifest is the crash-recovery idempotency case). An ABSENT
/// existing record allows the write (the bake populating a fresh persist skeleton); a MALFORMED
/// existing record refuses (fail-closed — damaged trust state is operator territory: restore-from
/// or re-provision, never a silent overwrite).
pub fn write_record_atomic(dir: &Path, r: &WeightsRecord) -> io::Result<()> {
    write_record_atomic_with_pause(dir, r, &|_| {})
}

/// The pause-capable variant (spec Component B, audit L-4): [`write_record_atomic`] is
/// the inert entry the `#[cfg(test)]` callers keep; ONLY `run_swap`'s box commit
/// path passes an ops-backed closure, firing `pre-rename` between the tmp fsync and
/// the rename — the one window where AC-B5 is provable. No pause check is reachable
/// from `cargo test`.
pub fn write_record_atomic_with_pause(
    dir: &Path,
    r: &WeightsRecord,
    pause: &dyn Fn(crate::swap::PausePoint),
) -> io::Result<()> {
    if r.manifest_bytes.is_empty() || r.manifest_bytes.len() as u64 > MANIFEST_MAX_LEN {
        return Err(io::Error::other(format!(
            "weights record: refusing to write manifest_len {} (1..={MANIFEST_MAX_LEN})",
            r.manifest_bytes.len()
        )));
    }
    let path = dir.join(CURRENT_FILE);
    match std::fs::metadata(&path) {
        Ok(_) => {
                                                                                               
                                                                                                  
            let existing = read_record_strict(dir).map_err(|e| {
                io::Error::other(format!(
                    "weights record: existing record unreadable — refusing overwrite \
                     (operator recovery: restore-from): {e}"
                ))
            })?;
            if r.floor_ctr < existing.floor_ctr {
                return Err(io::Error::other(format!(
                    "weights record: floor rollback refused (new {} < existing {})",
                    r.floor_ctr, existing.floor_ctr
                )));
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}                      
        Err(e) => {
            return Err(io::Error::other(format!(
                "weights record: cannot stat existing record: {e}"
            )));
        }
    }

    let mut buf = Vec::with_capacity(4 + 8 + 8 + r.manifest_bytes.len() + SIG_LEN);
    buf.extend_from_slice(&MAGIC);
    buf.extend_from_slice(&r.floor_ctr.to_le_bytes());
    buf.extend_from_slice(&(r.manifest_bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(&r.manifest_bytes);
    buf.extend_from_slice(&r.sig);

    let tmp = dir.join(format!(".{CURRENT_FILE}.tmp"));
    let mut f = std::fs::File::create(&tmp)
        .map_err(|e| io::Error::other(format!("weights record: create {}: {e}", tmp.display())))?;
    f.write_all(&buf)?;
    f.sync_all()?;
    pause(crate::swap::PausePoint::PreRename);
    std::fs::rename(&tmp, &path)?;
    std::fs::File::open(dir)?.sync_all()?;
    Ok(())
}

/// Parse the (ALREADY quince-verified) manifest bytes into the typed view. Strict whitelist
/// grammar — exactly these four lines, in this order, nothing else:
///
/// ```text
/// verity-root-hash=<64 lowercase hex>\n
/// verity-offset=<u64 decimal>\n
/// image-sha256=<64 lowercase hex>\n
/// image-size=<u64 decimal>\n
/// ```
///
/// Any unknown key, duplicate, reorder, missing line, malformed value, or trailing content is a
/// fail-closed `Err` (whitelist over blacklist — never act on a manifest shape we did not define).
pub fn parse_weights_manifest(bytes: &[u8]) -> io::Result<WeightsManifest> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| io::Error::other("weights manifest: not utf-8"))?;
    let mut lines = text.split_inclusive('\n');

    let root_hash = take_kv(&mut lines, 1, "verity-root-hash")?;
    require_hex64(root_hash, "verity-root-hash")?;
    let verity_offset = parse_u64_plain(take_kv(&mut lines, 2, "verity-offset")?, "verity-offset")?;
    let image_hex = take_kv(&mut lines, 3, "image-sha256")?;
    require_hex64(image_hex, "image-sha256")?;
    let image_size = parse_u64_plain(take_kv(&mut lines, 4, "image-size")?, "image-size")?;

    if lines.next().is_some() {
        return Err(io::Error::other(
            "weights manifest: trailing content after image-size",
        ));
    }

    let mut image_sha256 = [0u8; 32];
    for (i, byte) in image_sha256.iter_mut().enumerate() {
                                                                                   
        *byte = u8::from_str_radix(&image_hex[i * 2..i * 2 + 2], 16)
            .map_err(|e| io::Error::other(format!("weights manifest: image-sha256: {e}")))?;
    }

    Ok(WeightsManifest {
        root_hash: root_hash.to_string(),
        verity_offset,
        image_sha256,
        image_size,
    })
}

/// Take line `n` and strip `<key>=` + the trailing `\n` — fail-closed on a missing line, a wrong
/// key, or a missing terminator (the strict-order grammar has no lookahead).
fn take_kv<'a>(
    lines: &mut impl Iterator<Item = &'a str>,
    n: usize,
    key: &str,
) -> io::Result<&'a str> {
    let line = lines
        .next()
        .ok_or_else(|| io::Error::other(format!("weights manifest: missing {key} (line {n})")))?;
    line.strip_prefix(key)
        .and_then(|v| v.strip_prefix('='))
        .and_then(|v| v.strip_suffix('\n'))
        .ok_or_else(|| {
            io::Error::other(format!(
                "weights manifest: line {n} is not '{key}=<value>\\n'"
            ))
        })
}

/// Whitelist 64 lowercase hex chars (a SHA-256 / verity-root literal).
fn require_hex64(s: &str, key: &str) -> io::Result<()> {
    if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(io::Error::other(format!(
            "weights manifest: {key} is not 64 lowercase hex chars"
        )));
    }
    Ok(())
}

/// Whitelist a plain decimal u64 (no sign, no whitespace; leading zeros tolerated as u64::parse
/// would).
fn parse_u64_plain(s: &str, key: &str) -> io::Result<u64> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(io::Error::other(format!(
            "weights manifest: {key} is not a plain decimal u64"
        )));
    }
    s.parse()
        .map_err(|e| io::Error::other(format!("weights manifest: {key}: {e}")))
}

/// Render the canonical manifest bytes (the inverse of [`parse_weights_manifest`]; the bytes that
/// get sha256'd + signed). One canonical form — round-trip asserted in tests; orchard's bake and
/// `deploy-model` produce these exact bytes.
pub fn render_weights_manifest(m: &WeightsManifest) -> Vec<u8> {
    let image_hex: String = m.image_sha256.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "verity-root-hash={}\nverity-offset={}\nimage-sha256={}\nimage-size={}\n",
        m.root_hash, m.verity_offset, image_hex, m.image_size
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_manifest() -> WeightsManifest {
        WeightsManifest {
            root_hash: "ab".repeat(32),
            verity_offset: 8_388_608,
            image_sha256: [0xCD; 32],
            image_size: 8_650_752,
        }
    }

    fn sample() -> WeightsRecord {
        WeightsRecord {
            floor_ctr: 7,
            manifest_bytes: render_weights_manifest(&sample_manifest()),
            sig: [0x5A; SIG_LEN],
        }
    }

    #[test]
    fn write_then_read_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let r = sample();
        write_record_atomic(dir.path(), &r).expect("write");
        assert_eq!(read_record_strict(dir.path()).expect("read"), r);
                                          
        assert!(!dir.path().join(".current.tmp").exists());
    }

    #[test]
    fn absent_record_is_err_not_default() {
        let dir = tempfile::tempdir().expect("tempdir");
        let e = read_record_strict(dir.path()).unwrap_err();
        assert!(e.to_string().contains("weights record"), "{e}");
    }

    #[test]
    fn truncated_and_garbage_records_fail_closed() {
        let dir = tempfile::tempdir().expect("tempdir");
        let r = sample();
        write_record_atomic(dir.path(), &r).expect("write");
        let path = dir.path().join(CURRENT_FILE);
        let full = std::fs::read(&path).expect("read back");

                                                                          
        for cut in [0, 3, 4, 11, 12, 19, 20, full.len() - 1] {
            std::fs::write(&path, &full[..cut]).expect("truncate");
            assert!(
                read_record_strict(dir.path()).is_err(),
                "prefix of {cut} bytes must be rejected"
            );
        }
                                                                               
        let mut extended = full.clone();
        extended.push(0xEE);
        std::fs::write(&path, &extended).expect("extend");
        assert!(read_record_strict(dir.path()).is_err());

                                      
        let mut bad_magic = full.clone();
        bad_magic[0] ^= 0xFF;
        std::fs::write(&path, &bad_magic).expect("bad magic");
        assert!(read_record_strict(dir.path()).is_err());

                                                                                        
        let mut bad_len = full;
        bad_len[12..20].copy_from_slice(&(MANIFEST_MAX_LEN + 1).to_le_bytes());
        std::fs::write(&path, &bad_len).expect("bad len");
        assert!(read_record_strict(dir.path()).is_err());
    }

    #[test]
    fn writer_never_lowers_the_floor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut r = sample();
        write_record_atomic(dir.path(), &r).expect("write floor 7");

                                              
        r.floor_ctr = 6;
        let e = write_record_atomic(dir.path(), &r).unwrap_err();
        assert!(e.to_string().contains("floor rollback refused"), "{e}");
        assert_eq!(read_record_strict(dir.path()).expect("read").floor_ctr, 7);

                                                                                                    
        r.floor_ctr = 7;
        write_record_atomic(dir.path(), &r).expect("equal floor rewrite");

                              
        r.floor_ctr = 9;
        write_record_atomic(dir.path(), &r).expect("bump");
        assert_eq!(read_record_strict(dir.path()).expect("read").floor_ctr, 9);
    }

    #[test]
    fn writer_refuses_overwrite_of_a_malformed_existing_record() {
                                                                                             
                                                                         
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(CURRENT_FILE), b"garbage").expect("plant garbage");
        let e = write_record_atomic(dir.path(), &sample()).unwrap_err();
        assert!(e.to_string().contains("refusing overwrite"), "{e}");
    }

    #[test]
    fn manifest_round_trips_and_rejects_deviations() {
        let m = WeightsManifest {
            root_hash: "0123456789abcdef".repeat(4),
            verity_offset: 123_456_789,
            image_sha256: [0x0F; 32],
            image_size: 987_654_321,
        };
        let bytes = render_weights_manifest(&m);
        assert_eq!(parse_weights_manifest(&bytes).expect("round trip"), m);
                                                                                                
        assert_eq!(
            String::from_utf8(bytes).expect("utf8"),
            format!(
                "verity-root-hash={}\nverity-offset=123456789\nimage-sha256={}\nimage-size=987654321\n",
                "0123456789abcdef".repeat(4),
                "0f".repeat(32)
            )
        );

        let aa64 = "a".repeat(64);
        let tail = format!("image-sha256={aa64}\nimage-size=1\n");
        for bad in [
            String::new(),
            format!("verity-root-hash=short\nverity-offset=1\n{tail}"),
            format!(
                "verity-root-hash={}\nverity-offset=1\n{tail}",
                "A".repeat(64)
            ),             
            format!("verity-offset=1\nverity-root-hash={aa64}\n{tail}"),           
            format!("verity-root-hash={aa64}\n{tail}"),                                          
            format!("verity-root-hash={aa64}\nverity-offset=-1\n{tail}"),
            format!("verity-root-hash={aa64}\nverity-offset=1\n"),                       
            format!("verity-root-hash={aa64}\nverity-offset=1\nimage-sha256=zz\nimage-size=1\n"),
            format!("verity-root-hash={aa64}\nverity-offset=1\nimage-sha256={aa64}\nimage-size=\n"),
            format!("verity-root-hash={aa64}\nverity-offset=1\n{tail}extra=x\n"),            
            format!("verity-root-hash={aa64}\nverity-offset=1\nimage-sha256={aa64}\nimage-size=1"),         
        ] {
            assert!(
                parse_weights_manifest(bad.as_bytes()).is_err(),
                "must reject {bad:?}"
            );
        }
    }

    #[test]
    fn weights_store_is_disjoint_from_the_rootfs_reconcile_paths() {
                                                                                                 
                                                                                                   
                                                                                                
                                                                   
        use std::path::PathBuf;
        let weights_store = PathBuf::from(WEIGHTS_DIR).join(CURRENT_FILE);
        let rootfs_floor_files = [
            PathBuf::from(fb_update::floors::UPDATE_DIR)
                .join(fb_update::floors::VERSION_FLOOR_FILE),
            PathBuf::from(fb_update::floors::UPDATE_DIR).join(fb_update::floors::MINCTR_FLOOR_FILE),
        ];
        for f in &rootfs_floor_files {
            assert_ne!(
                &weights_store, f,
                "the weights record must never alias a rootfs floor file"
            );
        }
                                                                                               
        assert_ne!(WEIGHTS_DIR, fb_update::floors::UPDATE_DIR);
    }
}

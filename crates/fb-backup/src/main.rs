//! fb-backup: daily local snapshot of a tenant data directory.
//!
                                
//! Spec §7.1 / §5.1g; mode 0600, retention + restore drill, and
//! manifest-driven sources (NO hardcoded recipes data shape).
//!
//! Usage: fb-backup <data-dir>
//!
//! Reads its source/vacuum set from the signed `/etc/fb-backup/config` (baked by image-builder from the
//! service manifest's `[backup]` section — `source <rel>` lines + an optional `vacuum <rel>`), so a
//! NON-recipes tenant gets a correct backup instead of the hardcoded recipes layout. Outputs to
//! `<data-dir>/backups/`:
//!   db-<YYYYMMDD-HHMMSS>.sqlite    sqlite online-backup of the `vacuum` target (only if declared)
//!   data-<YYYYMMDD-HHMMSS>.tar.gz  tarball of the `source` dirs/files
//!
//! Retention: 14 most-recent of each prefix kept; older deleted.
         
//! Mode: 0600 on the output files (the tarball can contain private keys).
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

use anyhow::{Context, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::path::Path;

const RETENTION: usize = 14;

/// The signed (dm-verity + IMA-covered) config image-builder bakes from the manifest `[backup]`
             
/// section. fb-backup reads + re-validates it instead of hardcoding the recipes data shape.
const CONFIG_PATH: &str = "/etc/fb-backup/config";

/// The parsed backup policy: the dirs/files to tar + the optional sqlite db to VACUUM (all relative to
/// the data root). Replaces the old hardcoded `BACKUP_SUBDIRS`/`BACKUP_FILES`/`recipes.db`.
struct BackupConfig {
    sources: Vec<String>,
    vacuum: Option<String>,
}

/// Re-validate a config-declared path at the sink (defense-in-depth — image-builder's gate already ran
/// `validate_relative_path`, but the config is read at RUNTIME so fb-backup re-checks before joining it
/// under the data root, mirroring box-init's topology re-validation): non-empty, relative (no leading
/// `/`), no `..` component. So even a tampered config (below the dm-verity/IMA layer) cannot direct the
/// tarball to read outside the data dir.
fn is_safe_relative(path: &str) -> bool {
    !path.is_empty() && !path.starts_with('/') && !path.split('/').any(|c| c == "..")
}

/// Parse + re-validate the baked config. Whitelist-shaped + fail-closed (the project DNA): each
/// non-comment line is exactly `source <rel>` or `vacuum <rel>`; an unknown directive, a malformed
/// line, a duplicate `vacuum`, or an unsafe path REFUSES (a broken/poisoned config must not silently
/// degrade the backup or escape the data root — a wrong backup is worse than a loud failure).
fn parse_config(text: &str) -> Result<BackupConfig> {
    let mut sources = Vec::new();
    let mut vacuum = None;
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (directive, arg) = line.split_once(' ').ok_or_else(|| {
            anyhow::anyhow!(
                "fb-backup config line {}: not `<directive> <path>`: {line:?}",
                i + 1
            )
        })?;
        let arg = arg.trim();
        if !is_safe_relative(arg) {
            anyhow::bail!(
                "fb-backup config line {}: unsafe path {arg:?} (must be relative, no `..`)",
                i + 1
            );
        }
        match directive {
            "source" => sources.push(arg.to_string()),
            "vacuum" => {
                if vacuum.is_some() {
                    anyhow::bail!(
                        "fb-backup config line {}: duplicate `vacuum` directive",
                        i + 1
                    );
                }
                vacuum = Some(arg.to_string());
            }
            other => anyhow::bail!(
                "fb-backup config line {}: unknown directive {other:?}",
                i + 1
            ),
        }
    }
    Ok(BackupConfig { sources, vacuum })
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
                                                                       
                                                                          
                                                                       
                                                                        
                                                               
                                                                          
      
                                                                  
                                                                   
                                                                  
    #[cfg(unix)]
                                                                        
                                                                           
    unsafe {
        libc::umask(0o077);
    }

    let data_dir = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: fb-backup <data-dir>"))?;
    let data_dir = Path::new(&data_dir);
    let backup_dir = data_dir.join("backups");
    std::fs::create_dir_all(&backup_dir).context("create backups/")?;

                                                                                                
    let cfg_text = std::fs::read_to_string(CONFIG_PATH)
        .with_context(|| format!("read backup config {CONFIG_PATH}"))?;
    let cfg = parse_config(&cfg_text).context("parse backup config")?;

    let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S").to_string();

                                                                                                       
                                                                            
    if let Some(vt) = &cfg.vacuum {
        let db_out = backup_dir.join(format!("db-{ts}.sqlite"));
        backup_sqlite(&data_dir.join(vt), &db_out)
            .await
            .context("sqlite online backup")?;
        set_mode_0600(&db_out)?;
    }

                                                                                                        
                                                                                                   
                                                                                                           
    let tar_out = backup_dir.join(format!("data-{ts}.tar.gz"));
    tar_sources(data_dir, &cfg.sources, &tar_out).context("data tar.gz")?;
    set_mode_0600(&tar_out)?;

    prune(&backup_dir, "db-", RETENTION)?;
    prune(&backup_dir, "data-", RETENTION)?;
    Ok(())
}

async fn backup_sqlite(src: &Path, dst: &Path) -> Result<()> {
                                                                            
                                                                         
                                                                       
                                                                        
    let opts = SqliteConnectOptions::new().filename(src).read_only(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .context("open source db read-only")?;
    let dst_str = dst.to_str().context("dst path not utf-8")?;
                                                                         
                                                                
                                                                          
                                                                     
    if dst_str.contains('\'') {
        anyhow::bail!("dst path contains single-quote: {dst_str}");
    }
    sqlx::query(&format!("VACUUM INTO '{dst_str}'"))
        .execute(&pool)
        .await
        .context("VACUUM INTO")?;
    Ok(())
}

fn tar_sources(base: &Path, sources: &[String], dst: &Path) -> Result<()> {
                                                                           
                                                                     
                                                                         
                                                    
    let f = create_owner_only(dst).context("create tar.gz")?;
    let gz = flate2::write::GzEncoder::new(f, flate2::Compression::default());
    let mut tar = tar::Builder::new(gz);
                                                                                                     
                                                                                                     
                                                                                                       
    for src in sources {
        let p = base.join(src);
        if p.is_dir() {
            tar.append_dir_all(src, &p)
                .with_context(|| format!("tar dir {src}"))?;
        } else if p.is_file() {
            let mut fh = std::fs::File::open(&p).with_context(|| format!("open {p:?}"))?;
            tar.append_file(src, &mut fh)
                .with_context(|| format!("tar file {src}"))?;
        }
    }
    tar.finish().context("finalize tar")?;
    Ok(())
}

fn create_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

fn set_mode_0600(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod 0600 {path:?}"))?;
    }
    let _ = path;
    Ok(())
}

fn prune(dir: &Path, prefix: &str, keep: usize) -> Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .with_context(|| format!("read_dir {dir:?}"))?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.file_name()
                .to_str()
                .map(|n| n.starts_with(prefix))
                .unwrap_or(false)
        })
        .collect();
                                                                     
    entries.sort_by_key(|e| e.file_name());
    while entries.len() > keep {
        let oldest = entries.remove(0);
        std::fs::remove_file(oldest.path()).ok();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CRUX lock (Spec 2 §1 / AC#6): the box NEVER signs. `fb-backup` runs ON
    /// the box and emits backups UNSIGNED — the operator signs at pull-time off-box
    /// (`deploy sign-backup`). This pins the ABSENCE of any signing surface in this
    /// binary so a future "let the box sign its own backup" regression trips review.
                                    
    /// (Belt-and-suspenders with the cargo-tree lock, which proves
    /// dragonfruit is unreachable in a default-features box build at all.)
    #[test]
    fn backup_binary_has_no_signing_surface() {
        let src = include_str!("main.rs");
                                                                                        
                                                                                     
                                                                                 
                                                                                           
                                                                                          
                                                                                          
                                                                                            
                                                                                    
                                                                                       
                                                                                     
                                                                                       
                                                                   
        let attr_lines = src.lines().filter(|l| l.trim() == "#[cfg(test)]").count();
        assert_eq!(
            attr_lines, 1,
            "expected exactly one standalone #[cfg(test)] line (the test module); \
             found {attr_lines} — guard structure changed, review before trusting it"
        );
        let boundary = src
            .lines()
            .position(|l| l.trim() == "#[cfg(test)]")
            .expect("source has a #[cfg(test)] module boundary");
        let code = src.lines().take(boundary).collect::<Vec<_>>().join("\n");
        for forbidden in [
            "dragonfruit",
            "sign_attestation",
            "sign_delegation",
            "SigningKey",
        ] {
            assert!(
                !code.contains(forbidden),
                "fb-backup must not grow a signing path (found `{forbidden}`) — \
                 the box never signs (Spec 2 §1 CRUX); read it before touching this"
            );
        }
    }

    #[test]
    fn prune_keeps_only_the_last_n() {
        let dir = tempfile::tempdir().expect("tempdir");
                                                                   
                                               
        for i in 0..20 {
            let p = dir
                .path()
                .join(format!("db-2026{:02}01-000000.sqlite", i + 1));
            std::fs::write(&p, b"x").unwrap();
        }
        prune(dir.path(), "db-", 14).expect("prune");
        let remaining: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(remaining.len(), 14);
                                                                   
        assert!(
            remaining.iter().any(|n| n.starts_with("db-202620")),
            "newest survived",
        );
                                                                    
        assert!(
            !remaining.iter().any(|n| n.starts_with("db-202601")),
            "oldest pruned",
        );
    }

    /// A helper: build a `Vec<String>` sources list (the new tar_sources signature).
    fn srcs(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn tar_sources_archives_a_directory_source() {
        let base = tempfile::tempdir().expect("base");
        std::fs::create_dir_all(base.path().join("images")).unwrap();
        std::fs::write(base.path().join("images/x.webp"), b"hello").unwrap();
        let out = base.path().join("out.tar.gz");
                                                                                                          
        tar_sources(base.path(), &srcs(&["images", "shopping-lists"]), &out).expect("tar");
        assert!(out.exists());
        let f = std::fs::File::open(&out).unwrap();
        let gz = flate2::read::GzDecoder::new(f);
        let mut t = tar::Archive::new(gz);
        let names: Vec<String> = t
            .entries()
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path().unwrap().display().to_string())
            .collect();
        assert!(names.iter().any(|n| n.contains("x.webp")));
    }

    #[test]
    fn tar_sources_handles_file_and_dir_sources_in_one_list() {
                                                                                                        
                                                                                                        
                                                                                                       
                                                                                                        
                                                                                                       
        let base = tempfile::tempdir().expect("base");
        std::fs::create_dir_all(base.path().join("secrets")).unwrap();
        std::fs::write(base.path().join("secrets/ca.key"), b"keydata").unwrap();
        std::fs::write(base.path().join("ca.crt"), b"certdata").unwrap();
        let out = base.path().join("out.tar.gz");
        tar_sources(base.path(), &srcs(&["secrets", "ca.crt"]), &out).expect("tar");
        let f = std::fs::File::open(&out).unwrap();
        let gz = flate2::read::GzDecoder::new(f);
        let mut t = tar::Archive::new(gz);
        let names: Vec<String> = t
            .entries()
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path().unwrap().display().to_string())
            .collect();
        assert!(
            names.iter().any(|n| n == "ca.crt"),
            "a FILE source is a top-level entry; entries: {names:?}"
        );
        assert!(
            names.iter().any(|n| n.contains("secrets/ca.key")),
            "a DIR source is recursed; entries: {names:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn tar_sources_creates_archive_at_mode_0600_from_syscall() {
                                                                              
                                                                           
                                                                             
                                                                             
                                                                  
        use std::os::unix::fs::MetadataExt;
        let base = tempfile::tempdir().expect("base");
        std::fs::create_dir_all(base.path().join("images")).unwrap();
        std::fs::write(base.path().join("images/x.webp"), b"hello").unwrap();
        let out = base.path().join("out.tar.gz");
        tar_sources(base.path(), &srcs(&["images"]), &out).expect("tar");
        let mode = std::fs::metadata(&out).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600, "tar.gz must be created with mode 0600");
    }

    #[test]
    fn parse_config_reads_sources_and_vacuum_skips_comments() {
        let cfg = parse_config("# a comment\n\nvacuum recipes.db\nsource images\nsource ca.crt\n")
            .expect("valid config parses");
        assert_eq!(cfg.vacuum.as_deref(), Some("recipes.db"));
        assert_eq!(
            cfg.sources,
            vec!["images".to_string(), "ca.crt".to_string()]
        );
    }

    #[test]
    fn parse_config_allows_no_vacuum() {
                                                                                                           
        let cfg = parse_config("source widget\n").expect("parses");
        assert_eq!(cfg.vacuum, None);
        assert_eq!(cfg.sources, vec!["widget".to_string()]);
    }

    #[test]
    fn parse_config_fails_closed_on_unknown_directive() {
        assert!(
            parse_config("delete /etc\n").is_err(),
            "unknown directive must fail closed"
        );
    }

    #[test]
    fn parse_config_rejects_traversal_and_absolute_paths() {
                                                                                                       
                                                                         
        assert!(
            parse_config("source ../../etc\n").is_err(),
            "`..` source must be refused"
        );
        assert!(
            parse_config("source /etc\n").is_err(),
            "absolute source must be refused"
        );
        assert!(
            parse_config("vacuum ../x.db\n").is_err(),
            "`..` vacuum must be refused"
        );
    }

    #[test]
    fn is_safe_relative_accepts_clean_rejects_escapes() {
        for ok in ["images", "shopping-lists", "secrets/sub", "ca.crt"] {
            assert!(is_safe_relative(ok), "{ok:?} should be safe");
        }
        for bad in ["", "/etc", "../escape", "a/../b", "secrets/../.."] {
            assert!(!is_safe_relative(bad), "{bad:?} must be rejected");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn backup_sqlite_round_trip_with_mode_0600() {
        let base = tempfile::tempdir().expect("base");
        let src_db = base.path().join("recipes.db");

                                 
        let seed_opts = SqliteConnectOptions::new()
            .filename(&src_db)
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(seed_opts)
            .await
            .unwrap();
        sqlx::query("CREATE TABLE t (x INTEGER)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO t (x) VALUES (1)")
            .execute(&pool)
            .await
            .unwrap();
        drop(pool);

        let dst = base.path().join("db-backup.sqlite");
        backup_sqlite(&src_db, &dst).await.expect("backup");
        set_mode_0600(&dst).expect("chmod");
        assert!(dst.exists());

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let mode = std::fs::metadata(&dst).unwrap().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

                                                                 
        let opts = SqliteConnectOptions::new().filename(&dst);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        let row: i64 = sqlx::query_scalar("SELECT x FROM t LIMIT 1")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(row, 1);
    }
}

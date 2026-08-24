//! The §5.3 validators — all whitelist-shaped (accept-iff-in-allowed-set, NEVER a blocklist of
                                     
                                  
//! forbidden bytes): the argv-literal / path-token charset,
//! the env-key charset + forbidden-name set, the uid checks, the
//! `setuidgid { user }` name, and the backup-source traversal reject (§5.1g).
//!
                      
//! These are pure functions over already-parsed fields; the `ValidatedManifest`
//! gate (A.4) runs them across the whole manifest, and the renderer never sees an un-validated
//! manifest. The symlink-escape / canonicalize-and-prefix check is a BAKE-time check against the real
//! staging tree (image-builder), not here — these are the lexical + charset + identity
//! checks that need no filesystem.

use std::fmt;

use crate::manifest::{Identity, StagedFile};

/// A manifest validation failure (§5.3). Each variant names a refused fail-closed class; the bake
/// REFUSES on any of these (§9 carries a negative fixture per class).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
              
    /// A literal argv / path token carried a byte outside the allowed charset (§5.3).
    ArgvCharset { token: String, byte: u8 },
    /// A path token contained a `..` component (§5.3 / §5.1g traversal-reject).
    PathTraversal { path: String },
    /// A backup source path was absolute (must be relative under the tenant data root, §5.1g).
    PathAbsolute { path: String },
              
    /// An env KEY was not a POSIX env name `[A-Z_][A-Z0-9_]*` (§5.3).
    EnvKeyCharset { key: String },
              
    /// An env KEY was a loader/shell-trusted reserved name (`LD_*`, `PATH`, `IFS` — §5.3).
    EnvKeyForbidden { key: String },
              
    /// An env VALUE contained NUL or newline (§5.3).
    EnvValueControl { key: String },
              
    /// A tenant uid was 0 (root) — a service at uid 0 defeats the privilege-drop model (§5.3).
    UidRoot,
              
    /// A tenant uid collided with an OS-fixed identity (§5.3).
    UidCollision { uid: u32 },
              
    /// A `setuidgid { user }` named root / a uid-0 identity (a drop-to-root is not a drop).
    SetuidUserRoot { user: String },
              
    /// A `setuidgid { user }` named an identity not in the baked passwd (fail at BAKE).
    SetuidUserUnknown { user: String },
    /// A tenant identity NAME collided with an OS-fixed name OR a prior tenant name — the name-axis
                       
    /// twin of the uid check. A duplicate name → a duplicate `/etc/passwd` row AND a
    /// `setuidgid` that resolves to the FIRST (OS) uid, not the tenant's → identity/privilege aliasing.
    IdentityNameCollision { name: String },
    /// A service/boot-hook `setuidgid { envdir }` named a directory other than the manifest's single
                       
    /// declared `env.envdir`. The bake WRITES the envdir from `env.envdir` but each
    /// service READS from its own `setuidgid.envdir`; a divergence is a split-brain — the service would
    /// `s6-envdir` a directory the bake never populated → an empty environment → a crash-loop. Refused
    /// at bake so the envdir is single-source by construction (the two declarations must agree).
    EnvdirMismatch { declared: String, found: String },
    /// A `resource_domain.delegate_uid` passed [`validate_uid`] (non-zero, OS-disjoint) but is not one
    /// of the manifest's declared tenant identities — the delegated `work/` cgroup would be owned by a
    /// uid with no `/etc/passwd` row (§4.1a).
    ResourceDomainDelegateUidUnknown { uid: u32 },
    /// A `resource_domain` engine/orchestrator named a service that does not exist (§4.1a — named
    /// services MUST exist).
    ResourceDomainServiceUnknown { service: String },
    /// A `resource_domain` engine/orchestrator named a service that is not an `Exec` longrun (§4.1a —
    /// it must be an Exec that carries the placement prologue and runs as the delegate identity).
    ResourceDomainServiceNotExec { service: String },
    /// A `resource_domain` engine/orchestrator service does not `setuidgid`-drop to `delegate_uid`
    /// (R1-L3) — the identity that runs in the leaf must be the one that owns the delegated cgroup.
    ResourceDomainServiceUidMismatch { service: String },
    /// A `resource_domain.name` is not a safe cgroup-path component. It becomes `<name>` in box-init's
    /// `/sys/fs/cgroup/<name>` `Path::join` + `mkdir`, so it is checked against a strict ALLOWLIST (R2-L1
    /// / R3-L1 / R4-I1): a bounded `[A-Za-z0-9_-]` run with an alnum/`_` start. That rejects by
    /// construction `/` (escape), `.`/`..` and any `.`-bearing kernel interface-file collision
    /// (`cgroup.procs`, `cpu.stat`, `memory.*`, …), a leading `-`/`+`, and overflow — without enumerating
                                         
    /// them (a reject-list here was asymptotic).
    CgroupName { name: String },
    /// A `resource_domain`'s budget numbers are internally incoherent (R3-M1) — e.g. `memory_max` (Σ) = 0,
    /// an `engine.memory_max ≥ Σ` (the engine cap would never bite before the aggregate → the F10
    /// per-leaf localization silently inverts), `job_memory_max > Σ`, or reservations summing past Σ.
    ResourceDomainIncoherentBudget { detail: String },
    /// A `resource_domain` declared the SAME service as both `engine.service` and `work.orchestrator`
    /// (I-4). The renderer's `dha_leaf_cgroup` resolves a name to the engine leaf FIRST, so an aliased
    /// pair silently collapses both leaves onto `creatine` and leaves `work/orch` hosting no service.
    /// The engine and orchestrator must be distinct services.
    ResourceDomainLeafAliased { service: String },
    /// A service `setuidgid`-drops to `delegate_uid` but is NEITHER `engine.service` NOR
                
    /// `work.orchestrator`. The renderer places ONLY the two leaves into a cgroup; any other
    /// delegate-uid service renders no placement prologue → it runs UNCAPPED in the root cgroup,
    /// escaping the root-owned `dha/memory.max=Σ` ceiling by construction. Refused at the gate so every
    /// service that runs as the tenant identity is a placed, Σ-bounded leaf.
    ResourceDomainUnplacedDelegateService { service: String },
    /// A per-file `owner` (spec D7, per-uid rootfs baking) named an identity not in the manifest
    /// `[[identities]]` — the symbolic owner must resolve to exactly one declared tenant identity, else
    /// the baked file owner and the `s6-setuidgid`/`delegate_uid` uid could name different numbers →
    /// the dropped reader is a non-owner → EACCES → rescue. Fail-closed at resolve (never a default 0:0).
    OwnerIdentityUnknown { name: String },
    /// The dha config blocks are asymmetric/incomplete (§4.3, audit R1-LOW): `box_config` +
    /// `runtime_config` must be declared TOGETHER (a dha box has both — the orchestrator loads both as
    /// its `argv`), and their presence requires a `resource_domain` (the render derives `parent_cgroup` +
    /// the per-job budget from it). A partial set otherwise fails LATE — a `box_config` without a
    /// `runtime_config` renders NOTHING silently; a missing `resource_domain` errors at bake — so the gate
    /// names it at parse instead.
    DhaConfigIncomplete { detail: String },
    /// V1: a `[[staged_files]]` target is malformed — not absolute, carries a `..` component,
    /// or has a trailing slash. The bake writes the file at this path on the RO rootfs, so a malformed
    /// path is refused before any staging.
    StagedTargetMalformed { target: String },
    /// V2: a staged target is not under the `/opt/<dir>/<rest…>` allowlist — it must be
    /// absolute under `/opt/` with ≥2 non-empty segments below `/opt` (so `/opt/foo` alone is refused;
    /// `/opt/dha/uds-pipe` is the shortest accepted form). Narrows the write surface to a tenant subtree
                                         
    /// of `/opt/` by construction.
    StagedTargetOutsideOpt { target: String },
    /// V3: two `[[staged_files]]` entries declare the same `target` — the second write collides
    /// with the first (the bake `create_new(true)`s, so a dup is a guaranteed bake failure; refused early).
    StagedTargetDuplicate { target: String },
    /// V4: a staged `mode` is outside the allowlist `{0o644, 0o600, 0o755}` — a setuid/setgid/
    /// sticky/world-writable or otherwise unexpected mode on a signed rootfs file is refused (an
                                         
    /// allowlist, never a reject-list of unsafe bits).
    StagedModeUnknown { mode: u32 },
    /// V7: a staged file with a symbolic `owner` also carries an exec bit (`mode & 0o111`). An
    /// `owner` denotes config DATA owned by a tenant identity; a program is root-owned `0o755` with NO
    /// owner. An owned-and-executable file is a category error — refused.
    StagedOwnerExecForbidden { target: String },
    /// V8: the `runtime_config.client.config` path is under `/opt/` but no `[[staged_files]]`
    /// entry targets it — the orchestrator would read a config the bake never staged (a dangling
    /// reference). The `/opt/` client config MUST be one of the staged files.
    DanglingClientConfig { config: String },
    /// V9: two `[[staged_files]]` entries declare the same `key` — the bake would fetch the same
    /// store artifact under conflicting targets/modes; a duplicate key is a manifest error.
    StagedKeyDuplicate { key: String },
    /// V10 (spec §4): one staged `target` is a path-ancestor of another (e.g. `/opt/dha/a` and
    /// `/opt/dha/a/b`) — the bake creates parent dirs for each file, so a file-target that is also
    /// another target's parent dir is contradictory (a path is a file XOR a directory). Refused.
    StagedTargetNested {
        ancestor: String,
        descendant: String,
    },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArgvCharset { token, byte } => {
                write!(
                    f,
                    "argv/path token {token:?} contains a disallowed byte {byte:#04x}"
                )
            }
            Self::PathTraversal { path } => write!(f, "path {path:?} contains a `..` component"),
            Self::PathAbsolute { path } => write!(f, "backup source {path:?} must be relative"),
            Self::EnvKeyCharset { key } => {
                write!(
                    f,
                    "env key {key:?} is not a POSIX env name [A-Z_][A-Z0-9_]*"
                )
            }
            Self::EnvKeyForbidden { key } => {
                write!(
                    f,
                    "env key {key:?} is a reserved loader/shell name (LD_*/PATH/IFS)"
                )
            }
            Self::EnvValueControl { key } => {
                write!(f, "env value for {key:?} contains NUL or newline")
            }
            Self::UidRoot => write!(f, "a tenant uid of 0 (root) is refused"),
            Self::UidCollision { uid } => {
                write!(f, "tenant uid {uid} collides with an OS identity")
            }
            Self::SetuidUserRoot { user } => {
                write!(
                    f,
                    "setuidgid user {user:?} is root/uid-0 (a drop-to-root is not a drop)"
                )
            }
            Self::SetuidUserUnknown { user } => {
                write!(f, "setuidgid user {user:?} is not a baked identity")
            }
            Self::IdentityNameCollision { name } => {
                write!(
                    f,
                    "tenant identity name {name:?} collides with an OS-fixed or prior tenant name"
                )
            }
            Self::OwnerIdentityUnknown { name } => {
                write!(
                    f,
                    "per-file owner {name:?} is not a declared tenant identity in [[identities]]"
                )
            }
            Self::EnvdirMismatch { declared, found } => {
                write!(
                    f,
                    "setuidgid envdir {found:?} disagrees with the declared env.envdir {declared:?} \
                     (the envdir must be single-source; the bake populates only env.envdir)"
                )
            }
            Self::ResourceDomainDelegateUidUnknown { uid } => {
                write!(
                    f,
                    "resource_domain delegate_uid {uid} is not a declared tenant identity"
                )
            }
            Self::ResourceDomainServiceUnknown { service } => {
                write!(
                    f,
                    "resource_domain names service {service:?} which does not exist"
                )
            }
            Self::ResourceDomainServiceNotExec { service } => {
                write!(
                    f,
                    "resource_domain service {service:?} is not an Exec longrun"
                )
            }
            Self::ResourceDomainServiceUidMismatch { service } => {
                write!(
                    f,
                    "resource_domain service {service:?} does not setuidgid-drop to delegate_uid"
                )
            }
            Self::ResourceDomainLeafAliased { service } => {
                write!(
                    f,
                    "resource_domain engine.service and work.orchestrator are the same service \
                     {service:?} (the two leaves must be distinct)"
                )
            }
            Self::ResourceDomainUnplacedDelegateService { service } => {
                write!(
                    f,
                    "resource_domain service {service:?} drops to delegate_uid but is neither the \
                     engine nor the orchestrator leaf — it would run uncapped outside the Σ ceiling"
                )
            }
            Self::CgroupName { name } => {
                write!(
                    f,
                    "resource_domain name {name:?} is not a safe cgroup component \
                     (allowlist: an alnum/`_` start then `[A-Za-z0-9_-]`, ≤64 bytes)"
                )
            }
            Self::ResourceDomainIncoherentBudget { detail } => {
                write!(f, "resource_domain budget is incoherent: {detail}")
            }
            Self::DhaConfigIncomplete { detail } => {
                write!(f, "dha config blocks are incomplete: {detail}")
            }
            Self::StagedTargetMalformed { target } => {
                write!(
                    f,
                    "staged target {target:?} is malformed (must be absolute, no `..`, no trailing slash)"
                )
            }
            Self::StagedTargetOutsideOpt { target } => {
                write!(
                    f,
                    "staged target {target:?} is not under /opt/<dir>/<rest…> (≥2 segments below /opt)"
                )
            }
            Self::StagedTargetDuplicate { target } => {
                write!(f, "two staged files declare the same target {target:?}")
            }
            Self::StagedModeUnknown { mode } => {
                write!(
                    f,
                    "staged mode {mode:#o} is not one of the allowed {{0o644, 0o600, 0o755}}"
                )
            }
            Self::StagedOwnerExecForbidden { target } => {
                write!(
                    f,
                    "staged file {target:?} has an owner AND an exec bit (an owned file is config data, not a program)"
                )
            }
            Self::DanglingClientConfig { config } => {
                write!(
                    f,
                    "runtime_config.client.config {config:?} is under /opt/ but no staged_files entry targets it"
                )
            }
            Self::StagedKeyDuplicate { key } => {
                write!(f, "two staged files declare the same key {key:?}")
            }
            Self::StagedTargetNested {
                ancestor,
                descendant,
            } => {
                write!(
                    f,
                    "staged target {ancestor:?} is a path-ancestor of {descendant:?} (a target cannot be both a file and another target's parent dir)"
                )
            }
        }
    }
}

impl std::error::Error for ValidationError {}

          
/// The allowed charset for a literal argv / path token (§5.3): the closed set sufficient for a
/// `/bin/sh` word position — ASCII alphanumerics + `._/:@=+-`. EXCLUDES whitespace, every shell-special
/// byte (`; | & $ ( ) < > * ? [ ] { } ~ ! # \ ' "` backtick), newline, and NUL. Whitelist-shaped.
fn is_argv_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b':' | b'@' | b'=' | b'+' | b'-')
}

          
/// Validate a literal argv token (§5.3): accept IFF every byte is in the argv charset. An empty
/// token is allowed (an inert empty shell word); the security property is the absence of metacharacters.
pub fn validate_argv_literal(token: &str) -> Result<(), ValidationError> {
    match token.bytes().find(|&b| !is_argv_byte(b)) {
        Some(byte) => Err(ValidationError::ArgvCharset {
            token: token.to_string(),
            byte,
        }),
        None => Ok(()),
    }
}

/// Validate a path-bearing token (binary path, ca-file, cert path, envdir): the argv charset (so it
/// carries no shell metacharacter when it lands in a run-script / config word) AND no `..` component
/// (no traversal). Absolute paths are allowed here (unlike backup sources).
pub fn validate_path_token(path: &str) -> Result<(), ValidationError> {
                                                                                           
    validate_argv_literal(path)?;
    if path.split('/').any(|c| c == "..") {
        return Err(ValidationError::PathTraversal {
            path: path.to_string(),
        });
    }
    Ok(())
}

/// Validate a `resource_domain.name` as a SINGLE safe cgroup-path component. It becomes the `<name>` in
/// box-init's `/sys/fs/cgroup/<name>` `Path::join` + `mkdir` target, so it is checked against a strict
                                                            
/// ALLOWLIST (NOT a reject-list): a bounded
/// run of `[A-Za-z0-9_-]` that starts with an alnum or `_`. That rejects BY CONSTRUCTION every unsafe
/// shape the old reject-list chased asymptotically — `/` (a `Path::join`-escape / multi-segment), `.`/`..`
/// and any `.`-bearing kernel interface-file name (`cgroup.procs`, `cpu.stat`, `memory.*`, … → a `mkdir`
/// collision), a leading `-`/`+` (option-injection into a downstream tool), whitespace / shell
/// metacharacters — plus an upper length bound. Stricter than `validate_path_token` (which permits `/`,
/// `.`, and absolute paths).
pub fn validate_cgroup_name(name: &str) -> Result<(), ValidationError> {
                                                                                                     
    const MAX_LEN: usize = 64;
    let mut bytes = name.bytes();
    let first_ok = matches!(bytes.next(), Some(b) if b.is_ascii_alphanumeric() || b == b'_');
    let rest_ok = bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if name.is_empty() || name.len() > MAX_LEN || !(first_ok && rest_ok) {
        return Err(ValidationError::CgroupName {
            name: name.to_string(),
        });
    }
    Ok(())
}

/// Validate a backup SOURCE path (§5.1g): relative (NOT absolute) + no `..` component + charset-clean.
/// The bake-time canonicalize-and-prefix check (against the real data root) is in image-builder.
pub fn validate_relative_path(path: &str) -> Result<(), ValidationError> {
    if path.starts_with('/') {
        return Err(ValidationError::PathAbsolute {
            path: path.to_string(),
        });
    }
    validate_path_token(path)
}

          
/// Validate an env var KEY (§5.3): POSIX env-name charset `[A-Z_][A-Z0-9_]*` (so it cannot
/// escape the envdir filename `etc/<app>/env/<key>` — no `/`, no `.`, no `..`) AND not in the
/// forbidden loader/shell-trusted set.
pub fn validate_env_key(key: &str) -> Result<(), ValidationError> {
    let mut bytes = key.bytes();
    let first_ok = matches!(bytes.next(), Some(b) if b.is_ascii_uppercase() || b == b'_');
    let rest_ok = bytes.all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    if !(first_ok && rest_ok) {
        return Err(ValidationError::EnvKeyCharset {
            key: key.to_string(),
        });
    }
    if is_forbidden_env_name(key) {
        return Err(ValidationError::EnvKeyForbidden {
            key: key.to_string(),
        });
    }
    Ok(())
}

          
/// The renderer-owned forbidden env-name set (§5.3): loader + shell-trusted names a tenant must
/// not override. A blocklist is CORRECT here (the safe-name space is open — the tenant legitimately
/// needs arbitrary `DATA_DIR`-style names — so "names the OS reserves" cannot be whitelisted; R2-F5).
fn is_forbidden_env_name(key: &str) -> bool {
    key.starts_with("LD_") || matches!(key, "PATH" | "IFS")
}

          
/// Validate an env VALUE (§5.3): s6-envdir reads it as literal file content (no shell parse),
/// so it needs no charset restriction — but it MUST reject NUL + newline (one var per file; a newline
/// could split into a spurious second var under some writers).
pub fn validate_env_value(key: &str, value: &str) -> Result<(), ValidationError> {
    if value.bytes().any(|b| b == 0 || b == b'\n') {
        return Err(ValidationError::EnvValueControl {
            key: key.to_string(),
        });
    }
    Ok(())
}

          
/// Validate a tenant uid (§5.3): non-zero AND disjoint from the OS-fixed identity set (the
/// reserved set is DERIVED from the OS PASSWD/GROUP source of truth — passed in by image-builder —
/// not re-enumerated here).
pub fn validate_uid(uid: u32, os_fixed_uids: &[u32]) -> Result<(), ValidationError> {
    if uid == 0 {
        return Err(ValidationError::UidRoot);
    }
    if os_fixed_uids.contains(&uid) {
        return Err(ValidationError::UidCollision { uid });
    }
    Ok(())
}

          
/// Validate a `setuidgid { user }` NAME (§5.3): it MUST resolve in the baked passwd
/// (`baked_identities`: name → uid, OS-fixed ∪ tenant) to a NON-root identity. `root` / a uid-0
/// identity is refused (a drop-to-root is not a drop); an unbaked user is refused AT BAKE (never
/// deferred to a runtime `s6-setuidgid` failure).
pub fn validate_setuid_user(
    user: &str,
    baked_identities: &[(String, u32)],
) -> Result<(), ValidationError> {
    if user == "root" {
        return Err(ValidationError::SetuidUserRoot {
            user: user.to_string(),
        });
    }
    match baked_identities.iter().find(|(name, _)| name == user) {
        None => Err(ValidationError::SetuidUserUnknown {
            user: user.to_string(),
        }),
        Some((_, 0)) => Err(ValidationError::SetuidUserRoot {
            user: user.to_string(),
        }),
        Some(_) => Ok(()),
    }
}

/// Resolve a symbolic per-file `owner` NAME to its uid via the manifest `[[identities]]` (spec D7 — the
/// per-uid rootfs-baking owner declaration is a NAME, never a raw uid, so a typo can't diverge the baked
/// owner from the `s6-setuidgid`/`delegate_uid` uid). Fail-closed EXACTLY-ONE: zero matches is an unknown
/// owner (`OwnerIdentityUnknown`, D7); two-or-more is a duplicate row (`IdentityNameCollision`) that would
/// alias the baked owner. The single-source guarantee — config-owner resolution and
/// `ResourceDomain.delegate_uid` name the SAME uid — rests on this; `parse_and_validate` already forbids
/// duplicate tenant names at parse, so the duplicate arm is a self-contained belt (safe on un-gated input).
pub fn resolve_owner(name: &str, identities: &[Identity]) -> Result<u32, ValidationError> {
    let mut matches = identities.iter().filter(|id| id.name == name);
    let uid = matches
        .next()
        .ok_or_else(|| ValidationError::OwnerIdentityUnknown {
            name: name.to_string(),
        })?
        .uid;
    if matches.next().is_some() {
        return Err(ValidationError::IdentityNameCollision {
            name: name.to_string(),
        });
    }
    Ok(uid)
}

/// Validate a `[[staged_files]]` target path (rules V1/V2) — the write-surface allowlist. V1: the path
/// must be ABSOLUTE, carry no `..` component, and have no trailing slash. V2: it must live under
/// `/opt/<dir>/<rest…>` — ≥2 non-empty segments below `/opt`, none `.`/`..`/empty (so `/opt/foo` alone is
/// refused; `/opt/dha/uds-pipe` is the shortest accepted form; a `//` empty segment is caught).
/// Whitelist-shaped: the accepted grammar is enumerated, not a reject-list of unsafe shapes
                                     
fn validate_staged_target(target: &str) -> Result<(), ValidationError> {
                                                                             
    if !target.starts_with('/') || target.ends_with('/') || target.split('/').any(|c| c == "..") {
        return Err(ValidationError::StagedTargetMalformed {
            target: target.to_string(),
        });
    }
                                                                                                            
                                                                                
    let outside = || ValidationError::StagedTargetOutsideOpt {
        target: target.to_string(),
    };
    let rest = target.strip_prefix("/opt/").ok_or_else(outside)?;
    let segments: Vec<&str> = rest.split('/').collect();
    let well_formed = segments.len() >= 2
        && segments
            .iter()
            .all(|s| !s.is_empty() && *s != "." && *s != "..");
    if !well_formed {
        return Err(outside());
    }
    Ok(())
}

/// Validate a `[[staged_files]]` mode (rule V4): exactly one of the allowlist `{0o644, 0o600, 0o755}`
/// — the config-read / private-config / program-exec triad. An allowlist (never a reject-list of setuid/
/// world-writable/… bits): an unexpected mode on a signed rootfs file is refused by construction.
fn validate_staged_mode(mode: u32) -> Result<(), ValidationError> {
    match mode {
        0o644 | 0o600 | 0o755 => Ok(()),
        _ => Err(ValidationError::StagedModeUnknown { mode }),
    }
}

/// Is `ancestor` a strict, component-aligned path-ancestor of `descendant` (spec §4 V10)? True iff
/// `descendant` == `ancestor` + `/` + more: `/opt/dha/a` is an ancestor of `/opt/dha/a/b` but NOT of
/// `/opt/dha/ab` (the required trailing `/` keeps the match component-aligned — no partial-name FP).
fn is_path_ancestor(ancestor: &str, descendant: &str) -> bool {
    descendant
        .strip_prefix(ancestor)
        .is_some_and(|rest| rest.starts_with('/'))
}

/// Validate the `[[staged_files]]` block — the per-entry grammar/mode/owner rules
/// (V1/V2/V4/V6/V7) + the cross-entry key/target/nesting locks (V9/V3/V10) + the client-config↔target
/// coherence (V8). `identities` is the manifest's tenant identity set (for V6 owner resolution);
/// `client_config` is `runtime_config.client.config` when present (for V8). An empty `staged` slice (a
        
/// non-staging toy/recipes manifest) is vacuously Ok — nothing is staged. V5 (kind/exec coherence)
/// + V11 (S_IFREG) are BAKE-time checks (image-builder, Task 3), not here.
pub fn validate_staged_files(
    staged: &[StagedFile],
    identities: &[Identity],
    client_config: Option<&str>,
) -> Result<(), ValidationError> {
                                                                                                           
    for entry in staged {
        validate_staged_target(&entry.target)?;
        validate_staged_mode(entry.mode)?;
        if let Some(owner) = &entry.owner {
                                                                                                 
                                                                                                          
            resolve_owner(owner, identities)?;
                                                                              
            if entry.mode & 0o111 != 0 {
                return Err(ValidationError::StagedOwnerExecForbidden {
                    target: entry.target.clone(),
                });
            }
        }
    }
                                                                                                          
                                          
    for (i, a) in staged.iter().enumerate() {
        for b in &staged[i + 1..] {
            if a.key == b.key {
                return Err(ValidationError::StagedKeyDuplicate { key: a.key.clone() });
            }
            if a.target == b.target {
                return Err(ValidationError::StagedTargetDuplicate {
                    target: a.target.clone(),
                });
            }
            if is_path_ancestor(&a.target, &b.target) {
                return Err(ValidationError::StagedTargetNested {
                    ancestor: a.target.clone(),
                    descendant: b.target.clone(),
                });
            }
            if is_path_ancestor(&b.target, &a.target) {
                return Err(ValidationError::StagedTargetNested {
                    ancestor: b.target.clone(),
                    descendant: a.target.clone(),
                });
            }
        }
    }
                                                                                                    
                                                                                                          
                                                                                                         
                      
    if let Some(cfg) = client_config
        && cfg.starts_with("/opt/")
        && !staged.iter().any(|s| s.target == cfg)
    {
        return Err(ValidationError::DanglingClientConfig {
            config: cfg.to_string(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

                                             

    #[test]
    fn argv_literal_accepts_clean_tokens() {
        for ok in [
            "renew",
            "--domain",
            "/persist/acme/full.pem",
            "a.b_c-d:e@f=g+h",
            "",
        ] {
            assert!(
                validate_argv_literal(ok).is_ok(),
                "{ok:?} should be allowed"
            );
        }
    }

    #[test]
    fn argv_literal_rejects_every_shell_metacharacter_class() {
                                                                          
        for bad in [
            "foo; rm -rf /",
            "x$(reboot)",
            "a`reboot`",
            "a|b",
            "a&b",
            "a b",                              
            "a\nb",           
            "a\0b",       
            "*",           
            "a?b",
            "a>b",
            "a<b",
            "a'b",
            "a\"b",
            "a{b}",
            "a~b",
            "a#b",
            "a\\b",
        ] {
            assert!(
                matches!(
                    validate_argv_literal(bad),
                    Err(ValidationError::ArgvCharset { .. })
                ),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn path_token_rejects_dotdot_even_though_charset_allows_dot() {
                                                                                                          
        assert!(validate_argv_literal("/foo/../bar").is_ok());                           
        assert!(matches!(
            validate_path_token("/foo/../bar"),
            Err(ValidationError::PathTraversal { .. })
        ));
        assert!(validate_path_token("/persist/recipes/ca.crt").is_ok());
    }

    #[test]
    fn relative_path_rejects_absolute_and_traversal() {
        assert!(matches!(
            validate_relative_path("/etc/passwd"),
            Err(ValidationError::PathAbsolute { .. })
        ));
        assert!(matches!(
            validate_relative_path("../../etc"),
            Err(ValidationError::PathTraversal { .. })
        ));
        assert!(validate_relative_path("recipes/images").is_ok());
    }

                                         

    #[test]
    fn env_key_accepts_posix_names() {
        for ok in ["DATA_DIR", "PUBLIC_URL", "_X", "A1_B2"] {
            assert!(validate_env_key(ok).is_ok(), "{ok:?} should be allowed");
        }
    }

    #[test]
    fn env_key_rejects_traversal_and_lowercase_and_separators() {
        for bad in ["../escape", "a/b", "data_dir", "1ABC", "A.B", "A-B"] {
            assert!(
                matches!(
                    validate_env_key(bad),
                    Err(ValidationError::EnvKeyCharset { .. })
                ),
                "{bad:?} must be refused on charset"
            );
        }
    }

    #[test]
    fn env_key_rejects_loader_and_shell_trusted_names() {
        for bad in ["LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "PATH", "IFS"] {
            assert!(
                matches!(
                    validate_env_key(bad),
                    Err(ValidationError::EnvKeyForbidden { .. })
                ),
                "{bad:?} must be refused as forbidden"
            );
        }
    }

    #[test]
    fn env_value_rejects_nul_and_newline() {
        assert!(validate_env_value("K", "a normal value").is_ok());
        assert!(matches!(
            validate_env_value("K", "a\nb"),
            Err(ValidationError::EnvValueControl { .. })
        ));
        assert!(matches!(
            validate_env_value("K", "a\0b"),
            Err(ValidationError::EnvValueControl { .. })
        ));
    }

                             

    #[test]
    fn uid_rejects_zero_and_collision_accepts_disjoint() {
        let os_fixed = [101u32, 102, 103, 104, 105];                            
        assert!(matches!(
            validate_uid(0, &os_fixed),
            Err(ValidationError::UidRoot)
        ));
        assert!(matches!(
            validate_uid(104, &os_fixed),
            Err(ValidationError::UidCollision { uid: 104 })
        ));
        assert!(validate_uid(100, &os_fixed).is_ok());                                      
    }

                                        

    #[test]
    fn setuid_user_rejects_root_and_unknown_accepts_baked_nonroot() {
        let baked = vec![
            ("root".to_string(), 0u32),
            ("recipes".to_string(), 100),
            ("fb-acme".to_string(), 101),
        ];
        assert!(matches!(
            validate_setuid_user("root", &baked),
            Err(ValidationError::SetuidUserRoot { .. })
        ));
        assert!(matches!(
            validate_setuid_user("nobody", &baked),
            Err(ValidationError::SetuidUserUnknown { .. })
        ));
        assert!(validate_setuid_user("recipes", &baked).is_ok());
        assert!(validate_setuid_user("fb-acme", &baked).is_ok());
    }

    #[test]
    fn setuid_user_rejects_a_nonroot_named_alias_of_uid_zero() {
                                                                                    
        let baked = vec![("superuser".to_string(), 0u32)];
        assert!(matches!(
            validate_setuid_user("superuser", &baked),
            Err(ValidationError::SetuidUserRoot { .. })
        ));
    }

                                                                        

    #[test]
    fn resolve_owner_maps_symbolic_name_to_uid() {
        let ids = [
            Identity {
                name: "recipes".to_string(),
                uid: 4000,
            },
            Identity {
                name: "dha".to_string(),
                uid: 5000,
            },
        ];
        assert_eq!(resolve_owner("dha", &ids).unwrap(), 5000);
    }

    #[test]
    fn resolve_owner_rejects_an_unknown_name() {
        let ids = [Identity {
            name: "dha".to_string(),
            uid: 5000,
        }];
        assert!(matches!(
            resolve_owner("ghost", &ids),
            Err(ValidationError::OwnerIdentityUnknown { .. })
        ));
    }

    #[test]
    fn resolve_owner_rejects_a_duplicate_name() {
                                                                                                      
                                                                                        
                                                                                             
        let ids = [
            Identity {
                name: "dha".to_string(),
                uid: 5000,
            },
            Identity {
                name: "dha".to_string(),
                uid: 6000,
            },
        ];
        assert!(matches!(
            resolve_owner("dha", &ids),
            Err(ValidationError::IdentityNameCollision { .. })
        ));
    }

                                                                                           

    #[test]
    fn cgroup_name_allowlists_safe_components() {
        for ok in ["dha", "dha-1", "dha_engine", "A0", "_x", "x"] {
            assert!(validate_cgroup_name(ok).is_ok(), "{ok:?} should be allowed");
        }
    }

    #[test]
    fn cgroup_name_rejects_escapes_collisions_and_overflow() {
        for bad in [
            "",          
            ".",             
            "..",
            "/run/evil",                             
            "dha/sub",                      
            "cgroup.procs",                                                  
            "cpu.stat",                                                               
            "memory.stat",
            "io.pressure",
            "-x",                         
            "+memory",                    
            "dha; rm",                       
            "a b",                  
            "dhä",                 
        ] {
            assert!(
                matches!(
                    validate_cgroup_name(bad),
                    Err(ValidationError::CgroupName { .. })
                ),
                "{bad:?} must be refused"
            );
        }
                                                     
        assert!(matches!(
            validate_cgroup_name(&"x".repeat(65)),
            Err(ValidationError::CgroupName { .. })
        ));
    }

                                                                                                          

    fn sf(key: &str, target: &str, mode: u32, owner: Option<&str>) -> StagedFile {
        StagedFile {
            key: key.into(),
            target: target.into(),
            mode,
            owner: owner.map(Into::into),
        }
    }

    fn dha_ids() -> Vec<Identity> {
        vec![Identity {
            name: "dha".into(),
            uid: 110,
        }]
    }

    #[test]
    fn staged_v1_rejects_malformed_targets() {
                                                                   
        for bad in ["opt/dha/x", "/opt/dha/../x", "/opt/dha/x/"] {
            assert!(
                matches!(
                    validate_staged_files(&[sf("k", bad, 0o755, None)], &[], None),
                    Err(ValidationError::StagedTargetMalformed { .. })
                ),
                "{bad:?} must be StagedTargetMalformed"
            );
        }
    }

    #[test]
    fn staged_v2_rejects_outside_opt_and_enforces_the_two_segment_boundary() {
                                                                                                       
        for bad in ["/etc/dha/x", "/opt/foo", "/opt", "/opt/dha//x"] {
            assert!(
                matches!(
                    validate_staged_files(&[sf("k", bad, 0o755, None)], &[], None),
                    Err(ValidationError::StagedTargetOutsideOpt { .. })
                ),
                "{bad:?} must be StagedTargetOutsideOpt"
            );
        }
                                                                                                       
        assert!(
            validate_staged_files(&[sf("k", "/opt/dha/uds-pipe", 0o755, None)], &[], None).is_ok()
        );
        assert!(validate_staged_files(&[sf("k", "/opt/dha/a/b", 0o755, None)], &[], None).is_ok());
    }

    #[test]
    fn staged_v4_mode_allowlist() {
        for ok in [0o644, 0o600, 0o755] {
            assert!(
                validate_staged_files(&[sf("k", "/opt/dha/x", ok, None)], &[], None).is_ok(),
                "{ok:o} should be allowed"
            );
        }
                                                                                                
        for bad in [0o777, 0o700, 0o666, 0o400, 0o4755] {
            assert!(
                matches!(
                    validate_staged_files(&[sf("k", "/opt/dha/x", bad, None)], &[], None),
                    Err(ValidationError::StagedModeUnknown { .. })
                ),
                "{bad:o} must be StagedModeUnknown"
            );
        }
    }

    #[test]
    fn staged_v3_rejects_a_duplicate_target() {
        let r = validate_staged_files(
            &[
                sf("a", "/opt/dha/x", 0o755, None),
                sf("b", "/opt/dha/x", 0o644, None),
            ],
            &[],
            None,
        );
        assert!(
            matches!(r, Err(ValidationError::StagedTargetDuplicate { .. })),
            "{r:?}"
        );
    }

    #[test]
    fn staged_v9_rejects_a_duplicate_key() {
        let r = validate_staged_files(
            &[
                sf("k", "/opt/dha/x", 0o755, None),
                sf("k", "/opt/dha/y", 0o644, None),
            ],
            &[],
            None,
        );
        assert!(
            matches!(r, Err(ValidationError::StagedKeyDuplicate { .. })),
            "{r:?}"
        );
    }

    #[test]
    fn staged_v10_rejects_a_nested_target_in_either_order() {
                                                                                                          
                                                                         
        let ancestor_first = validate_staged_files(
            &[
                sf("a", "/opt/dha/sub", 0o755, None),
                sf("b", "/opt/dha/sub/file", 0o644, None),
            ],
            &[],
            None,
        );
        assert!(
            matches!(
                ancestor_first,
                Err(ValidationError::StagedTargetNested { .. })
            ),
            "{ancestor_first:?}"
        );
        let descendant_first = validate_staged_files(
            &[
                sf("b", "/opt/dha/sub/file", 0o644, None),
                sf("a", "/opt/dha/sub", 0o755, None),
            ],
            &[],
            None,
        );
        assert!(
            matches!(
                descendant_first,
                Err(ValidationError::StagedTargetNested { .. })
            ),
            "{descendant_first:?}"
        );
                                                                                                    
        assert!(
            validate_staged_files(
                &[
                    sf("a", "/opt/dha/sub", 0o755, None),
                    sf("b", "/opt/dha/subtle", 0o644, None),
                ],
                &[],
                None,
            )
            .is_ok()
        );
    }

    #[test]
    fn staged_v7_rejects_an_owned_executable() {
                                                                                                   
        let r = validate_staged_files(
            &[sf("k", "/opt/dha/epa.json", 0o755, Some("dha"))],
            &dha_ids(),
            None,
        );
        assert!(
            matches!(r, Err(ValidationError::StagedOwnerExecForbidden { .. })),
            "{r:?}"
        );
    }

    #[test]
    fn staged_v6_rejects_an_unknown_owner() {
                                                                                           
        let r = validate_staged_files(
            &[sf("k", "/opt/dha/epa.json", 0o600, Some("ghost"))],
            &dha_ids(),
            None,
        );
        assert!(
            matches!(r, Err(ValidationError::OwnerIdentityUnknown { .. })),
            "{r:?}"
        );
    }

    #[test]
    fn staged_v8_rejects_a_dangling_client_config() {
                                                                 
        let dangling = validate_staged_files(
            &[sf("k", "/opt/dha/uds-pipe", 0o755, None)],
            &dha_ids(),
            Some("/opt/dha/epa.json"),
        );
        assert!(
            matches!(dangling, Err(ValidationError::DanglingClientConfig { .. })),
            "{dangling:?}"
        );
                         
        let staged = validate_staged_files(
            &[sf("k", "/opt/dha/epa.json", 0o600, Some("dha"))],
            &dha_ids(),
            Some("/opt/dha/epa.json"),
        );
        assert!(staged.is_ok(), "{staged:?}");
                                                                                                        
        assert!(validate_staged_files(&[], &dha_ids(), Some("/etc/dha/other.json")).is_ok());
    }

    #[test]
    fn staged_happy_path_the_five_dha_entries() {
                                                                                                   
                                                                                                         
        let entries = [
            sf("uds-pipe", "/opt/dha/uds-pipe", 0o755, None),
            sf("dha-intake-probe", "/opt/dha/intake-probe.sh", 0o644, None),
            sf(
                "dha-real-job-probe",
                "/opt/dha/real-job-probe.sh",
                0o644,
                None,
            ),
            sf(
                "dha-ac-i-selftest",
                "/opt/dha/ac-i-selftest.sh",
                0o644,
                None,
            ),
            sf("dha-epa-config", "/opt/dha/epa.json", 0o600, Some("dha")),
        ];
        let r = validate_staged_files(&entries, &dha_ids(), Some("/opt/dha/epa.json"));
        assert!(r.is_ok(), "the five dha staged files must validate: {r:?}");
    }

    #[test]
    fn staged_empty_is_ok() {
                                                                          
        assert!(validate_staged_files(&[], &[], None).is_ok());
    }
}

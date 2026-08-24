//! `fb-manifest` — the Fruit-Basket-owned service-manifest schema + fail-closed parser.
//!
//! The typed, validated TCB input describing a tenant's OS topology (spec §5 / §5.3, R7-folded),
//! on the `toml` substrate. Consumed by Orchard's image-builder (renders every output from a
//! [`ValidatedManifest`]) and Fruit Basket's box-init (parses the baked topology file at boot).
//!
//! **The fail-closed bake is a TYPE-STATE, not a convention.** A [`ValidatedManifest`] can ONLY be
//! built by [`parse_and_validate`], which parses (deny-unknown) + runs every §5.3 validator; its inner
//! [`Manifest`] is private, so the renderer cannot obtain one without passing validation (the
//! project's `HouseholdScoped<T>` DNA applied to a TCB input).
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

pub mod argv;
pub mod manifest;
pub mod topology;
pub mod validate;

use argv::{ArgvFragment, ArgvToken, KnownPlaceholder};
use manifest::{EnvFragment, Manifest, Priv, ServiceShape};
use validate::{
    ValidationError, validate_argv_literal, validate_cgroup_name, validate_env_key,
    validate_env_value, validate_path_token, validate_relative_path, validate_setuid_user,
    validate_staged_files, validate_uid,
};

/// The schema version this build of `fb-manifest` understands. A manifest declaring any other version
/// fails closed at the gate (§5.1e — the bake fails on version mismatch).
pub const SCHEMA_VERSION: u32 = 1;

/// The OS-fixed identity set — root + the OS-infra service uids (haproxy / dropbear-rescue / fb-acme /
/// fb-backup / fb-cert-check), the source of truth from image-builder's `PASSWD`/`GROUP`. The uid
          
/// validation DERIVES its reserved set from this (§5.3), so a future OS uid auto-extends the
/// exclusion; the library never hardcodes the passwd.
#[derive(Debug, Clone)]
pub struct OsIdentities {
    /// `(name, uid)` for every OS-baked row (incl. `("root", 0)`).
    pub fixed: Vec<(String, u32)>,
}

impl OsIdentities {
    fn uids(&self) -> Vec<u32> {
        self.fixed.iter().map(|(_, u)| *u).collect()
    }
}

/// A bake-time failure: a malformed, version-mismatched, or §5.3-invalid manifest is REFUSED.
#[derive(Debug)]
pub enum BakeError {
    /// `toml` rejected the input (syntax, unknown field, missing required field, duplicate key, …).
    Parse(toml::de::Error),
    /// The `schema_version` did not match [`SCHEMA_VERSION`].
    SchemaVersion { found: u32, expected: u32 },
    /// A §5.3 validator refused a field.
    Validation(ValidationError),
}

impl std::fmt::Display for BakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "manifest parse error: {e}"),
            Self::SchemaVersion { found, expected } => {
                write!(f, "manifest schema_version {found} != supported {expected}")
            }
            Self::Validation(e) => write!(f, "manifest validation error: {e}"),
        }
    }
}

impl std::error::Error for BakeError {}

/// A manifest that has passed [`parse_and_validate`] — the ONLY type the renderer accepts. The inner
/// [`Manifest`] is private: a `ValidatedManifest` cannot exist without having run every §5.3 validator,
/// so the fail-closed bake is structural, not a convention an author could forget (§5.3).
#[derive(Debug)]
pub struct ValidatedManifest(Manifest);

impl ValidatedManifest {
    /// Borrow the validated manifest for rendering. (There is no `&mut` accessor and no public
    /// constructor — a `ValidatedManifest` is immutable + validation-proven.)
    pub fn manifest(&self) -> &Manifest {
        &self.0
    }
}

/// Parse + validate a service manifest into a [`ValidatedManifest`] (the fail-closed bake gate, §5.3).
///
/// `os` is image-builder's OS-fixed identity set (the PASSWD/GROUP source of truth). Returns
/// [`BakeError`] on any parse / version / validation failure — the bake REFUSES (never best-effort).
pub fn parse_and_validate(input: &str, os: &OsIdentities) -> Result<ValidatedManifest, BakeError> {
    let m: Manifest = toml::from_str(input).map_err(BakeError::Parse)?;
    if m.schema_version != SCHEMA_VERSION {
        return Err(BakeError::SchemaVersion {
            found: m.schema_version,
            expected: SCHEMA_VERSION,
        });
    }
    validate_manifest(&m, os).map_err(BakeError::Validation)?;
    Ok(ValidatedManifest(m))
}

/// Run every §5.3 validator across the parsed manifest. The reserved-uid set + the baked-identity set
/// (for `setuidgid` name resolution) are DERIVED from `os.fixed` ∪ the tenant identities.
fn validate_manifest(m: &Manifest, os: &OsIdentities) -> Result<(), ValidationError> {
    let os_uids = os.uids();

                                                                                                
                                                                                   
    let mut baked: Vec<(String, u32)> = os.fixed.clone();
    for id in &m.identities {
        validate_uid(id.uid, &os_uids)?;
                                                                                                        
                                                                                                   
                                                                                                       
                                                                 
        if baked.iter().any(|(name, _)| name == &id.name) {
            return Err(ValidationError::IdentityNameCollision {
                name: id.name.clone(),
            });
        }
        baked.push((id.name.clone(), id.uid));
    }

                                                                                                     
    validate_path_token(&m.env.envdir)?;
    for (k, fragments) in &m.env.vars {
        validate_env_key(k)?;
        for frag in fragments {
                                                                                                   
            if let EnvFragment::Text { value } = frag {
                validate_env_value(k, value)?;
            }
        }
    }

                                                                                                      
                                                                                          
                                                                                                        
    for s in &m.services {
        match &s.shape {
            ServiceShape::Exec {
                binary,
                argv,
                privilege,
                env,
                ..
            } => {
                validate_path_token(binary)?;
                validate_argv(argv)?;
                validate_priv(privilege, &baked, &m.env.envdir)?;
                                                                                                            
                                                                                                           
                                                                                                       
                if let Some(env) = env {
                    for kv in env {
                        validate_env_key(&kv.key)?;
                        validate_env_value(&kv.key, &kv.value)?;
                    }
                }
            }
            ServiceShape::PeriodicLoop {
                binary,
                argv,
                privilege,
                ..
            } => {
                validate_path_token(binary)?;
                validate_argv(argv)?;
                validate_priv(privilege, &baked, &m.env.envdir)?;
            }
        }
    }
    for h in &m.boot_hooks {
        validate_path_token(&h.binary)?;
        validate_argv(&h.argv)?;
        validate_priv(&h.privilege, &baked, &m.env.envdir)?;
    }

                                                                                                     
    validate_path_token(&m.edge.ca_file)?;
    validate_argv_literal(&m.edge.backend)?;
    for p in &m.edge.redacted_paths {
        validate_path_token(p)?;
    }
    for q in &m.edge.redacted_query_params {
                                                                                                  
        validate_argv_literal(q)?;
    }
    for p in &m.edge.mtls_paths {
        validate_path_token(p)?;
    }
    for t in &m.edge.throttle_rules {
        for p in &t.paths {
            validate_path_token(p)?;
        }
    }

                                                                                                        
    for d in &m.persist {
        validate_path_token(&d.path)?;
    }

                                                                                         
    for src in &m.backup.sources {
        validate_relative_path(src)?;
    }
    if let Some(vt) = &m.backup.vacuum_target {
        validate_relative_path(vt)?;
    }

                                         
    validate_path_token(&m.probe.path)?;

                                                                                                     
                                                                                          
    if let Some(rd) = &m.resource_domain {
        validate_resource_domain(rd, m, &baked, &os_uids)?;
    }

                                                                                                     
                                                                                                   
                                                                                          
    match (m.box_config.is_some(), m.runtime_config.is_some()) {
        (true, false) | (false, true) => {
            return Err(ValidationError::DhaConfigIncomplete {
                detail: "box_config and runtime_config must be declared together".into(),
            });
        }
        (true, true) if m.resource_domain.is_none() => {
            return Err(ValidationError::DhaConfigIncomplete {
                detail:
                    "box_config/runtime_config require a resource_domain (parent_cgroup + budget derive from it)"
                        .into(),
            });
        }
        _ => {}
    }

                                                                                                      
                                                                                                      
                                                                                                        
                                                                                                      
                                                                                                       
                                                                                                        
    if let Some(bc) = &m.box_config {
        validate_path_token(&bc.root)?;
        validate_path_token(&bc.secrets)?;
        if let Some(scratch) = &bc.scratch {
            validate_path_token(scratch)?;
        }
        if let Some(logdir) = &bc.logdir {
            validate_path_token(logdir)?;
        }
    }
    if let Some(rc) = &m.runtime_config {
        validate_path_token(&rc.client.program)?;
        validate_path_token(&rc.client.config)?;
        if let Some(sp) = &rc.socket_path {
            validate_path_token(sp)?;
        }
        validate_path_token(&rc.creatine.memory_events)?;
        validate_path_token(&rc.creatine.uds)?;
        validate_path_token(&rc.creatine.service_dir)?;
        if let Some(bin) = &rc.creatine.s6_svstat_bin {
            validate_path_token(bin)?;
        }
    }

                                                                                                       
                                                                                                  
                                                                                                  
                                                                                                        
                                                                                         
    validate_staged_files(
        m.staged_files.as_deref().unwrap_or(&[]),
        &m.identities,
        m.runtime_config
            .as_ref()
            .map(|rc| rc.client.config.as_str()),
    )?;

    Ok(())
}

/// Validate the optional tenant resource domain (§4.1a). The `delegate_uid` is non-zero + OS-disjoint
/// (reuse [`validate_uid`]) AND a declared tenant identity; the engine (if present) + the orchestrator
/// name EXISTING `Exec` longruns whose `setuidgid` user resolves to `delegate_uid` — so box-init's
/// `work/` delegation hands the cgroup to exactly the identity those services run as (R1-L3). The cgroup
/// `name` reaches a `/sys/fs/cgroup/<name>` path sink, so it is charset- + traversal-checked.
fn validate_resource_domain(
    rd: &manifest::ResourceDomain,
    m: &Manifest,
    baked: &[(String, u32)],
    os_uids: &[u32],
) -> Result<(), ValidationError> {
    validate_cgroup_name(&rd.name)?;
    validate_uid(rd.delegate_uid.0, os_uids)?;
    if !m.identities.iter().any(|id| id.uid == rd.delegate_uid.0) {
        return Err(ValidationError::ResourceDomainDelegateUidUnknown {
            uid: rd.delegate_uid.0,
        });
    }
    if let Some(engine) = &rd.engine {
        validate_domain_leaf_service(&engine.service, m, baked, rd.delegate_uid.0)?;
    }
    validate_domain_leaf_service(&rd.work.orchestrator, m, baked, rd.delegate_uid.0)?;

                                                                                                       
                                                                                                
                                                                                                      
                                                                                 
    if rd
        .engine
        .as_ref()
        .is_some_and(|e| e.service == rd.work.orchestrator)
    {
        return Err(ValidationError::ResourceDomainLeafAliased {
            service: rd.work.orchestrator.clone(),
        });
    }
                                                                                                         
                                                                                                      
                                                                                                    
                                                                                                         
    for s in &m.services {
        let (ServiceShape::Exec { privilege, .. } | ServiceShape::PeriodicLoop { privilege, .. }) =
            &s.shape;
        let Priv::Setuidgid { user, .. } = privilege else {
            continue;                                                                      
        };
        let drops_to_delegate =
            baked.iter().find(|(n, _)| n == user).map(|(_, u)| *u) == Some(rd.delegate_uid.0);
        if drops_to_delegate {
            let is_leaf = rd.engine.as_ref().is_some_and(|e| e.service == s.name)
                || rd.work.orchestrator == s.name;
            if !is_leaf {
                return Err(ValidationError::ResourceDomainUnplacedDelegateService {
                    service: s.name.clone(),
                });
            }
        }
    }

                                                                                                         
                                                                                                        
                                                                                                            
                              
    let sigma = rd.memory_max.0;
    let bad = |detail: &str| ValidationError::ResourceDomainIncoherentBudget {
        detail: detail.to_string(),
    };
    if sigma == 0 {
        return Err(bad("memory_max (Σ) must be > 0"));
    }
    if let Some(engine) = &rd.engine {
        if engine.memory_max.0 >= sigma {
            return Err(bad(
                "engine.memory_max must be < Σ (so the engine cap bites before the aggregate)",
            ));
        }
        if engine
            .memory_min
            .is_some_and(|min| min.0 > engine.memory_max.0)
        {
            return Err(bad("engine.memory_min must be ≤ engine.memory_max"));
        }
    }
    if rd.work.job_memory_max.0 == 0 || rd.work.job_memory_max.0 > sigma {
        return Err(bad("work.job_memory_max must be > 0 and ≤ Σ"));
    }
    let reservations = rd
        .engine
        .as_ref()
        .and_then(|e| e.memory_min)
        .map_or(0, |m| m.0)
        .saturating_add(rd.work.orch_memory_min.map_or(0, |m| m.0));
    if reservations > sigma {
        return Err(bad("engine.memory_min + orch_memory_min must be ≤ Σ"));
    }
    if rd.work.work_pids_max == 0 {
        return Err(bad(
            "work.work_pids_max (the root-owned pids backstop) must be > 0",
        ));
    }
    if rd
        .work
        .job_pids_max
        .is_some_and(|j| j > rd.work.work_pids_max)
    {
        return Err(bad(
            "work.job_pids_max must be ≤ work.work_pids_max (the aggregate ceiling)",
        ));
    }
    Ok(())
}

/// A resource-domain leaf service (the engine or the orchestrator) MUST be a declared `Exec` longrun
/// whose `setuidgid` user resolves (via the baked passwd) to `delegate_uid` (§4.1a / R1-L3).
fn validate_domain_leaf_service(
    service_name: &str,
    m: &Manifest,
    baked: &[(String, u32)],
    delegate_uid: u32,
) -> Result<(), ValidationError> {
    let svc = m
        .services
        .iter()
        .find(|s| s.name == service_name)
        .ok_or_else(|| ValidationError::ResourceDomainServiceUnknown {
            service: service_name.to_string(),
        })?;
    let ServiceShape::Exec { privilege, .. } = &svc.shape else {
        return Err(ValidationError::ResourceDomainServiceNotExec {
            service: service_name.to_string(),
        });
    };
    let Priv::Setuidgid { user, .. } = privilege else {
        return Err(ValidationError::ResourceDomainServiceUidMismatch {
            service: service_name.to_string(),
        });
    };
                                                                                                     
    let resolved = baked.iter().find(|(n, _)| n == user).map(|(_, u)| *u);
    if resolved != Some(delegate_uid) {
        return Err(ValidationError::ResourceDomainServiceUidMismatch {
            service: service_name.to_string(),
        });
    }
    Ok(())
}

/// Validate an argv token vector's literals against the §5.3 charset (placeholders are closed typed
/// variants, safe). Pub so box-init's `topology::parse_topology` can RE-validate the baked topology's
/// argv at the parse layer (defense-in-depth at the `sh -c` sink — the bake already ran this, but
/// box-init re-checks so the sink is safe-by-construction, not merely trusted across the bake boundary).
pub fn validate_argv(argv: &[ArgvToken]) -> Result<(), ValidationError> {
    for t in argv {
                                                                                                     
        match t {
            ArgvToken::Literal { value } => validate_argv_literal(value)?,
            ArgvToken::Placeholder { .. } => {}
            ArgvToken::Template { fragments } => {
                for frag in fragments {
                    if let ArgvFragment::Literal { value } = frag {
                        validate_argv_literal(value)?;
                    }
                }
            }
        }
    }
    Ok(())
}

fn validate_priv(
    p: &Priv,
    baked: &[(String, u32)],
    env_envdir: &str,
) -> Result<(), ValidationError> {
    if let Priv::Setuidgid { user, envdir } = p {
        validate_setuid_user(user, baked)?;
        if let Some(dir) = envdir {
            validate_path_token(dir)?;
                                                                                                      
                                                                                                       
                                                                                                         
                                                                         
            if dir != env_envdir {
                return Err(ValidationError::EnvdirMismatch {
                    declared: env_envdir.to_string(),
                    found: dir.clone(),
                });
            }
        }
    }
    Ok(())
}

          
/// The build context for filling OS-invariant placeholders (§5.3).
#[derive(Debug, Clone)]
pub struct PlaceholderCtx {
    /// The box's configured domain (fills [`KnownPlaceholder::Domain`]).
    pub domain: String,
    /// The build clock floor (fills [`KnownPlaceholder::SourceDateEpoch`]).
    pub source_date_epoch: u64,
}

impl KnownPlaceholder {
    /// Fill this OS-invariant placeholder from the build context — the typed-variant match shared by
              
    /// argv + env rendering (§5.3; never string substitution).
    pub fn fill(self, ctx: &PlaceholderCtx) -> String {
        match self {
            KnownPlaceholder::Domain => ctx.domain.clone(),
            KnownPlaceholder::SourceDateEpoch => ctx.source_date_epoch.to_string(),
        }
    }
}

             
/// Single-quote a tenant literal for a `/bin/sh` word position (§5.3 line 111 — the STRUCTURAL
/// barrier). Inside `'…'` every byte is literal to the shell, so no metacharacter can act — even if
/// the charset validator (the SECOND, defense-in-depth barrier) ever regresses to admit one. The
/// POSIX-safe escape for an embedded `'` is `'\''` (close-quote, escaped-quote, re-open); the §5.3
/// charset currently EXCLUDES `'`, so for validated data this never fires and the wrap is byte-for-byte
/// `'<value>'` — but implementing the escape is what makes the barrier safe-by-CONSTRUCTION, not merely
/// safe-by-validation (the property the re-bless blessed as "independent double coverage").
fn sq(value: &str) -> String {
    if value.contains('\'') {
        format!("'{}'", value.replace('\'', "'\\''"))
    } else {
        format!("'{value}'")
    }
}

impl ArgvToken {
    /// Render this token to its final command-line string.
    ///
    /// A [`ArgvToken::Literal`] renders its value **verbatim** — NO substitution; a
    /// [`ArgvToken::Placeholder`] renders the OS-invariant value by **matching the typed variant**. So
    /// a `Literal` whose value is the text `{source_date_epoch}` renders that text verbatim, NEVER the
              
    /// epoch — a tenant literal can never alias an OS-invariant value (§5.3). String
    /// substitution over a tenant argv stream is structurally impossible: there is no string to
    /// substitute over, only a typed token vector.
    ///
    /// This is the VALUE form (used for env values + the aliasing-property tests). The shell-word form
    /// the run-scripts / boot-hook bodies emit is [`ArgvToken::render_shell_word`] (single-quoted).
    pub fn render(&self, ctx: &PlaceholderCtx) -> String {
        match self {
            ArgvToken::Literal { value } => value.clone(),
            ArgvToken::Placeholder { name } => name.fill(ctx),
                                                                                           
            ArgvToken::Template { fragments } => fragments
                .iter()
                .map(|f| match f {
                    ArgvFragment::Literal { value } => value.clone(),
                    ArgvFragment::Placeholder { name } => name.fill(ctx),
                })
                .collect(),
        }
    }

                 
    /// Render this token as a single `/bin/sh` WORD with the §5.3 structural barrier applied.
    ///
    /// A tenant [`Literal`] is single-quoted ([`sq`]) so it cannot reach a metacharacter position; a
    /// [`Placeholder`] fills BARE — its value is renderer-owned (the build `--domain`/epoch, or box-init's
    /// runtime `"$(cat /etc/box-domain)"`), which MUST stay un-quoted so the command substitution
    /// expands (single-quoting it would emit the literal text `$(cat …)`). A [`Template`] concatenates
    /// its fragments with NO separators (one word): each `Literal` fragment quoted, each `Placeholder`
    /// fragment bare — `'…'<bare-fill>'…'` is a single shell word by adjacency. This is the structural
    /// (PREFERRED) barrier; the gate charset is the second, defense-in-depth one.
    pub fn render_shell_word(&self, ctx: &PlaceholderCtx) -> String {
        match self {
            ArgvToken::Literal { value } => sq(value),
            ArgvToken::Placeholder { name } => name.fill(ctx),
            ArgvToken::Template { fragments } => fragments
                .iter()
                .map(|f| match f {
                    ArgvFragment::Literal { value } => sq(value),
                    ArgvFragment::Placeholder { name } => name.fill(ctx),
                })
                .collect(),
        }
    }
}

impl EnvFragment {
    /// Render this env-value fragment. `Text` is verbatim; `Placeholder` fills the OS value by typed
              
    /// match — a `Text` of the literal `{domain}` renders that text, never the domain.
    pub fn render(&self, ctx: &PlaceholderCtx) -> String {
        match self {
            EnvFragment::Text { value } => value.clone(),
            EnvFragment::Placeholder { name } => name.fill(ctx),
        }
    }
}

/// Render a full env-var VALUE by concatenating its typed fragments (§5.1b).
pub fn render_env_value(fragments: &[EnvFragment], ctx: &PlaceholderCtx) -> String {
    fragments.iter().map(|f| f.render(ctx)).collect()
}

/// The s6 privilege-drop prefix for a [`Priv`] (§5.1c). `root`/`self_drop` → no prefix (runs as root,
/// or the binary drops its own privilege); `setuidgid` → `s6-envdir <dir>` (optional) + `s6-setuidgid
/// <user>` composed from the typed fields (the `s6-*` tokens are renderer-owned, never tenant strings —
/// §5.3). The ONE source shared by image-builder's service run-scripts AND box-init's boot-hook bodies.
pub fn priv_prefix(p: &Priv) -> String {
                                                                                                  
                                                                                                        
    match p {
        Priv::Root {} | Priv::SelfDrop {} => String::new(),
        Priv::Setuidgid { user, envdir } => match envdir {
            Some(dir) => format!("s6-envdir {} s6-setuidgid {} ", sq(dir), sq(user)),
            None => format!("s6-setuidgid {} ", sq(user)),
        },
    }
}

/// Render a typed command line — `{priv-prefix}{binary}{ argv…}` — the shared core of a service
/// run-script (image-builder wraps it in `#!/bin/sh\nexec …` / the `while … sleep … done` loop) AND a
/// box-init boot-hook body (run as `sh -c <body>`). The argv tokens render by typed-variant match
          
/// (placeholders filled from `ctx`, literals verbatim — §5.3); the `s6-*` prefix is renderer-owned.
pub fn render_command(
    binary: &str,
    argv: &[ArgvToken],
    privilege: &Priv,
    ctx: &PlaceholderCtx,
) -> String {
    let prefix = priv_prefix(privilege);
                                                                                                       
                                                                                                         
    let args: String = argv
        .iter()
        .map(|t| format!(" {}", t.render_shell_word(ctx)))
        .collect();
    format!("{prefix}{}{args}", sq(binary))
}

/// Render a tenant boot-hook (§5.1e) to the `sh -c` body box-init runs pre-supervision — its typed
/// `{binary, argv, priv}` as one command line. box-init fills `ctx.domain` with its runtime domain
/// source-of-truth (`"$(cat /etc/box-domain)"`), so the rendered body matches the OS-invariant
/// boot-hooks' form; the body is argv DATA passed to `sh -c`, NEVER a tmpfs script (the box-init
             
/// keystone — a tmpfs script would be unsigned + on a `noexec` mount → EACCES).
pub fn render_boot_hook_body(hook: &manifest::BootHook, ctx: &PlaceholderCtx) -> String {
    render_command(&hook.binary, &hook.argv, &hook.privilege, ctx)
}

#[cfg(test)]
mod gate_tests {
    use super::*;

    fn os() -> OsIdentities {
                                                                                                
        OsIdentities {
            fixed: vec![
                ("root".into(), 0),
                ("fb-acme".into(), 101),
                ("fb-backup".into(), 102),
                ("fb-cert-check".into(), 103),
                ("haproxy".into(), 104),
                ("dropbear-rescue".into(), 105),
            ],
        }
    }

    const VALID: &str = r#"
schema_version = 1
[[identities]]
name = "recipes"
uid = 100
[env]
envdir = "/etc/recipes/env"
[env.vars]
DATA_DIR = [ { text = { value = "/persist/recipes" } } ]
[[services]]
name = "recipes"
shape = { exec = { binary = "/usr/bin/recipes", argv = [], priv = { setuidgid = { user = "recipes", envdir = "/etc/recipes/env" } } } }
[[boot_hooks]]
name = "set-hostname"
binary = "/usr/bin/fb-oneshots"
argv = [ { literal = { value = "set-hostname" } }, { placeholder = { name = "domain" } } ]
priv = { root = {} }
order = 10
timeout_secs = 5
on_failure = { rescue = {} }
[edge]
backend = "127.0.0.1:8000"
ca_file = "/persist/recipes/ca.crt"
redacted_paths = [ "/api/pair/" ]
redacted_query_params = [ "via" ]
mtls_paths = [ "/api/v1/" ]
throttle_rules = [ { paths = [ "/login" ], match = "exact", max_req_rate = 10 } ]
[[persist]]
path = "recipes"
uid = 100
mode = 0o700
[backup]
sources = [ "recipes" ]
[probe]
port = 443
path = "/"
[nftables]
tcp_ports = [ 80, 443, 22 ]
"#;

    /// Replace a fragment of the valid manifest to build a negative fixture.
    fn mutate(from: &str, to: &str) -> String {
        VALID.replace(from, to)
    }

    #[test]
    fn the_valid_manifest_passes_the_gate() {
        let vm = parse_and_validate(VALID, &os()).expect("valid manifest passes");
        assert_eq!(vm.manifest().identities[0].uid, 100);
    }

    #[test]
    fn wrong_schema_version_is_refused() {
        let err = parse_and_validate(&mutate("schema_version = 1", "schema_version = 2"), &os());
        assert!(matches!(
            err,
            Err(BakeError::SchemaVersion {
                found: 2,
                expected: 1
            })
        ));
    }

    #[test]
    fn a_service_at_uid_zero_is_refused() {
        let err = parse_and_validate(&mutate("uid = 100", "uid = 0"), &os());
        assert!(
            matches!(err, Err(BakeError::Validation(ValidationError::UidRoot))),
            "{err:?}"
        );
    }

    #[test]
    fn a_uid_colliding_with_an_os_identity_is_refused() {
        let err = parse_and_validate(&mutate("uid = 100", "uid = 104"), &os());
        assert!(
            matches!(
                err,
                Err(BakeError::Validation(ValidationError::UidCollision {
                    uid: 104
                }))
            ),
            "{err:?}"
        );
    }

    #[test]
    fn a_setuidgid_root_service_is_refused() {
        let err = parse_and_validate(&mutate(r#"user = "recipes""#, r#"user = "root""#), &os());
        assert!(
            matches!(
                err,
                Err(BakeError::Validation(
                    ValidationError::SetuidUserRoot { .. }
                ))
            ),
            "{err:?}"
        );
    }

    #[test]
    fn an_unbaked_setuidgid_user_is_refused() {
                                                                                               
                                                                                                        
        let err = parse_and_validate(&mutate(r#"user = "recipes""#, r#"user = "ghost""#), &os());
        assert!(
            matches!(
                err,
                Err(BakeError::Validation(
                    ValidationError::SetuidUserUnknown { .. }
                ))
            ),
            "{err:?}"
        );
    }

    #[test]
    fn an_argv_metacharacter_literal_is_refused() {
        let err = parse_and_validate(
            &mutate(r#"value = "set-hostname""#, r#"value = "x; reboot""#),
            &os(),
        );
        assert!(
            matches!(
                err,
                Err(BakeError::Validation(ValidationError::ArgvCharset { .. }))
            ),
            "{err:?}"
        );
    }

    #[test]
    fn an_ld_preload_env_key_is_refused() {
        let err = parse_and_validate(&mutate("DATA_DIR =", "LD_PRELOAD ="), &os());
        assert!(
            matches!(
                err,
                Err(BakeError::Validation(
                    ValidationError::EnvKeyForbidden { .. }
                ))
            ),
            "{err:?}"
        );
    }

    #[test]
    fn a_traversal_env_key_is_refused() {
                                                                                              
                                                                                                          
        let err = parse_and_validate(&mutate("DATA_DIR =", r#""../escape" ="#), &os());
        assert!(
            matches!(
                err,
                Err(BakeError::Validation(ValidationError::EnvKeyCharset { .. }))
            ),
            "{err:?}"
        );
    }

    #[test]
    fn a_backup_traversal_source_is_refused() {
        let err = parse_and_validate(
            &mutate(r#"sources = [ "recipes" ]"#, r#"sources = [ "../../etc" ]"#),
            &os(),
        );
        assert!(
            matches!(
                err,
                Err(BakeError::Validation(ValidationError::PathTraversal { .. }))
            ),
            "{err:?}"
        );
    }

    #[test]
    fn a_setuidgid_envdir_disagreeing_with_env_envdir_is_refused() {
                                                                                                     
                                                                                                          
                                                                                                         
                                                                               
        let err = parse_and_validate(
            &mutate(
                r#"user = "recipes", envdir = "/etc/recipes/env""#,
                r#"user = "recipes", envdir = "/etc/other/env""#,
            ),
            &os(),
        );
        assert!(
            matches!(
                err,
                Err(BakeError::Validation(
                    ValidationError::EnvdirMismatch { .. }
                ))
            ),
            "{err:?}"
        );
    }

                                                                         

    #[test]
    fn a_literal_of_a_placeholder_string_renders_verbatim() {
        let ctx = PlaceholderCtx {
            domain: "box.test".into(),
            source_date_epoch: 1_700_000_000,
        };
        let literal = ArgvToken::Literal {
            value: "{source_date_epoch}".into(),
        };
        assert_eq!(literal.render(&ctx), "{source_date_epoch}");                 
        let placeholder = ArgvToken::Placeholder {
            name: KnownPlaceholder::SourceDateEpoch,
        };
        assert_eq!(placeholder.render(&ctx), "1700000000");                           
        let domain = ArgvToken::Placeholder {
            name: KnownPlaceholder::Domain,
        };
        assert_eq!(domain.render(&ctx), "box.test");
    }

    #[test]
    fn env_value_fragments_render_with_typed_domain_fill() {
        use crate::manifest::EnvFragment;
        let ctx = PlaceholderCtx {
            domain: "box.test".into(),
            source_date_epoch: 0,
        };
                                                                                    
        let public_url = vec![
            EnvFragment::Text {
                value: "https://".into(),
            },
            EnvFragment::Placeholder {
                name: KnownPlaceholder::Domain,
            },
        ];
        assert_eq!(render_env_value(&public_url, &ctx), "https://box.test");
                                                                                                 
        let literal = vec![EnvFragment::Text {
            value: "{domain}".into(),
        }];
        assert_eq!(render_env_value(&literal, &ctx), "{domain}");
    }

    #[test]
    fn a_template_argv_word_embeds_the_domain_in_one_word() {
        use crate::argv::ArgvFragment;
        let ctx = PlaceholderCtx {
            domain: "box.test".into(),
            source_date_epoch: 0,
        };
                                                                                                    
        let cert_path = ArgvToken::Template {
            fragments: vec![
                ArgvFragment::Literal {
                    value: "/persist/acme/".into(),
                },
                ArgvFragment::Placeholder {
                    name: KnownPlaceholder::Domain,
                },
                ArgvFragment::Literal {
                    value: "/full.pem".into(),
                },
            ],
        };
        assert_eq!(cert_path.render(&ctx), "/persist/acme/box.test/full.pem");
                                                                                         
        let aliased = ArgvToken::Template {
            fragments: vec![ArgvFragment::Literal {
                value: "{domain}".into(),
            }],
        };
        assert_eq!(aliased.render(&ctx), "{domain}");
    }

    #[test]
    fn render_shell_word_applies_the_structural_single_quote_barrier() {
        use crate::argv::ArgvFragment;
        let ctx = PlaceholderCtx {
            domain: "\"$(cat /etc/box-domain)\"".into(),
            source_date_epoch: 1_700_000_000,
        };
                                             
        assert_eq!(
            ArgvToken::Literal {
                value: "--domain".into()
            }
            .render_shell_word(&ctx),
            "'--domain'"
        );
                                                                                                       
        assert_eq!(
            ArgvToken::Placeholder {
                name: KnownPlaceholder::Domain
            }
            .render_shell_word(&ctx),
            "\"$(cat /etc/box-domain)\""
        );
                                                                                                      
        let cert = ArgvToken::Template {
            fragments: vec![
                ArgvFragment::Literal {
                    value: "/persist/acme/".into(),
                },
                ArgvFragment::Placeholder {
                    name: KnownPlaceholder::Domain,
                },
                ArgvFragment::Literal {
                    value: "/full.pem".into(),
                },
            ],
        };
        assert_eq!(
            cert.render_shell_word(&ctx),
            "'/persist/acme/'\"$(cat /etc/box-domain)\"'/full.pem'"
        );
                                                                                                           
                                                                                                        
                                                                                                         
                                                                   
        assert_eq!(
            ArgvToken::Literal {
                value: "x; reboot".into()
            }
            .render_shell_word(&ctx),
            "'x; reboot'"
        );
                                                                                                           
        assert_eq!(
            ArgvToken::Literal {
                value: "a'b".into()
            }
            .render_shell_word(&ctx),
            "'a'\\''b'"
        );
    }

    #[test]
    fn render_boot_hook_body_reproduces_box_inits_compiled_in_bodies() {
                                                                                                 
                                                                                                        
                                                                                                           
                                                                                                        
                                                                                                            
        use crate::topology::parse_topology;
        let fixture = r#"
schema_version = 1
persist = []
[[boot_hooks]]
name = "set-hostname"
binary = "/usr/bin/fb-oneshots"
argv = [ { literal = { value = "set-hostname" } }, { literal = { value = "--fallback" } }, { placeholder = { name = "domain" } } ]
priv = { root = {} }
order = 10
timeout_secs = 30
on_failure = { rescue = {} }
[[boot_hooks]]
name = "bootstrap-ca"
binary = "/usr/bin/recipes-admin"
argv = [ { literal = { value = "bootstrap-ca" } } ]
priv = { setuidgid = { user = "recipes", envdir = "/etc/recipes/env" } }
order = 20
timeout_secs = 30
on_failure = { rescue = {} }
[[boot_hooks]]
name = "bootstrap-acme-cert"
binary = "/usr/bin/fb-oneshots"
argv = [ { literal = { value = "selfsign-acme-cert" } }, { literal = { value = "--domain" } }, { placeholder = { name = "domain" } } ]
priv = { setuidgid = { user = "fb-acme" } }
order = 30
timeout_secs = 30
on_failure = { rescue = {} }
"#;
        let t = parse_topology(fixture).expect("the 3 app-domain hooks parse");
        let ctx = PlaceholderCtx {
            domain: "\"$(cat /etc/box-domain)\"".into(),
            source_date_epoch: 0,
        };
        let body = |name: &str| {
            render_boot_hook_body(
                t.boot_hooks
                    .iter()
                    .find(|h| h.name == name)
                    .expect("hook present"),
                &ctx,
            )
        };
                                                                                             
                                                                                                       
                                                                                                       
        assert_eq!(
            body("set-hostname"),
            "'/usr/bin/fb-oneshots' 'set-hostname' '--fallback' \"$(cat /etc/box-domain)\""
        );
        assert_eq!(
            body("bootstrap-ca"),
            "s6-envdir '/etc/recipes/env' s6-setuidgid 'recipes' '/usr/bin/recipes-admin' 'bootstrap-ca'"
        );
        assert_eq!(
            body("bootstrap-acme-cert"),
            "s6-setuidgid 'fb-acme' '/usr/bin/fb-oneshots' 'selfsign-acme-cert' '--domain' \"$(cat /etc/box-domain)\""
        );
    }

                                                     

    /// The VALID gate fixture extended with a dha tenant: a `dha` identity (uid 110), the creatine +
    /// orchestrator Exec longruns dropping to it, and a `[resource_domain]` wiring them.
    const VALID_DHA: &str = r#"
schema_version = 1
[[identities]]
name = "recipes"
uid = 100
[[identities]]
name = "dha"
uid = 110
[env]
envdir = "/etc/recipes/env"
[env.vars]
DATA_DIR = [ { text = { value = "/persist/recipes" } } ]
[[services]]
name = "recipes"
shape = { exec = { binary = "/usr/bin/recipes", argv = [], priv = { setuidgid = { user = "recipes", envdir = "/etc/recipes/env" } } } }
[[services]]
name = "dha-creatine"
shape = { exec = { binary = "/usr/bin/dha-creatine", argv = [], priv = { setuidgid = { user = "dha" } } } }
[[services]]
name = "dha-orchestrator"
shape = { exec = { binary = "/usr/bin/dha-orchestrator", argv = [], priv = { setuidgid = { user = "dha" } } } }
[[boot_hooks]]
name = "set-hostname"
binary = "/usr/bin/fb-oneshots"
argv = [ { literal = { value = "set-hostname" } }, { placeholder = { name = "domain" } } ]
priv = { root = {} }
order = 10
timeout_secs = 5
on_failure = { rescue = {} }
[edge]
backend = "127.0.0.1:8000"
ca_file = "/persist/recipes/ca.crt"
redacted_paths = [ "/api/pair/" ]
redacted_query_params = [ "via" ]
mtls_paths = [ "/api/v1/" ]
throttle_rules = [ { paths = [ "/login" ], match = "exact", max_req_rate = 10 } ]
[[persist]]
path = "recipes"
uid = 100
mode = 0o700
[backup]
sources = [ "recipes" ]
[probe]
port = 443
path = "/"
[nftables]
tcp_ports = [ 80, 443, 22 ]
[resource_domain]
name = "dha"
memory_max = 8000000000
delegate_uid = 110
[resource_domain.engine]
service = "dha-creatine"
memory_max = 6000000000
memory_min = 4000000000
oom_group = true
[resource_domain.work]
orchestrator = "dha-orchestrator"
orch_memory_min = 64000000
job_memory_max = 512000000
job_pids_max = 64
max_descendants = 16
max_depth = 2
work_pids_max = 256
"#;

    fn mutate_dha(from: &str, to: &str) -> String {
        let out = VALID_DHA.replace(from, to);
        assert_ne!(
            out, VALID_DHA,
            "the mutation target {from:?} must be present"
        );
        out
    }

    #[test]
    fn a_valid_dha_manifest_passes_the_gate() {
        let vm = parse_and_validate(VALID_DHA, &os()).expect("valid dha manifest passes");
        let rd = vm
            .manifest()
            .resource_domain
            .as_ref()
            .expect("resource_domain present");
        assert_eq!(rd.name, "dha");
        assert_eq!(rd.delegate_uid.0, 110);
        assert_eq!(rd.engine.as_ref().unwrap().service, "dha-creatine");
        assert_eq!(rd.work.orchestrator, "dha-orchestrator");
    }

    #[test]
    fn a_resource_domain_delegate_uid_zero_is_refused() {
                                                                                                      
        let err = parse_and_validate(&mutate_dha("delegate_uid = 110", "delegate_uid = 0"), &os());
        assert!(
            matches!(err, Err(BakeError::Validation(ValidationError::UidRoot))),
            "{err:?}"
        );
    }

    #[test]
    fn a_resource_domain_delegate_uid_colliding_with_an_os_identity_is_refused() {
                                                                        
        let err = parse_and_validate(
            &mutate_dha("delegate_uid = 110", "delegate_uid = 104"),
            &os(),
        );
        assert!(
            matches!(
                err,
                Err(BakeError::Validation(ValidationError::UidCollision {
                    uid: 104
                }))
            ),
            "{err:?}"
        );
    }

    #[test]
    fn a_resource_domain_delegate_uid_not_a_tenant_identity_is_refused() {
                                                                                                     
                                                         
        let err = parse_and_validate(
            &mutate_dha("delegate_uid = 110", "delegate_uid = 120"),
            &os(),
        );
        assert!(
            matches!(
                err,
                Err(BakeError::Validation(
                    ValidationError::ResourceDomainDelegateUidUnknown { uid: 120 }
                ))
            ),
            "{err:?}"
        );
    }

    #[test]
    fn a_resource_domain_engine_dropping_to_a_different_uid_is_refused() {
                                                                                                           
                                                                                             
        let err = parse_and_validate(
            &mutate_dha(
                r#"binary = "/usr/bin/dha-creatine", argv = [], priv = { setuidgid = { user = "dha" } }"#,
                r#"binary = "/usr/bin/dha-creatine", argv = [], priv = { setuidgid = { user = "recipes" } }"#,
            ),
            &os(),
        );
        assert!(
            matches!(
                err,
                Err(BakeError::Validation(
                    ValidationError::ResourceDomainServiceUidMismatch { .. }
                ))
            ),
            "{err:?}"
        );
    }

    #[test]
    fn a_resource_domain_naming_an_unknown_service_is_refused() {
        let err = parse_and_validate(
            &mutate_dha(r#"service = "dha-creatine""#, r#"service = "ghost""#),
            &os(),
        );
        assert!(
            matches!(
                err,
                Err(BakeError::Validation(
                    ValidationError::ResourceDomainServiceUnknown { .. }
                ))
            ),
            "{err:?}"
        );
    }

    #[test]
    fn a_resource_domain_orchestrator_that_is_not_an_exec_longrun_is_refused() {
                                                                                                    
                                        
        let err = parse_and_validate(
            &mutate_dha(
                r#"shape = { exec = { binary = "/usr/bin/dha-orchestrator", argv = [], priv = { setuidgid = { user = "dha" } } } }"#,
                r#"shape = { periodic_loop = { binary = "/usr/bin/dha-orchestrator", argv = [], interval_secs = 60, priv = { setuidgid = { user = "dha" } } } }"#,
            ),
            &os(),
        );
        assert!(
            matches!(
                err,
                Err(BakeError::Validation(
                    ValidationError::ResourceDomainServiceNotExec { .. }
                ))
            ),
            "{err:?}"
        );
    }

    #[test]
    fn a_resource_domain_name_with_a_shell_metacharacter_is_refused() {
                                                                                                      
                                                                                                                
                                                                                                             
        let err = parse_and_validate(
            &mutate_dha(
                "name = \"dha\"\nmemory_max = 8000000000",
                "name = \"dha; reboot\"\nmemory_max = 8000000000",
            ),
            &os(),
        );
        assert!(
            matches!(
                err,
                Err(BakeError::Validation(ValidationError::CgroupName { .. }))
            ),
            "{err:?}"
        );
    }

    #[test]
    fn a_resource_domain_name_that_escapes_the_cgroup_root_is_refused() {
                                                                                                            
                                                                                                      
                                                                              
        for bad in [
            "/run/evil",
            "a/b",
            "",
            "..",
            ".",
            "cgroup.procs",
            "-rf",
            "+memory",
        ] {
            let m = mutate_dha(
                "name = \"dha\"\nmemory_max",
                &format!("name = {bad:?}\nmemory_max"),
            );
            assert!(
                matches!(
                    parse_and_validate(&m, &os()),
                    Err(BakeError::Validation(ValidationError::CgroupName { .. }))
                ),
                "rd.name {bad:?} must be refused as a cgroup component"
            );
        }
    }

    #[test]
    fn a_resource_domain_with_an_incoherent_budget_is_refused() {
                                                                                                        
                                                                                                         
                                                               
        let engine_ge_sigma = mutate_dha("memory_max = 6000000000", "memory_max = 8000000000");
        let job_gt_sigma = mutate_dha("job_memory_max = 512000000", "job_memory_max = 9000000000");
        let sigma_zero = mutate_dha("memory_max = 8000000000", "memory_max = 0");
        let work_pids_zero = mutate_dha("work_pids_max = 256", "work_pids_max = 0");
        let job_pids_gt_work = mutate_dha("job_pids_max = 64", "job_pids_max = 300");
        for m in [
            engine_ge_sigma,
            job_gt_sigma,
            sigma_zero,
            work_pids_zero,
            job_pids_gt_work,
        ] {
            assert!(
                matches!(
                    parse_and_validate(&m, &os()),
                    Err(BakeError::Validation(
                        ValidationError::ResourceDomainIncoherentBudget { .. }
                    ))
                ),
                "an incoherent budget must be refused"
            );
        }
    }

    #[test]
    fn a_third_delegate_uid_service_that_is_not_a_leaf_is_refused() {
                                                                                                    
                                                                                                      
                                                                                                  
                                                                                                           
        let err = parse_and_validate(&mutate_dha(r#"user = "recipes""#, r#"user = "dha""#), &os());
        assert!(
            matches!(
                err,
                Err(BakeError::Validation(
                    ValidationError::ResourceDomainUnplacedDelegateService { .. }
                ))
            ),
            "{err:?}"
        );
    }

    #[test]
    fn a_resource_domain_with_aliased_leaves_is_refused() {
                                                                                                  
                                                                                                        
                                                                                           
        let err = parse_and_validate(
            &mutate_dha(
                r#"orchestrator = "dha-orchestrator""#,
                r#"orchestrator = "dha-creatine""#,
            ),
            &os(),
        );
        assert!(
            matches!(
                err,
                Err(BakeError::Validation(
                    ValidationError::ResourceDomainLeafAliased { .. }
                ))
            ),
            "{err:?}"
        );
    }
}

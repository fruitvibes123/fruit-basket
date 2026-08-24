//! The box-init `Topology` subset (boot-hooks; schema-version field) + its fail-closed parser
//! (deny-unknown-fields; unparseable / version-mismatch → the caller's rescue branch — §5.1e).
//!
                      
//! Orchard's image-builder RENDERS this subset from a [`ValidatedManifest`] and
//! bakes it into the signed dm-verity rootfs; Fruit Basket's box-init PARSES it at boot to build its
//! app-domain boot-hook list (replacing the compiled-in `oneshots::bootstrap()`). FB owns this schema
//! (the stricter party, R2-4). The argv `Placeholder`s survive into the topology; box-init fills the
//! box domain (from `/etc/box-domain`) at boot. An unparseable / wrong-version file →
//! box-init's `OnFailure::Rescue`, never best-effort.

use crate::manifest::{BootHook, PersistDir, ResourceDomain};
use serde::{Deserialize, Serialize};

/// The rendered topology box-init reads at boot. Carries the schema version (fail-closed on mismatch),
/// the tenant's app-domain boot-hooks (set-hostname / bootstrap-ca / bootstrap-acme-cert), AND the
/// tenant `persist` dirs (§5.1d) so box-init's `setup-dirs` oneshot renders the tenant mkdir/chown from
                 
/// the manifest instead of hardcoding `recipes` (runtime de-hardcoding — a non-recipes
/// tenant otherwise hit `chown: unknown user/group recipes:recipes` → setup-dirs fail → rescue divert).
/// The rest of the OS-infra boot sequence (nftables-load, mount-persist, the acme/log dirs) stays
/// compiled into box-init (the §5.2 OS-invariant partition).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Topology {
    pub schema_version: u32,
    pub boot_hooks: Vec<BootHook>,
    pub persist: Vec<PersistDir>,
    /// The optional tenant cgroup resource domain (§4.2) — box-init builds the minimal-root cgroup tree
    /// from it; absent = a non-dha box (box-init skips the cgroup block). Rides the SIGNED topology
    /// (rendered + baked before the IMA/EVM signer → Σ integrity-covered). LAST field (a table) so
    /// `schema_version` stays the only scalar, emitted before every table (the ValueAfterTable guard).
    pub resource_domain: Option<ResourceDomain>,
}

/// A topology-file parse failure. box-init maps any of these to its rescue branch (§5.1e — never
/// best-effort); the file is also dm-verity-covered + IMA-appraised, so corruption is already
/// fail-closed at the integrity layer below this parse-layer backstop.
#[derive(Debug)]
pub enum TopologyError {
    /// `toml` rejected the baked file (syntax, unknown field, missing required field, …).
    Parse(toml::de::Error),
    /// The `schema_version` did not match the box-init build's [`crate::SCHEMA_VERSION`].
    SchemaVersion { found: u32, expected: u32 },
    /// A shell-sink value (a persist path, a boot-hook binary/argv/priv) failed the §5.3 charset at
    /// box-init's parse-layer RE-validation (defense-in-depth — the bake already ran this).
    Validation(crate::validate::ValidationError),
}

impl std::fmt::Display for TopologyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "topology parse error: {e}"),
            Self::SchemaVersion { found, expected } => {
                write!(f, "topology schema_version {found} != supported {expected}")
            }
            Self::Validation(e) => write!(f, "topology content validation error: {e}"),
        }
    }
}

/// RE-validate the shell-sink content of a parsed topology at box-init's parse layer (defense-in-depth).
/// Every value that reaches a shell sink — the persist paths (`setup-dirs` `chown /persist/<path>`), the
/// boot-hook binary + argv + `setuidgid` user/envdir (the bodies run as `sh -c`) — must be charset-clean
/// (no shell metacharacter) and traversal-free. The Orchard bake ALREADY ran these validators and the
/// baked `box-topology.toml` is dm-verity-covered + IMA-appraised, so this is a backstop — but box-init
/// re-checks so each sink is safe-BY-CONSTRUCTION at the sink, not merely trusted across the bake
                                                       
/// boundary. A failure is fail-closed →
/// `TopologyError::Validation` → box-init's rescue branch.
///
              
/// SCOPE: this re-check is the shell-INJECTION sink guard — charset + traversal only. The
/// AUTHORIZATION invariant that a `setuidgid` user is non-root and a baked-passwd identity
/// (`validate_setuid_user`, run by `validate_priv` at bake) is deliberately NOT re-run here: it needs the
/// baked passwd set (which box-init does not carry), and reaching a tampered user value would require
/// bypassing BOTH the bake gate AND dm-verity+IMA. So the non-root property is trusted across the bake
/// boundary by design; only the injection-safety property is made safe-by-construction at this sink.
fn validate_topology_content(t: &Topology) -> Result<(), crate::validate::ValidationError> {
    use crate::manifest::Priv;
    use crate::validate::{validate_argv_literal, validate_cgroup_name, validate_path_token};
    for d in &t.persist {
        validate_path_token(&d.path)?;
    }
    for h in &t.boot_hooks {
        validate_path_token(&h.binary)?;
        crate::validate_argv(&h.argv)?;
        if let Priv::Setuidgid { user, envdir } = &h.privilege {
            validate_argv_literal(user)?;
            if let Some(dir) = envdir {
                validate_path_token(dir)?;
            }
        }
    }
                                                                                                           
                                                                                                           
                                                                                                           
                                                                                                 
                                                                       
    if let Some(rd) = &t.resource_domain {
        validate_cgroup_name(&rd.name)?;
    }
    Ok(())
}

impl std::error::Error for TopologyError {}

/// Parse a baked topology file, fail-closed on version/shape mismatch (§5.1e). box-init calls this at
/// boot; an `Err` diverts to the rescue branch.
pub fn parse_topology(input: &str) -> Result<Topology, TopologyError> {
    let t: Topology = toml::from_str(input).map_err(TopologyError::Parse)?;
    if t.schema_version != crate::SCHEMA_VERSION {
        return Err(TopologyError::SchemaVersion {
            found: t.schema_version,
            expected: crate::SCHEMA_VERSION,
        });
    }
                                                                                                        
                                                                                                      
    validate_topology_content(&t).map_err(TopologyError::Validation)?;
    Ok(t)
}

/// Render a [`Topology`] back to the TOML box-init parses at boot — the inverse of [`parse_topology`].
/// image-builder bakes the result into the signed rootfs from a validated manifest's boot-hooks.
                     
/// The round-trip `render_topology` → `parse_topology` is identity (tested), so the
/// bake reproduces exactly what box-init will accept; the typed `Placeholder`s survive the round-trip.
pub fn render_topology(t: &Topology) -> Result<String, toml::ser::Error> {
    toml::to_string(t)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::argv::{ArgvToken, KnownPlaceholder};
    use crate::manifest::{
        ByteSize, EngineLeaf, OnFailure, PersistDir, Priv, ResourceDomain, Uid, WorkSubtree,
    };

    const VALID: &str = r#"
schema_version = 1
[[boot_hooks]]
name = "set-hostname"
binary = "/usr/bin/fb-oneshots"
argv = [ { literal = { value = "set-hostname" } }, { literal = { value = "--fallback" } }, { placeholder = { name = "domain" } } ]
priv = { root = {} }
order = 10
timeout_secs = 5
on_failure = { rescue = {} }
[[persist]]
path = "app"
uid = 100
mode = 0o700
"#;

    #[test]
    fn parses_a_valid_topology_keeping_the_placeholder() {
        let t = parse_topology(VALID).expect("valid topology parses");
        assert_eq!(t.schema_version, 1);
        assert_eq!(t.boot_hooks.len(), 1);
        let h = &t.boot_hooks[0];
        assert_eq!(h.name, "set-hostname");
        assert_eq!(h.privilege, Priv::Root {});
        assert_eq!(h.on_failure, OnFailure::Rescue {});
                                                                                                      
        assert_eq!(
            h.argv[2],
            ArgvToken::Placeholder {
                name: KnownPlaceholder::Domain
            }
        );
                                                                                                    
        assert_eq!(t.persist.len(), 1);
        assert_eq!(t.persist[0].path, "app");
        assert_eq!(t.persist[0].uid, 100);
    }

    #[test]
    fn an_empty_boot_hook_list_is_valid() {
                                                                                                       
        let t = parse_topology("schema_version = 1\nboot_hooks = []\npersist = []\n")
            .expect("empty hooks ok");
        assert!(t.boot_hooks.is_empty());
    }

    #[test]
    fn a_missing_persist_section_is_refused() {
                                                                                                     
                                                 
        let bad = VALID.replace("[[persist]]\npath = \"app\"\nuid = 100\nmode = 0o700\n", "");
        assert_ne!(bad, VALID, "the persist block must be present to drop");
        assert!(matches!(parse_topology(&bad), Err(TopologyError::Parse(_))));
    }

    #[test]
    fn a_shell_metacharacter_in_a_persist_path_is_refused() {
                                                                                             
                                                                                                         
                                                                                                  
        let bad = VALID.replace("path = \"app\"", "path = \"app; reboot\"");
        assert_ne!(bad, VALID);
        assert!(matches!(
            parse_topology(&bad),
            Err(TopologyError::Validation(_))
        ));
    }

    #[test]
    fn a_shell_metacharacter_in_a_boot_hook_argv_is_refused() {
                                                                                                     
        let bad = VALID.replace("value = \"set-hostname\"", "value = \"x; reboot\"");
        assert_ne!(bad, VALID);
        assert!(matches!(
            parse_topology(&bad),
            Err(TopologyError::Validation(_))
        ));
    }

    #[test]
    fn a_shell_metacharacter_in_the_resource_domain_name_is_refused() {
                                                                                                     
                                                                                               
        let bad = r#"
schema_version = 1
boot_hooks = []
persist = []
[resource_domain]
name = "dha; reboot"
memory_max = 8000000000
delegate_uid = 110
[resource_domain.work]
orchestrator = "dha-orchestrator"
job_memory_max = 512000000
max_descendants = 16
max_depth = 2
work_pids_max = 256
"#;
        assert!(matches!(
            parse_topology(bad),
            Err(TopologyError::Validation(_))
        ));
    }

    #[test]
    fn a_resource_domain_name_escaping_the_cgroup_root_is_refused_at_parse() {
                                                                                              
                                                                                                             
        let bad = r#"
schema_version = 1
boot_hooks = []
persist = []
[resource_domain]
name = "/run/evil"
memory_max = 8000000000
delegate_uid = 110
[resource_domain.work]
orchestrator = "dha-orchestrator"
job_memory_max = 512000000
max_descendants = 16
max_depth = 2
work_pids_max = 256
"#;
        assert!(matches!(
            parse_topology(bad),
            Err(TopologyError::Validation(_))
        ));
    }

    #[test]
    fn a_wrong_schema_version_is_refused() {
        let bad = VALID.replace("schema_version = 1", "schema_version = 99");
        assert!(matches!(
            parse_topology(&bad),
            Err(TopologyError::SchemaVersion {
                found: 99,
                expected: 1
            })
        ));
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let bad = format!("backdoor = true\n{VALID}");
        assert!(matches!(parse_topology(&bad), Err(TopologyError::Parse(_))));
    }

    #[test]
    fn a_missing_schema_version_is_refused() {
        let bad = VALID.replace("schema_version = 1\n", "");
        assert!(matches!(parse_topology(&bad), Err(TopologyError::Parse(_))));
    }

    #[test]
    fn an_unknown_field_in_a_boot_hook_is_refused() {
        let bad = VALID.replace(
            "name = \"set-hostname\"",
            "evil = 1\nname = \"set-hostname\"",
        );
        assert!(matches!(parse_topology(&bad), Err(TopologyError::Parse(_))));
    }

    #[test]
    fn render_then_parse_is_identity() {
                                                                                                    
                                                                                                      
        let t = parse_topology(VALID).expect("valid topology parses");
        let rendered = render_topology(&t).expect("topology serializes to toml");
        let reparsed = parse_topology(&rendered).expect("the rendered topology re-parses");
        assert_eq!(t, reparsed);
    }

    #[test]
    fn render_then_parse_roundtrips_every_variant() {
                                                                                               
                                                                                                      
                                                                                                     
                                                                                                      
                                                                                                           
        use crate::argv::ArgvFragment;
        let t = Topology {
            schema_version: 1,
            boot_hooks: vec![
                BootHook {
                    name: "h-root".into(),
                    binary: "/bin/a".into(),
                    argv: vec![
                        ArgvToken::Literal { value: "x".into() },
                        ArgvToken::Placeholder {
                            name: KnownPlaceholder::Domain,
                        },
                        ArgvToken::Template {
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
                        },
                    ],
                    privilege: Priv::Root {},
                    order: 10,
                    timeout_secs: 5,
                    on_failure: OnFailure::Rescue {},
                },
                BootHook {
                    name: "h-drop".into(),
                    binary: "/bin/b".into(),
                    argv: vec![],
                    privilege: Priv::Setuidgid {
                        user: "recipes".into(),
                        envdir: Some("/etc/recipes/env".into()),
                    },
                    order: 20,
                    timeout_secs: 30,
                    on_failure: OnFailure::Reboot {},
                },
                BootHook {
                    name: "h-drop2".into(),
                    binary: "/bin/c".into(),
                    argv: vec![ArgvToken::Literal { value: "y".into() }],
                    privilege: Priv::Setuidgid {
                        user: "fb-acme".into(),
                        envdir: None,
                    },
                    order: 30,
                    timeout_secs: 30,
                    on_failure: OnFailure::Rescue {},
                },
            ],
            persist: vec![PersistDir {
                path: "app".into(),
                uid: 100,
                mode: 0o700,
            }],
            resource_domain: Some(ResourceDomain {
                name: "dha".into(),
                memory_max: ByteSize(8_000_000_000),
                delegate_uid: Uid(110),
                engine: Some(EngineLeaf {
                    service: "dha-creatine".into(),
                    memory_max: ByteSize(6_000_000_000),
                    memory_min: Some(ByteSize(4_000_000_000)),
                    oom_group: true,
                }),
                work: WorkSubtree {
                    orchestrator: "dha-orchestrator".into(),
                    orch_memory_min: Some(ByteSize(64_000_000)),
                    job_memory_max: ByteSize(512_000_000),
                    job_pids_max: Some(64),
                    max_descendants: 16,
                    max_depth: 2,
                    work_pids_max: 256,
                },
            }),
        };
        let rendered = render_topology(&t).expect("topology with every variant serializes");
        let reparsed = parse_topology(&rendered).expect("re-parses");
        assert_eq!(
            t, reparsed,
            "render→parse must be identity\n--- rendered ---\n{rendered}"
        );
    }
}

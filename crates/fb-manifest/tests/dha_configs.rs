//! Task 1 (dha real-binary integration) — the `box.json` + runtime-config manifest schema blocks +
//! the `ServiceShape::Exec` inline `env` list.
//!
//! Proves the SEAM CONTRACT the box-side render (Task 4) + creatine env render (Task 5) consume:
//! - a dha manifest carries `box_config` + `runtime_config` (both `Some`) and the creatine service
//!   declares an inline `env` list;
        
//! - a non-dha manifest omits all three (`None`) — the byte-identity opt-in property at the
//!   schema layer (an absent block never appears);
//! - an unknown field inside a config block fails closed (`deny_unknown_fields`);
//! - the gate VALIDATES the new blocks — an `Exec.env` key runs through the same `validate_env_key`
//!   allowlist as `[env.vars]` (a forbidden `LD_*` is refused), and a config path field runs through
//!   `validate_path_token` (a `..` traversal is refused).
//!
//! Uses the real fail-closed gate [`parse_and_validate`] (not a bare parse) so the tests exercise both
//! the typed shape AND the §5.3 validation wiring. The fixtures mirror lib.rs's `VALID_DHA` / `VALID`
//! gate fixtures (which are `#[cfg(test)]`-private to the crate) with the new blocks added.

use fb_manifest::manifest::{Manifest, ServiceShape};
use fb_manifest::validate::ValidationError;
use fb_manifest::{BakeError, OsIdentities, parse_and_validate};

/// The OS-fixed identity set (root + the OS-infra service uids), mirroring lib.rs's gate-test `os()`.
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

/// A complete valid dha manifest (mirrors lib.rs `VALID_DHA`) EXTENDED with the two config blocks and
/// an inline `env` on the creatine service — the shapes Task 4/Task 5 render from.
const DHA: &str = r#"
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
shape = { exec = { binary = "/usr/bin/dha-creatine", argv = [], priv = { setuidgid = { user = "dha" } }, env = [ { key = "CREATINE_BIND", value = "unix:/run/creatine/creatine.sock" }, { key = "CREATINE_MODEL_PATH", value = "/models/model.gguf" } ] } }
[[services]]
name = "dha-orchestrator"
shape = { exec = { binary = "/usr/bin/dha-orchestrator", argv = [ { literal = { value = "/etc/dha/box.json" } }, { literal = { value = "/etc/dha/runtime.json" } } ], priv = { setuidgid = { user = "dha" } } } }
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
[box_config]
sensitive = true
tier_b = false
root = "/persist/dha/root"
secrets = "/persist/dha/secrets"
git = false
creatine_mode = "uds"
[runtime_config]
max_jobs = 4
max_conns = 8
[runtime_config.client]
kind = "epa"
program = "/usr/bin/epa"
config = "/etc/dha/epa.toml"
[runtime_config.creatine]
memory_events = "/sys/fs/cgroup/dha/creatine/memory.events"
uds = "/run/creatine/creatine.sock"
service_dir = "/etc/box-svc/creatine"
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

/// A valid non-dha (recipes-only) manifest (mirrors lib.rs `VALID`): no config blocks, no inline env.
const RECIPES_ONLY: &str = r#"
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

fn exec_env<'a>(m: &'a Manifest, service: &str) -> &'a Option<Vec<fb_manifest::manifest::EnvKv>> {
    let svc = m
        .services
        .iter()
        .find(|s| s.name == service)
        .unwrap_or_else(|| panic!("service {service} present"));
    match &svc.shape {
        ServiceShape::Exec { env, .. } => env,
        _ => panic!("service {service} is an Exec"),
    }
}

#[test]
fn dha_manifest_parses_both_config_blocks_and_creatine_env() {
    let vm = parse_and_validate(DHA, &os()).expect("dha manifest parses + validates");
    let m = vm.manifest();
    assert!(m.box_config.is_some(), "box_config present");
    assert!(m.runtime_config.is_some(), "runtime_config present");
    let env = exec_env(m, "dha-creatine")
        .as_ref()
        .expect("creatine declares an inline env");
    assert_eq!(env.len(), 2);
    assert_eq!(env[0].key, "CREATINE_BIND");
    assert_eq!(env[0].value, "unix:/run/creatine/creatine.sock");
    assert_eq!(env[1].key, "CREATINE_MODEL_PATH");
                                                                          
    let rc = m.runtime_config.as_ref().unwrap();
    assert_eq!(rc.max_jobs, 4);
    assert_eq!(rc.client.program, "/usr/bin/epa");
    assert_eq!(rc.creatine.uds, "/run/creatine/creatine.sock");
    assert!(rc.socket_path.is_none());                                                    
}

#[test]
fn non_dha_manifest_has_no_config_blocks_and_empty_env() {
    let vm = parse_and_validate(RECIPES_ONLY, &os()).expect("recipes-only manifest validates");
    let m = vm.manifest();
    assert!(m.box_config.is_none() && m.runtime_config.is_none());
                                                                                           
    assert!(exec_env(m, "recipes").is_none());
}

#[test]
fn unknown_field_in_box_config_fails_closed() {
                                                                                                       
    let bad = DHA.replace("sensitive = true", "sensitive = true\nbogus = 1");
    assert!(matches!(
        parse_and_validate(&bad, &os()),
        Err(BakeError::Parse(_))
    ));
}

#[test]
fn a_forbidden_env_key_on_exec_env_is_refused() {
                                                                                                         
                                                                                                        
    let bad = DHA.replace("CREATINE_BIND", "LD_PRELOAD");
    assert!(matches!(
        parse_and_validate(&bad, &os()),
        Err(BakeError::Validation(
            ValidationError::EnvKeyForbidden { .. }
        ))
    ));
}

#[test]
fn a_control_char_in_an_exec_env_value_is_refused() {
                                                                                                         
                                          
    let bad = DHA.replace("unix:/run/creatine/creatine.sock", "a\\nb");
                                                                                                          
    assert!(matches!(
        parse_and_validate(&bad, &os()),
        Err(BakeError::Validation(
            ValidationError::EnvValueControl { .. }
        ))
    ));
}

#[test]
fn box_config_without_runtime_config_is_refused() {
                                                                                                       
                                                                                
    let asymmetric = format!(
        "{RECIPES_ONLY}\n[box_config]\nsensitive = true\ntier_b = false\nroot = \"/persist/dha\"\n\
         secrets = \"/run/dha-secrets\"\ngit = false\ncreatine_mode = \"uds\"\n"
    );
    assert!(matches!(
        parse_and_validate(&asymmetric, &os()),
        Err(BakeError::Validation(
            ValidationError::DhaConfigIncomplete { .. }
        ))
    ));
}

#[test]
fn a_traversal_in_a_config_path_is_refused() {
                                                                                                    
                                                                                    
    let bad = DHA.replace(
        r#"root = "/persist/dha/root""#,
        r#"root = "/persist/../etc""#,
    );
    assert!(matches!(
        parse_and_validate(&bad, &os()),
        Err(BakeError::Validation(ValidationError::PathTraversal { .. }))
    ));
}

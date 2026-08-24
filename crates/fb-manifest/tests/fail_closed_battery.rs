                   
//! §5.3 — the CO-PRIMARY fail-closed battery: the PRIMARY guard is BOTH
//! (a) unknown-field-at-every-depth with adversarial field order AND (b) missing-required-field at
//! every depth. Inputs are HAND-CRAFTED (NOT a serialize-then-deserialize round-trip, which emits
//! tag-first and fills every field — insufficient for either axis per §5.3). Parse-level only
//! (`toml::from_str::<Manifest>`): this proves the serde shape is fail-closed BEFORE the gate's
//! cross-field validators even run.

use fb_manifest::manifest::Manifest;

fn parses(s: &str) -> bool {
    toml::from_str::<Manifest>(s).is_ok()
}

/// A complete, minimal, VALID manifest (every required field present, all containers possibly empty).
const BASE: &str = r#"
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
shape = { exec = { binary = "/usr/bin/recipes", argv = [], priv = { setuidgid = { user = "recipes" } } } }
[[boot_hooks]]
name = "set-hostname"
binary = "/usr/bin/fb-oneshots"
argv = []
priv = { root = {} }
order = 10
timeout_secs = 5
on_failure = { rescue = {} }
[edge]
backend = "127.0.0.1:8000"
ca_file = "/persist/recipes/ca.crt"
redacted_paths = []
redacted_query_params = []
mtls_paths = []
throttle_rules = []
[[persist]]
path = "recipes"
uid = 100
mode = 0
[backup]
sources = []
[probe]
port = 443
path = "/"
[nftables]
tcp_ports = [ 80 ]
"#;

#[test]
fn the_base_manifest_is_valid() {
    assert!(
        parses(BASE),
        "the BASE fixture must parse — otherwise the negative tests are vacuous"
    );
}

                                                                

#[test]
fn unknown_field_at_top_level_refused_either_position() {
                                                                                                      
                                                                                       
    assert!(
        !parses(&format!("backdoor = true\n{BASE}")),
        "unknown field first must refuse"
    );
    assert!(
        !parses(&format!("{BASE}\nbackdoor = true")),
        "unknown field last must refuse"
    );
}

#[test]
fn unknown_field_in_deeply_nested_setuidgid_refused() {
                                                                                                      
                    
    let bad = BASE.replace(
        r#"priv = { setuidgid = { user = "recipes" } }"#,
        r#"priv = { setuidgid = { evil = 1, user = "recipes" } }"#,
    );
    assert_ne!(bad, BASE, "the replace must have matched");
    assert!(!parses(&bad), "an unknown field in setuidgid must refuse");
}

#[test]
fn unknown_field_in_service_shape_exec_refused() {
                                                                                         
    let bad = BASE.replace("exec = { binary", "exec = { evil = 1, binary");
    assert_ne!(bad, BASE, "the replace must have matched");
    assert!(
        !parses(&bad),
        "an unknown field in the Exec variant must refuse"
    );
}

#[test]
fn unknown_field_in_an_empty_struct_variant_refused() {
                                                                                                  
    let bad = BASE.replace("priv = { root = {} }", "priv = { root = { evil = 1 } }");
    assert_ne!(bad, BASE);
    assert!(
        !parses(&bad),
        "trailing junk in an empty-struct variant must refuse"
    );
}

                                                      

#[test]
fn missing_required_top_level_section_refused() {
    for section in [
        "[probe]\nport = 443\npath = \"/\"\n",
        "[nftables]\ntcp_ports = [ 80 ]\n",
        "[backup]\nsources = []\n",
    ] {
        let bad = BASE.replace(section, "");
        assert_ne!(bad, BASE, "the section {section:?} must be present to drop");
        assert!(
            !parses(&bad),
            "dropping the required section {section:?} must refuse"
        );
    }
}

#[test]
fn missing_required_nested_field_refused() {
                                                                                              
    let bad = BASE.replace(r#"setuidgid = { user = "recipes" }"#, "setuidgid = { }");
    assert_ne!(bad, BASE);
    assert!(
        !parses(&bad),
        "a setuidgid missing its required `user` must refuse"
    );

                                                                          
    let bad2 = BASE.replace("order = 10\n", "");
    assert_ne!(bad2, BASE);
    assert!(
        !parses(&bad2),
        "a boot hook missing its required `order` must refuse"
    );

                                                
    let bad3 = BASE.replace("name = \"recipes\"\nuid = 100", "name = \"recipes\"");
    assert_ne!(bad3, BASE);
    assert!(
        !parses(&bad3),
        "an identity missing its required `uid` must refuse"
    );
}

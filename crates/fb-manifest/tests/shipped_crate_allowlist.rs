//! Crypto-supply allowlist (CLOSED SET) for the Fruit Basket ship-and-build dependency trees.
//!
//! This was a 4-name blocklist (`no_forbidden_crypto_deps`: openssl-sys / native-tls / aws-lc-*).
//! A blocklist answers "is this KNOWN-bad crate absent?" and silently passes everything it did not
//! enumerate — a *renamed* C-crypto crate, a new TLS backend, a transitive surprise. This is the
//! allowlist counter-pattern (cf. `rambutan/tests/tree_lock.rs`): assert the shipped crate set is
                       
//! *exactly* the listed crates, so any addition (new, renamed, transitive) trips the suite
//! loudly and forces a deliberate decision. The threat is unchanged (the Phase-0.5 surface cut: no
//! TLS C-stack; the ACME client and all in-image binaries use rustls + the pure-`ring` provider, so
//! `ring` / `rustls` / `rustls-webpki` / `webpki-roots` are sanctioned and ARE listed, while
//! `openssl-sys`/`native-tls`/`aws-lc-*` are not — their entry, or a rename, is an unlisted member →
//! RED); the mechanism moves from "deny 4 names" to "the set is closed" — strictly stronger on the
//! name axis (a *renamed* C-crypto crate now trips) and matched on the build axis (see Scope below).
//!
//! NOTE on `openssl-probe`: it IS in the workspace set (pulled by `instant-acme` →
//! `rustls-platform-verifier` → `rustls-native-certs`). It is a pure-Rust crate that probes the
//! filesystem for the system CA-bundle PATH — it does NOT link `openssl-sys` or any C crypto, so it
//! is not a surface-cut violation (the old blocklist correctly passed it). It is locked here like any
//! other shipped crate.
//!
//! Four trees, each pinned to its real ship target so the set is host-independent:
//!   * the Fruit Basket workspace (fb-acme / fb-cert-check / fb-backup / fb-oneshots / fb-manifest) —
//!     musl box userland (`x86_64-unknown-linux-musl`; gnu and musl resolve identically);
//!   * `box-init` and `initramfs-init` — the crt-static musl PID-1 / installer standalones
//!     (`x86_64-unknown-linux-musl`); and
//!   * `rambutan` — the UEFI loader standalone (`x86_64-unknown-uefi`; mirrors its own tree_lock).
//!
//! ## Scope — what the closed set covers, and what it deliberately does NOT
//!
//! Per tree, two edge sets, each pinned to its ship target and resolved `--locked` (a stale lock
//! fails loud, never a silent re-resolve):
//!   * `--edges normal` == `*_SHIPPED` — what links into the artifact.
//!   * `--edges normal,build` == `*_SHIPPED` ∪ `*_BUILD_ONLY` — what ships OR runs in the build. The
//!     workspace build-only delta is the sanctioned host build toolchain (cc / bindgen / clang-sys /
//!     pkg-config / vcpkg + the build-script version probes); a NEW build-time C-FFI crate (e.g.
//!     `openssl-sys` via `[build-dependencies]`, dragging the C toolchain into the image build) is an
//!     unlisted member → RED. This is the axis the old `Cargo.lock`-text scan covered and the
//!     `--edges normal` cut had dropped. (The box-init / initramfs-init standalones have an EMPTY
//!     build-only delta — their build chains carry no toolchain, and the closed set keeps it that way.)
//!
//! Out of scope BY DESIGN (named per the Safeguards rule — a replacement that narrows coverage must
//! say so): **dev-dependencies** (host-only `cargo test` tooling) and **non-ship-target** crates
//! (macOS/Windows-cfg crypto-FFI such as `security-framework-sys` / `schannel`, present in
//! `Cargo.lock` via `rustls-platform-verifier` but never compiled for the musl box or the UEFI
//! loader). Granularity is crate-NAME level by design. Update the arrays ONLY alongside an audited
//! dependency change.

use std::collections::BTreeSet;
use std::process::Command;

/// The exact shipped set (normal edges) of the Fruit Basket workspace, resolved for the box userland.
const WORKSPACE_SHIPPED: &[&str] = &[
    "adler2",
    "allocator-api2",
    "anstream",
    "anstyle",
    "anstyle-parse",
    "anstyle-query",
    "anyhow",
    "asn1-rs",
    "asn1-rs-derive",
    "asn1-rs-impl",
    "async-trait",
    "atoi",
    "atomic-waker",
    "axum",
    "axum-core",
    "base64",
    "bitflags",
    "block-buffer",
    "bytes",
    "cfg-if",
    "chrono",
    "clap",
    "clap_builder",
    "clap_derive",
    "clap_lex",
    "colorchoice",
    "concurrent-queue",
    "cpufeatures",
    "crc",
    "crc32fast",
    "crc-catalog",
    "crossbeam-queue",
    "crossbeam-utils",
    "crypto-common",
    "curve25519-dalek",
    "curve25519-dalek-derive",
    "data-encoding",
    "deranged",
    "der-parser",
    "digest",
    "displaydoc",
    "ed25519",
    "ed25519-dalek",
    "either",
    "equivalent",
    "errno",
    "event-listener",
    "fb-acme",
    "fb-backup",
    "fb-cert-check",
    "fb-manifest",
    "fb-oneshots",
    "filetime",
    "flate2",
    "flume",
    "fnv",
    "foldhash",
    "form_urlencoded",
    "futures-channel",
    "futures-core",
    "futures-executor",
    "futures-intrusive",
    "futures-io",
    "futures-sink",
    "futures-task",
    "futures-util",
    "generic-array",
    "getrandom",
    "grape",
    "h2",
    "hashbrown",
    "hashlink",
    "heck",
    "hkdf",
    "hmac",
    "http",
    "httparse",
    "http-body",
    "http-body-util",
    "httpdate",
    "http-range-header",
    "hyper",
    "hyper-rustls",
    "hyper-util",
    "iana-time-zone",
    "icu_collections",
    "icu_locale_core",
    "icu_normalizer",
    "icu_normalizer_data",
    "icu_properties",
    "icu_properties_data",
    "icu_provider",
    "idna",
    "idna_adapter",
    "indexmap",
    "instant-acme",
    "is_terminal_polyfill",
    "itoa",
    "lazy_static",
    "libc",
    "libsqlite3-sys",
    "linux-raw-sys",
    "litemap",
    "lock_api",
    "log",
    "matchit",
    "memchr",
    "mime",
    "mime_guess",
    "minimal-lexical",
    "miniz_oxide",
    "mio",
    "nom",
    "num-bigint",
    "num-conv",
    "num-integer",
    "num-traits",
    "oid-registry",
    "once_cell",
    "openssl-probe",
    "parking",
    "parking_lot",
    "parking_lot_core",
    "pem",
    "percent-encoding",
    "pin-project-lite",
    "potential_utf",
    "powerfmt",
    "proc-macro2",
    "quote",
    "rcgen",
    "ring",
    "rusticata-macros",
    "rustix",
    "rustls",
    "rustls-native-certs",
    "rustls-pki-types",
    "rustls-platform-verifier",
    "rustls-webpki",
    "ryu",
    "scopeguard",
    "serde",
    "serde_core",
    "serde_derive",
    "serde_json",
    "serde_spanned",
    "serde_urlencoded",
    "sha2",
    "signal-hook-registry",
    "signature",
    "simd-adler32",
    "slab",
    "smallvec",
    "socket2",
    "spin",
    "sqlx",
    "sqlx-core",
    "sqlx-sqlite",
    "stable_deref_trait",
    "strsim",
    "subtle",
    "syn",
    "sync_wrapper",
    "synstructure",
    "tar",
    "thiserror",
    "thiserror-impl",
    "time",
    "time-core",
    "time-macros",
    "tinystr",
    "tokio",
    "tokio-macros",
    "tokio-rustls",
    "tokio-stream",
    "tokio-util",
    "toml",
    "toml_datetime",
    "toml_edit",
    "toml_write",
    "tower",
    "tower-http",
    "tower-layer",
    "tower-service",
    "tracing",
    "tracing-attributes",
    "tracing-core",
    "try-lock",
    "typenum",
    "unicase",
    "unicode-ident",
    "untrusted",
    "url",
    "utf8_iter",
    "utf8parse",
    "want",
    "webpki-roots",
    "winnow",
    "writeable",
    "x509-parser",
    "xattr",
    "yasna",
    "yoke",
    "yoke-derive",
    "zerofrom",
    "zerofrom-derive",
    "zeroize",
    "zerotrie",
    "zerovec",
    "zerovec-derive",
    "zmij",
];

/// The build-only delta for the Fruit Basket workspace: the sanctioned host build toolchain
/// (cc / bindgen / clang-sys / pkg-config / vcpkg + bindgen's `regex`/`itertools`/… subtree + the
/// build-script version probes). Its own short list so the build-time C surface is reviewable; a NEW
/// build-time C-FFI crate (openssl-sys, native-tls, …) is a DISTINCT name absent from both lists →
/// ENTERED → RED.
const WORKSPACE_BUILD_ONLY: &[&str] = &[
    "autocfg",
    "bindgen",
    "cc",
    "cexpr",
    "clang-sys",
    "find-msvc-tools",
    "glob",
    "itertools",
    "lazycell",
    "libloading",
    "pkg-config",
    "regex",
    "regex-automata",
    "regex-syntax",
    "rustc-hash",
    "rustc_version",
    "semver",
    "shlex",
    "vcpkg",
    "version_check",
];

/// The exact shipped set of the `box-init` standalone (the musl PID-1 that parses the baked manifest
/// topology at boot), resolved for the box target.
const BOX_INIT_SHIPPED: &[&str] = &[
    "bitflags",
    "box-init",
    "equivalent",
    "fb-manifest",
    "hashbrown",
    "indexmap",
    "libc",
    "linux-raw-sys",
    "proc-macro2",
    "quote",
    "rustix",
    "serde",
    "serde_core",
    "serde_derive",
    "serde_spanned",
    "syn",
    "toml",
    "toml_datetime",
    "toml_edit",
    "toml_write",
    "unicode-ident",
    "winnow",
];

/// The build-only delta for `box-init`: EMPTY by design — the musl PID-1 carries no build toolchain
/// (its build-deps are all also normal-edge deps). A build-time C-FFI crate appearing here would be
/// an unlisted member → RED, keeping the PID-1 build chain toolchain-free.
const BOX_INIT_BUILD_ONLY: &[&str] = &[];

/// The exact shipped set of the `initramfs-init` standalone (the pure-Rust installer / initramfs
/// PID-1). C1 added the VERIFY-ONLY `dragonfruit` closure (`quince` → `dragonfruit`, ed25519 /
/// curve25519 / sha2 + the derive-macro deps) for the restore-from tarball verify; the `sign` feature
/// is NEVER in this graph — the box-never-signs CRUX. (`sign` and the bundle-minting test deps are
/// pulled ONLY by dev-dependencies, the excluded `--edges dev` axis, so they never appear here.)
/// The hotswap v4 extraction (§9/R3-I7) moved the runtime dm-verity + PARTUUID layer into
/// `fb-verity-rt` (libc-only, no new transitive deps) — deliberately enrolled here.
const INITRAMFS_INIT_SHIPPED: &[&str] = &[
    "block-buffer",
    "cfg-if",
    "cpufeatures",
    "crypto-common",
    "curve25519-dalek",
    "curve25519-dalek-derive",
    "digest",
    "dragonfruit",
    "ed25519",
    "ed25519-dalek",
    "fb-verity-rt",
    "generic-array",
    "initramfs-init",
    "libc",
    "proc-macro2",
    "quince",
    "quote",
    "sha2",
    "signature",
    "subtle",
    "syn",
    "thiserror",
    "thiserror-impl",
    "typenum",
    "unicode-ident",
    "zeroize",
];

/// The build-only delta for `initramfs-init`: the curve25519-dalek build-script version probes
/// (`rustc_version` → `semver`; `version_check`) — all pure-Rust, all already in the workspace
/// build-only set. NOT empty since C1 (the verify closure carries these probes); a `sign`-only crate
/// or a NEW build-time C-FFI crate appearing here is an unlisted member → RED, keeping the installer
/// build chain free of a C toolchain.
const INITRAMFS_INIT_BUILD_ONLY: &[&str] = &["rustc_version", "semver", "version_check"];

/// The exact shipped set of the `rambutan` UEFI loader standalone. Mirrors
/// `crates/rambutan/tests/tree_lock.rs`.
const RAMBUTAN_SHIPPED: &[&str] = &[
    "block-buffer",
    "cfg-if",
    "cpufeatures",
    "crypto-common",
    "digest",
    "generic-array",
    "rambutan",
    "sha2",
    "typenum",
];

/// The build-only delta for the `rambutan` UEFI loader: just the `version_check` build-script probe.
/// The loader build chain must stay pure-Rust; a C-FFI build-dep here is an unlisted member → RED.
const RAMBUTAN_BUILD_ONLY: &[&str] = &["version_check"];

/// The exact shipped set of the `fb-update` standalone (os-update A/B v1 — the box-side A/B update
/// engine). It carries the SAME verify-only `dragonfruit` closure as initramfs-init (`quince` →
/// `dragonfruit`, ed25519 / curve25519 / sha2 + the derive-macro deps) for the update-manifest verify;
/// the `sign` feature is NEVER in this graph — the box-never-signs CRUX (both the crate's own poisoned
/// `sign` feature `compile_error!` and the feature sweep below enforce it).
///
/// **Both bins ship from this ONE crate** (`fb-update` apply/status/reconcile-floors + `fb-mark-good`
/// the probation longrun): the S8 decision NOT to split fb-mark-good into a crypto-free crate means
/// `fb-mark-good`'s tree legitimately includes quince/dragonfruit (dead verify code it never calls) —
/// accepted, since dragonfruit already ships via initramfs-init and the CRUX guard covers both bins
/// regardless. `cargo tree` resolves the PACKAGE, so this one set locks both binary targets.
const FB_UPDATE_SHIPPED: &[&str] = &[
                                                                     
    "block-buffer",
    "cfg-if",
    "cpufeatures",
    "crypto-common",
    "curve25519-dalek",
    "curve25519-dalek-derive",
    "digest",
    "dragonfruit",
    "ed25519",
    "ed25519-dalek",
    "fb-update",
    "generic-array",
    "libc",
    "proc-macro2",
    "quince",
    "quote",
    "sha2",
    "signature",
    "subtle",
    "syn",
    "thiserror",
    "thiserror-impl",
    "typenum",
    "unicode-ident",
    "zeroize",
                                                                                     
                                                                                       
                                                                                     
                                                                                   
                                                                                     
                                                                                    
    "asn1-rs",
    "asn1-rs-derive",
    "asn1-rs-impl",
    "data-encoding",
    "der-parser",
    "deranged",
    "displaydoc",
    "getrandom",
    "lazy_static",
    "memchr",
    "minimal-lexical",
    "nom",
    "num-bigint",
    "num-conv",
    "num-integer",
    "num-traits",
    "oid-registry",
    "once_cell",
    "powerfmt",
    "ring",
    "rusticata-macros",
    "rustls",
    "rustls-pki-types",
    "rustls-webpki",
    "synstructure",
    "time",
    "time-core",
    "time-macros",
    "untrusted",
    "x509-parser",
];

/// The build-only delta for `fb-update`: the curve25519-dalek build-script version probes (identical
/// to initramfs-init's) + ring's build script (`cc`/`shlex`/`find-msvc-tools` — ring compiles its own
/// vendored asm; the ONE sanctioned C-toolchain build edge, same as the fb-acme tree) + `autocfg`
/// (num-* version probes). A NEW build-time C-FFI crate beyond ring's own build here → RED.
const FB_UPDATE_BUILD_ONLY: &[&str] = &[
    "autocfg",
    "cc",
    "find-msvc-tools",
    "rustc_version",
    "semver",
    "shlex",
    "version_check",
];

/// fb-weights (hotswap v4) shipped/normal set — the quince→dragonfruit VERIFY-ONLY closure
/// (identical to initramfs-init's crypto set) + `fb-verity-rt` (the extracted runtime verity/
/// partuuid/teardown). NO rustls/x509 (fb-weights carries no fb-mark-good-style TLS probe), and NO
/// `fb-update` (a distinct standalone). The `sign`-feature dragonfruit is confined to
/// `[dev-dependencies]` (the excluded `--edges dev` axis), so it never appears here — box-never-signs
                
/// holds, and this closed set now GUARDS a regression.
const FB_WEIGHTS_SHIPPED: &[&str] = &[
    "block-buffer",
    "cfg-if",
    "cpufeatures",
    "crypto-common",
    "curve25519-dalek",
    "curve25519-dalek-derive",
    "digest",
    "dragonfruit",
    "ed25519",
    "ed25519-dalek",
    "fb-verity-rt",
    "fb-weights",
    "generic-array",
    "libc",
    "proc-macro2",
    "quince",
    "quote",
    "sha2",
    "signature",
    "subtle",
    "syn",
    "thiserror",
    "thiserror-impl",
    "typenum",
    "unicode-ident",
    "zeroize",
];

/// The build-only delta for `fb-weights`: the curve25519-dalek/num version probes (`rustc_version`
/// → `semver`, `version_check`). NO `cc`/`ring` — fb-weights ships no ring TLS stack, so it has no
/// build-time C-toolchain edge at all. A new C-FFI build-dep here → RED.
const FB_WEIGHTS_BUILD_ONLY: &[&str] = &["rustc_version", "semver", "version_check"];

const BOX_TARGET: &str = "x86_64-unknown-linux-musl";
const UEFI_TARGET: &str = "x86_64-unknown-uefi";

/// Repo root, relative to this crate (`crates/fb-manifest`).
fn workspace_root() -> String {
    format!("{}/../..", env!("CARGO_MANIFEST_DIR"))
}

/// Parse `cargo tree --prefix none` output into the set of crate names (first column per non-empty
/// line; `(*)` dedup markers and version columns dropped). A `BTreeSet` sorts and dedups.
fn parse_tree(tree: &str) -> BTreeSet<String> {
    tree.lines()
        .filter_map(|line| line.split_whitespace().next())
        .map(str::to_string)
        .collect()
}

/// Run `cargo tree` with the given args from `dir` and return the shipped crate-name set. Fails
/// closed: a non-zero exit panics rather than silently scanning an empty set.
fn cargo_tree_set(dir: &str, args: &[&str]) -> BTreeSet<String> {
    let out = Command::new(env!("CARGO"))
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap_or_else(|e| panic!("spawn `cargo tree {args:?}`: {e}"));
    assert!(
        out.status.success(),
        "`cargo tree {args:?}` failed (status {:?}): {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
    );
    parse_tree(&String::from_utf8(out.stdout).expect("cargo tree stdout is utf8"))
}

/// The closed-set comparison, factored out so `diff_self_test` exercises it without shelling out.
/// Returns `(entered, left)`: crates in `actual` but not allowlisted, and allowlisted but absent.
fn diff_against_allowlist(
    actual: &BTreeSet<String>,
    expected: &[&str],
) -> (Vec<String>, Vec<String>) {
    let expected_set: BTreeSet<&str> = expected.iter().copied().collect();
    let entered: Vec<String> = actual
        .iter()
        .filter(|c| !expected_set.contains(c.as_str()))
        .cloned()
        .collect();
    let left: Vec<String> = expected
        .iter()
        .filter(|c| !actual.contains(**c))
        .map(|c| c.to_string())
        .collect();
    (entered, left)
}

fn assert_closed_set(actual: &BTreeSet<String>, expected: &[&str], scope: &str) {
    let (entered, left) = diff_against_allowlist(actual, expected);
    assert!(
        entered.is_empty() && left.is_empty(),
        "dependency set for {scope} no longer matches the allowlist.\n  \
         ENTERED (in the tree, not allowlisted): {entered:?}\n  \
         LEFT (allowlisted, not in the tree):    {left:?}\n\
         \n  \
         This gate is a CLOSED SET, not a blocklist: every crate in scope must be listed, so a renamed\n  \
         or new C/TLS crypto stack (openssl-sys, native-tls, aws-lc-*, ...) — shipped OR a build-dep\n  \
         dragging in the C toolchain — cannot slip in unnoticed. If an ENTERED crate pulls a C/TLS\n  \
         crypto stack, pin rustls consumers to the `ring` provider and drop the dependency instead of\n  \
         listing it; if it is a build-time C-FFI crate, keep it out of the build. Otherwise the change\n  \
         is legitimate — update the allowlist DELIBERATELY (this red is the decision point), in the\n  \
         same commit as the audited dependency change."
    );
}

fn box_tree(manifest_path: &str, target: &str, edges: &str) -> BTreeSet<String> {
    cargo_tree_set(
        &workspace_root(),
        &[
            "tree",
            "--manifest-path",
            manifest_path,
            "--edges",
            edges,
            "--target",
            target,
            "--locked",
            "--prefix",
            "none",
        ],
    )
}

/// break-B C-1 (CRITICAL): the exact-set crate-NAME allowlists above are structurally BLIND to the
/// `sign` FEATURE — `dragonfruit`'s `sign = []` adds NO crate, so a one-line `features = ["sign"]` flip
/// on a box graph's dragonfruit dep compiles the private-key signer (`sign_delegation`/`sign_attestation`)
/// into the binary while the crate-name SET stays byte-identical, and every name-set gate stays green.
/// This guards the box-never-signs CRUX at the FEATURE level: parse the `{p}|{f}` feature column and
/// report whether `dragonfruit` requests `sign` anywhere in the resolved graph.
fn box_graph_requests_dragonfruit_sign(
    manifest_path: &str,
    target: &str,
    edges: &str,
    whole_workspace: bool,
) -> bool {
    let mut args = vec![
        "tree",
        "--manifest-path",
        manifest_path,
        "--edges",
        edges,
        "--target",
        target,
        "--locked",
        "--prefix",
        "none",
        "-f",
        "{p}|{f}",
    ];
                                                                                                         
                                                                                                    
                                                                                                      
    if whole_workspace {
        args.push("--workspace");
    }
    let out = Command::new(env!("CARGO"))
        .args(&args)
        .current_dir(workspace_root())
        .output()
        .unwrap_or_else(|e| panic!("spawn `cargo tree -f` for {manifest_path}: {e}"));
    assert!(
        out.status.success(),
        "`cargo tree -f` ({manifest_path}, --edges {edges}) failed: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    String::from_utf8(out.stdout)
        .expect("cargo tree -f stdout is utf8")
        .lines()
        .any(line_requests_dragonfruit_sign)
}

/// Pure predicate (self-testable, like `diff_self_test`): does a `cargo tree -f "{p}|{f}"` line show
/// `dragonfruit` carrying the `sign` feature? Extracted so the guard's firing is proven directly, without
/// flipping a real Cargo.toml.
fn line_requests_dragonfruit_sign(line: &str) -> bool {
    let Some((pkg, feats)) = line.split_once('|') else {
        return false;
    };
                                                                                                        
                                                                                                       
                                                                                                        
                                                                                                
    let feats = feats.trim_end().trim_end_matches("(*)");
    pkg.split_whitespace().next() == Some("dragonfruit")
        && feats.split(',').any(|f| f.trim() == "sign")
}

#[test]
fn workspace_shipped_set_is_exactly_the_allowlist() {
    let actual = cargo_tree_set(
        &workspace_root(),
        &[
            "tree",
            "--workspace",
            "--edges",
            "normal",
            "--target",
            BOX_TARGET,
            "--locked",
            "--prefix",
            "none",
        ],
    );
    assert_closed_set(
        &actual,
        WORKSPACE_SHIPPED,
        "the Fruit Basket workspace, shipped/normal edges (x86_64-unknown-linux-musl)",
    );
}

/// The build-edge closed set: `--edges normal,build` must equal `WORKSPACE_SHIPPED` ∪
/// `WORKSPACE_BUILD_ONLY`. Recovers the build-dependency axis the old `Cargo.lock`-text blocklist
/// covered (and the `--edges normal` shipped cut had dropped): a C-crypto stack entering via
/// `[build-dependencies]` (dragging the C toolchain into the image build) is an unlisted member → RED.
#[test]
fn workspace_build_edge_set_is_exactly_shipped_plus_build_tools() {
    let actual = cargo_tree_set(
        &workspace_root(),
        &[
            "tree",
            "--workspace",
            "--edges",
            "normal,build",
            "--target",
            BOX_TARGET,
            "--locked",
            "--prefix",
            "none",
        ],
    );
    let expected: Vec<&str> = WORKSPACE_SHIPPED
        .iter()
        .chain(WORKSPACE_BUILD_ONLY)
        .copied()
        .collect();
    assert_closed_set(
        &actual,
        &expected,
        "the Fruit Basket workspace, ship+build edges (x86_64-unknown-linux-musl)",
    );
}

#[test]
fn box_init_shipped_set_is_exactly_the_allowlist() {
    let actual = box_tree("crates/box-init/Cargo.toml", BOX_TARGET, "normal");
    assert_closed_set(
        &actual,
        BOX_INIT_SHIPPED,
        "the box-init standalone, shipped/normal edges (x86_64-unknown-linux-musl)",
    );
}

/// box-init build-edge closed set: `--edges normal,build` must equal `BOX_INIT_SHIPPED` ∪
/// `BOX_INIT_BUILD_ONLY` (empty) — i.e. the PID-1 build chain carries NO build toolchain; any
/// build-time C-FFI crate appearing here is an unlisted member → RED.
#[test]
fn box_init_build_edge_set_is_exactly_shipped_plus_build_tools() {
    let actual = box_tree("crates/box-init/Cargo.toml", BOX_TARGET, "normal,build");
    let expected: Vec<&str> = BOX_INIT_SHIPPED
        .iter()
        .chain(BOX_INIT_BUILD_ONLY)
        .copied()
        .collect();
    assert_closed_set(
        &actual,
        &expected,
        "the box-init standalone, ship+build edges (x86_64-unknown-linux-musl)",
    );
}

#[test]
fn initramfs_init_shipped_set_is_exactly_the_allowlist() {
    let actual = box_tree("crates/initramfs-init/Cargo.toml", BOX_TARGET, "normal");
    assert_closed_set(
        &actual,
        INITRAMFS_INIT_SHIPPED,
        "the initramfs-init standalone, shipped/normal edges (x86_64-unknown-linux-musl)",
    );
}

/// initramfs-init build-edge closed set: `--edges normal,build` must equal `INITRAMFS_INIT_SHIPPED`
/// ∪ `INITRAMFS_INIT_BUILD_ONLY` (empty) — the tightest tree stays `core` + `libc` with no build
/// toolchain; any build-time C-FFI crate here is an unlisted member → RED.
#[test]
fn initramfs_init_build_edge_set_is_exactly_shipped_plus_build_tools() {
    let actual = box_tree(
        "crates/initramfs-init/Cargo.toml",
        BOX_TARGET,
        "normal,build",
    );
    let expected: Vec<&str> = INITRAMFS_INIT_SHIPPED
        .iter()
        .chain(INITRAMFS_INIT_BUILD_ONLY)
        .copied()
        .collect();
    assert_closed_set(
        &actual,
        &expected,
        "the initramfs-init standalone, ship+build edges (x86_64-unknown-linux-musl)",
    );
}

/// The box-never-signs CRUX at the FEATURE level (break-B C-1). The crate-name allowlists prove the
/// signer CRATE is absent; THIS proves no box graph turns on dragonfruit's `sign` feature (which would
/// compile the signer into a box binary without changing the crate set). Coverage: the three box
/// standalones (`initramfs-init` — the only one carrying dragonfruit today, verify-only via quince, C1;
/// `box-init` / `rambutan` — none, but swept so a future pull-in is feature-guarded from day one), PLUS
/// the whole Fruit Basket root workspace in one `--workspace` sweep (fb-acme / fb-cert-check / fb-backup /
/// fb-oneshots / fb-manifest — none today; pre-guarded for a future verify path, e.g. fb-backup restore).
/// Both edge sets (normal, normal+build).
///
                  
/// SCOPE: the sweep resolves the SHIP targets only
/// (`x86_64-unknown-linux-musl` for the userland/PID-1, `x86_64-unknown-uefi` for the loader), matching
/// the crate-name allowlists above — NOT every rustc target. A `sign` feature enabled ONLY under a
/// not-yet-existing substrate cfg (a gnu/bare-metal `[target.'cfg(...)'.dependencies]` block) resolves
/// under a different `--target` and is OUT of this gate's view → forward-debt to the substrate-selector
                                                      
/// thread: add that target here when it lands.
#[test]
fn box_graphs_never_request_the_dragonfruit_sign_feature() {
                                                                                                     
                                                                                                       
                                                                                       
    for (mf, target) in [
        ("crates/initramfs-init/Cargo.toml", BOX_TARGET),
        ("crates/fb-update/Cargo.toml", BOX_TARGET),
                                                                                             
                                                                                                      
                                                                                            
                                                                               
        ("crates/fb-weights/Cargo.toml", BOX_TARGET),
        ("crates/box-init/Cargo.toml", BOX_TARGET),
        ("crates/rambutan/Cargo.toml", UEFI_TARGET),
    ] {
        for edges in ["normal", "normal,build"] {
            assert!(
                !box_graph_requests_dragonfruit_sign(mf, target, edges, false),
                "box-never-signs CRUX VIOLATION: {mf} requests dragonfruit's `sign` feature on \
                 --edges {edges} — the box only VERIFIES (spec §6f). Drop the feature; never compile \
                 sign_delegation/sign_attestation into a box binary."
            );
        }
    }
                                                                                                         
                                                                                                            
                                                                                                          
                                                                                                             
                                                                       
    for edges in ["normal", "normal,build"] {
        assert!(
            !box_graph_requests_dragonfruit_sign("Cargo.toml", BOX_TARGET, edges, true),
            "box-never-signs CRUX VIOLATION: a Fruit Basket workspace member requests dragonfruit's \
             `sign` feature on --edges {edges} — the box only VERIFIES (spec §6f). Drop the feature; \
             never compile sign_delegation/sign_attestation into a box binary."
        );
    }
}

/// Self-test (mirrors `diff_self_test`): a guard that cannot fire is theater. Prove the sign-feature
/// predicate FIRES on a dragonfruit `sign` line and stays silent on the verify-only/clean line, an
/// unrelated feature, the wrong crate, and a malformed line.
#[test]
fn sign_feature_predicate_fires_both_directions() {
    assert!(line_requests_dragonfruit_sign(
        "dragonfruit v0.3.0 (/p)|sign"
    ));
    assert!(line_requests_dragonfruit_sign(
        "dragonfruit v0.3.0 (/p)|sign,zeroize"
    ));
                                                                                                           
                                                                                                       
    assert!(line_requests_dragonfruit_sign(
        "dragonfruit v0.3.0 (/p)|backup,sign (*)"
    ));
                                                                                            
    assert!(!line_requests_dragonfruit_sign(
        "dragonfruit v0.3.0 (/p)|backup,zeroize (*)"
    ));
    assert!(!line_requests_dragonfruit_sign("dragonfruit v0.3.0 (/p)|"));                                         
    assert!(!line_requests_dragonfruit_sign(
        "dragonfruit v0.3.0 (/p)|zeroize"
    ));                     
    assert!(!line_requests_dragonfruit_sign("ed25519-dalek v2.2.0|sign"));               
    assert!(!line_requests_dragonfruit_sign("garbage no pipe"));
}

#[test]
fn rambutan_shipped_set_is_exactly_the_allowlist() {
    let actual = box_tree("crates/rambutan/Cargo.toml", UEFI_TARGET, "normal");
    assert_closed_set(
        &actual,
        RAMBUTAN_SHIPPED,
        "the rambutan UEFI loader standalone, shipped/normal edges (x86_64-unknown-uefi)",
    );
}

#[test]
fn fb_update_shipped_set_is_exactly_the_allowlist() {
    let actual = box_tree("crates/fb-update/Cargo.toml", BOX_TARGET, "normal");
    assert_closed_set(
        &actual,
        FB_UPDATE_SHIPPED,
        "the fb-update standalone (both bins), shipped/normal edges (x86_64-unknown-linux-musl)",
    );
}

/// fb-update build-edge closed set: `--edges normal,build` must equal `FB_UPDATE_SHIPPED` ∪
/// `FB_UPDATE_BUILD_ONLY` — the verify closure's pure-Rust version probes only, no build-time C
/// toolchain; a new C-FFI build-dep here is an unlisted member → RED.
#[test]
fn fb_update_build_edge_set_is_exactly_shipped_plus_build_tools() {
    let actual = box_tree("crates/fb-update/Cargo.toml", BOX_TARGET, "normal,build");
    let expected: Vec<&str> = FB_UPDATE_SHIPPED
        .iter()
        .chain(FB_UPDATE_BUILD_ONLY)
        .copied()
        .collect();
    assert_closed_set(
        &actual,
        &expected,
        "the fb-update standalone (both bins), ship+build edges (x86_64-unknown-linux-musl)",
    );
}

/// fb-weights (hotswap v4) shipped closed set — `--edges normal` must equal `FB_WEIGHTS_SHIPPED`
/// EXACTLY (a new transitive shipped dep, or a dropped one, → RED). The allowlist-shaped twin of
                
/// the sign-feature sweep entry above.
#[test]
fn fb_weights_shipped_set_is_exactly_the_allowlist() {
    let actual = box_tree("crates/fb-weights/Cargo.toml", BOX_TARGET, "normal");
    assert_closed_set(
        &actual,
        FB_WEIGHTS_SHIPPED,
        "the fb-weights standalone (setup+swap), shipped/normal edges (x86_64-unknown-linux-musl)",
    );
}

/// fb-weights build-edge closed set: `--edges normal,build` must equal `FB_WEIGHTS_SHIPPED` ∪
/// `FB_WEIGHTS_BUILD_ONLY` — pure-Rust version probes only, no build-time C toolchain; a new C-FFI
/// build-dep → RED.
#[test]
fn fb_weights_build_edge_set_is_exactly_shipped_plus_build_tools() {
    let actual = box_tree("crates/fb-weights/Cargo.toml", BOX_TARGET, "normal,build");
    let expected: Vec<&str> = FB_WEIGHTS_SHIPPED
        .iter()
        .chain(FB_WEIGHTS_BUILD_ONLY)
        .copied()
        .collect();
    assert_closed_set(
        &actual,
        &expected,
        "the fb-weights standalone (setup+swap), ship+build edges (x86_64-unknown-linux-musl)",
    );
}

/// rambutan build-edge closed set: `--edges normal,build` must equal `RAMBUTAN_SHIPPED` ∪
/// `RAMBUTAN_BUILD_ONLY`. The loader build chain must stay pure-Rust; a C-FFI build-dep → RED.
#[test]
fn rambutan_build_edge_set_is_exactly_shipped_plus_build_tools() {
    let actual = box_tree("crates/rambutan/Cargo.toml", UEFI_TARGET, "normal,build");
    let expected: Vec<&str> = RAMBUTAN_SHIPPED
        .iter()
        .chain(RAMBUTAN_BUILD_ONLY)
        .copied()
        .collect();
    assert_closed_set(
        &actual,
        &expected,
        "the rambutan UEFI loader standalone, ship+build edges (x86_64-unknown-uefi)",
    );
}

/// Self-test: prove the closed-set comparison fires in both directions (a guard that cannot fire is
/// theater). An intruder is reported as ENTERED; a dropped member as LEFT.
#[test]
fn diff_self_test_fires_on_intruder_and_on_missing() {
    let expected = &["alpha", "beta", "gamma"];

                                                                      
    let with_intruder: BTreeSet<String> = ["alpha", "beta", "gamma", "openssl-sys"]
        .into_iter()
        .map(str::to_string)
        .collect();
    let (entered, left) = diff_against_allowlist(&with_intruder, expected);
    assert_eq!(
        entered,
        vec!["openssl-sys".to_string()],
        "intruder must be ENTERED"
    );
    assert!(left.is_empty());

                                                  
    let with_missing: BTreeSet<String> =
        ["alpha", "gamma"].into_iter().map(str::to_string).collect();
    let (entered, left) = diff_against_allowlist(&with_missing, expected);
    assert!(entered.is_empty());
    assert_eq!(
        left,
        vec!["beta".to_string()],
        "dropped member must be LEFT"
    );

                                                                            
    let exact: BTreeSet<String> = expected.iter().map(|s| s.to_string()).collect();
    let (entered, left) = diff_against_allowlist(&exact, expected);
    assert!(
        entered.is_empty() && left.is_empty(),
        "exact match must be clean"
    );
}

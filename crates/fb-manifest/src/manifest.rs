//! The operator `Manifest` types — §5.1 (a)–(h) + the v1 identities/env base, on the §5.3 serde
//! discipline (externally-tagged struct variants, `deny_unknown_fields`, required fields, empty-struct
//! data-free arms).
//!
                      
//! The `ValidatedManifest` type-state gate (the only render entrypoint) lands in
//! A.4; the whitelist validators in A.3. This module carries the typed shapes only — a field that
//! parses here is NOT yet validated (charset/uid/traversal/env-key happen at the gate).
//!
//! **Service-partition decision (flagged for the §5.2-partition audit, E.3):** the manifest declares
//! the tenant longruns (the app + ntpd/dropbear/fb-acme/fb-backup/fb-cert-check, per §5.1c) and the 3
//! app-domain boot-hooks (set-hostname/bootstrap-ca/bootstrap-acme-cert, per §5.1e). The OS-invariant
//! pieces stay renderer/box-init-owned and are NOT manifest data (§5.2): the haproxy service + its
//! strip-then-set config shape, the rescue-dropbear service + the rescue branch, and the OS-infra
//! boot-hooks (nftables-load, prepare/mount-persist, setup-dirs, services-keys-stage).

use crate::argv::{ArgvToken, KnownPlaceholder};
                                                                                                   
                                                                                                      
                                                                                                          
                                                                                 
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// The privilege mode a service / boot-hook runs under (§5.1c/e).
///
/// **Externally-tagged** (serde default) with **struct variants** + `deny_unknown_fields` (§5.3).
          
/// The data-free arms `Root`/`SelfDrop` are **EMPTY-STRUCT variants `{}`**, NEVER unit (§5.3):
/// in TOML this is the table form `priv = { root = {} }`, NOT the bare string `priv = "root"` (which
          
/// only the forbidden unit form would accept — §5.3; do NOT switch to unit to enable the
/// bare-string idiom). The empty-struct form rejects trailing/sibling junk, which the unit form would
/// silently accept under some representations.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum Priv {
    /// Run as root (uid 0). The renderer emits no privilege-drop prefix.
    Root {},
    /// Drop to a baked tenant identity via `s6-setuidgid <user>` (the user NAME is validated at the
              
    /// gate: must resolve to a non-root baked identity — §5.3). `envdir`, when present, adds an
    /// `s6-envdir <dir>` prefix; its **absence is a documented-safe state** (no envdir prefix), the
              
    /// only `Option` permitted on this struct (§5.3) — NO `#[serde(default)]` (forbidden).
    Setuidgid {
        user: String,
        envdir: Option<String>,
    },
    /// The binary drops its own privilege (e.g. haproxy's `user` directive) — a distinct third mode.
    SelfDrop {},
}

/// What box-init does if an app-domain boot-hook fails (§5.1e `on_failure_class`). Empty-struct
/// externally-tagged variants (§5.3). Maps to box-init's `OnFailure` (oneshots.rs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum OnFailure {
    /// Divert to the rescue surface (safe-but-degraded).
    Rescue {},
    /// Reboot fail-closed (reserved for preconditions that MUST hold before any exposure).
    Reboot {},
}

/// A supervised longrun's run-script shape (§5.1c). Externally-tagged: S1 exec vs S2 periodic-loop.
/// The loop/exec STRUCTURE is an OS-invariant render template; only the typed fields are data.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum ServiceShape {
    /// S1 — a plain `exec <binary> <argv>` longrun (ntpd/dropbear/the app/fb-acme).
    Exec {
        binary: String,
        argv: Vec<ArgvToken>,
        #[serde(rename = "priv")]
        privilege: Priv,
        /// Optional inline environment exported before `exec` (the dha creatine `CREATINE_*` vars —
        /// env-only, no argv; §4.5). image-builder renders it as `export KEY='VAL'` lines before the
        /// `s6-setuidgid` drop (which preserves the environment). Each KV's key/value pass the SAME gate
                  
        /// as `[env.vars]` (`validate_env_key`/`validate_env_value`, §5.3). Absent = no env
                  
        /// prologue — the documented-safe-absence `Option` (§5.3: NO `#[serde(default)]`), mirroring
        /// `restart_cap`; modeled `Option<Vec<_>>` (not a bare `Vec`) so a non-env service's manifest
                
        /// stays byte-identical (the key is simply omitted).
        env: Option<Vec<EnvKv>>,
        /// Optional per-service restart cap (§4.1b) — ONLY an Exec longrun may carry one (a dha
        /// orchestrator/creatine); a `PeriodicLoop`'s restart IS its purpose, so the field lives on this
        /// variant by construction. Absent = no `finish` emitted (the box's existing no-restart-throttle
                  
        /// behavior, §8). The documented-safe-absence `Option` (§5.3 — no `#[serde(default)]`).
        restart_cap: Option<RestartCap>,
    },
    /// S2 — a `while : ; do <binary> <argv> ; sleep <interval_secs> ; done` loop (fb-backup,
    /// fb-cert-check). The interval is data; the loop is the invariant template.
    PeriodicLoop {
        binary: String,
        argv: Vec<ArgvToken>,
        interval_secs: u64,
        #[serde(rename = "priv")]
        privilege: Priv,
    },
}

/// One `KEY=VALUE` inline environment entry for a [`ServiceShape::Exec`] (§4.5) — rendered as an
/// `export KEY='VAL'` line before the service `exec` (creatine's `CREATINE_BIND` / `CREATINE_MODEL_PATH`
/// / `CREATINE_MODEL`). The KEY is a POSIX env name outside the loader/shell-reserved set; the VALUE is
/// NUL/newline-free — both enforced at the gate by the SAME validators as `[env.vars]`
          
/// (`validate_env_key` / `validate_env_value`, §5.3), so the inline-env path cannot smuggle an
/// `LD_PRELOAD` or split a var with a newline.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvKv {
    pub key: String,
    pub value: String,
}

/// One supervised tenant longrun (§5.1c). OS-invariant services (haproxy, rescue-dropbear) are NOT
/// declared here — see the module-level partition note.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceSpec {
    pub name: String,
    pub shape: ServiceShape,
}

/// A tenant app-domain boot-hook (§5.1e) — the highest-privilege tenant surface (root,
/// pre-supervision). The legacy `Oneshot.body` free shell-string is decomposed into typed
/// `{binary, argv, priv}` (§5.3 — no free-text body). Only the 3 app-domain hooks are declared; the
/// OS-infra hooks stay box-init-owned.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BootHook {
    pub name: String,
    pub binary: String,
    pub argv: Vec<ArgvToken>,
    #[serde(rename = "priv")]
    pub privilege: Priv,
    /// Sort key for the OS boot sequence — the renderer interleaves the hook at this position among
    /// box-init's OS-infra hooks (explicit ordering, not list-position-dependent).
    pub order: u32,
    /// Wall-clock SIGKILL backstop (maps to `Oneshot.timeout_secs`); a hung hook is a failure.
    pub timeout_secs: u64,
    pub on_failure: OnFailure,
}

/// A tenant identity baked into `/etc/passwd`+`/etc/group` (§5.1 v1 "uids"). The uid is validated
          
/// non-zero + disjoint from the OS-fixed identity set at the gate (§5.3).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub name: String,
    pub uid: u32,
}

/// A fragment of an env-var VALUE (§5.1b) — a TYPED template (NOT a free string with substitution; the
          
/// spirit applied to env values). A value is a `Vec<EnvFragment>` rendered by concatenation, so
/// a tenant `Text` can never alias an OS-invariant value (a `Text` of the literal `{domain}` stays that
/// text). `Text` is arbitrary content — env values are envdir FILE CONTENT, NOT shell words, so there
          
/// is no charset limit; only NUL/newline are rejected at the gate (§5.3).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum EnvFragment {
    /// Literal text (e.g. `https://`, `/persist/recipes`).
    Text { value: String },
    /// An OS-invariant placeholder the renderer fills (the box `Domain`; the build epoch).
    Placeholder { name: KnownPlaceholder },
}

/// The app env contract (§5.1b) — the envdir name + the KV. Each KEY is validated (POSIX env-name
          
/// charset + forbidden-name set: `LD_*`/`PATH`/`IFS`) at the gate (§5.3); each VALUE is a typed
/// `Vec<EnvFragment>` template (e.g. `PUBLIC_URL = [Text "https://", Placeholder Domain]`), rendered by
/// concatenation, rejecting NUL/newline.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvSpec {
    pub envdir: String,
    pub vars: BTreeMap<String, Vec<EnvFragment>>,
}

/// How a throttle rule's paths match (§5.1a) — the current edge uses BOTH: `path` (EXACT, for
/// `/login`||`/recover`) and `path_beg` (PREFIX, for `/api/pair/`). A scalar choice enum (like
/// `KnownPlaceholder`): `match = "exact"` / `"prefix"`; an unknown value fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThrottleMatch {
    /// Exact path match (`acl … path <p>`).
    Exact,
    /// Path-prefix match (`acl … path_beg <p>`).
    Prefix,
}

/// A per-path throttle class (§5.1a) — the path SET (one acl, possibly multi-path) + the match kind +
/// the per-class request-rate cap. The per-IP stick-table + the global rate + the deny grammar are
/// OS-invariant; only WHICH paths + the per-class rate are data.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThrottleRule {
    pub paths: Vec<String>,
    #[serde(rename = "match")]
    pub match_kind: ThrottleMatch,
    pub max_req_rate: u32,
}

/// The edge/haproxy policy inputs (§5.1a). The tenant declares WHICH path / query-param sets are
/// redacted / mTLS-gated / throttle-classed + the backend + ca-file; the renderer composes the
/// regsub/acl grammar (the grammar + strip-then-set + the per-IP stick-table + the global rate + HSTS
          
/// are OS-invariant, §5.2). Each path token is validated at the gate (anchored, URL-path bytes).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdgeSpec {
    pub backend: String,
    pub ca_file: String,
    /// Path-segment redactions: `^/<p>/[^/?]+ -> /<p>/<redacted>` (e.g. `/api/pair/`, `/invite/`).
    pub redacted_paths: Vec<String>,
    /// Query-param redactions: `<q>=[^&]+ -> <q>=<redacted>` (e.g. `via`).
    pub redacted_query_params: Vec<String>,
    pub mtls_paths: Vec<String>,
    pub throttle_rules: Vec<ThrottleRule>,
}

/// A tenant dir under `/persist` (§5.1d), with its uid + mode. Serializable because box-init's
/// `Topology` carries the persist dirs (so box-init's `setup-dirs` renders the tenant mkdir/chown from
                 
/// the manifest instead of hardcoding `recipes` — runtime de-hardcoding).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersistDir {
    pub path: String,
    pub uid: u32,
    pub mode: u32,
}

/// Backup policy (§5.1g). Sources are traversal-rejected relative paths under the tenant data root
        
/// (validated at the gate — §5.3); the VACUUM target's ABSENCE = "no VACUUM" (the documented-safe
          
/// `Option` per §5.3).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupSpec {
    pub sources: Vec<String>,
    pub vacuum_target: Option<String>,
}

/// The "tenant alive" health probe the gate uses (§5.1f).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeSpec {
    pub port: u16,
    pub path: String,
}

/// The nftables open-port set (§5.1h) — the default-deny SHAPE + golden ruleset are OS-invariant
/// (§5.2); only the open TCP ports are data.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NftSpec {
    pub tcp_ports: Vec<u16>,
}

/// A size in bytes — a cgroup `memory.max` / `memory.min` value. A typed newtype (R5-Info-2,
/// secure-by-construction) so a byte count cannot be transposed with a [`Uid`] or a bare count at a call
/// site; `u64` because a box memory ceiling exceeds `u32` (>4 GiB). `#[serde(transparent)]`: it (de)
/// serializes as a bare TOML integer (bytes) — a negative/non-integer fails closed at the toml layer,
/// and as a SCALAR it stays before nested tables (the `ValueAfterTable` guard).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct ByteSize(pub u64);

/// A POSIX user id — a typed newtype over `u32` (R5-Info-2, secure-by-construction) so a `delegate_uid`
/// cannot be transposed with a [`ByteSize`] or a count. `#[serde(transparent)]`: a bare TOML integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(transparent)]
pub struct Uid(pub u32);

/// The tenant cgroup resource domain (§4.1a / spec §2 D4) — the opt-in budget box-init builds into a
/// minimal-root cgroup tree (`<name>/` Σ ceiling, `<name>/creatine`, the delegated `<name>/work`).
/// OPTIONAL on [`Manifest`] + [`crate::topology::Topology`]: a manifest without one is a non-dha box.
/// box-init consumes it from the SIGNED topology (integrity-covered), so it derives `Serialize` too.
///
/// **Field order: scalars (`name`/`memory_max`/`delegate_uid`) BEFORE the nested `engine`/`work`
/// tables** — `toml` serialization rejects a scalar emitted after a table (the `ValueAfterTable`
/// footgun the `render_then_parse_roundtrips_every_variant` test guards; L-R4-2).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceDomain {
    /// The cgroup subtree name under `/sys/fs/cgroup` — the Σ-ceiling root (e.g. `dha`).
    pub name: String,
    /// The aggregate ceiling Σ — root-owned `memory.max` on `<name>/`: the box's whole stake, tenant-
    /// unliftable. box-init validates `Σ + BOX_RESERVE ≤ MemTotal` (best-effort v1; §4.2.2).
    pub memory_max: ByteSize,
    /// The non-root tenant uid that owns the delegated `work/` subtree (validated non-zero + OS-disjoint
    /// + a declared tenant identity; the engine/orchestrator `setuidgid` user must resolve to it — R1-L3).
    pub delegate_uid: Uid,
    /// The warm-engine leaf (creatine): root-owned cap, `oom.group=1`, the ancestor-Σ OOM victim.
    /// Optional (a future engine-less mode); v1 uds sets it (§2 D3).
    pub engine: Option<EngineLeaf>,
    /// The delegated per-job `work/` subtree (orchestrator + dynamic clients), bounded by Σ and by the
    /// root-owned `cgroup.max.{descendants,depth}` set above the delegation point.
    pub work: WorkSubtree,
}

/// The warm-engine cgroup leaf (creatine — §2 D4). Root-owned cap; the ideal ancestor-Σ OOM victim
       
/// (`oom.group=1` → clean whole-engine kill; it holds the weights and MUST stay killable).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EngineLeaf {
    /// The declared service name running in this leaf — an Exec longrun whose `setuidgid` == `delegate_uid`.
    pub service: String,
    /// The engine's own `memory.max`: a runaway OOMs HERE first (at its own cap), before the aggregate
    /// reaches Σ — per-leaf-cap localization makes the ancestor-Σ case the rare fallback (§3 F10).
    pub memory_max: ByteSize,
    /// Optional `memory.min` (a swapless-box belt — O3; reclaim protection, NOT kill protection).
    pub memory_min: Option<ByteSize>,
    /// `memory.oom.group` — true for the engine (kill the whole leaf as a unit on its own-cap OOM).
    pub oom_group: bool,
}

/// The delegated per-job `work/` subtree (§2 D4). box-init creates it + stamps the root-owned
/// `cgroup.max.{descendants,depth}` BEFORE delegating ONLY the structural files to `delegate_uid`; the
/// orchestrator then creates the dynamic `work/<id>` leaves under it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WorkSubtree {
    /// The orchestrator service name — an Exec longrun in `work/orch` whose `setuidgid` == `delegate_uid`.
    pub orchestrator: String,
    /// Optional root-owned `memory.min` on `work/orch` (keeps the orchestrator's set resident; O2/O3).
    pub orch_memory_min: Option<ByteSize>,
    /// The `memory.max` stamped on each dynamic per-job `work/<id>` leaf.
    pub job_memory_max: ByteSize,
    /// Optional `pids.max` per `work/<id>` leaf (the `CONFIG_CGROUP_PIDS` backstop).
    pub job_pids_max: Option<u32>,
    /// Root-owned `cgroup.max.descendants` on `work/` — the cgroup-creation backstop (R1-H2), set
    /// before delegation so the tenant cannot raise it.
    pub max_descendants: u32,
    /// Root-owned `cgroup.max.depth` on `work/`.
    pub max_depth: u32,
    /// Root-owned `pids.max` on `work/` — the AGGREGATE fork-bomb backstop (R3-H1), set before
    /// delegation so the tenant cannot raise it. Hierarchically bounds the total pids/threads of ALL
    /// `work/<id>` (the per-job `job_pids_max` is a tenant-set sub-limit within this root-owned ceiling).
    /// The pids twin of `max_descendants`; matches dha S-FB-COMPOSITION §94. Its VALUE is an owed dha
    /// measurement (placeholder in fixtures).
    pub work_pids_max: u32,
}

/// A per-service restart cap (§4.1b) — optional on an Exec longrun. The renderer (image-builder) emits a
/// `finish` script `s6-permafailon <window_secs> <max_restarts> <events> <emitter>`: on ≥`max_restarts`
/// deaths (cause in `events`) within `window_secs`, s6-supervise stops respawning (`exit 125` =
/// permanent-down). `window_secs` MUST be sized to the pinned model's cold-reload time so a legit slow
/// reload does not false-trip (R2-B-M1). Manifest-only: box-init never reads it (s6 enforces it).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestartCap {
    pub max_restarts: u32,
    pub window_secs: u64,
    pub events: DeathEvents,
    pub on_exhaust: OnExhaust,
}

/// Which s6-supervise death causes count toward a [`RestartCap`] (§4.1b, R2-B-M1) — maps to
/// s6-permafailon's death-event argument (rendered in D2). The recommended default counts BOTH genuine
/// failures (a crash by signal, and a non-zero exit); a clean exit-0 (e.g. during a cold model reload)
/// does NOT count, so a slow reload cannot false-trip the cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeathEvents {
    /// Count a death by signal (a crash — SIGSEGV / SIGABRT / SIGKILL / …).
    pub on_signal: bool,
    /// Count a death by non-zero exit code.
    pub on_nonzero_exit: bool,
}

/// What box-init/s6 does when a [`RestartCap`] is exhausted (§4.1b). Empty-struct externally-tagged
          
/// variants (§5.3 — NEVER unit), mirroring [`OnFailure`]: `Down` leaves the service permanently
/// down (s6 `exit 125`); `Rescue` wraps it with a divert to the box rescue surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
pub enum OnExhaust {
    Down {},
    Rescue {},
}

/// Which submission-engine wiring the `box.json` gate expects (§4.3, dha `startup`). A scalar choice
/// enum like [`ThrottleMatch`] — `creatine_mode = "in-process" | "uds" | "remote"`; an unknown value
/// fails closed (serde "unknown variant"). Distinct from [`BoxConfigSpec::in_process`], which carries
/// the in-process sub-config when this is `InProcess`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CreatineMode {
    InProcess,
    Uds,
    Remote,
}

/// The dynamic-client kind the orchestrator dispatches to (§4.3, dha runtime-config). A scalar choice
/// enum (`kind = "pecan" | "epa"`); the box maps the kind → the staged client store-key (Task 3) and
/// renders it into `runtime.json`. v1 ships `epa`/`pecan` ring-tier (only `dha-orchestrator` is zero-C).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientKind {
    Pecan,
    Epa,
}

/// The in-process creatine sub-config (§4.3) — present only when `creatine_mode = "in-process"`. Both
/// flags are REQUIRED when the block is present; documented-safe absence is the WHOLE block being
/// `None` (`BoxConfigSpec::in_process`), never a per-field `#[serde(default)]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InProcessSpec {
    pub combined_unit_cgroup: bool,
    pub input_parse_hardening: bool,
}

/// The `box.json` gate config (§4.3) — image-builder renders it as a `dha`-owned `0600` JSON file on
/// the signed RO rootfs, read by `dha-orchestrator` AS the dropped `dha` uid (the confinement gate: the
/// client `--root` is `Validated.root()` from HERE, never the runtime-config, so it cannot be diverged).
/// Path fields are gate-validated (`validate_path_token`); `scratch` / `logdir` / `in_process` are
/// documented-safe-absent `Option`s (no `#[serde(default)]`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoxConfigSpec {
    pub sensitive: bool,
    pub tier_b: bool,
    pub root: String,
    pub secrets: String,
    pub scratch: Option<String>,
    pub logdir: Option<String>,
    pub git: bool,
    pub creatine_mode: CreatineMode,
    pub in_process: Option<InProcessSpec>,
}

/// The dynamic-client spec inside the runtime-config (§4.3) — the kind + the client program + its
/// config path. `program` / `config` are gate-validated path tokens (they land in the rendered
/// `runtime.json` the orchestrator reads).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSpecIn {
    pub kind: ClientKind,
    pub program: String,
    pub config: String,
}

/// The creatine warm-engine probe wiring inside the runtime-config (§4.3) — the paths the orchestrator
/// uses to observe/reach creatine. All path fields are gate-validated; `s6_svstat_bin` is a
/// documented-safe-absent `Option`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreatineProbeIn {
    pub memory_events: String,
    pub uds: String,
    pub service_dir: String,
    pub s6_svstat_bin: Option<String>,
}

/// The `runtime.json` orchestrator config (§4.3) — image-builder renders it as a `dha`-owned `0600`
/// JSON file. The `parent_cgroup` + `budget` fields dha's `OrchestratorRuntime` also carries are
/// DERIVED from [`ResourceDomain`] at render time (Task 4), NOT declared here — so the delegated cgroup
/// and the per-job budget stay single-sourced from the resource domain and cannot diverge from it.
/// `socket_path` / `client_oom_score_adj` are documented-safe-absent `Option`s (no `#[serde(default)]`).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeConfigSpec {
    pub max_jobs: u32,
    pub max_conns: u32,
    pub socket_path: Option<String>,
    pub client: ClientSpecIn,
    pub client_oom_score_adj: Option<i32>,
    pub creatine: CreatineProbeIn,
}

/// A file staged onto the RO rootfs from a pinned store artifact (spec §3/§4, D4/D5) — the
/// `[[staged_files]]` mechanism. `key` names the consume-pins/store artifact; `target` is the absolute
/// on-rootfs path (gate-validated `/opt/<dir>/<rest…>`, ≥2 segments below `/opt`, no traversal — V1/V2);
/// `mode` is one of the allowlist `{0o644, 0o600, 0o755}` (V4); `owner` is a symbolic `[[identities]]`
/// NAME resolved to a uid at the gate (V6, [`crate::validate::resolve_owner`]). `owner`'s ABSENCE means
          
/// root (0:0) — the documented-safe-absence `Option` (§5.3: NO `#[serde(default)]`, mirroring
/// [`ServiceShape::Exec::env`]). An owned file must be non-executable (V7): an `owner` denotes config
/// DATA, never a program.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StagedFile {
    pub key: String,
    pub target: String,
    pub mode: u32,
    pub owner: Option<String>,
}

/// The full tenant service manifest (§5.1 a–h + the v1 identities/env base). The operator-supplied TCB
/// input; `toml::from_str` here (deny-unknown), then validated into a `ValidatedManifest` (A.4) before
/// image-builder renders it. A `schema_version` mismatch / unknown field / missing required field
/// fails closed.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub identities: Vec<Identity>,
    pub env: EnvSpec,
    pub services: Vec<ServiceSpec>,
    pub boot_hooks: Vec<BootHook>,
    pub edge: EdgeSpec,
    pub persist: Vec<PersistDir>,
    pub backup: BackupSpec,
    pub probe: ProbeSpec,
    pub nftables: NftSpec,
    /// The optional tenant cgroup resource domain (§4.1a) — opt-in: absent = a non-dha box (box-init
    /// skips the entire cgroup block; the service-dir + IMA goldens stay byte-identical). box-init
    /// consumes it from the SIGNED `box-topology.toml` (integrity-covered), never the manifest directly.
    pub resource_domain: Option<ResourceDomain>,
    /// The optional `box.json` gate config (§4.3) — opt-in, dha-box only: absent = a non-dha box (no
            
    /// `/etc/dha/box.json` rendered; the byte-identity holds). Rendered as `dha`-owned `0600` rootfs
    /// DATA (image-builder, Task 4), NOT a consume-pins artifact — so the config count stays unchanged.
    pub box_config: Option<BoxConfigSpec>,
    /// The optional `runtime.json` orchestrator config (§4.3) — opt-in, dha-box only (paired with
    /// `box_config`: the render emits both or neither). `parent_cgroup` + `budget` derive from
    /// `resource_domain` at render time.
    pub runtime_config: Option<RuntimeConfigSpec>,
    /// The optional pinned files staged onto the RO rootfs under `/opt/<dir>/…` (spec §3/§4) — the
    /// `[[staged_files]]` mechanism (a dha box stages uds-pipe + the probe scripts + `epa.json`). Absent =
    /// a non-staging manifest (toy/recipes): the bake stages nothing extra and the rootfs tree stays
                    
    /// byte-identical. NO `#[serde(default)]` — the documented-safe-absence `Option` (§5.3),
    /// so a non-dha manifest omits the key entirely and parses byte-stably.
    pub staged_files: Option<Vec<StagedFile>>,
}

#[cfg(test)]
mod priv_tests {
    use super::*;

    /// Test wrapper — `priv` is a Rust keyword, so the field is renamed (rename is on the §5.3
    /// whitelist). TOML uses the `priv` key per §5.1c.
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct W {
        #[serde(rename = "priv")]
        privilege: Priv,
    }

    fn parse(s: &str) -> Result<W, toml::de::Error> {
        toml::from_str(s)
    }

    #[test]
    fn root_empty_struct_parses() {
        assert_eq!(
            parse(r#"priv = { root = {} }"#).unwrap().privilege,
            Priv::Root {}
        );
    }

    #[test]
    fn self_drop_empty_struct_parses() {
        assert_eq!(
            parse(r#"priv = { self_drop = {} }"#).unwrap().privilege,
            Priv::SelfDrop {}
        );
    }

    #[test]
    fn setuidgid_without_envdir_gives_none() {
                                                                                                 
                                                                                           
                                                                                                        
        let p = parse(r#"priv = { setuidgid = { user = "recipes" } }"#)
            .unwrap()
            .privilege;
        assert_eq!(
            p,
            Priv::Setuidgid {
                user: "recipes".into(),
                envdir: None
            }
        );
    }

    #[test]
    fn setuidgid_with_envdir_parses() {
        let p =
            parse(r#"priv = { setuidgid = { user = "recipes", envdir = "/etc/recipes/env" } }"#)
                .unwrap()
                .privilege;
        assert_eq!(
            p,
            Priv::Setuidgid {
                user: "recipes".into(),
                envdir: Some("/etc/recipes/env".into())
            }
        );
    }

    #[test]
    fn empty_struct_variant_rejects_trailing_junk() {
                                                                                                    
                                                                                                       
        let err = parse(r#"priv = { root = { evil = 1 } }"#).unwrap_err();
        assert!(
            err.to_string().contains("evil") || err.to_string().contains("unknown"),
            "{err}"
        );
    }

    #[test]
    fn bare_string_priv_is_refused() {
                                                                                                
                                                                                                      
                                                         
        let err = parse(r#"priv = "root""#).unwrap_err();
        assert!(
            !err.to_string().is_empty(),
            "bare-string priv must be refused: {err}"
        );
    }

    #[test]
    fn setuidgid_unknown_field_is_refused() {
        let err = parse(r#"priv = { setuidgid = { user = "x", evil = "y" } }"#).unwrap_err();
        assert!(
            err.to_string().contains("evil") || err.to_string().contains("unknown"),
            "{err}"
        );
    }

    #[test]
    fn setuidgid_missing_required_user_is_refused() {
                                                                                                   
        let err = parse(r#"priv = { setuidgid = { envdir = "/x" } }"#).unwrap_err();
        assert!(
            err.to_string().contains("user") || err.to_string().contains("missing"),
            "{err}"
        );
    }

    #[test]
    fn unknown_priv_variant_is_refused() {
        let err = parse(r#"priv = { god_mode = {} }"#).unwrap_err();
        assert!(
            err.to_string().contains("unknown variant") || err.to_string().contains("god_mode"),
            "{err}"
        );
    }
}

#[cfg(test)]
mod manifest_tests {
    use super::*;
    use crate::argv::KnownPlaceholder;

    /// A representative (not the full reference) manifest covering every §5.1 section.
    const FIXTURE: &str = r#"
schema_version = 1

[[identities]]
name = "recipes"
uid = 100

[env]
envdir = "/etc/recipes/env"
[env.vars]
DATA_DIR = [ { text = { value = "/persist/recipes" } } ]
PUBLIC_URL = [ { text = { value = "https://" } }, { placeholder = { name = "domain" } } ]

[[services]]
name = "ntpd"
shape = { exec = { binary = "/usr/sbin/ntpd", argv = [ { literal = { value = "-n" } } ], priv = { root = {} } } }

[[services]]
name = "recipes"
shape = { exec = { binary = "/usr/bin/recipes", argv = [], priv = { setuidgid = { user = "recipes", envdir = "/etc/recipes/env" } } } }

[[services]]
name = "fb-backup"
shape = { periodic_loop = { binary = "/usr/bin/fb-backup", argv = [ { literal = { value = "/persist/recipes" } } ], interval_secs = 86400, priv = { root = {} } } }

[[boot_hooks]]
name = "set-hostname"
binary = "/usr/bin/fb-oneshots"
argv = [ { literal = { value = "set-hostname" } }, { literal = { value = "--fallback" } }, { placeholder = { name = "domain" } } ]
priv = { root = {} }
order = 10
timeout_secs = 5
on_failure = { rescue = {} }

[edge]
backend = "127.0.0.1:8000"
ca_file = "/persist/recipes/ca.crt"
redacted_paths = [ "/api/pair/", "/invite/" ]
redacted_query_params = [ "via" ]
mtls_paths = [ "/api/v1/", "/download/" ]
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

    #[test]
    fn parses_a_representative_manifest() {
        let m: Manifest = toml::from_str(FIXTURE).expect("representative manifest parses");
        assert_eq!(m.schema_version, 1);
        assert_eq!(
            m.identities,
            vec![Identity {
                name: "recipes".into(),
                uid: 100
            }]
        );
        assert_eq!(m.services.len(), 3);
        assert_eq!(m.boot_hooks.len(), 1);
                                    
        assert_eq!(m.persist[0].mode, 0o700);
                                                     
        assert_eq!(m.backup.vacuum_target, None);
        assert_eq!(m.nftables.tcp_ports, vec![80, 443, 22]);
        assert_eq!(m.probe.port, 443);
                                                                                                 
        assert!(m.staged_files.is_none());
                                                                      
        match &m.boot_hooks[0].argv[2] {
            ArgvToken::Placeholder { name } => assert_eq!(*name, KnownPlaceholder::Domain),
            other => panic!("expected a Domain placeholder, got {other:?}"),
        }
                                       
        match &m.services[2].shape {
            ServiceShape::PeriodicLoop { interval_secs, .. } => assert_eq!(*interval_secs, 86400),
            other => panic!("expected a periodic loop, got {other:?}"),
        }
    }

    #[test]
    fn unknown_top_level_field_is_refused() {
                                                                                                  
        let augmented = format!("{FIXTURE}\nbackdoor = true\n");
        let err = toml::from_str::<Manifest>(&augmented).unwrap_err();
        assert!(
            err.to_string().contains("backdoor") || err.to_string().contains("unknown"),
            "{err}"
        );
    }

    #[test]
    fn missing_required_section_is_refused() {
                                                                                     
        let truncated = FIXTURE.replace("[nftables]\ntcp_ports = [ 80, 443, 22 ]\n", "");
        let err = toml::from_str::<Manifest>(&truncated).unwrap_err();
        assert!(
            err.to_string().contains("nftables") || err.to_string().contains("missing"),
            "{err}"
        );
    }
}

#[cfg(test)]
mod resource_domain_tests {
    use super::*;

    /// A full resource domain (§4.1a): scalars (name/memory_max/delegate_uid) BEFORE the nested
    /// engine/work tables (the toml ValueAfterTable serializer footgun — round-trip-guarded in topology).
    const RD_FIXTURE: &str = r#"
name = "dha"
memory_max = 8000000000
delegate_uid = 110
[engine]
service = "dha-creatine"
memory_max = 6000000000
memory_min = 4000000000
oom_group = true
[work]
orchestrator = "dha-orchestrator"
orch_memory_min = 64000000
job_memory_max = 512000000
job_pids_max = 64
max_descendants = 16
max_depth = 2
work_pids_max = 256
"#;

    #[test]
    fn a_full_resource_domain_deserializes() {
        let rd: ResourceDomain = toml::from_str(RD_FIXTURE).expect("resource domain parses");
        assert_eq!(rd.name, "dha");
        assert_eq!(rd.memory_max, ByteSize(8_000_000_000));
        assert_eq!(rd.delegate_uid, Uid(110));
        let engine = rd.engine.expect("engine present");
        assert_eq!(engine.service, "dha-creatine");
        assert_eq!(engine.memory_max, ByteSize(6_000_000_000));
        assert_eq!(engine.memory_min, Some(ByteSize(4_000_000_000)));
        assert!(engine.oom_group);
        assert_eq!(rd.work.orchestrator, "dha-orchestrator");
        assert_eq!(rd.work.orch_memory_min, Some(ByteSize(64_000_000)));
        assert_eq!(rd.work.job_memory_max, ByteSize(512_000_000));
        assert_eq!(rd.work.job_pids_max, Some(64));
        assert_eq!(rd.work.max_descendants, 16);
        assert_eq!(rd.work.max_depth, 2);
        assert_eq!(rd.work.work_pids_max, 256);
    }

    #[test]
    fn a_resource_domain_without_an_engine_and_optionals_parses() {
                                                                                                   
                                                                                                                 
        let s = r#"
name = "dha"
memory_max = 8000000000
delegate_uid = 110
[work]
orchestrator = "dha-orchestrator"
job_memory_max = 512000000
max_descendants = 16
max_depth = 2
work_pids_max = 256
"#;
        let rd: ResourceDomain = toml::from_str(s).expect("parses without engine");
        assert!(rd.engine.is_none());
        assert!(rd.work.job_pids_max.is_none());
        assert!(rd.work.orch_memory_min.is_none());
    }

    #[test]
    fn an_unknown_key_in_a_resource_domain_is_refused() {
        let augmented = format!("{RD_FIXTURE}\nbackdoor = true\n");
        let err = toml::from_str::<ResourceDomain>(&augmented).unwrap_err();
        assert!(
            err.to_string().contains("backdoor") || err.to_string().contains("unknown"),
            "{err}"
        );
    }

    #[test]
    fn an_unknown_key_in_the_work_subtree_is_refused() {
        let augmented = RD_FIXTURE.replace("max_depth = 2", "max_depth = 2\nevil = 1");
        let err = toml::from_str::<ResourceDomain>(&augmented).unwrap_err();
        assert!(
            err.to_string().contains("evil") || err.to_string().contains("unknown"),
            "{err}"
        );
    }
}

#[cfg(test)]
mod restart_cap_tests {
    use super::*;

    #[test]
    fn an_exec_service_with_a_restart_cap_parses() {
        let s = r#"
name = "dha-creatine"
shape = { exec = { binary = "/usr/bin/dha-creatine", argv = [], priv = { setuidgid = { user = "dha" } }, restart_cap = { max_restarts = 5, window_secs = 3600, events = { on_signal = true, on_nonzero_exit = true }, on_exhaust = { down = {} } } } }
"#;
        let svc: ServiceSpec = toml::from_str(s).expect("service with restart_cap parses");
        let ServiceShape::Exec { restart_cap, .. } = svc.shape else {
            panic!("expected an exec service")
        };
        let rc = restart_cap.expect("restart_cap present");
        assert_eq!(rc.max_restarts, 5);
        assert_eq!(rc.window_secs, 3600);
        assert!(rc.events.on_signal);
        assert!(rc.events.on_nonzero_exit);
        assert_eq!(rc.on_exhaust, OnExhaust::Down {});
    }

    #[test]
    fn an_exec_service_without_a_restart_cap_gives_none() {
                                                                                                
                                                                                             
        let s = r#"
name = "ntpd"
shape = { exec = { binary = "/usr/sbin/ntpd", argv = [], priv = { root = {} } } }
"#;
        let svc: ServiceSpec = toml::from_str(s).expect("service without restart_cap parses");
        let ServiceShape::Exec { restart_cap, .. } = svc.shape else {
            panic!("expected an exec service")
        };
        assert!(restart_cap.is_none());
    }

    #[test]
    fn an_unknown_restart_cap_key_is_refused() {
        let s = r#"
name = "x"
shape = { exec = { binary = "/b", argv = [], priv = { root = {} }, restart_cap = { max_restarts = 5, window_secs = 3600, events = { on_signal = true, on_nonzero_exit = true }, on_exhaust = { down = {} }, evil = 1 } } }
"#;
        let err = toml::from_str::<ServiceSpec>(s).unwrap_err();
        assert!(
            err.to_string().contains("evil") || err.to_string().contains("unknown"),
            "{err}"
        );
    }

    #[test]
    fn an_on_exhaust_bare_string_is_refused() {
                                                                                                  
                                                                                  
        let s = r#"
name = "x"
shape = { exec = { binary = "/b", argv = [], priv = { root = {} }, restart_cap = { max_restarts = 5, window_secs = 3600, events = { on_signal = true, on_nonzero_exit = true }, on_exhaust = "down" } } }
"#;
        assert!(toml::from_str::<ServiceSpec>(s).is_err());
    }
}

#[cfg(test)]
mod staged_file_tests {
    use super::*;

    #[test]
    fn a_staged_file_with_an_owner_parses() {
        let s = r#"
key = "dha-epa-config"
target = "/opt/dha/epa.json"
mode = 0o600
owner = "dha"
"#;
        let sf: StagedFile = toml::from_str(s).expect("staged file parses");
        assert_eq!(
            sf,
            StagedFile {
                key: "dha-epa-config".into(),
                target: "/opt/dha/epa.json".into(),
                mode: 0o600,
                owner: Some("dha".into()),
            }
        );
    }

    #[test]
    fn a_staged_file_without_an_owner_gives_none() {
                                                                                                    
                                                                                                       
                                                                                                                
        let s = r#"
key = "uds-pipe"
target = "/opt/dha/uds-pipe"
mode = 0o755
"#;
        let sf: StagedFile = toml::from_str(s).expect("staged file without owner parses");
        assert_eq!(sf.owner, None);
    }

    #[test]
    fn a_staged_file_unknown_field_is_refused() {
                                                                             
        let s = r#"
key = "k"
target = "/opt/dha/x"
mode = 0o644
backdoor = true
"#;
        let err = toml::from_str::<StagedFile>(s).unwrap_err();
        assert!(
            err.to_string().contains("backdoor") || err.to_string().contains("unknown"),
            "{err}"
        );
    }
}

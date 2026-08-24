//! `fb.net=` kernel-cmdline parsing + the static IPv4 bring-up (box network bring-up, build-A).
                                                                        
//!
//! `parse_net` + the bring-up *plan* builder are PURE (no syscalls) so they are host-unit-tested. They
//! mirror the `crates/initramfs-init/src/cmdline.rs` DISCIPLINE (whitelist-validate, fail-closed, typed
//! errors with a clear `Display`) but `parse_net` is a NEW, STRICTER parser: it rejects duplicate keys,
//! caps the dns list at 3, and validates address SEMANTICS (per-octet range, no leading zeros, gw class +
//! on-subnet), none of which `parse_cmdline` does. The bring-up is Rust-native (`ip` via argv, files via
//! `std::fs`) — NO shell, so no cmdline value ever reaches `/bin/sh` (spec §3).

use core::fmt;
use std::io;
use std::process::Command;

/// Max resolvers honored: musl reads at most 3 `nameserver` lines, so a longer list is rejected rather
/// than written to a file the resolver won't fully read (spec §4.1).
const MAX_DNS: usize = 3;

/// Build-A addressing mode. `Dhcp` is RECOGNIZED (seam 1) but bring-up fail-closes it (C4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Static,
    Dhcp,
}

/// A validated network config parsed from `fb.net=`. `Static` carries whitelist-validated dotted-quad
/// `ip`/`gw` strings + a `/1..=32` prefix + 1..=3 validated dns; `Dhcp` carries nothing (build-A rejects it
/// at bring-up — the static fields, if present alongside `mode=dhcp`, are not consumed; the DHCP arm, when
/// built, takes addressing from the lease, not the cmdline).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetConfig {
    Static {
        ip: String,
        prefix: u8,
        gw: String,
        dns: Vec<String>,
    },
    Dhcp,
}

/// A `fb.net=` value box-init cannot safely act on. Each maps to a clear `Display`; the caller
/// (box-init) maps ANY error to the rescue divert with link-only networking (C2/C5(b)) — never a default.
#[derive(Debug, PartialEq, Eq)]
pub enum NetCmdlineError {
    /// No `fb.net=` token on the cmdline at all.
    Missing,
    /// `mode=` absent or empty (fail-closed: an unconfigured network is never a silent default).
    MissingMode,
    /// `mode=` value other than `static`/`dhcp`.
    UnknownMode(String),
    /// A required `mode=static` field absent/empty (`ip`/`gw`/`dns`). The whitespace-truncation guard
    /// surfaces here too: a stray space ends the token early, so a later required field is missing.
    MissingField(&'static str),
    /// A sub-key outside the `{mode,ip,gw,dns}` whitelist (and not the reserved `{ip6,gw6}`).
    UnknownField(String),
    /// `ip6=`/`gw6=` — reserved for the managed-static-IPv6 seam (§5.2); errors in build-A.
    ReservedField(&'static str),
    /// The same key appeared twice (NOT silent last-wins — an operator-owned grammar; spec §4.1).
    DuplicateField(String),
    /// An `ip`/`gw`/`dns` value that is not a valid dotted-quad (octet range, leading zero, shape).
    InvalidAddr { field: &'static str, value: String },
    /// `ip` prefix outside `/1..=32` (rejects `/0` as a degenerate host prefix — R2-6).
    InvalidPrefix(String),
    /// `gw` is not a plausible unicast next hop (unspecified/broadcast/loopback/multicast/reserved).
    GatewayNotUnicast(String),
    /// `gw` is not within the `ip=` prefix (off-subnet; build-A parse-rejects — the on-link fallback is §9).
    GatewayOffSubnet { ip: String, prefix: u8, gw: String },
    /// More than `MAX_DNS` (3) resolvers.
    TooManyDns(usize),
}

impl fmt::Display for NetCmdlineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => write!(f, "fb.net= not set on cmdline"),
            Self::MissingMode => write!(f, "fb.net mode= not set"),
            Self::UnknownMode(v) => write!(f, "fb.net mode unrecognized: {v:?}"),
            Self::MissingField(k) => write!(f, "fb.net {k}= required for mode=static"),
            Self::UnknownField(k) => write!(f, "fb.net unknown field: {k:?}"),
            Self::ReservedField(k) => {
                write!(f, "fb.net {k}= reserved (IPv6 seam); not built in build-A")
            }
            Self::DuplicateField(k) => write!(f, "fb.net duplicate field: {k:?}"),
            Self::InvalidAddr { field, value } => {
                write!(f, "fb.net {field} not a valid IPv4 address: {value:?}")
            }
            Self::InvalidPrefix(v) => write!(f, "fb.net ip prefix not /1..=32: {v:?}"),
            Self::GatewayNotUnicast(v) => write!(f, "fb.net gw not a unicast next hop: {v:?}"),
            Self::GatewayOffSubnet { ip, prefix, gw } => {
                write!(
                    f,
                    "fb.net gw {gw} not on-subnet for {ip}/{prefix} (build-A; on-link fallback is deferred)"
                )
            }
            Self::TooManyDns(n) => {
                write!(f, "fb.net dns list has {n} entries (max {MAX_DNS})")
            }
        }
    }
}

/// Parse `fb.net=` from a kernel cmdline (space-separated tokens, the form `/proc/cmdline` carries).
/// The token's VALUE is a space-free `;`-separated field set; a stray space ends the token (the kernel
/// tokenizes on whitespace), so a truncated token fails the required-field check (never a silent
/// shortening — §4.1). Every field whitelist-validated; any error → the caller's rescue divert (C5).
pub fn parse_net(cmdline: &str) -> Result<NetConfig, NetCmdlineError> {
    let value = cmdline
        .split_whitespace()
        .find_map(|tok| tok.strip_prefix("fb.net="))
        .ok_or(NetCmdlineError::Missing)?;

    let mut mode: Option<Mode> = None;
    let mut ip: Option<String> = None;
    let mut gw: Option<String> = None;
    let mut dns: Option<String> = None;
    let mut seen: Vec<&str> = Vec::new();

    for field in value.split(';').filter(|s| !s.is_empty()) {
        let (key, val) = field.split_once('=').unwrap_or((field, ""));
        if seen.contains(&key) {
            return Err(NetCmdlineError::DuplicateField(key.to_string()));
        }
        seen.push(key);
        match key {
            "mode" => {
                mode = Some(match val {
                    "static" => Mode::Static,
                    "dhcp" => Mode::Dhcp,
                    other => return Err(NetCmdlineError::UnknownMode(other.to_string())),
                });
            }
            "ip" => ip = non_empty(val),
            "gw" => gw = non_empty(val),
            "dns" => dns = non_empty(val),
            "ip6" => return Err(NetCmdlineError::ReservedField("ip6")),
            "gw6" => return Err(NetCmdlineError::ReservedField("gw6")),
            other => return Err(NetCmdlineError::UnknownField(other.to_string())),
        }
    }

    match mode.ok_or(NetCmdlineError::MissingMode)? {
        Mode::Dhcp => Ok(NetConfig::Dhcp),
        Mode::Static => {
            let ip_cidr = ip.ok_or(NetCmdlineError::MissingField("ip"))?;
            let gw = gw.ok_or(NetCmdlineError::MissingField("gw"))?;
            let dns_raw = dns.ok_or(NetCmdlineError::MissingField("dns"))?;

            let (ip, prefix) = parse_cidr(&ip_cidr)?;
            validate_ipv4("gw", &gw)?;
            if !is_unicast_gateway(&gw) {
                return Err(NetCmdlineError::GatewayNotUnicast(gw));
            }
            if !on_subnet(&ip, prefix, &gw) {
                return Err(NetCmdlineError::GatewayOffSubnet { ip, prefix, gw });
            }

            let dns: Vec<String> = dns_raw
                .split(',')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
            if dns.is_empty() {
                return Err(NetCmdlineError::MissingField("dns"));
            }
            if dns.len() > MAX_DNS {
                return Err(NetCmdlineError::TooManyDns(dns.len()));
            }
            for d in &dns {
                validate_ipv4("dns", d)?;
            }

            Ok(NetConfig::Static {
                ip,
                prefix,
                gw,
                dns,
            })
        }
    }
}

fn non_empty(s: &str) -> Option<String> {
    (!s.is_empty()).then(|| s.to_string())
}

/// Split `A.B.C.D/prefix`, validate the address + `prefix in 1..=32` (rejects `/0` — R2-6).
fn parse_cidr(s: &str) -> Result<(String, u8), NetCmdlineError> {
    let (addr, pfx) = s
        .split_once('/')
        .ok_or_else(|| NetCmdlineError::InvalidPrefix(s.to_string()))?;
    validate_ipv4("ip", addr)?;
    let prefix: u8 = pfx
        .parse()
        .map_err(|_| NetCmdlineError::InvalidPrefix(s.to_string()))?;
    if !(1..=32).contains(&prefix) {
        return Err(NetCmdlineError::InvalidPrefix(s.to_string()));
    }
    Ok((addr.to_string(), prefix))
}

/// Dotted-quad with NO leading zeros (each octet `0` or `[1-9][0-9]{0,2}`, value `0..=255`). Returns the
/// `InvalidAddr` error tagged with `field` so the caller's message names which field was bad.
fn validate_ipv4(field: &'static str, s: &str) -> Result<(), NetCmdlineError> {
    let bad = || NetCmdlineError::InvalidAddr {
        field,
        value: s.to_string(),
    };
    let octets: Vec<&str> = s.split('.').collect();
    if octets.len() != 4 {
        return Err(bad());
    }
    for o in octets {
                                                                                  
        if o.is_empty()
            || (o.len() > 1 && o.starts_with('0'))
            || !o.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(bad());
        }
        if o.parse::<u16>().map_err(|_| bad())? > 255 {
            return Err(bad());
        }
    }
    Ok(())
}

/// `s` (already a valid dotted-quad) → its u32. Infallible given `validate_ipv4` passed.
fn ipv4_to_u32(s: &str) -> u32 {
    s.split('.').fold(0u32, |acc, o| {
        (acc << 8) | o.parse::<u32>().expect("validated by validate_ipv4")
    })
}

/// A plausible unicast next hop: reject unspecified/broadcast/loopback(127/8)/multicast(224/4)/reserved(240/4).
fn is_unicast_gateway(gw: &str) -> bool {
    let n = ipv4_to_u32(gw);
    let first = (n >> 24) as u8;
    n != 0
        && n != u32::MAX
        && first != 127
        && !(224..=239).contains(&first)
        && !(240..=255).contains(&first)
}

/// `gw` within the `ip/prefix` subnet: `(ip & mask) == (gw & mask)`. `prefix` is 1..=32 (so the `<<` is in
/// range and `/0` — which would make this vacuous — is already parse-rejected, R2-6).
fn on_subnet(ip: &str, prefix: u8, gw: &str) -> bool {
    let mask: u32 = if prefix == 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    (ipv4_to_u32(ip) & mask) == (ipv4_to_u32(gw) & mask)
}

/// The ordered bring-up steps for `mode=static` (spec §4.2), built PURELY from a `NetConfig::Static` so it
/// is unit-testable without a live interface. The step-0 best-effort fields run in spec order — `link_lo`,
                
/// then `sysctls`, then `v6_flush`; `core` is the fail-fast chain; `resolv_conf` is the
/// `/run/resolv.conf` bytes. All `ip` argv are owned `String` words — no shell string is built.
pub struct BringUpPlan {
    /// Best-effort, run FIRST: `lo` up (the internal-hop loopback; nothing else brings it up).
    pub link_lo: Vec<String>,
    /// Best-effort `/proc/sys` writes (forbid v6 autoconfig + redirects), run AFTER `link_lo` and before the
    /// link comes up so no RA is processed on an up link (§4.2). `(path, "0")` pairs.
    pub sysctls: Vec<(String, String)>,
    /// Best-effort, run AFTER the sysctls: flush any pre-existing global v6 address (§4.2 order).
    pub v6_flush: Vec<String>,
    /// Fail-fast `ip` argv (link up, addr replace, route replace) — any failure → bring-up fails → rescue.
    pub core: Vec<Vec<String>>,
    /// The `/run/resolv.conf` content: one `nameserver <addr>\n` per dns entry, in order.
    pub resolv_conf: String,
}

/// The interface the bring-up targets. Justified (not assumed): the box has no systemd/udev renamer, so the
/// kernel's legacy naming yields `eth0` for the single virtio-net NIC (spec §8-I; boot-gate-confirmed).
const IFACE: &str = "eth0";

/// The IPv6 (+ v4 redirect) hardening sysctl writes: forbid autoconfig + redirects on `eth0`/`all`/`default`
/// (spec §3/C3). `(path, "0")` pairs, best-effort. Shared by `plan_static` (the services bring-up) AND
                
/// `link_only` (the no-parse rescue), so the IPv6 refusal holds on BOTH paths.
fn v6_hardening_sysctls() -> Vec<(String, String)> {
    let mut s = Vec::new();
    for scope in ["eth0", "all", "default"] {
        for knob in ["accept_ra", "autoconf", "accept_redirects"] {
            s.push((
                format!("/proc/sys/net/ipv6/conf/{scope}/{knob}"),
                "0".to_string(),
            ));
        }
        s.push((
            format!("/proc/sys/net/ipv4/conf/{scope}/accept_redirects"),
            "0".to_string(),
        ));
    }
    s
}

/// Build the ordered static-IPv4 bring-up plan (pure; spec §4.2). Step 0 (best-effort): `lo` up → the v6
                
/// hardening sysctls → the v6 global flush (in THAT order). Steps 1-3: the fail-fast core
/// (`ip` link/addr/route `replace`). Step 4: the resolv.conf content.
pub fn plan_static(ip: &str, prefix: u8, gw: &str, dns: &[String]) -> BringUpPlan {
    let words = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<String>>();
    BringUpPlan {
        link_lo: words(&["link", "set", "lo", "up"]),
        sysctls: v6_hardening_sysctls(),
        v6_flush: words(&["-6", "addr", "flush", "dev", IFACE, "scope", "global"]),
        core: vec![
            words(&["link", "set", IFACE, "up"]),
            vec![
                "addr".into(),
                "replace".into(),
                format!("{ip}/{prefix}"),
                "dev".into(),
                IFACE.into(),
            ],
            vec![
                "route".into(),
                "replace".into(),
                "default".into(),
                "via".into(),
                gw.to_string(),
                "dev".into(),
                IFACE.into(),
            ],
        ],
        resolv_conf: dns.iter().map(|d| format!("nameserver {d}\n")).collect(),
    }
}

/// Apply a parsed network config — the services-path bring-up + the C5(a) rescue re-apply. `Static` runs
/// the [`plan_static`] steps via the bounded `ip` spawns (no shell) + the sysctl/resolv.conf writes;
/// returns `Ok(false)` (→ rescue) on a fail-fast core failure. `Dhcp` is the build-A fail-closed seam
/// (C4): recognized, rejected here until the DHCP arm is built. Idempotent (`ip addr/route replace`), so
/// the rescue re-apply succeeds cleanly even when the address is already installed (R1-11).
pub fn apply(cfg: &NetConfig) -> io::Result<bool> {
    match cfg {
        NetConfig::Dhcp => {
            eprintln!("box-init: mode=dhcp not built in build-A (static-only) → fail-closed (C4)");
            Ok(false)
        }
        NetConfig::Static {
            ip,
            prefix,
            gw,
            dns,
        } => {
            let plan = plan_static(ip, *prefix, gw, dns);
                                                                                                             
                                                                                                            
            let _ = run_ip(&plan.link_lo);
            for (path, val) in &plan.sysctls {
                let _ = std::fs::write(path, val);
            }
            let _ = run_ip(&plan.v6_flush);
                                                                  
            for argv in &plan.core {
                if !run_ip(argv)? {
                    return Ok(false);
                }
            }
                                                                                              
            std::fs::write("/run/resolv.conf", &plan.resolv_conf)?;
            Ok(true)
        }
    }
}

/// Best-effort link-up only (the no-parse / unsupported-config rescue path, C5(b)): forbid v6 autoconfig
                
/// FIRST (the shared hardening sysctls, so even a malformed-cmdline box refuses a
/// network-supplied v6 address, §3), then `lo` + `eth0` up, no address. Always `Ok(true)` — rescue-dropbear
/// + the console come up regardless; SSH-to-rescue is not guaranteed (no address), so recovery is via VNC.
pub fn link_only() -> io::Result<bool> {
    for (path, val) in v6_hardening_sysctls() {
        let _ = std::fs::write(&path, &val);
    }
    let _ = run_ip(&["link".into(), "set".into(), "lo".into(), "up".into()]);
    let _ = run_ip(&["link".into(), "set".into(), IFACE.into(), "up".into()]);
    Ok(true)
}

/// Spawn `ip <args>` (argv vector — NO shell, so no value reaches `/bin/sh`; spec §3) bounded by the shared
/// liveness guard. `ip` is a busybox applet on the signed rootfs, resolved via box-init's `PATH`. Returns
                    
/// `Ok(true)` on exit-0. A stuck `ip` is SIGKILLed at the deadline → `Ok(false)`.
fn run_ip(args: &[String]) -> io::Result<bool> {
    let child = Command::new("ip").args(args).spawn()?;
    Ok(
        crate::oneshots::run_bounded(child, "network-up", crate::oneshots::FAST_TIMEOUT_SECS)?
            .success(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(v: &str) -> Result<NetConfig, NetCmdlineError> {
                                                                            
        parse_net(&format!(
            "fb.root-hash=abc ro fb.net={v} lockdown=integrity"
        ))
    }

    #[test]
    fn valid_static_parses() {
        assert_eq!(
            p("mode=static;ip=192.0.2.10/24;gw=192.0.2.1;dns=1.1.1.1,8.8.8.8").unwrap(),
            NetConfig::Static {
                ip: "192.0.2.10".into(),
                prefix: 24,
                gw: "192.0.2.1".into(),
                dns: vec!["1.1.1.1".into(), "8.8.8.8".into()],
            }
        );
    }

    #[test]
    fn dhcp_parses_as_dhcp() {
        assert_eq!(parse_net("fb.net=mode=dhcp").unwrap(), NetConfig::Dhcp);
    }

    #[test]
    fn missing_token_is_missing() {
        assert_eq!(
            parse_net("fb.root-hash=abc ro"),
            Err(NetCmdlineError::Missing)
        );
    }

    #[test]
    fn missing_mode_errors() {
        assert_eq!(
            p("ip=192.0.2.10/24;gw=192.0.2.1;dns=1.1.1.1"),
            Err(NetCmdlineError::MissingMode)
        );
    }

    #[test]
    fn out_of_range_octet_rejected() {
        assert_eq!(
            p("mode=static;ip=256.0.0.1/24;gw=192.0.2.1;dns=1.1.1.1"),
            Err(NetCmdlineError::InvalidAddr {
                field: "ip",
                value: "256.0.0.1".into()
            })
        );
        assert!(matches!(
            p("mode=static;ip=192.0.2.10/24;gw=999.1.2.3;dns=1.1.1.1"),
            Err(NetCmdlineError::InvalidAddr { field: "gw", .. })
        ));
    }

    #[test]
    fn leading_zero_octet_rejected() {
        assert_eq!(
            p("mode=static;ip=010.0.0.1/24;gw=10.0.0.254;dns=1.1.1.1"),
            Err(NetCmdlineError::InvalidAddr {
                field: "ip",
                value: "010.0.0.1".into()
            })
        );
    }

    #[test]
    fn prefix_zero_and_oversize_rejected_thirtyone_and_two_ok() {
        assert!(matches!(
            p("mode=static;ip=192.0.2.10/0;gw=192.0.2.1;dns=1.1.1.1"),
            Err(NetCmdlineError::InvalidPrefix(_))
        ));
        assert!(matches!(
            p("mode=static;ip=192.0.2.10/33;gw=192.0.2.1;dns=1.1.1.1"),
            Err(NetCmdlineError::InvalidPrefix(_))
        ));
                                                    
        assert!(p("mode=static;ip=192.0.2.10/31;gw=192.0.2.11;dns=1.1.1.1").is_ok());
                                                                                                            
        assert!(matches!(
            p("mode=static;ip=192.0.2.10/32;gw=192.0.2.1;dns=1.1.1.1"),
            Err(NetCmdlineError::GatewayOffSubnet { .. })
        ));
    }

    #[test]
    fn gateway_class_rejected() {
        for bad in [
            "0.0.0.0",
            "255.255.255.255",
            "127.0.0.1",
            "224.0.0.1",
            "240.0.0.1",
        ] {
            let r = p(&format!(
                "mode=static;ip=192.0.2.10/24;gw={bad};dns=1.1.1.1"
            ));
            assert!(
                matches!(r, Err(NetCmdlineError::GatewayNotUnicast(_))),
                "gw {bad} must be rejected, got {r:?}"
            );
        }
    }

    #[test]
    fn off_subnet_gateway_rejected() {
        assert_eq!(
            p("mode=static;ip=192.0.2.10/24;gw=198.51.100.1;dns=1.1.1.1"),
            Err(NetCmdlineError::GatewayOffSubnet {
                ip: "192.0.2.10".into(),
                prefix: 24,
                gw: "198.51.100.1".into()
            })
        );
    }

    #[test]
    fn dns_capped_at_three() {
        assert_eq!(
            p("mode=static;ip=192.0.2.10/24;gw=192.0.2.1;dns=1.1.1.1,8.8.8.8,9.9.9.9,1.0.0.1"),
            Err(NetCmdlineError::TooManyDns(4))
        );
    }

    #[test]
    fn empty_and_missing_required_fields_rejected() {
        assert_eq!(
            p("mode=static;ip=;gw=192.0.2.1;dns=1.1.1.1"),
            Err(NetCmdlineError::MissingField("ip"))
        );
        assert_eq!(
            p("mode=static;ip=192.0.2.10/24;gw=192.0.2.1"),
            Err(NetCmdlineError::MissingField("dns"))
        );
        assert_eq!(
            p("mode=static;ip=192.0.2.10/24;gw=192.0.2.1;dns="),
            Err(NetCmdlineError::MissingField("dns"))
        );
                                                                                                           
        assert!(p("mode=static;ip=192.0.2.10/24;gw=192.0.2.1;dns=1.1.1.1,").is_ok());
    }

    #[test]
    fn duplicate_key_rejected() {
        assert_eq!(
            p("mode=static;mode=dhcp;ip=192.0.2.10/24;gw=192.0.2.1;dns=1.1.1.1"),
            Err(NetCmdlineError::DuplicateField("mode".into()))
        );
    }

    #[test]
    fn unknown_and_reserved_keys_rejected() {
        assert_eq!(
            p("mode=static;ip=192.0.2.10/24;gw=192.0.2.1;dns=1.1.1.1;foo=bar"),
            Err(NetCmdlineError::UnknownField("foo".into()))
        );
        assert!(matches!(
            p("mode=static;ip=192.0.2.10/24;gw=192.0.2.1;dns=1.1.1.1;ip6=2001:db8::1/64"),
            Err(NetCmdlineError::ReservedField("ip6"))
        ));
    }

    #[test]
    fn whitespace_truncation_surfaces_as_missing_field() {
                                                                                                     
                                                                                                           
        let r = parse_net("fb.net=mode=static;ip=192.0.2.10/24;gw=192.0.2.1 dns=1.1.1.1");
        assert_eq!(r, Err(NetCmdlineError::MissingField("dns")));
    }

    #[test]
    fn no_shell_metachar_in_validated_values() {
                                                                                      
        assert!(matches!(
            p("mode=static;ip=192.0.2.10/24;gw=$(reboot);dns=1.1.1.1"),
            Err(NetCmdlineError::InvalidAddr { field: "gw", .. })
        ));
    }

    #[test]
    fn static_plan_is_the_expected_ordered_argv_and_resolv() {
                                                                                                               
        let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<String>>();
        let plan = plan_static(
            "192.0.2.10",
            24,
            "192.0.2.1",
            &["1.1.1.1".into(), "8.8.8.8".into()],
        );
                                                                                            
        assert_eq!(plan.link_lo, s(&["link", "set", "lo", "up"]));
        assert!(plan.sysctls.iter().any(|(p, v)| p.as_str()
            == "/proc/sys/net/ipv6/conf/eth0/accept_ra"
            && v.as_str() == "0"));
        assert!(plan.sysctls.iter().any(|(p, v)| p.as_str()
            == "/proc/sys/net/ipv6/conf/eth0/autoconf"
            && v.as_str() == "0"));
        assert!(plan.sysctls.iter().any(|(p, v)| p.as_str()
            == "/proc/sys/net/ipv6/conf/eth0/accept_redirects"
            && v.as_str() == "0"));
        assert!(plan.sysctls.iter().any(|(p, v)| p.as_str()
            == "/proc/sys/net/ipv4/conf/eth0/accept_redirects"
            && v.as_str() == "0"));
        assert_eq!(
            plan.v6_flush,
            s(&["-6", "addr", "flush", "dev", "eth0", "scope", "global"])
        );
                                                                             
        assert_eq!(
            plan.core,
            vec![
                s(&["link", "set", "eth0", "up"]),
                s(&["addr", "replace", "192.0.2.10/24", "dev", "eth0"]),
                s(&[
                    "route",
                    "replace",
                    "default",
                    "via",
                    "192.0.2.1",
                    "dev",
                    "eth0"
                ]),
            ]
        );
        assert_eq!(plan.resolv_conf, "nameserver 1.1.1.1\nnameserver 8.8.8.8\n");
    }

    #[test]
    fn dhcp_apply_is_fail_closed_in_build_a() {
                                                                                   
        assert!(!apply(&NetConfig::Dhcp).unwrap());
    }
}

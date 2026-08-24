//! `fb-mark-good` — the probation health-probe commit/rollback longrun (spec §5 C-D).
//!
//! Rendered as a Services-scandir PeriodicLoop (T19): a one-shot binary re-run every
//! ~10 s by `while : ; do fb-mark-good --boot-dev <dev>; sleep 10; done`. ONE iteration
        
//! per invocation. Services-only ⇒ a rescue boot never commits. Runs root +
//! CAP_SYS_BOOT so its `reboot(2)` reboots (the rollback driver).
//!
//! Iteration: read the probation record; no record means Idle (exit). A record that
//! does NOT match the running slot+root_hash means Stale (write last-failure, clear it,
//! keep serving). A MATCHING record is a probation boot: on the first such iteration
//! this boot it durably re-clears the ADV (spec §4e/M1, gated by a tmpfs `/run`
//! marker), then probes (haproxy TLS :443, a time-valid cert, the tenant health route
//! returning 200) and decides between Commit (patch DEFAULT, set floors, clear record),
//! Probe (keep waiting), and Rollback (sync then reboot).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use fb_update::Record;
use fb_update::floors::record_matches_running;
use fb_update::mark_good::{Decision, commit_floors_and_clear, decide};
use fb_update::selector::{SeabiosGptSelector, SlotSelector};

const UPDATE_DIR: &str = "/persist/update";
const BOOT_MNT: &str = "/run/fb-update/boot";
/// The tmpfs marker gating the once-per-boot ADV re-clear (cleared each boot).
const RECLEAR_MARKER: &str = "/run/fb-mark-good.recleared";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
                                                                                        
                                                                                          
                                         
    let boot_dev = match fb_update::selector::resolve_boot_dev(flag(&args, "--boot-dev")) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("fb-mark-good: {e}");
            return ExitCode::from(2);
        }
    };
                                                                                   
                                                                                        
                                                                                          
                                                        
    let probe = ProbeCfg {
        port: flag(&args, "--probe-port").and_then(|p| p.parse::<u16>().ok()),
        path: flag(&args, "--probe-path").map(str::to_string),
        host: flag(&args, "--probe-host").map(str::to_string),
    };

    let update_dir = Path::new(UPDATE_DIR);
                                                                                               
                                                                                                  
                                                                                                     
    let record = match std::fs::read(update_dir.join("record")) {
        Ok(bytes) => match Record::parse(&bytes) {
            Ok(r) => r,
            Err(_) => {
                let _ = std::fs::write(
                    update_dir.join("last-failure"),
                    b"malformed probation record (corrupted /persist)\n",
                );
                return ExitCode::SUCCESS;
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return ExitCode::SUCCESS,
        Err(_) => {
            let _ = std::fs::write(
                update_dir.join("last-failure"),
                b"unreadable probation record (corrupted /persist)\n",
            );
            return ExitCode::SUCCESS;
        }
    };

    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let (Some(running_slot), Some(running_rh)) = (
        fb_update::cmdline::running_slot(&cmdline),
        fb_update::cmdline::root_hash(&cmdline),
    ) else {
                                                                                 
        return ExitCode::SUCCESS;
    };

    let selector = SeabiosGptSelector {
        boot_dev,
        cmdline: cmdline.clone(),
        boot_mnt: PathBuf::from(BOOT_MNT),
    };

                                                                                          
                                                                                                     
                                                                                                   
                                                                                            
                                                                                                      
                                                                                                   
                                                                    
    let _lock = match acquire_lock(update_dir) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("fb-mark-good: cannot take the update lock: {e}");
            return ExitCode::from(1);
        }
    };

                                                                                     
                                                                                    
                                                                                     
    if record_matches_running(&record, running_slot, running_rh)
        && !Path::new(RECLEAR_MARKER).exists()
    {
        match selector.reclear() {
            Ok(_) => {
                let _ = std::fs::write(RECLEAR_MARKER, b"1");
            }
            Err(e) => {
                                                                                        
                                                                    
                eprintln!("fb-mark-good: ADV re-clear failed: {e:?}");
            }
        }
    }

    let healthy = probe_healthy(&probe);
    let uptime = read_uptime_secs();
    match decide(Some(&record), running_slot, running_rh, healthy, uptime) {
        Decision::Idle => ExitCode::SUCCESS,
        Decision::Probe => ExitCode::SUCCESS,                             
        Decision::Stale => {
                                                                                     
                                                           
            let _ = std::fs::write(
                update_dir.join("last-failure"),
                format!(
                    "stale-record slot={} root_hash={}\n",
                    record.slot.as_str(),
                    record.root_hash
                ),
            );
            let _ = std::fs::remove_file(update_dir.join("record"));
            ExitCode::SUCCESS
        }
        Decision::Commit => {
                                                                                     
                                                                                      
                                                               
            if let Err(e) = selector.commit_default(record.slot) {
                eprintln!("fb-mark-good: commit DEFAULT patch failed: {e:?}");
                return ExitCode::from(1);
            }
            if let Err(e) = commit_floors_and_clear(update_dir, &record) {
                eprintln!("fb-mark-good: commit floors/record failed: {e}");
                return ExitCode::from(1);
            }
            ExitCode::SUCCESS
        }
        Decision::Rollback => {
                                                                                        
                                                                                         
            eprintln!("fb-mark-good: probation deadline exceeded — rolling back (reboot)");
            let _ = std::fs::write(
                update_dir.join("last-failure"),
                format!(
                    "rollback slot={} version={}\n",
                    record.slot.as_str(),
                    record.version
                ),
            );
            reboot();
            ExitCode::from(1)                                     
        }
    }
}

/// The bake-rendered probe wiring (tenant manifest `[probe]` + the box domain).
struct ProbeCfg {
    port: Option<u16>,
    path: Option<String>,
    host: Option<String>,
}

/// The deep readiness probe (§5 C-D): a haproxy TLS handshake on 127.0.0.1:`port` with a
/// TIME-VALID leaf, then the tenant's declared health route answering THROUGH the edge.
/// Fail-closed AND of the sub-checks — a refused connect, a failed handshake, a
/// time-invalid leaf, or a 4xx/5xx all mean unhealthy; any missing wiring flag keeps the
/// pre-wiring fail-closed posture (delay-then-rollback, never false-commit).
///
/// "Answers" = a 2xx/3xx status on the manifest-declared probe path — the same §5.1f
/// tenant-alive semantic the produced-bytes boot gates assert (the reference tenant's
/// `/` answers 303-to-login for an anonymous probe, so a strict `== 200` would
/// false-rollback a healthy box; 4xx/5xx — a broken route or a dead backend behind a
/// live edge — stays unhealthy). The chain-of-trust is deliberately NOT verified (the
/// box probing its own loopback edge has no CA relationship to it — first-boot certs
/// are self-signed); the leaf's VALIDITY WINDOW is (the fb-cert-check expiry alarm's
/// enforcement twin at commit time).
fn probe_healthy(cfg: &ProbeCfg) -> bool {
    let (Some(port), Some(path), Some(host)) = (cfg.port, cfg.path.as_deref(), cfg.host.as_deref())
    else {
        eprintln!(
            "fb-mark-good: probe wiring incomplete (--probe-port/--probe-path/--probe-host) — \
             fail-closed unhealthy"
        );
        return false;
    };
    match probe::https_status(port, path, host) {
        Ok(code) => {
            let healthy = (200..=399).contains(&code);
            if !healthy {
                eprintln!("fb-mark-good: probe {path} answered {code} — unhealthy");
            }
            healthy
        }
        Err(e) => {
            eprintln!("fb-mark-good: probe failed: {e} — unhealthy");
            false
        }
    }
}

/// The thin TLS/HTTP probe client (box-only I/O; exercised on produced bytes by
                                     
/// the update boot gate). rustls with the ring provider — the same TLS stack the box
/// already ships in fb-acme — plus x509-parser for the leaf validity window (the
/// fb-cert-check parser). Sync sans-io (`rustls::Stream` over a std `TcpStream`); the
/// HTTP GET is a hand-rolled request + status-line parse (one round-trip, no client dep).
mod probe {
    use std::io::{Read as _, Write as _};
    use std::sync::Arc;

    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    /// Accept any chain, but REQUIRE the leaf to be time-valid at the handshake instant
    /// (the §5 C-D "time-valid cert" leg). Signature checks are accepted unverified —
    /// the probe's target is the box's OWN loopback edge; there is no CA relationship
    /// to verify, and the integrity signal is the validity window, not the chain.
    #[derive(Debug)]
    struct TimeValidLeafOnly {
        schemes: Vec<SignatureScheme>,
    }

    impl ServerCertVerifier for TimeValidLeafOnly {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            let (_, cert) = x509_parser::parse_x509_certificate(end_entity.as_ref())
                .map_err(|e| rustls::Error::General(format!("leaf does not parse: {e}")))?;
            let at = x509_parser::time::ASN1Time::from_timestamp(now.as_secs() as i64)
                .map_err(|e| rustls::Error::General(format!("handshake time: {e}")))?;
            if cert.validity().is_valid_at(at) {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(rustls::Error::General(format!(
                    "leaf not time-valid at {} (not_before {}, not_after {})",
                    now.as_secs(),
                    cert.validity().not_before,
                    cert.validity().not_after,
                )))
            }
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.schemes.clone()
        }
    }

    /// GET `path` from `https://127.0.0.1:<port>` (SNI/Host = `host`, the box domain);
    /// return the response status code. Err on connect/handshake/time-validity/read
    /// failure — the caller maps every Err to unhealthy.
    pub fn https_status(port: u16, path: &str, host: &str) -> Result<u16, String> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let schemes = provider
            .signature_verification_algorithms
            .supported_schemes();
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("tls versions: {e}"))?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(TimeValidLeafOnly { schemes }))
            .with_no_client_auth();
        let server_name =
            ServerName::try_from(host.to_string()).map_err(|e| format!("bad probe host: {e}"))?;
        let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)
            .map_err(|e| format!("tls client: {e}"))?;

        let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
        let mut sock = std::net::TcpStream::connect_timeout(&addr, IO_TIMEOUT)
            .map_err(|e| format!("connect {addr}: {e}"))?;
        sock.set_read_timeout(Some(IO_TIMEOUT))
            .and_then(|()| sock.set_write_timeout(Some(IO_TIMEOUT)))
            .map_err(|e| format!("socket timeouts: {e}"))?;

        let mut tls = rustls::Stream::new(&mut conn, &mut sock);
        tls.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
        )
        .map_err(|e| format!("send request (handshake?): {e}"))?;

                                                                                  
                                                                                      
        let mut buf = Vec::with_capacity(1024);
        let mut chunk = [0u8; 512];
        while !buf.windows(2).any(|w| w == b"\r\n") && buf.len() < 8 * 1024 {
            match tls.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) => return Err(format!("read response: {e}")),
            }
        }
        parse_status_line(&buf)
    }

    /// Parse `HTTP/1.x <code> …` from the response head.
    pub fn parse_status_line(head: &[u8]) -> Result<u16, String> {
        let line_end = head
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("no status line in response")?;
        let line = std::str::from_utf8(&head[..line_end])
            .map_err(|_| "status line is not utf-8".to_string())?;
        let mut parts = line.split_whitespace();
        let proto = parts.next().ok_or("empty status line")?;
        if !proto.starts_with("HTTP/") {
            return Err(format!("not an HTTP status line: {line:?}"));
        }
        parts
            .next()
            .and_then(|c| c.parse::<u16>().ok())
            .ok_or_else(|| format!("no status code in {line:?}"))
    }

    #[cfg(test)]
    mod tests {
        use super::parse_status_line;

        #[test]
        fn parses_the_status_code() {
            assert_eq!(
                parse_status_line(b"HTTP/1.1 303 See Other\r\nServer: x\r\n\r\n").unwrap(),
                303
            );
            assert_eq!(parse_status_line(b"HTTP/1.1 200 OK\r\n").unwrap(), 200);
            assert!(parse_status_line(b"garbage\r\n").is_err());
            assert!(parse_status_line(b"HTTP/1.1\r\n").is_err());
            assert!(parse_status_line(b"no line ending").is_err());
        }
    }
}

/// `/proc/uptime` whole seconds (clock-free deadline comparison).
fn read_uptime_secs() -> u64 {
    std::fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|s| s.split_whitespace().next()?.split('.').next()?.parse().ok())
        .unwrap_or(0)
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

/// Take the exclusive `<update_dir>/lock` `flock`, held until the returned File drops (spec §4f).
/// The SAME lock file `fb-update apply` takes, so an apply-vs-mark-good mutation cannot interleave.
fn acquire_lock(update_dir: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::io::AsRawFd as _;
    std::fs::create_dir_all(update_dir)?;
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(update_dir.join("lock"))?;
                                                               
    let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(f)
}

fn reboot() {
                                                                                      
                                                                               
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_AUTOBOOT);
    }
}

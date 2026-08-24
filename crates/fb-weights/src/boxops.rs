//! The REAL (box-side) [`crate::swap::SwapOps`] + the baked runtime configuration readers.
//!
//! The sequencing brains live in `swap.rs` (host-tested); this module is the thin, root-only
//! side-effect layer the bin wires in: `s6-svc` control against the live `/run/service` scandir,
//! the raw-partition streaming write (write-then-reread), the fb-verity-rt device calls, and the
//! REAL-inference health probe (a plain HTTP/1.1 POST over `TcpStream` to the engine's loopback
//! listener — std-only, no HTTP dependency for a localhost call).
//!
//! Two BAKED config files parameterize the box shape (written by the orchard v4 bake, signed
//! rootfs — Task 7):
//! - `/etc/recipes/weights-engine` — one line: the engine's s6 service name (the manifest's
//!   `resource_domain.engine.service`, e.g. `creatine`).
//! - `/etc/recipes/weights-health` — the real-inference probe: `port=<u16>\npath=<abs path>\n
//!   body=<one-line JSON>\n` (strict order, the stores.rs line-grammar style).

use crate::setup::{DM_NAME, MODELS_MOUNT};
use crate::swap::{PausePoint, SwapOps};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Baked engine-service-name file (one trimmed line).
pub const WEIGHTS_ENGINE_FILE: &str = "/etc/recipes/weights-engine";
/// Baked health-probe config file.
pub const WEIGHTS_HEALTH_FILE: &str = "/etc/recipes/weights-health";
/// The live s6 scandir (box-init's tmpfs scandir — `scandir.rs`).
pub const SCANDIR: &str = "/run/service";

/// The parsed health-probe config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthCfg {
    pub port: u16,
    pub path: String,
    pub body: String,
}

/// Parse the baked health config (strict 3-line whitelist, same posture as the weights manifest:
/// exactly `port=`, `path=`, `body=` in order, nothing else).
pub fn parse_health_cfg(text: &str) -> io::Result<HealthCfg> {
    let mut lines = text.split_inclusive('\n');
    let port_s = take(&mut lines, "port")?;
    let port: u16 = port_s
        .parse()
        .map_err(|e| io::Error::other(format!("weights-health: port: {e}")))?;
    let path = take(&mut lines, "path")?.to_string();
    if !path.starts_with('/') {
        return Err(io::Error::other("weights-health: path must be absolute"));
    }
    let body = take(&mut lines, "body")?.to_string();
    if lines.next().is_some() {
        return Err(io::Error::other("weights-health: trailing content"));
    }
    Ok(HealthCfg { port, path, body })
}

fn take<'a>(lines: &mut impl Iterator<Item = &'a str>, key: &str) -> io::Result<&'a str> {
    lines
        .next()
        .and_then(|l| l.strip_prefix(key))
        .and_then(|l| l.strip_prefix('='))
        .and_then(|l| l.strip_suffix('\n'))
        .ok_or_else(|| io::Error::other(format!("weights-health: missing/malformed {key}= line")))
}

/// Read the baked engine service name (one line; strict: non-empty, no whitespace inside).
pub fn read_engine_service(path: &Path) -> io::Result<String> {
    let s = std::fs::read_to_string(path)
        .map_err(|e| io::Error::other(format!("weights-engine {}: {e}", path.display())))?;
    let name = s.trim();
    if name.is_empty() || name.contains(char::is_whitespace) {
        return Err(io::Error::other(
            "weights-engine: expected one bare service name",
        ));
    }
    Ok(name.to_string())
}

/// Is an HTTP/1.x response's status line a 200? (The health gate's pure half — the engine either
/// completed a real forward pass and said 200, or it didn't.)
pub fn http_status_is_200(response_head: &[u8]) -> bool {
    let Some(line_end) = response_head.iter().position(|&b| b == b'\n') else {
        return false;
    };
    let line = &response_head[..line_end];
                                              
    let s = String::from_utf8_lossy(line);
    let mut parts = s.split_whitespace();
    matches!(
        (parts.next(), parts.next()),
        (Some(proto), Some("200")) if proto.starts_with("HTTP/1.")
    )
}

/// The real box ops. `weights_dev` is the PARTUUID-resolved partition node (resolved ONCE, before
/// the engine stops — a resolve failure is a clean preflight refusal).
pub struct BoxSwapOps {
    pub weights_dev: PathBuf,
    pub health: HealthCfg,
}

impl SwapOps for BoxSwapOps {
    fn partition_size(&mut self) -> io::Result<u64> {
        fb_verity_rt::block_device_size(&self.weights_dev)
    }

    fn svc_stop_wait(&mut self, service: &str) -> io::Result<()> {
        s6_svc(&["-wD", "-d"], service)
    }

    fn svc_start(&mut self, service: &str) -> io::Result<()> {
        s6_svc(&["-u"], service)
    }

    fn pause_point(&self, p: PausePoint) {
        let Ok(want) = std::env::var("FB_WEIGHTS_PAUSE_AT") else {
            return;
        };
        if PausePoint::from_env(&want) != Some(p) {
            return;
        }
                                                                                    
                                                                      
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open("/run/fb-weights.paused")
        {
            let _ = writeln!(f, "{} {}", p.as_str(), std::process::id());
            let _ = f.sync_all();
        }
        loop {
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    }

    fn umount_models(&mut self) -> io::Result<()> {
        fb_verity_rt::umount(Path::new(MODELS_MOUNT))
    }

    fn dev_remove_model(&mut self) -> io::Result<()> {
        fb_verity_rt::dev_remove(DM_NAME)
    }

    fn write_image(
        &mut self,
        src: &mut dyn Read,
        size: u64,
        expected: &[u8; 32],
    ) -> io::Result<()> {
                                                                                                    
                                                                                               
                                                                                 
        const CHUNK: usize = 4 * 1024 * 1024;
        let mut dev = std::fs::OpenOptions::new()
            .write(true)
            .open(&self.weights_dev)?;
        let mut hasher = Sha256::new();
        let mut remaining = size;
        let mut buf = vec![0u8; CHUNK];
        let mut mid_write_fired = false;
        while remaining > 0 {
            let want = remaining.min(CHUNK as u64) as usize;
            let n = src.read(&mut buf[..want])?;
            if n == 0 {
                return Err(io::Error::other(format!(
                    "image stream ended {remaining} bytes short"
                )));
            }
            hasher.update(&buf[..n]);
            dev.write_all(&buf[..n])?;
            remaining -= n as u64;
            if !mid_write_fired {
                mid_write_fired = true;
                self.pause_point(PausePoint::MidWrite);
            }
        }
        let streamed: [u8; 32] = hasher.finalize().into();
        if &streamed != expected {
            return Err(io::Error::other("streamed image sha256 mismatch"));
        }
        dev.sync_all()?;
        drop(dev);

                                                                                                 
                                                           
        let mut dev = std::fs::File::open(&self.weights_dev)?;
        let mut hasher = Sha256::new();
        let mut remaining = size;
        while remaining > 0 {
            let want = remaining.min(CHUNK as u64) as usize;
            let n = dev.read(&mut buf[..want])?;
            if n == 0 {
                return Err(io::Error::other("partition reread ended short"));
            }
            hasher.update(&buf[..n]);
            remaining -= n as u64;
        }
        let reread: [u8; 32] = hasher.finalize().into();
        if &reread != expected {
            return Err(io::Error::other("partition reread sha256 mismatch"));
        }
        Ok(())
    }

    fn setup_and_mount(&mut self, root_hash: &str, verity_offset: u64) -> io::Result<()> {
        let dev = self
            .weights_dev
            .to_str()
            .ok_or_else(|| io::Error::other("weights dev path is not utf-8"))?;
        let node = fb_verity_rt::setup_verity_device(
            DM_NAME,
            dev,
            root_hash,
            verity_offset,
            fb_verity_rt::CorruptionMode::Default,
        )?;
        fb_verity_rt::mount_squashfs_ro(&node, Path::new(MODELS_MOUNT))
    }

    fn health_check(&mut self) -> io::Result<()> {
                                                                                                
                                                                                           
                                                                              
        use std::net::{SocketAddr, TcpStream};
        let addr: SocketAddr = format!("127.0.0.1:{}", self.health.port)
            .parse()
            .map_err(|e| io::Error::other(format!("health addr: {e}")))?;
                                                                                                   
                                                                                                
                                                                                                    
                                                                                                     
                                                                                                  
                                                                                
        let connect_deadline = std::time::Instant::now() + Duration::from_secs(90);
        let mut conn = loop {
            match TcpStream::connect_timeout(&addr, Duration::from_secs(5)) {
                Ok(c) => break c,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset
                    ) && std::time::Instant::now() < connect_deadline =>
                {
                    std::thread::sleep(Duration::from_secs(1));
                }
                Err(e) => {
                    return Err(io::Error::other(format!(
                        "engine health probe could not connect to {addr} within the startup window: {e}"
                    )));
                }
            }
        };
        conn.set_read_timeout(Some(Duration::from_secs(120)))?;                                  
        conn.set_write_timeout(Some(Duration::from_secs(10)))?;
        let req = format!(
            "POST {} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.health.path,
            self.health.body.len(),
            self.health.body
        );
        conn.write_all(req.as_bytes())?;
        let mut response = Vec::new();
        conn.take(64 * 1024).read_to_end(&mut response)?;
        if !http_status_is_200(&response) {
            return Err(io::Error::other(format!(
                "engine health probe not 200: {:?}",
                String::from_utf8_lossy(&response[..response.len().min(200)])
            )));
        }
        Ok(())
    }

    fn now_unix(&mut self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)                                                                        
    }

    fn sleep(&mut self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// Run `s6-svc <flags> /run/service/<service>`, mapping a non-zero exit to an error. `s6-svc` is
/// censused in the box's REQUIRED_PATH_COMMANDS (the dha AC-I precedent).
fn s6_svc(flags: &[&str], service: &str) -> io::Result<()> {
    let dir = format!("{SCANDIR}/{service}");
    let status = std::process::Command::new("s6-svc")
        .args(flags)
        .arg(&dir)
        .status()
        .map_err(|e| io::Error::other(format!("spawn s6-svc: {e}")))?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "s6-svc {flags:?} {dir}: exit {status}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn health_cfg_parses_and_rejects_deviations() {
        let cfg = parse_health_cfg(
            "port=8080\npath=/v1/completions\nbody={\"prompt\":\"2+2=\",\"max_tokens\":1}\n",
        )
        .expect("parses");
        assert_eq!(cfg.port, 8080);
        assert_eq!(cfg.path, "/v1/completions");
        assert!(cfg.body.contains("max_tokens"));

        for bad in [
            "",
            "port=99999\npath=/x\nbody={}\n",                       
            "path=/x\nport=80\nbody={}\n",                    
            "port=80\npath=relative\nbody={}\n",                        
            "port=80\npath=/x\nbody={}\nextra=1\n",            
            "port=80\npath=/x\nbody={}",                                  
        ] {
            assert!(parse_health_cfg(bad).is_err(), "must reject {bad:?}");
        }
    }

    #[test]
    fn engine_service_reader_is_strict() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("weights-engine");
        std::fs::write(&p, "creatine\n").expect("write");
        assert_eq!(read_engine_service(&p).expect("read"), "creatine");
        for bad in ["", "  \n", "two words\n"] {
            std::fs::write(&p, bad).expect("write");
            assert!(read_engine_service(&p).is_err(), "{bad:?} must reject");
        }
    }

    #[test]
    fn http_status_line_parse() {
        assert!(http_status_is_200(
            b"HTTP/1.1 200 OK\r\ncontent-type: json\r\n\r\n{}"
        ));
        assert!(http_status_is_200(b"HTTP/1.0 200 OK\n"));
        assert!(!http_status_is_200(b"HTTP/1.1 503 Service Unavailable\r\n"));
        assert!(!http_status_is_200(b"HTTP/1.1 404 Not Found\r\n"));
        assert!(!http_status_is_200(b"garbage"));
        assert!(!http_status_is_200(b""));
    }
}

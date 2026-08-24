//! `fb-oneshots set-hostname` — the bootstrap oneshot that sets the kernel hostname
//! (box-init bootstrap sequence; spec L744). Reads the operator-set `/persist/etc/hostname`
//! (survives image swaps); on a fresh /persist that file is absent, so it falls back to
//! the image default baked into the run script (`--fallback`). The fallback is
//! load-bearing: without it a first boot would set no hostname / the oneshot could stall
//! (plan L-4).

use std::path::Path;

/// Resolve which hostname to set: the trimmed `/persist/etc/hostname` contents if present
/// AND valid, else the `fallback` (which must itself be valid). A present-but-garbage
/// persist file falls through to the fallback rather than setting an invalid hostname.
pub fn resolve_hostname(persist_contents: Option<&str>, fallback: &str) -> Result<String, String> {
    if let Some(raw) = persist_contents {
        let trimmed = raw.trim();
        if valid_hostname(trimmed) {
            return Ok(trimmed.to_string());
        }
                                                                                    
    }
    if valid_hostname(fallback) {
        Ok(fallback.to_string())
    } else {
        Err(format!(
            "no valid hostname: /persist file absent/invalid and fallback {fallback:?} is invalid"
        ))
    }
}

/// RFC-1123-shaped hostname validation, capped at Linux `HOST_NAME_MAX` (64). Rejects
/// empty / over-long names and anything outside `[A-Za-z0-9.-]` per dot-label — closing
/// the "set a whitespace / control-char / injected hostname" vector.
pub fn valid_hostname(name: &str) -> bool {
    if name.is_empty() || name.len() > 64 {
        return false;
    }
    if name.starts_with('.') || name.ends_with('.') {
        return false;
    }
    name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// Entry point: read the persist file, resolve the name, set the kernel hostname.
pub fn set_hostname(persist_path: &Path, fallback: &str) -> Result<(), Box<dyn std::error::Error>> {
    let contents = std::fs::read_to_string(persist_path).ok();
    let name = resolve_hostname(contents.as_deref(), fallback)
        .map_err(|m| std::io::Error::new(std::io::ErrorKind::InvalidInput, m))?;
    apply_hostname(&name)?;
    println!("fb-oneshots set-hostname: kernel hostname set to {name:?}");
    Ok(())
}

/// Set the live kernel hostname via `sethostname(2)` (equivalent to writing
/// `/proc/sys/kernel/hostname`). Runs as root under PID-1's s6 tree (CAP_SYS_ADMIN). The
/// syscall is the side effect, so it is exercised by the QEMU boot-test, not unit tests.
#[cfg(unix)]
fn apply_hostname(name: &str) -> std::io::Result<()> {
    let bytes = name.as_bytes();
    let rc = unsafe { libc::sethostname(bytes.as_ptr() as *const libc::c_char, bytes.len()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn apply_hostname(_name: &str) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persist_file_wins_when_valid() {
        assert_eq!(
            resolve_hostname(Some("box-1.example.org\n"), "fallback-host").unwrap(),
            "box-1.example.org"
        );
    }

    #[test]
    fn falls_back_when_persist_absent() {
        assert_eq!(
            resolve_hostname(None, "fallback-host").unwrap(),
            "fallback-host"
        );
    }

    #[test]
    fn falls_back_when_persist_invalid() {
                                                                                     
                                   
        assert_eq!(
            resolve_hostname(Some("bad host name"), "fallback-host").unwrap(),
            "fallback-host"
        );
        assert_eq!(
            resolve_hostname(Some(""), "fallback-host").unwrap(),
            "fallback-host"
        );
        assert_eq!(
            resolve_hostname(Some("x\nbind"), "fallback-host").unwrap(),
            "fallback-host"
        );
    }

    #[test]
    fn errors_when_both_invalid() {
        assert!(resolve_hostname(None, "bad fallback!").is_err());
        assert!(resolve_hostname(Some("also bad!"), "also bad!").is_err());
    }

    #[test]
    fn valid_hostname_accepts_and_rejects() {
        assert!(valid_hostname("recipes-box"));
        assert!(valid_hostname("box.example.org"));
        assert!(valid_hostname("a"));
        assert!(!valid_hostname(""));
        assert!(!valid_hostname("has space"));
        assert!(!valid_hostname("x\ninject"));
        assert!(!valid_hostname("-lead"));
        assert!(!valid_hostname("trail-"));
        assert!(!valid_hostname(".lead"));
        assert!(!valid_hostname("under_score"));
        assert!(!valid_hostname(&"a".repeat(65)));
    }
}

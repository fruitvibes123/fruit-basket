//! The ACME issuance seam + clock-sync gate.
//!
//! `AcmeClient` is the testable seam (mirrors image-builder's `Fetcher`): the
//! renew orchestration (gate → obtain → persist → backoff) is written against
//! the trait, so it's unit-tested with a fake while the live `instant-acme`
//! adapter ([`crate::instant_client`]) is exercised by the QEMU deploy smoke.

use std::time::Duration;

/// A freshly-issued cert: the leaf+intermediate chain PEM and the matching
/// private-key PEM. [`full_pem`](CertMaterial::full_pem) concatenates them in
/// the HAProxy `crt` form (key ‖ chain in one file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertMaterial {
    /// PEM-encoded private key for the issued certificate.
    pub private_key_pem: String,
    /// PEM-encoded certificate chain (leaf first, then intermediates).
    pub certificate_chain_pem: String,
}

impl CertMaterial {
    /// The combined PEM HAProxy's `bind ... crt <file>` directive expects:
    /// private key followed by the full chain, each block newline-terminated.
    pub fn full_pem(&self) -> String {
        format!(
            "{}\n{}\n",
            self.private_key_pem.trim_end(),
            self.certificate_chain_pem.trim_end()
        )
    }
}

/// How the renew loop should treat an ACME failure (spec §"ACME retry/backoff",
             
/// per-error-class handling).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryClass {
    /// Network / DNS / transient server error → standard exponential backoff.
    Backoff,
    /// ACME rate-limit hit → sleep until the rate-limit window expires; the
    /// operator verifies config against `--acme-mode=staging` meanwhile.
    RateLimit,
    /// Account-key / authorization failure → do NOT retry; operator must
    /// intervene (a retry just burns the same auth failure).
    Fatal,
}

/// A classified ACME issuance error. The variant determines [`RetryClass`].
#[derive(Debug, thiserror::Error)]
pub enum AcmeError {
    /// ACME server returned a rate-limit response.
    #[error("ACME rate limited: {0}")]
    RateLimited(String),
    /// Network / DNS / transient transport or server error.
    #[error("ACME network/transport error: {0}")]
    Network(String),
    /// Account-key or authorization failure (auth-class — not retryable).
    #[error("ACME account/authorization error: {0}")]
    Account(String),
    /// Anything else — treated as retryable (Backoff) by default.
    #[error("ACME error: {0}")]
    Other(String),
}

impl AcmeError {
    /// Map the error to its retry class (the per-error-class handling pin).
    pub fn retry_class(&self) -> RetryClass {
        match self {
            AcmeError::RateLimited(_) => RetryClass::RateLimit,
            AcmeError::Account(_) => RetryClass::Fatal,
            AcmeError::Network(_) | AcmeError::Other(_) => RetryClass::Backoff,
        }
    }
}

/// The network-ACME seam. Production = [`crate::instant_client::InstantAcmeClient`];
/// tests inject a fake. The implementation owns the directory URL, the
/// (loaded-or-created) account, and the challenge-dir writes; the orchestration
/// only sees "obtain a cert for these domains, or a classified error".
#[allow(async_fn_in_trait)]                                                
pub trait AcmeClient {
    /// Run the full HTTP-01 order for `domains` and return the issued material.
    /// The impl writes each challenge token into the served challenge dir.
    async fn obtain_certificate(&self, domains: &[String]) -> Result<CertMaterial, AcmeError>;
}

/// The clock-readiness gate seam. Production = [`crate::instant_client::EpochFloorClock`]
/// (the build-epoch floor of [`clock_past_build_epoch`] read off the live clock); tests
/// fake it. Renew defers issuance until the gate reports ready. (Decision 2 — the
/// `chronyc tracking` poll was dropped together with chrony itself; busybox `ntpd` +
/// kvm-clock now step the clock, and the build-epoch floor is the readiness proxy.)
pub trait ClockSync {
    /// `Ok(true)` once the system clock is trustworthy enough to issue certs —
    /// i.e. it has advanced past the image's build epoch (see
    /// [`clock_past_build_epoch`]).
    fn is_synced(&self) -> Result<bool, String>;
}

/// Clock-readiness gate (Decision 2 — replaces the `chronyc tracking` poll after
/// chrony was dropped for busybox `ntpd` + kvm-clock).
                                                   
/// The system clock is "synced enough"
/// to contact Let's Encrypt once it has advanced strictly past the image's build
/// epoch (`SOURCE_DATE_EPOCH`). A first boot whose clock hasn't yet been stepped by
/// `ntpd` (an RTC-less / mis-set VPS clock) reads a pre-build time → below the floor
/// → defer. This is a monotonic lower bound: the image cannot have been built in the
/// future, so a clock at/below the build epoch is definitionally not yet trustworthy
/// for cert-validity windows. It is NOT a full NTP-sync proof — issuing with a clock
/// that is past the floor but still skewed degrades to ACME-retry, not a web outage
/// (the self-signed bootstrap cert keeps HAProxy up meanwhile; spec L775).
pub fn clock_past_build_epoch(now_unix_secs: u64, build_epoch_secs: u64) -> bool {
    now_unix_secs > build_epoch_secs
}

             
/// Exponential backoff schedule (spec §"ACME retry/backoff"):
/// initial 5 min, doubling, capped at 24h; max 5 attempts per 24h window, then
/// sleep a full 24h window before the next series.
pub const BACKOFF_INITIAL: Duration = Duration::from_secs(5 * 60);
pub const BACKOFF_CAP: Duration = Duration::from_secs(24 * 60 * 60);
pub const BACKOFF_MAX_ATTEMPTS: u32 = 5;
/// Rate-limit cool-off: Let's Encrypt's longest standard window is 7 days.
pub const RATE_LIMIT_WAIT: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// What the renew loop should do after attempt `attempt` (0-based) failed with
/// the given retry class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackoffDecision {
    /// Sleep this long, then retry.
    Retry(Duration),
    /// Stop retrying — operator intervention required (auth-class failure).
    Bail,
}

/// Decide the next action after a failed attempt. Pure (no sleeping) so the
/// schedule is unit-testable; the loop wires it to `tokio::time::sleep`.
pub fn next_backoff(attempt: u32, class: RetryClass) -> BackoffDecision {
    match class {
        RetryClass::Fatal => BackoffDecision::Bail,
        RetryClass::RateLimit => BackoffDecision::Retry(RATE_LIMIT_WAIT),
        RetryClass::Backoff => {
            if attempt >= BACKOFF_MAX_ATTEMPTS {
                                                                                    
                return BackoffDecision::Retry(BACKOFF_CAP);
            }
                                               
            let secs = BACKOFF_INITIAL
                .as_secs()
                .saturating_mul(1u64 << attempt.min(32))
                .min(BACKOFF_CAP.as_secs());
            BackoffDecision::Retry(Duration::from_secs(secs))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_classes_map_correctly() {
        assert_eq!(
            AcmeError::RateLimited("429".into()).retry_class(),
            RetryClass::RateLimit
        );
        assert_eq!(
            AcmeError::Network("dns".into()).retry_class(),
            RetryClass::Backoff
        );
        assert_eq!(
            AcmeError::Account("bad key".into()).retry_class(),
            RetryClass::Fatal
        );
        assert_eq!(
            AcmeError::Other("?".into()).retry_class(),
            RetryClass::Backoff
        );
    }

    #[test]
    fn backoff_fatal_bails() {
        assert_eq!(next_backoff(0, RetryClass::Fatal), BackoffDecision::Bail);
        assert_eq!(next_backoff(3, RetryClass::Fatal), BackoffDecision::Bail);
    }

    #[test]
    fn backoff_ratelimit_waits_a_week() {
        assert_eq!(
            next_backoff(0, RetryClass::RateLimit),
            BackoffDecision::Retry(RATE_LIMIT_WAIT)
        );
    }

    #[test]
    fn backoff_exponential_then_capped() {
        assert_eq!(
            next_backoff(0, RetryClass::Backoff),
            BackoffDecision::Retry(Duration::from_secs(5 * 60))
        );
        assert_eq!(
            next_backoff(1, RetryClass::Backoff),
            BackoffDecision::Retry(Duration::from_secs(10 * 60))
        );
        assert_eq!(
            next_backoff(2, RetryClass::Backoff),
            BackoffDecision::Retry(Duration::from_secs(20 * 60))
        );
                                                            
        assert_eq!(
            next_backoff(BACKOFF_MAX_ATTEMPTS, RetryClass::Backoff),
            BackoffDecision::Retry(BACKOFF_CAP)
        );
    }

    #[test]
    fn full_pem_is_key_then_chain() {
        let m = CertMaterial {
            private_key_pem: "-----BEGIN PRIVATE KEY-----\nKKKK\n-----END PRIVATE KEY-----".into(),
            certificate_chain_pem: "-----BEGIN CERTIFICATE-----\nCCCC\n-----END CERTIFICATE-----"
                .into(),
        };
        let full = m.full_pem();
        let key_at = full.find("PRIVATE KEY").unwrap();
        let cert_at = full.find("CERTIFICATE").unwrap();
        assert!(key_at < cert_at, "key precedes chain in HAProxy crt form");
        assert!(full.ends_with('\n'));
    }

    #[test]
    fn clock_gate_defers_at_or_below_build_epoch() {
                                                                                  
        assert!(!clock_past_build_epoch(0, 1_700_000_500));
        assert!(!clock_past_build_epoch(1_700_000_000, 1_700_000_500));
                                                                         
        assert!(!clock_past_build_epoch(1_700_000_500, 1_700_000_500));
    }

    #[test]
    fn clock_gate_passes_strictly_above_build_epoch() {
        assert!(clock_past_build_epoch(1_700_000_501, 1_700_000_500));
        assert!(clock_past_build_epoch(u64::MAX, 1_700_000_500));
    }
}

//! Live production adapters behind the [`crate::acme`] seams:
//! [`InstantAcmeClient`] (the `instant-acme` HTTP-01 flow) and [`EpochFloorClock`]
//! (the build-epoch clock-readiness gate). The live adapters' network behavior is
//! exercised by the QEMU deploy smoke (a dryrun against the Let's Encrypt
//! staging directory); the renew orchestration is tested via fakes in [`crate::renew`]
//! and the floor comparison via the pure [`crate::acme::clock_past_build_epoch`]. The
//! one piece unit-tested here is the C-1 trust store ([`webpki_root_store`]) — its
//! non-emptiness is the regression guard for "the box can verify Let's Encrypt".

use std::path::PathBuf;

use bytes::Bytes;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client as HyperClient;
use hyper_util::rt::TokioExecutor;
use instant_acme::{
    Account, AccountCredentials, BodyWrapper, ChallengeType, HttpClient, Identifier, NewAccount,
    NewOrder, RetryPolicy,
};

use crate::acme::{AcmeClient, AcmeError, CertMaterial, ClockSync, clock_past_build_epoch};

/// Build the ACME HTTPS client from the COMPILED-IN Mozilla roots ([`webpki_root_store`])
/// instead of instant-acme's default client, which uses `rustls-platform-verifier` →
/// `rustls-native-certs` → the box's `/etc/ssl/certs`. The box ships no system CA trust
/// store, so that default has zero anchors and the TLS handshake to Let's Encrypt's API
/// fails (network-bringup holistic R2, C-1). Injecting our own client via
/// [`Account::builder_with_http`] puts the trust anchors inside the signed, dm-verity-
/// protected binary — no filesystem trust store. Both LE prod and staging API endpoints
/// are served with publicly-trusted (Mozilla-rooted) certs, so this single store covers
/// production issuance AND the staging boot-gate. Construction mirrors instant-acme's own
/// `DefaultClient::with_roots`, so the `HttpClient` blanket impl applies.
fn acme_http_client() -> Box<dyn HttpClient> {
    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(webpki_root_store())
        .with_no_client_auth();
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_only()
        .enable_http1()
        .enable_http2()
        .build();
                                                                              
                                                                            
    let client: HyperClient<_, BodyWrapper<Bytes>> =
        HyperClient::builder(TokioExecutor::new()).build(https);
    Box::new(client)
}

/// The compiled-in Mozilla root set (C-1). A non-empty store is the regression guard:
/// drop the `webpki-roots` dep and the store is empty → TLS to LE fails exactly as the
/// holistic R2 found. Pinned by `webpki_root_store_has_anchors`.
fn webpki_root_store() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

/// Live ACME client. Owns the directory URL, the per-domain account-state path,
/// and the served challenge dir; performs load-or-create account → order →
/// HTTP-01 → finalize → download.
pub struct InstantAcmeClient {
    pub directory_url: String,
    /// `/run/fb-acme/challenges` — where `serve` reads challenge files.
    pub challenge_dir: PathBuf,
    /// `<persist>/<domain>/account.json` — persisted ACME account credentials.
    pub account_path: PathBuf,
    /// Optional `mailto:` contact for the ACME account registration.
    pub contact_email: Option<String>,
}

impl InstantAcmeClient {
    /// Load the persisted account, or register a new one and persist it.
    async fn load_or_create_account(&self) -> Result<Account, AcmeError> {
        if let Ok(bytes) = std::fs::read(&self.account_path) {
            let creds: AccountCredentials = serde_json::from_slice(&bytes)
                .map_err(|e| AcmeError::Other(format!("parse account.json: {e}")))?;
            return Account::builder_with_http(acme_http_client())
                .from_credentials(creds)
                .await
                .map_err(|e| map_err(&e));
        }

        let contact: Vec<String> = self
            .contact_email
            .iter()
            .map(|e| format!("mailto:{e}"))
            .collect();
        let contact_refs: Vec<&str> = contact.iter().map(String::as_str).collect();
        let (account, creds) = Account::builder_with_http(acme_http_client())
            .create(
                &NewAccount {
                    contact: &contact_refs,
                    terms_of_service_agreed: true,
                    only_return_existing: false,
                },
                self.directory_url.clone(),
                None,
            )
            .await
            .map_err(|e| map_err(&e))?;

                                                                                 
        let json = serde_json::to_vec(&creds)
            .map_err(|e| AcmeError::Other(format!("serialize account: {e}")))?;
        write_0600(&self.account_path, &json)
            .map_err(|e| AcmeError::Other(format!("write account.json: {e}")))?;
        Ok(account)
    }

    /// Write a challenge response file `<challenge_dir>/<token>` = key auth.
    fn write_challenge(&self, token: &str, key_authorization: &str) -> Result<(), AcmeError> {
        std::fs::create_dir_all(&self.challenge_dir)
            .map_err(|e| AcmeError::Other(format!("create challenge dir: {e}")))?;
                                                                              
                                                              
        if token.is_empty() || token.contains('/') || token.contains("..") {
            return Err(AcmeError::Other(format!(
                "invalid challenge token {token:?}"
            )));
        }
        std::fs::write(self.challenge_dir.join(token), key_authorization)
            .map_err(|e| AcmeError::Other(format!("write challenge file: {e}")))
    }
}

impl AcmeClient for InstantAcmeClient {
    async fn obtain_certificate(&self, domains: &[String]) -> Result<CertMaterial, AcmeError> {
        let account = self.load_or_create_account().await?;

        let identifiers: Vec<Identifier> =
            domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(|e| map_err(&e))?;

                                                                        
                                                                         
        {
            let mut authzs = order.authorizations();
            while let Some(authz) = authzs.next().await {
                let mut authz = authz.map_err(|e| map_err(&e))?;
                let Some(mut challenge) = authz.challenge(ChallengeType::Http01) else {
                    return Err(AcmeError::Other(
                        "order authorization offered no HTTP-01 challenge".into(),
                    ));
                };
                let token = challenge.token.to_string();
                let key_auth = challenge.key_authorization().as_str().to_string();
                self.write_challenge(&token, &key_auth)?;
                challenge.set_ready().await.map_err(|e| map_err(&e))?;
            }
        }

        order
            .poll_ready(&RetryPolicy::default())
            .await
            .map_err(|e| map_err(&e))?;
                                                                                 
                                                                            
        let private_key_pem = order.finalize().await.map_err(|e| map_err(&e))?;
        let certificate_chain_pem = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .map_err(|e| map_err(&e))?;

        Ok(CertMaterial {
            private_key_pem,
            certificate_chain_pem,
        })
    }
}

/// Best-effort classification of an `instant_acme::Error` into a [`RetryClass`]
/// via [`AcmeError`]. The ACME problem URN (`...:error:rateLimited`,
/// `...:error:unauthorized` / `accountDoesNotExist`) is matched on the rendered
/// error; live LE responses refine this over time. Conservative default:
/// network/backoff (retryable), since `Account → Fatal` stops the daemon.
             
/// Matched on the SPECIFIC auth-class URN substrings only — a bare
/// `"account"` match was too broad (a transient error merely mentioning "account"
/// would falsely bail the renewal daemon → silent TLS-cert outage).
fn map_err(e: &instant_acme::Error) -> AcmeError {
    let s = e.to_string();
    let l = s.to_ascii_lowercase();
    if l.contains("ratelimited") || l.contains("rate limit") {
        AcmeError::RateLimited(s)
    } else if l.contains("unauthorized") || l.contains("accountdoesnotexist") {
        AcmeError::Account(s)
    } else {
        AcmeError::Network(s)
    }
}

             
/// Write account.json at 0600 via the shared hardened open (create_new +
/// O_NOFOLLOW — account.json is only written on first account creation, so the path
/// is fresh; an unlink-retry covers a stale leftover).
fn write_0600(path: &std::path::Path, contents: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = crate::renew::open_fresh_0600(path)?;
    f.write_all(contents)?;
    f.sync_all()
}

/// Clock-readiness gate backed by the build-epoch floor (Decision 2; replaces the
/// dropped `chronyc tracking` poll). Holds the image's `SOURCE_DATE_EPOCH` (passed via
/// `fb-acme renew --min-epoch`, interpolated into the s6 run script at build time);
/// reports ready once the live clock has advanced strictly past it. Reading
/// `SystemTime::now()` isn't injectable, so this adapter is not unit-tested here — the
/// pure floor comparison [`clock_past_build_epoch`] carries the logic + is tested in
/// [`crate::acme`].
pub struct EpochFloorClock {
    build_epoch_secs: u64,
}

impl EpochFloorClock {
    pub fn new(build_epoch_secs: u64) -> Self {
        Self { build_epoch_secs }
    }
}

impl ClockSync for EpochFloorClock {
    fn is_synced(&self) -> Result<bool, String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);                                                          
        Ok(clock_past_build_epoch(now, self.build_epoch_secs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn webpki_root_store_has_anchors() {
                                                                                        
                                                                                      
                                                                                        
                                                                                  
        let store = webpki_root_store();
        assert!(
            store.len() > 100,
            "expected the compiled-in Mozilla root set, got {} anchors",
            store.len()
        );
    }

    #[test]
    fn acme_http_client_builds_from_our_roots() {
                                                                                   
                                                                                     
                                                                                        
                                             
        let _client: Box<dyn HttpClient> = acme_http_client();
    }
}

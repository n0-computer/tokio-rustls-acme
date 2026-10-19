use std::convert::Infallible;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};
use futures::future::try_join_all;
use futures::{FutureExt, Stream, ready};
use rcgen::{CertificateParams, DistinguishedName, Error as RcgenError, PKCS_ECDSA_P256_SHA256};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer as RustlsCertificate, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, SignatureScheme};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Sleep;
use x509_parser::parse_x509_certificate;

struct ParsedCert {
    certified_key: CertifiedKey,
    validity: [DateTime<Utc>; 2],
    signature_schemes: Vec<SignatureScheme>,
}

use crate::acceptor::AcmeAcceptor;
use crate::acme::{
    Account, AcmeError, Auth, AuthStatus, Directory, Identifier, Order, OrderStatus,
};
use crate::config::CertChainPreference;
use crate::{AcmeConfig, Incoming, ResolvesServerCertAcme};

type Timer = std::pin::Pin<Box<Sleep>>;
type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

pub fn after(d: std::time::Duration) -> Timer {
    Box::pin(tokio::time::sleep(d))
}

/// Drives ACME orders and renewals, surfacing lifecycle events as a [`Stream`].
///
/// Owns the [`ResolvesServerCertAcme`] populated as new certificates are
/// issued. Construct one from [`AcmeConfig::state`].
#[allow(clippy::type_complexity)]
pub struct AcmeState<EC: Debug = Infallible, EA: Debug = EC> {
    config: Arc<AcmeConfig<EC, EA>>,
    resolver: Arc<ResolvesServerCertAcme>,
    account_key: Option<Vec<u8>>,

    early_action: Option<BoxFuture<Event<EC, EA>>>,
    load_cert: Option<BoxFuture<Result<Option<CachedCert>, EC>>>,
    load_account: Option<BoxFuture<Result<Option<Vec<u8>>, EA>>>,
    order: Option<BoxFuture<Result<OrderResult, OrderError>>>,
    backoff_cnt: usize,
    wait: Option<Timer>,
}

pub type Event<EC, EA> = Result<EventOk, EventError<EC, EA>>;

#[derive(Debug)]
pub enum EventOk {
    DeployedCachedCert,
    DeployedNewCert,
    CertCacheStore,
    AccountCacheStore,
}

#[derive(Error, Debug)]
pub enum EventError<EC: Debug, EA: Debug> {
    #[error("cert cache load: {0}")]
    CertCacheLoad(EC),
    #[error("account cache load: {0}")]
    AccountCacheLoad(EA),
    #[error("cert cache store: {0}")]
    CertCacheStore(EC),
    #[error("account cache store: {0}")]
    AccountCacheStore(EA),
    #[error("cached cert parse: {0}")]
    CachedCertParse(CertParseError),
    #[error("order: {0}")]
    Order(OrderError),
    #[error("new cert parse: {0}")]
    NewCertParse(CertParseError),
}

#[derive(Error, Debug)]
pub enum OrderError {
    #[error("acme error: {0}")]
    Acme(#[from] AcmeError),
    #[error("certificate generation error: {0}")]
    Rcgen(#[from] RcgenError),
    #[error("bad order object: {0:?}")]
    BadOrder(Order),
    #[error("bad auth object: {0:?}")]
    BadAuth(Auth),
    #[error("authorization for {0} failed too many times")]
    TooManyAttemptsAuth(String),
    #[error("order status stayed on processing too long")]
    ProcessingTimeout(Order),
}

#[derive(Error, Debug)]
pub enum CertParseError {
    #[error("X509 parsing error: {0}")]
    X509(#[from] x509_parser::nom::Err<x509_parser::error::X509Error>),
    #[error("expected 2 or more pem, got: {0}")]
    Pem(#[from] pem::PemError),
    #[error("expected 2 or more pem, got: {0}")]
    TooFewPem(usize),
    #[error("unsupported private key type")]
    InvalidPrivateKey,
}

struct OrderResult {
    primary: Vec<u8>,
    alternate: Option<Vec<u8>>,
}

/// Certificate loaded from the cache, plus the alternate chain in DualChain mode.
struct CachedCert {
    primary: Vec<u8>,
    alternate: Option<Vec<u8>>,
}

/// Extract the issuer common name of the last certificate in a PEM chain.
/// For a typical chain [leaf, intermediate], this returns the CN of whoever
/// signed the intermediate — i.e. the root CA, which may not be included
/// in the chain itself.
fn chain_root_issuer(cert_pem: &str) -> Option<String> {
    let pems = pem::parse_many(cert_pem).ok()?;
    let last_der = pems.last()?.contents().to_vec();
    let (_, cert) = parse_x509_certificate(&last_der).ok()?;
    cert.issuer()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string())
}

/// Map an X.509 signature algorithm OID to the corresponding rustls SignatureScheme.
///
/// This is a heuristic: a TLS scheme also fixes the signer's curve (ECDSA) or
/// the PSS hash, which the OID alone doesn't. ECDSA is mapped by hash
/// (`ecdsa-with-SHA384` to `ECDSA_NISTP384_SHA384`) and RSA-PSS to
/// `RSA_PSS_SHA256`. That's right for Let's Encrypt's chains, whose ECDSA
/// intermediates and roots are P-384.
fn sig_oid_to_scheme(oid: &x509_parser::asn1_rs::Oid) -> Option<SignatureScheme> {
    use x509_parser::oid_registry::*;

    if *oid == OID_PKCS1_SHA256WITHRSA {
        Some(SignatureScheme::RSA_PKCS1_SHA256)
    } else if *oid == OID_PKCS1_SHA384WITHRSA {
        Some(SignatureScheme::RSA_PKCS1_SHA384)
    } else if *oid == OID_PKCS1_SHA512WITHRSA {
        Some(SignatureScheme::RSA_PKCS1_SHA512)
    } else if *oid == OID_PKCS1_RSASSAPSS {
        Some(SignatureScheme::RSA_PSS_SHA256)
    } else if *oid == OID_SIG_ECDSA_WITH_SHA256 {
        Some(SignatureScheme::ECDSA_NISTP256_SHA256)
    } else if *oid == OID_SIG_ECDSA_WITH_SHA384 {
        Some(SignatureScheme::ECDSA_NISTP384_SHA384)
    } else if *oid == OID_SIG_ECDSA_WITH_SHA512 {
        Some(SignatureScheme::ECDSA_NISTP521_SHA512)
    } else if *oid == OID_SIG_ED25519 {
        Some(SignatureScheme::ED25519)
    } else if *oid == OID_SIG_ED448 {
        Some(SignatureScheme::ED448)
    } else {
        None
    }
}

impl<EC: 'static + Debug, EA: 'static + Debug> AcmeState<EC, EA> {
    /// Wraps `tcp_incoming` so each connection is dispatched to ACME
    /// validation or to application TLS, returning an [`Incoming`] stream.
    ///
    /// `alpn_protocols` lists application protocols offered to clients,
    /// most preferred first. Pass an empty `Vec` to disable ALPN.
    pub fn incoming<
        TCP: AsyncRead + AsyncWrite + Unpin,
        ETCP,
        ITCP: Stream<Item = Result<TCP, ETCP>> + Unpin,
    >(
        self,
        tcp_incoming: ITCP,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Incoming<TCP, ETCP, ITCP, EC, EA> {
        let acceptor = self.acceptor();
        Incoming::new(tcp_incoming, self, acceptor, alpn_protocols)
    }

    /// Like [`AcmeState::incoming`] but uses `server_config` for the
    /// application TLS handshake.
    ///
    /// Use this when the caller needs to customize the rustls
    /// [`ServerConfig`] beyond ALPN (e.g. session storage, mTLS).
    pub fn incoming_with_server<
        TCP: AsyncRead + AsyncWrite + Unpin,
        ETCP,
        ITCP: Stream<Item = Result<TCP, ETCP>> + Unpin,
    >(
        self,
        tcp_incoming: ITCP,
        server_config: ServerConfig,
    ) -> Incoming<TCP, ETCP, ITCP, EC, EA> {
        let acceptor = self.acceptor();
        Incoming::new_with_server(tcp_incoming, self, acceptor, server_config)
    }

    /// Returns an [`AcmeAcceptor`] for use with custom TCP accept loops.
    pub fn acceptor(&self) -> AcmeAcceptor {
        AcmeAcceptor::new(self.resolver(), self.crypto_provider())
    }

    /// Returns the [`CryptoProvider`] used by this state machine.
    pub fn crypto_provider(&self) -> Arc<CryptoProvider> {
        self.config.crypto_provider().clone()
    }

    #[cfg(feature = "axum")]
    pub fn axum_acceptor(
        &self,
        rustls_config: Arc<rustls::ServerConfig>,
    ) -> crate::axum::AxumAcceptor {
        crate::axum::AxumAcceptor::new(self.acceptor(), rustls_config)
    }
    /// Returns the certificate resolver populated by this state machine.
    pub fn resolver(&self) -> Arc<ResolvesServerCertAcme> {
        self.resolver.clone()
    }

    /// Creates a state machine from `config`. Equivalent to
    /// [`AcmeConfig::state`].
    pub fn new(config: AcmeConfig<EC, EA>) -> Self {
        let config = Arc::new(config);
        Self {
            config: config.clone(),
            resolver: ResolvesServerCertAcme::new(),
            account_key: None,
            early_action: None,
            load_cert: Some(Box::pin({
                let config = config.clone();
                async move {
                    let Some(primary) = config
                        .cache
                        .load_cert(&config.domains, &config.directory_url)
                        .await?
                    else {
                        return Ok(None);
                    };
                    // Only DualChain serves an alternate. A cached one from an
                    // earlier DualChain run is ignored in the other modes.
                    let alternate = match config.cert_chain {
                        CertChainPreference::DualChain(_) => match config
                            .cache
                            .load_alt_cert(&config.domains, &config.directory_url)
                            .await
                        {
                            Ok(alternate) => alternate,
                            Err(err) => {
                                log::warn!("failed to load cached alternate cert: {err:?}");
                                None
                            }
                        },
                        _ => None,
                    };
                    Ok(Some(CachedCert { primary, alternate }))
                }
            })),
            load_account: Some(Box::pin({
                let config = config;
                async move {
                    config
                        .cache
                        .load_account(&config.contact, &config.directory_url)
                        .await
                }
            })),
            order: None,
            backoff_cnt: 0,
            wait: None,
        }
    }
    fn parse_cert(
        crypto_provider: &CryptoProvider,
        pem: &[u8],
    ) -> Result<ParsedCert, CertParseError> {
        let mut pems = pem::parse_many(pem)?;
        if pems.len() < 2 {
            return Err(CertParseError::TooFewPem(pems.len()));
        }
        let pk_bytes = pems.remove(0).into_contents();
        let pk_der: PrivatePkcs8KeyDer<'static> = pk_bytes.into();
        let pk_der: PrivateKeyDer<'static> = pk_der.into();
        let pk = match crypto_provider.key_provider.load_private_key(pk_der) {
            Ok(pk) => pk,
            Err(_) => return Err(CertParseError::InvalidPrivateKey),
        };
        let cert_chain: Vec<RustlsCertificate> =
            pems.into_iter().map(|p| p.into_contents().into()).collect();

        let mut validity = None;
        let mut required_schemes = Vec::new();

        for der in cert_chain.iter() {
            let (_, cert) = parse_x509_certificate(der.as_ref()).map_err(CertParseError::X509)?;
            if validity.is_none() {
                let v = cert.validity();
                validity = Some(
                    [v.not_before, v.not_after]
                        .map(|t| Utc.timestamp_opt(t.timestamp(), 0).earliest().unwrap()),
                );
            }
            if let Some(scheme) = sig_oid_to_scheme(&cert.signature_algorithm.algorithm)
                && !required_schemes.contains(&scheme)
            {
                required_schemes.push(scheme);
            }
        }

        let validity = validity.expect("length checked above");
        let cert = CertifiedKey::new(cert_chain, pk);
        Ok(ParsedCert {
            certified_key: cert,
            validity,
            signature_schemes: required_schemes,
        })
    }

    #[allow(clippy::result_large_err)]
    fn process_cert(
        &mut self,
        pem: Vec<u8>,
        alternate: Option<Vec<u8>>,
        cached: bool,
    ) -> Event<EC, EA> {
        let provider = self.crypto_provider();
        let parsed = match (Self::parse_cert(&provider, &pem), cached) {
            (Ok(r), _) => r,
            (Err(err), cached) => {
                return match cached {
                    true => Err(EventError::CachedCertParse(err)),
                    false => Err(EventError::NewCertParse(err)),
                };
            }
        };
        self.resolver
            .set_cert(Arc::new(parsed.certified_key), parsed.signature_schemes);
        // After the primary: the resolver only accepts an alternate with the
        // primary's leaf, and clears a stale one.
        let alternate = alternate.filter(|alt_pem| match Self::parse_cert(&provider, alt_pem) {
            Ok(alt) => self
                .resolver
                .set_alt_cert(Some((Arc::new(alt.certified_key), alt.signature_schemes))),
            Err(err) => {
                log::warn!("failed to parse alternate cert chain: {err}");
                false
            }
        });
        if alternate.is_none() {
            self.resolver.set_alt_cert(None);
        }
        let validity = parsed.validity;
        let wait_duration = (validity[1] - (validity[1] - validity[0]) / 3 - Utc::now())
            .max(chrono::Duration::zero())
            .to_std()
            .unwrap_or_default();
        self.wait = Some(after(wait_duration));
        if cached {
            return Ok(EventOk::DeployedCachedCert);
        }
        let config = self.config.clone();
        self.early_action = Some(Box::pin(async move {
            let stored = async {
                config
                    .cache
                    .store_cert(&config.domains, &config.directory_url, &pem)
                    .await?;
                if let Some(alternate) = &alternate {
                    config
                        .cache
                        .store_alt_cert(&config.domains, &config.directory_url, alternate)
                        .await?;
                }
                Ok(())
            };
            match stored.await {
                Ok(()) => Ok(EventOk::CertCacheStore),
                Err(err) => Err(EventError::CertCacheStore(err)),
            }
        }));
        Event::Ok(EventOk::DeployedNewCert)
    }
    async fn order(
        config: Arc<AcmeConfig<EC, EA>>,
        resolver: Arc<ResolvesServerCertAcme>,
        key_pair: Vec<u8>,
    ) -> Result<OrderResult, OrderError> {
        let directory = Directory::discover(&config.client_config, &config.directory_url).await?;
        let account = Account::create_with_keypair(
            &config.client_config,
            directory,
            &config.contact,
            &key_pair,
            &config.eab,
        )
        .await?;

        let mut params = CertificateParams::new(config.domains.clone())?;
        params.distinguished_name = DistinguishedName::new();
        let key_pair = rcgen::KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;

        let (order_url, mut order) = account
            .new_order(&config.client_config, config.domains.clone())
            .await?;
        loop {
            match order.status {
                OrderStatus::Pending => {
                    let auth_futures = order
                        .authorizations
                        .iter()
                        .map(|url| Self::authorize(&config, &resolver, &account, url));
                    try_join_all(auth_futures).await?;
                    log::info!("completed all authorizations");
                    order = account.order(&config.client_config, &order_url).await?;
                }
                OrderStatus::Processing => {
                    for i in 0u64..10 {
                        log::info!("order processing");
                        after(Duration::from_secs(1u64 << i)).await;
                        order = account.order(&config.client_config, &order_url).await?;
                        if order.status != OrderStatus::Processing {
                            break;
                        }
                    }
                    if order.status == OrderStatus::Processing {
                        return Err(OrderError::ProcessingTimeout(order));
                    }
                }
                OrderStatus::Ready => {
                    log::info!("sending csr");
                    let csr = params.serialize_request(&key_pair)?;
                    order = account
                        .finalize(&config.client_config, order.finalize, csr.der().to_vec())
                        .await?
                }
                OrderStatus::Valid { certificate } => {
                    log::info!("download certificate");
                    let cert_response = account
                        .certificate_with_alternate_urls(&config.client_config, &certificate)
                        .await?;
                    let key_pem = key_pair.serialize_pem();

                    // Build key+cert PEM bundle(s) based on chain preference.
                    let make_pem = |cert_pem: &str| -> Vec<u8> {
                        [&key_pem, "\n", cert_pem].concat().into_bytes()
                    };

                    let (primary, alternate) = match &config.cert_chain {
                        // Use the default chain as-is.
                        CertChainPreference::Default => (make_pem(&cert_response.pem), None),

                        // Use a single chain: prefer an alternate matching `issuer`,
                        // fall back to the default if not found.
                        CertChainPreference::PreferredChain(issuer) => {
                            let default_matches =
                                chain_root_issuer(&cert_response.pem).as_deref() == Some(issuer);
                            let pem = if default_matches {
                                cert_response.pem
                            } else {
                                Self::fetch_chain_by_issuer(
                                    &account,
                                    &config.client_config,
                                    &cert_response.alternate_urls,
                                    issuer,
                                )
                                .await
                                .unwrap_or(cert_response.pem)
                            };
                            (make_pem(&pem), None)
                        }

                        // Serve two chains: the default as primary, and an alternate
                        // matching `issuer` for clients whose signature schemes differ.
                        CertChainPreference::DualChain(issuer) => {
                            let alternate = Self::fetch_chain_by_issuer(
                                &account,
                                &config.client_config,
                                &cert_response.alternate_urls,
                                issuer,
                            )
                            .await
                            .map(|pem| make_pem(&pem));
                            (make_pem(&cert_response.pem), alternate)
                        }
                    };

                    return Ok(OrderResult { primary, alternate });
                }
                OrderStatus::Invalid => return Err(OrderError::BadOrder(order)),
            }
        }
    }
    /// Fetch the first alternate chain whose root issuer CN matches `target_issuer`.
    /// Returns `None` if no match is found.
    ///
    /// Download errors are logged and skipped, not returned. By now the order
    /// is valid and the default chain is in hand. Failing the order would
    /// throw away the issued certificate and order a new one, which counts
    /// against the CA's rate limits.
    async fn fetch_chain_by_issuer(
        account: &Account,
        client_config: &Arc<rustls::ClientConfig>,
        alternate_urls: &[String],
        target_issuer: &str,
    ) -> Option<String> {
        for url in alternate_urls {
            log::debug!("fetching alternate chain from {url}");
            let alt_pem = match account.certificate(client_config, url).await {
                Ok(pem) => pem,
                Err(err) => {
                    log::warn!("failed to fetch alternate chain from {url}: {err}");
                    continue;
                }
            };
            if let Some(issuer) = chain_root_issuer(&alt_pem) {
                log::debug!("alternate chain root issuer: '{issuer}'");
                if issuer == target_issuer {
                    return Some(alt_pem);
                }
            }
        }
        log::warn!(
            "no alternate chain found matching issuer '{target_issuer}', using default chain"
        );
        None
    }
    async fn authorize(
        config: &AcmeConfig<EC, EA>,
        resolver: &ResolvesServerCertAcme,
        account: &Account,
        url: &String,
    ) -> Result<(), OrderError> {
        let auth = account.auth(&config.client_config, url).await?;
        let (domain, challenge_url) = match auth.status {
            AuthStatus::Pending => {
                let Identifier::Dns(domain) = auth.identifier;
                log::info!("trigger challenge for {}", domain);
                let (challenge, auth_key) = account.tls_alpn_01(
                    config.crypto_provider(),
                    &auth.challenges,
                    domain.clone(),
                )?;
                resolver.set_auth_key(domain.clone(), Arc::new(auth_key));
                account
                    .challenge(&config.client_config, &challenge.url)
                    .await?;
                (domain, challenge.url.clone())
            }
            AuthStatus::Valid => return Ok(()),
            _ => return Err(OrderError::BadAuth(auth)),
        };
        for i in 0u64..5 {
            after(Duration::from_secs(1u64 << i)).await;
            let auth = account.auth(&config.client_config, url).await?;
            match auth.status {
                AuthStatus::Pending => {
                    log::info!("authorization for {} still pending", domain);
                    account
                        .challenge(&config.client_config, &challenge_url)
                        .await?
                }
                AuthStatus::Valid => return Ok(()),
                _ => return Err(OrderError::BadAuth(auth)),
            }
        }
        Err(OrderError::TooManyAttemptsAuth(domain))
    }
    fn poll_next_infinite(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Event<EC, EA>> {
        loop {
            // queued early action
            if let Some(early_action) = &mut self.early_action {
                let result = ready!(early_action.poll_unpin(cx));
                self.early_action.take();
                return Poll::Ready(result);
            }

            // sleep
            if let Some(timer) = &mut self.wait {
                ready!(timer.poll_unpin(cx));
                self.wait.take();
            }

            // load from cert cache
            if let Some(load_cert) = &mut self.load_cert {
                let result = ready!(load_cert.poll_unpin(cx));
                self.load_cert.take();
                match result {
                    Ok(Some(cached)) => {
                        return Poll::Ready(Self::process_cert(
                            self.get_mut(),
                            cached.primary,
                            cached.alternate,
                            true,
                        ));
                    }
                    Ok(None) => {}
                    Err(err) => return Poll::Ready(Err(EventError::CertCacheLoad(err))),
                }
            }

            // load from account cache
            if let Some(load_account) = &mut self.load_account {
                let result = ready!(load_account.poll_unpin(cx));
                self.load_account.take();
                match result {
                    Ok(Some(key_pair)) => self.account_key = Some(key_pair),
                    Ok(None) => {}
                    Err(err) => return Poll::Ready(Err(EventError::AccountCacheLoad(err))),
                }
            }

            // execute order
            if let Some(order) = &mut self.order {
                let result = ready!(order.poll_unpin(cx));
                self.order.take();
                match result {
                    Ok(order_result) => {
                        self.backoff_cnt = 0;
                        return Poll::Ready(Self::process_cert(
                            self.get_mut(),
                            order_result.primary,
                            order_result.alternate,
                            false,
                        ));
                    }
                    Err(err) => {
                        // TODO: replace key on some errors or high backoff_cnt?
                        self.wait = Some(after(Duration::from_secs(1 << self.backoff_cnt)));
                        self.backoff_cnt = (self.backoff_cnt + 1).min(16);
                        return Poll::Ready(Err(EventError::Order(err)));
                    }
                }
            }

            // schedule order
            let account_key = match &self.account_key {
                None => {
                    let account_key = Account::generate_key_pair();
                    self.account_key = Some(account_key.clone());
                    let config = self.config.clone();
                    let account_key_clone = account_key.clone();
                    self.early_action = Some(Box::pin(async move {
                        match config
                            .cache
                            .store_account(
                                &config.contact,
                                &config.directory_url,
                                &account_key_clone,
                            )
                            .await
                        {
                            Ok(()) => Ok(EventOk::AccountCacheStore),
                            Err(err) => Err(EventError::AccountCacheStore(err)),
                        }
                    }));
                    account_key
                }
                Some(account_key) => account_key.clone(),
            };
            let config = self.config.clone();
            let resolver = self.resolver.clone();
            self.order = Some(Box::pin(Self::order(config, resolver, account_key)));
        }
    }
}

impl<EC: 'static + Debug, EA: 'static + Debug> Stream for AcmeState<EC, EA> {
    type Item = Event<EC, EA>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(Some(ready!(self.poll_next_infinite(cx))))
    }
}

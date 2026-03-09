use std::convert::Infallible;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use chrono::{DateTime, TimeZone, Utc};
use futures::future::try_join_all;
use futures::{ready, FutureExt, Stream};
use rcgen::{CertificateParams, DistinguishedName, Error as RcgenError, PKCS_ECDSA_P256_SHA256};
use rustls::crypto::ring::sign::any_ecdsa_type;
use rustls::pki_types::{CertificateDer as RustlsCertificate, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use rustls::{ServerConfig, SignatureScheme};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Sleep;
use x509_parser::parse_x509_certificate;

use crate::acceptor::AcmeAcceptor;
use crate::acme::{
    Account, AcmeError, Auth, AuthStatus, Directory, Identifier, Order, OrderStatus,
};
use crate::cache::CertChainKind;
use crate::config::CertChainPreference;
use crate::{AcmeConfig, Incoming, ResolvesServerCertAcme};

type Timer = std::pin::Pin<Box<Sleep>>;
type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

pub fn after(d: std::time::Duration) -> Timer {
    Box::pin(tokio::time::sleep(d))
}

#[allow(clippy::type_complexity)]
pub struct AcmeState<EC: Debug = Infallible, EA: Debug = EC> {
    config: Arc<AcmeConfig<EC, EA>>,
    resolver: Arc<ResolvesServerCertAcme>,
    account_key: Option<Vec<u8>>,

    early_action: Option<BoxFuture<Event<EC, EA>>>,
    load_cert: Option<BoxFuture<Result<Option<Vec<u8>>, EC>>>,
    load_alt_cert: Option<BoxFuture<Result<Option<Vec<u8>>, EC>>>,
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

/// Extract the subject common name of the last certificate (root) in a PEM chain.
fn chain_root_issuer(cert_pem: &str) -> Option<String> {
    let pems = pem::parse_many(cert_pem).ok()?;
    let last_der = pems.last()?.contents().to_vec();
    let (_, cert) = parse_x509_certificate(&last_der).ok()?;
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string());
    cn
}

/// Map an X.509 signature algorithm OID to the corresponding rustls SignatureScheme.
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

    pub fn acceptor(&self) -> AcmeAcceptor {
        AcmeAcceptor::new(self.resolver())
    }

    #[cfg(feature = "axum")]
    pub fn axum_acceptor(
        &self,
        rustls_config: Arc<rustls::ServerConfig>,
    ) -> crate::axum::AxumAcceptor {
        crate::axum::AxumAcceptor::new(self.acceptor(), rustls_config)
    }
    pub fn resolver(&self) -> Arc<ResolvesServerCertAcme> {
        self.resolver.clone()
    }
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
                    config
                        .cache
                        .load_cert(
                            &config.domains,
                            &config.directory_url,
                            CertChainKind::Default,
                        )
                        .await
                }
            })),
            load_alt_cert: Some(Box::pin({
                let config = config.clone();
                async move {
                    config
                        .cache
                        .load_cert(
                            &config.domains,
                            &config.directory_url,
                            CertChainKind::Alternate,
                        )
                        .await
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
        pem: &[u8],
    ) -> Result<(CertifiedKey, [DateTime<Utc>; 2], Vec<SignatureScheme>), CertParseError> {
        let mut pems = pem::parse_many(pem)?;
        if pems.len() < 2 {
            return Err(CertParseError::TooFewPem(pems.len()));
        }
        let pk_bytes = pems.remove(0).into_contents();
        let pk_der: PrivatePkcs8KeyDer = pk_bytes.into();
        let pk: PrivateKeyDer = pk_der.into();
        let pk = match any_ecdsa_type(&pk) {
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
            if let Some(scheme) = sig_oid_to_scheme(&cert.signature_algorithm.algorithm) {
                if !required_schemes.contains(&scheme) {
                    required_schemes.push(scheme);
                }
            }
        }

        let validity = validity.expect("length checked above");
        let cert = CertifiedKey::new(cert_chain, pk);
        Ok((cert, validity, required_schemes))
    }

    #[allow(clippy::result_large_err)]
    fn process_cert(&mut self, pem: Vec<u8>, cached: bool) -> Event<EC, EA> {
        let (cert, validity, schemes) = match (Self::parse_cert(&pem), cached) {
            (Ok(r), _) => r,
            (Err(err), cached) => {
                return match cached {
                    true => Err(EventError::CachedCertParse(err)),
                    false => Err(EventError::NewCertParse(err)),
                }
            }
        };
        self.resolver.set_cert(Arc::new(cert), schemes);
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
            match config
                .cache
                .store_cert(
                    &config.domains,
                    &config.directory_url,
                    CertChainKind::Default,
                    &pem,
                )
                .await
            {
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
                                .await?
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
                            .await?
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
    async fn fetch_chain_by_issuer(
        account: &Account,
        client_config: &Arc<rustls::ClientConfig>,
        alternate_urls: &[String],
        target_issuer: &str,
    ) -> Result<Option<String>, AcmeError> {
        for url in alternate_urls {
            log::info!("fetching alternate chain from {url}");
            let alt_pem = account.certificate(client_config, url).await?;
            if let Some(issuer) = chain_root_issuer(&alt_pem) {
                log::info!("alternate chain root issuer: '{issuer}'");
                if issuer == target_issuer {
                    return Ok(Some(alt_pem));
                }
            }
        }
        log::warn!(
            "no alternate chain found matching issuer '{target_issuer}', using default chain"
        );
        Ok(None)
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
                log::info!("trigger challenge for {}", &domain);
                let (challenge, auth_key) =
                    account.tls_alpn_01(&auth.challenges, domain.clone())?;
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
                    log::info!("authorization for {} still pending", &domain);
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
                    Ok(Some(pem)) => {
                        return Poll::Ready(Self::process_cert(self.get_mut(), pem, true));
                    }
                    Ok(None) => {}
                    Err(err) => return Poll::Ready(Err(EventError::CertCacheLoad(err))),
                }
            }

            // load alt cert from cache (for DualChain mode)
            if let Some(load_alt_cert) = &mut self.load_alt_cert {
                let result = ready!(load_alt_cert.poll_unpin(cx));
                self.load_alt_cert.take();
                match result {
                    Ok(Some(pem)) => match Self::parse_cert(&pem) {
                        Ok((alt_cert, _, schemes)) => {
                            self.resolver
                                .set_alt_cert(Some((Arc::new(alt_cert), schemes)));
                        }
                        Err(err) => {
                            log::warn!("failed to parse cached alternate cert: {err}");
                        }
                    },
                    Ok(None) => {}
                    Err(err) => {
                        log::warn!("failed to load cached alternate cert: {err:?}");
                    }
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
                        // Set alternate cert if present (DualChain mode).
                        if let Some(alt_pem) = &order_result.alternate {
                            match Self::parse_cert(alt_pem) {
                                Ok((alt_cert, _, schemes)) => {
                                    self.resolver
                                        .set_alt_cert(Some((Arc::new(alt_cert), schemes)));
                                    // Store alt cert in cache.
                                    let alt_pem = alt_pem.clone();
                                    let config = self.config.clone();
                                    tokio::spawn(async move {
                                        if let Err(err) = config
                                            .cache
                                            .store_cert(
                                                &config.domains,
                                                &config.directory_url,
                                                CertChainKind::Alternate,
                                                &alt_pem,
                                            )
                                            .await
                                        {
                                            log::warn!("failed to cache alternate cert: {err:?}");
                                        }
                                    });
                                }
                                Err(err) => {
                                    log::warn!("failed to parse alternate cert chain: {err}");
                                }
                            }
                        } else {
                            self.resolver.set_alt_cert(None);
                        }
                        return Poll::Ready(Self::process_cert(
                            self.get_mut(),
                            order_result.primary,
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
            self.order = Some(Box::pin({
                Self::order(config.clone(), resolver.clone(), account_key)
            }));
        }
    }
}

impl<EC: 'static + Debug, EA: 'static + Debug> Stream for AcmeState<EC, EA> {
    type Item = Event<EC, EA>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(Some(ready!(self.poll_next_infinite(cx))))
    }
}

use std::collections::VecDeque;
use std::convert::Infallible;
use std::fmt::{self, Debug};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use n0_future::{FutureExt, Stream, ready, try_join_all};
use rcgen::{CertificateParams, DistinguishedName, PKCS_ECDSA_P256_SHA256};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer as RustlsCertificate, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, ServerConfig};
use thiserror::Error;
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{Sleep, timeout};
use tracing::{debug, error, info, warn};
use x509_parser::parse_x509_certificate;

use crate::acceptor::AcmeAcceptor;
use crate::acme::{
    Account, AcmeError, Auth, AuthStatus, Directory, Identifier, Order, OrderStatus,
};
use crate::chain::CertChain;
use crate::config::{CertChainPreference, ChainRoot};
use crate::resolver::AlternateChain;
use crate::{AcmeConfig, Incoming, ResolvesServerCertAcme};

/// First delay of the order backoffs, which double it on each retry.
const BACKOFF_BASE_DELAY: Duration = Duration::from_secs(1);

/// Longest renewal sleep, because the monotonic timer misses clock corrections and host suspend.
const MAX_RENEWAL_SLEEP: Duration = Duration::from_secs(60 * 60);

/// Number of order rounds that can fail to advance the order status before the order fails.
const MAX_STALLED_ROUNDS: u32 = 10;

/// Limit for looking up an alternate chain, in the cache or at the CA.
///
/// The alternate is optional, so a slow cache or CA must not hold up the state machine.
const ALTERNATE_TIMEOUT: Duration = Duration::from_secs(10);

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

pub(crate) fn after(d: Duration) -> Pin<Box<Sleep>> {
    Box::pin(tokio::time::sleep(d))
}

/// Returns the time left from `now` until `deadline`, or `None` once it is reached.
fn time_until(deadline: OffsetDateTime, now: OffsetDateTime) -> Option<Duration> {
    let left: Duration = (deadline - now).try_into().ok()?;
    (!left.is_zero()).then_some(left)
}

/// Returns how long to sleep before the next renewal check, or `None` once renewal is due.
fn renewal_sleep(renew_at: OffsetDateTime, now: OffsetDateTime) -> Option<Duration> {
    time_until(renew_at, now).map(|left| left.min(MAX_RENEWAL_SLEEP))
}

/// Runs the alternate chain lookup `lookup`, or returns `None` after [`ALTERNATE_TIMEOUT`].
async fn bounded<T>(lookup: impl Future<Output = Option<T>>) -> Option<T> {
    timeout(ALTERNATE_TIMEOUT, lookup)
        .await
        .unwrap_or_else(|_| {
            warn!("looking up the alternate chain timed out, serving the default chain only");
            None
        })
}

/// Serves `chain` as the alternate of the certificate `cert`, and returns whether it does.
fn serve_alternate(
    resolver: &ResolvesServerCertAcme,
    cert: &CertifiedKey,
    chain: CertChain,
    provider: &CryptoProvider,
) -> bool {
    let alternate = AlternateChain::new(cert, chain, &provider.signature_verification_algorithms);
    let selectable = alternate.is_selectable();
    let served = resolver.set_alternate(alternate);
    match (served, selectable) {
        (true, true) => {
            info!("serving an alternate chain to clients that can't verify the default")
        }
        (true, false) => warn!("no client can verify the alternate chain but not the default one"),
        (false, _) => {}
    }
    served
}

/// Returns the delay after stalled order round `round`, or `None` once the order should fail.
fn stall_delay(round: u32) -> Option<Duration> {
    (round < MAX_STALLED_ROUNDS).then(|| BACKOFF_BASE_DELAY * (1 << round))
}

/// A failed order.
struct OrderFailure {
    error: OrderError,
    /// Whether the CA rejected the account key at `newAccount`.
    account_rejected: bool,
}

/// Drives ACME orders and renewals, surfacing lifecycle events as a [`Stream`].
///
/// Owns the [`ResolvesServerCertAcme`] populated as new certificates are
/// issued. Construct one from [`AcmeConfig::state`].
#[allow(
    clippy::type_complexity,
    reason = "the boxed futures are each used once, aliases would only move them"
)]
pub struct AcmeState<EC: Debug = Infallible, EA: Debug = EC> {
    config: Arc<AcmeConfig<EC, EA>>,
    resolver: Arc<ResolvesServerCertAcme>,
    account_key: Option<Vec<u8>>,

    /// Work that runs before anything else, and that may end with an event.
    early_actions: VecDeque<BoxFuture<Option<Event<EC, EA>>>>,
    load_cert: Option<BoxFuture<Result<Option<Vec<u8>>, EC>>>,
    load_account: Option<BoxFuture<Result<Option<Vec<u8>>, EA>>>,
    order: Option<BoxFuture<Result<IssuedCert, OrderFailure>>>,
    backoff_cnt: usize,
    wait: Option<Pin<Box<Sleep>>>,
    renew_at: Option<OffsetDateTime>,
}

/// Item of the [`AcmeState`] stream, reporting the outcome of one step.
pub type Event<EC, EA> = Result<EventOk, EventError<EC, EA>>;

/// A successful step of [`AcmeState`].
#[derive(Debug)]
#[non_exhaustive]
pub enum EventOk {
    /// A certificate from the cache is now served.
    DeployedCachedCert,
    /// A newly issued certificate is now served.
    DeployedNewCert,
    /// The newly issued certificate was stored in the cache.
    CertCacheStore,
    /// A newly generated account key was stored in the cache.
    AccountCacheStore,
}

/// A failed step of [`AcmeState`].
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum EventError<EC: Debug, EA: Debug> {
    /// Loading the certificate from the cache failed.
    #[error("cert cache load: {0}")]
    CertCacheLoad(EC),
    /// The account cache could not be read, so this run orders with a new key that is not stored.
    ///
    /// Return `Ok(None)` from [`AccountCache::load_account`] when no key is stored.
    /// Otherwise every start uses a new account.
    ///
    /// [`AccountCache::load_account`]: crate::AccountCache::load_account
    #[error("account cache load: {0}")]
    AccountCacheLoad(EA),
    /// Storing the newly issued certificate in the cache failed.
    #[error("cert cache store: {0}")]
    CertCacheStore(EC),
    /// Storing the alternate chain of the newly issued certificate failed.
    ///
    /// The alternate is served, but after a restart only from the next renewal on.
    #[error("alternate cert cache store: {0}")]
    AltCertCacheStore(EC),
    /// Loading the cached alternate chain failed, so it is served from the next renewal on.
    #[error("alternate cert cache load: {0}")]
    AltCertCacheLoad(EC),
    /// No valid alternate chain to the root of DualChain came for the new certificate in time.
    ///
    /// The alternate of the previous certificate is served until it expires.
    #[error("no alternate chain to the preferred root")]
    AltCertUnavailable,
    /// Storing the newly generated account key in the cache failed.
    #[error("account cache store: {0}")]
    AccountCacheStore(EA),
    /// The certificate from the cache could not be parsed.
    #[error("cached cert parse: {0}")]
    CachedCertParse(CertParseError),
    /// An order failed, and the next one starts after a backoff.
    ///
    /// If the CA rejects the account, later orders use a new account key kept in memory only.
    #[error("order: {0}")]
    Order(OrderError),
    /// The newly issued certificate could not be parsed.
    #[error("new cert parse: {0}")]
    NewCertParse(CertParseError),
}

/// An error that stopped a certificate order.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum OrderError {
    /// The ACME client failed.
    #[error("acme error: {0}")]
    Acme(#[from] AcmeError),
    /// Generating the certificate key or the CSR failed.
    ///
    /// Usually downcasts to `rcgen::Error`. The concrete type is not covered by semver.
    #[error("certificate generation error: {0}")]
    Rcgen(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The server marked the order invalid.
    #[error("bad order object: {0:?}")]
    BadOrder(Order),
    /// An authorization reached a status other than pending or valid.
    #[error("bad auth object: {0:?}")]
    BadAuth(Auth),
    /// The authorization for the given domain was still pending after the last check.
    #[error("authorization for {0} failed too many times")]
    TooManyAttemptsAuth(String),
    /// The order stayed `processing` or stopped advancing for too long.
    #[error("order did not reach a final status in time, last status {:?}", .0.status)]
    ProcessingTimeout(Order),
}

/// An error from parsing a PEM bundle of private key and certificate chain.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum CertParseError {
    /// The end-entity certificate is not valid X.509.
    ///
    /// Usually downcasts to `x509_parser::nom::Err<x509_parser::error::X509Error>`. The concrete type is not covered by semver.
    #[error("X509 parsing error: {0}")]
    X509(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The data is not valid PEM.
    ///
    /// Usually downcasts to `pem::PemError`. The concrete type is not covered by semver.
    #[error("expected 2 or more pem, got: {0}")]
    Pem(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// The bundle holds fewer than two PEM blocks, so the key or the certificate is missing.
    #[error("expected 2 or more pem, got: {0}")]
    TooFewPem(usize),
    /// The crypto provider cannot load the private key, or it does not match the certificate.
    #[error("private key is unsupported or does not match the certificate")]
    InvalidPrivateKey,
    /// The newly issued certificate has already expired.
    #[error("certificate has already expired")]
    Expired,
}

/// A parsed certificate chain with its key.
struct ParsedCert {
    certified_key: CertifiedKey,
    /// `notBefore` of the leaf.
    not_before: OffsetDateTime,
    /// `notAfter` of the leaf.
    not_after: OffsetDateTime,
}

/// A newly issued certificate.
struct IssuedCert {
    /// The PEM bundle of key and certificate chain.
    pem: Vec<u8>,
    /// Downloads the alternate chain of [`CertChainPreference::DualChain`].
    alternate: Option<BoxFuture<Option<CertChain>>>,
}

fn rcgen_err(err: rcgen::Error) -> OrderError {
    OrderError::Rcgen(err.into())
}

impl<EC: Debug, EA: Debug> fmt::Debug for AcmeState<EC, EA> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcmeState")
            .field("config", &self.config)
            .field("renew_at", &self.renew_at)
            .field("backoff_cnt", &self.backoff_cnt)
            .finish_non_exhaustive()
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

    /// Returns an [`AxumAcceptor`] that uses `rustls_config` for application TLS.
    ///
    /// [`AxumAcceptor`]: crate::axum::AxumAcceptor
    #[cfg(feature = "axum")]
    pub fn axum_acceptor(
        &self,
        rustls_config: Arc<rustls::ServerConfig>,
    ) -> crate::axum::AxumAcceptor {
        crate::axum::AxumAcceptor::new(self.acceptor(), rustls_config)
    }
    /// Returns the certificate resolver populated by this state machine.
    ///
    /// It serves the alternate chain of [`CertChainPreference::DualChain`] only through
    /// [`AcmeAcceptor::into_stream`], see [`ResolvesServerCertAcme`].
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
            early_actions: VecDeque::new(),
            load_cert: Some(Box::pin({
                let config = config.clone();
                async move {
                    config
                        .cache
                        .load_cert(&config.domains, &config.directory_url)
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
            renew_at: None,
        }
    }
    fn parse_cert(
        crypto_provider: &CryptoProvider,
        pem: &[u8],
    ) -> Result<ParsedCert, CertParseError> {
        let mut pems = pem::parse_many(pem).map_err(|err| CertParseError::Pem(err.into()))?;
        if pems.len() < 2 {
            return Err(CertParseError::TooFewPem(pems.len()));
        }
        let pk_bytes = pems.remove(0).into_contents();
        let pk_der: PrivatePkcs8KeyDer<'static> = pk_bytes.into();
        let cert_chain: Vec<RustlsCertificate> =
            pems.into_iter().map(|p| p.into_contents().into()).collect();

        let (_, leaf) = parse_x509_certificate(cert_chain[0].as_ref())
            .map_err(|err| CertParseError::X509(err.into()))?;
        let validity = leaf.validity();
        let (not_before, not_after) = (
            validity.not_before.to_datetime(),
            validity.not_after.to_datetime(),
        );
        let certified_key = CertifiedKey::from_der(cert_chain, pk_der.into(), crypto_provider)
            .map_err(|err| {
                warn!(%err, "rejecting certificate and private key");
                CertParseError::InvalidPrivateKey
            })?;
        Ok(ParsedCert {
            certified_key,
            not_before,
            not_after,
        })
    }

    /// Parses the PEM bundle `pem` of key and certificate chain, serves it, and returns it.
    ///
    /// A new certificate that has already expired is rejected, so the deployed one stays.
    #[allow(
        clippy::result_large_err,
        reason = "runs once per certificate, so the error size does not matter"
    )]
    fn deploy_cert(
        &mut self,
        pem: &[u8],
        cached: bool,
    ) -> Result<Arc<CertifiedKey>, EventError<EC, EA>> {
        let parsed = match Self::parse_cert(&self.crypto_provider(), pem) {
            Ok(parsed) => parsed,
            Err(err) if cached => return Err(EventError::CachedCertParse(err)),
            Err(err) => return Err(EventError::NewCertParse(err)),
        };
        let (not_before, not_after) = (parsed.not_before, parsed.not_after);
        // The deployed certificate may still be valid, so keep it and the cache.
        if !cached && not_after <= OffsetDateTime::now_utc() {
            warn!(%not_after, "the CA issued an expired certificate, keeping the deployed one");
            return Err(EventError::NewCertParse(CertParseError::Expired));
        }
        let cert = Arc::new(parsed.certified_key);
        self.resolver.set_cert(cert.clone());
        self.renew_at = Some(not_after - (not_after - not_before) / 3_i32);
        Ok(cert)
    }

    /// Serves the cached PEM bundle `pem`, then loads its alternate chain in DualChain mode.
    #[allow(
        clippy::result_large_err,
        reason = "runs once per certificate, so the error size does not matter"
    )]
    fn process_cached_cert(&mut self, pem: &[u8]) -> Event<EC, EA> {
        let cert = self.deploy_cert(pem, true)?;
        // Only DualChain serves an alternate. One cached by an earlier DualChain run is ignored.
        if let CertChainPreference::DualChain(root) = &self.config.cert_chain {
            let (config, resolver, root) =
                (self.config.clone(), self.resolver.clone(), root.clone());
            let provider = self.crypto_provider();
            self.early_actions.push_back(Box::pin(async move {
                let load = config
                    .cache
                    .load_alt_cert(&config.domains, &config.directory_url);
                let pem = match timeout(ALTERNATE_TIMEOUT, load).await {
                    Ok(Ok(pem)) => pem?,
                    Ok(Err(err)) => return Some(Err(EventError::AltCertCacheLoad(err))),
                    Err(_) => {
                        warn!("loading the cached alternate chain timed out");
                        return None;
                    }
                };
                let leaf = cert.end_entity_cert().ok()?;
                let algorithms = &provider.signature_verification_algorithms;
                match CertChain::from_pem(&pem) {
                    Some(chain) if chain.is_alternate_for(leaf, &root, algorithms) => {
                        serve_alternate(&resolver, &cert, chain, &provider);
                    }
                    _ => {
                        warn!(%root, "cached alternate is no chain to the root for the certificate")
                    }
                }
                None
            }));
        }
        Ok(EventOk::DeployedCachedCert)
    }

    /// Serves and stores the new certificate `issued`, then its alternate in DualChain mode.
    #[allow(
        clippy::result_large_err,
        reason = "runs once per certificate, so the error size does not matter"
    )]
    fn process_new_cert(&mut self, issued: IssuedCert) -> Event<EC, EA> {
        let cert = self.deploy_cert(&issued.pem, false)?;
        let config = self.config.clone();
        let pem = issued.pem;
        self.early_actions.push_back(Box::pin(async move {
            let stored = config
                .cache
                .store_cert(&config.domains, &config.directory_url, &pem)
                .await;
            Some(match stored {
                Ok(()) => Ok(EventOk::CertCacheStore),
                Err(err) => Err(EventError::CertCacheStore(err)),
            })
        }));
        if let Some(download) = issued.alternate {
            let (config, resolver) = (self.config.clone(), self.resolver.clone());
            let provider = self.crypto_provider();
            self.early_actions.push_back(Box::pin(async move {
                let alternate = bounded(download).await.and_then(|chain| {
                    let pem = chain.to_pem();
                    serve_alternate(&resolver, &cert, chain, &provider).then_some(pem)
                });
                // Without an alternate, this removes the one of an earlier certificate.
                let stored = config
                    .cache
                    .store_alt_cert(&config.domains, &config.directory_url, alternate.as_deref())
                    .await;
                match (stored, alternate) {
                    (Err(err), _) => Some(Err(EventError::AltCertCacheStore(err))),
                    (Ok(()), None) => Some(Err(EventError::AltCertUnavailable)),
                    (Ok(()), Some(_)) => None,
                }
            }));
        }
        Ok(EventOk::DeployedNewCert)
    }

    /// Runs one order.
    #[allow(
        clippy::result_large_err,
        reason = "returns once per order, so the error size does not matter"
    )]
    async fn order(
        config: Arc<AcmeConfig<EC, EA>>,
        resolver: Arc<ResolvesServerCertAcme>,
        key_pair: Vec<u8>,
    ) -> Result<IssuedCert, OrderFailure> {
        let account = async {
            let directory =
                Directory::discover(&config.client_config, &config.directory_url).await?;
            Account::create_with_keypair(
                &config.client_config,
                directory,
                &config.contact,
                &key_pair,
                &config.eab,
            )
            .await
        }
        .await
        .map_err(|err| OrderFailure {
            account_rejected: err.rejects_account(),
            error: err.into(),
        })?;
        // CAs also use `unauthorized` for order problems, so only account errors count.
        Self::order_with_account(&config, &resolver, &Arc::new(account))
            .await
            .map_err(|error| OrderFailure {
                error,
                account_rejected: false,
            })
    }
    async fn order_with_account(
        config: &AcmeConfig<EC, EA>,
        resolver: &ResolvesServerCertAcme,
        account: &Arc<Account>,
    ) -> Result<IssuedCert, OrderError> {
        let mut params = CertificateParams::new(config.domains.clone()).map_err(rcgen_err)?;
        params.distinguished_name = DistinguishedName::new();
        let key_pair = rcgen::KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(rcgen_err)?;

        let (order_url, mut order) = account
            .new_order(&config.client_config, config.domains.clone())
            .await?;
        let mut stalled_rounds = 0;
        loop {
            let previous_progress = order.status.progress();
            match order.status {
                OrderStatus::Pending => {
                    let auth_futures = order
                        .authorizations
                        .iter()
                        .map(|url| Self::authorize(config, resolver, account, url));
                    try_join_all(auth_futures).await?;
                    info!("completed all authorizations");
                    order = account.order(&config.client_config, &order_url).await?;
                }
                OrderStatus::Processing => {
                    for i in 0u64..10 {
                        info!("order processing");
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
                    info!("sending csr");
                    let csr = params.serialize_request(&key_pair).map_err(rcgen_err)?;
                    order = account
                        .finalize(&config.client_config, order.finalize, csr.der().to_vec())
                        .await?
                }
                OrderStatus::Valid { certificate } => {
                    info!("download certificate");
                    let response = account
                        .certificate_with_alternate_urls(&config.client_config, &certificate)
                        .await?;
                    let key_pem = key_pair.serialize_pem();
                    let bundle = |chain: &[u8]| [key_pem.as_bytes(), b"\n", chain].concat();
                    let default = bundle(response.pem.as_bytes());
                    let (CertChainPreference::PreferredChain(root)
                    | CertChainPreference::DualChain(root)) = &config.cert_chain
                    else {
                        return Ok(IssuedCert {
                            pem: default,
                            alternate: None,
                        });
                    };
                    // No alternate if the default chain ends at the root already. A default
                    // chain that doesn't parse fails when it is deployed.
                    let Some(default_chain) = CertChain::from_pem(response.pem.as_bytes())
                        .filter(|chain| !chain.ends_at(root))
                    else {
                        return Ok(IssuedCert {
                            pem: default,
                            alternate: None,
                        });
                    };
                    let download = Box::pin(Self::fetch_alternate_chain(
                        account.clone(),
                        config.client_config.clone(),
                        response.alternate_urls,
                        default_chain.leaf().clone(),
                        root.clone(),
                    ));
                    if let CertChainPreference::DualChain(_) = &config.cert_chain {
                        // Served next to the default chain, so it can follow the deployment.
                        return Ok(IssuedCert {
                            pem: default,
                            alternate: Some(download),
                        });
                    }
                    // PreferredChain serves the alternate instead, so it is needed now.
                    let pem = match bounded(download).await {
                        Some(alternate) => bundle(&alternate.to_pem()),
                        None => default,
                    };
                    return Ok(IssuedCert {
                        pem,
                        alternate: None,
                    });
                }
                OrderStatus::Invalid => return Err(OrderError::BadOrder(order)),
            }
            // A CA can lag in updating the status, and a broken CA can move it backwards.
            if order.status.progress() <= previous_progress {
                let Some(delay) = stall_delay(stalled_rounds) else {
                    return Err(OrderError::ProcessingTimeout(order));
                };
                info!(status = ?order.status, "order status did not advance");
                after(delay).await;
                stalled_rounds += 1;
            }
        }
    }
    /// Fetches the first alternate chain for `leaf` that is valid and ends at `root`.
    ///
    /// Download errors are logged, not returned: the order is valid, and a new one would count
    /// against the CA's rate limits.
    async fn fetch_alternate_chain(
        account: Arc<Account>,
        client_config: Arc<ClientConfig>,
        alternate_urls: Vec<String>,
        leaf: RustlsCertificate<'static>,
        root: ChainRoot,
    ) -> Option<CertChain> {
        let algorithms = &client_config
            .crypto_provider()
            .signature_verification_algorithms;
        for url in alternate_urls {
            debug!(%url, "fetching alternate chain");
            match account.certificate(&client_config, &url).await {
                Ok(pem) => match CertChain::from_pem(pem.as_bytes()) {
                    Some(chain) if chain.is_alternate_for(&leaf, &root, algorithms) => {
                        return Some(chain);
                    }
                    _ => debug!(%url, "alternate is no valid chain to the root for the leaf"),
                },
                Err(err) => warn!(%url, %err, "failed to fetch alternate chain"),
            }
        }
        warn!(%root, "no alternate chain ends at the root, using the default chain");
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
                info!(%domain, "trigger challenge");
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
                    info!(%domain, "authorization still pending");
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
    /// Delays the next order with an exponential backoff.
    fn back_off(&mut self) {
        self.wait = Some(after(BACKOFF_BASE_DELAY * (1 << self.backoff_cnt)));
        self.backoff_cnt = (self.backoff_cnt + 1).min(16);
    }
    fn poll_next_infinite(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Event<EC, EA>> {
        loop {
            // queued early actions, in order
            if let Some(early_action) = self.early_actions.front_mut() {
                let event = ready!(early_action.poll(cx));
                self.early_actions.pop_front();
                match event {
                    Some(event) => return Poll::Ready(event),
                    None => continue,
                }
            }

            // sleep
            if let Some(timer) = &mut self.wait {
                ready!(timer.poll(cx));
                self.wait.take();
            }

            // wait for renewal
            if let Some(renew_at) = self.renew_at {
                match renewal_sleep(renew_at, OffsetDateTime::now_utc()) {
                    Some(sleep) => {
                        self.wait = Some(after(sleep));
                        continue;
                    }
                    None => self.renew_at = None,
                }
            }

            // load from cert cache
            if let Some(load_cert) = &mut self.load_cert {
                let result = ready!(load_cert.poll(cx));
                self.load_cert.take();
                match result {
                    Ok(Some(pem)) => return Poll::Ready(self.process_cached_cert(&pem)),
                    Ok(None) => {}
                    Err(err) => return Poll::Ready(Err(EventError::CertCacheLoad(err))),
                }
            }

            // load from account cache
            if let Some(load_account) = &mut self.load_account {
                let result = ready!(load_account.poll(cx));
                self.load_account.take();
                // Never overwrite a stored key, it may be the only access to an account.
                match result {
                    Ok(Some(key_pair)) => match Account::check_key_pair(&key_pair) {
                        Ok(()) => self.account_key = Some(key_pair),
                        Err(err) => {
                            error!(
                                %err,
                                "cannot use the cached account key, fix or delete it. Ordering with a new key that is not stored"
                            );
                            self.account_key = Some(Account::generate_key_pair());
                        }
                    },
                    Ok(None) => {}
                    Err(err) => {
                        self.account_key = Some(Account::generate_key_pair());
                        return Poll::Ready(Err(EventError::AccountCacheLoad(err)));
                    }
                }
            }

            // execute order
            if let Some(order) = &mut self.order {
                let result = ready!(order.poll(cx));
                self.order.take();
                match result {
                    Ok(issued) => {
                        let event = self.process_new_cert(issued);
                        // An unusable or already due certificate counts as a failed order.
                        let now = OffsetDateTime::now_utc();
                        let due = self.renew_at.is_some_and(|t| time_until(t, now).is_none());
                        if event.is_err() || due {
                            self.back_off();
                        } else {
                            self.backoff_cnt = 0;
                        }
                        return Poll::Ready(event);
                    }
                    Err(OrderFailure {
                        error,
                        account_rejected,
                    }) => {
                        // Keeps the stored key, so a wrong CA answer cannot lose a valid account.
                        if account_rejected {
                            error!(
                                "the CA rejected the ACME account, ordering with a new account key that is not stored"
                            );
                            self.account_key = Some(Account::generate_key_pair());
                        }
                        self.back_off();
                        return Poll::Ready(Err(EventError::Order(error)));
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
                    self.early_actions.push_back(Box::pin(async move {
                        let stored = config
                            .cache
                            .store_account(
                                &config.contact,
                                &config.directory_url,
                                &account_key_clone,
                            )
                            .await;
                        Some(match stored {
                            Ok(()) => Ok(EventOk::AccountCacheStore),
                            Err(err) => Err(EventError::AccountCacheStore(err)),
                        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CertCache;
    use crate::caches::NoCache;
    use crate::fixture::{
        self, CROSS_SIGNED_ROOT, Cert, EC_ROOT_CN, HIERARCHIES, LEAF_NAME, chain,
    };
    use async_trait::async_trait;
    use n0_future::StreamExt;
    use rustls::RootCertStore;
    use rustls::crypto::ring;
    use std::future;
    use std::sync::Mutex;
    use tokio::time::Instant;

    const MIN: Duration = Duration::from_secs(60);
    const HOUR: Duration = Duration::from_secs(60 * 60);
    /// The error of [`MemCertCache`] when it fails to store an alternate.
    const STORE_FAILED: &str = "store failed";
    /// The error of [`MemCertCache`] when it fails to load an alternate.
    const LOAD_FAILED: &str = "load failed";

    /// The state of the tests, with [`MemCertCache`].
    type TestState = AcmeState<&'static str, Infallible>;

    /// How [`MemCertCache`] treats alternate chains.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum AlternateCache {
        /// It loads and stores them.
        Working,
        /// It never finishes loading one.
        StallingLoads,
        /// It fails to load them.
        FailingLoads,
        /// It fails to store them.
        FailingStores,
    }

    /// A cert cache in memory, shared by its clones.
    #[derive(Debug, Clone)]
    struct MemCertCache {
        cert: Arc<Mutex<Option<Vec<u8>>>>,
        alternate: Arc<Mutex<Option<Vec<u8>>>>,
        behavior: AlternateCache,
    }

    impl MemCertCache {
        /// Creates a cache that holds `cert` and `alternate`.
        fn new(
            cert: Option<Vec<u8>>,
            alternate: Option<Vec<u8>>,
            behavior: AlternateCache,
        ) -> Self {
            Self {
                cert: Arc::new(Mutex::new(cert)),
                alternate: Arc::new(Mutex::new(alternate)),
                behavior,
            }
        }

        fn cert(&self) -> Option<Vec<u8>> {
            self.cert.lock().expect("poisoned").clone()
        }

        fn alternate(&self) -> Option<Vec<u8>> {
            self.alternate.lock().expect("poisoned").clone()
        }
    }

    #[async_trait]
    impl CertCache for MemCertCache {
        type EC = &'static str;
        async fn load_cert(&self, _: &[String], _: &str) -> Result<Option<Vec<u8>>, Self::EC> {
            Ok(self.cert())
        }
        async fn store_cert(&self, _: &[String], _: &str, cert: &[u8]) -> Result<(), Self::EC> {
            *self.cert.lock().expect("poisoned") = Some(cert.to_vec());
            Ok(())
        }
        async fn load_alt_cert(&self, _: &[String], _: &str) -> Result<Option<Vec<u8>>, Self::EC> {
            match self.behavior {
                AlternateCache::StallingLoads => future::pending().await,
                AlternateCache::FailingLoads => Err(LOAD_FAILED),
                _ => Ok(self.alternate()),
            }
        }
        async fn store_alt_cert(
            &self,
            _: &[String],
            _: &str,
            chain: Option<&[u8]>,
        ) -> Result<(), Self::EC> {
            if self.behavior == AlternateCache::FailingStores {
                return Err(STORE_FAILED);
            }
            *self.alternate.lock().expect("poisoned") = chain.map(<[u8]>::to_vec);
            Ok(())
        }
    }

    /// Returns a DualChain state for the fixture's ECDSA root, with `cache`.
    fn dual_chain_state(cache: &MemCertCache) -> TestState {
        let client_config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring supports the default versions")
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        AcmeConfig::new_with_client_tls_config([LEAF_NAME], Arc::new(client_config))
            .cert_chain(CertChainPreference::dual_chain(EC_ROOT_CN))
            .cache_compose(cache.clone(), NoCache::<Infallible, Infallible>::new())
            .state()
    }

    /// Starts a state with `cache`, and asserts that it serves the cached certificate.
    async fn start_cached(cache: &MemCertCache) -> TestState {
        let mut state = dual_chain_state(cache);
        let event = state.next().await;
        assert!(
            matches!(event, Some(Ok(EventOk::DeployedCachedCert))),
            "{event:?}"
        );
        state
    }

    /// Serves and stores a new certificate for `primary`, with the alternate download `alternate`.
    ///
    /// Returns the event of the alternate, or `None` if it reports none.
    async fn store_new(
        state: &mut TestState,
        primary: &[Cert],
        alternate: impl Future<Output = Option<CertChain>> + Send + 'static,
    ) -> Option<Event<&'static str, Infallible>> {
        let event = state.process_new_cert(IssuedCert {
            pem: fixture::bundle(primary),
            alternate: Some(Box::pin(alternate)),
        });
        assert!(matches!(event, Ok(EventOk::DeployedNewCert)), "{event:?}");
        let event = state.next().await;
        assert!(
            matches!(event, Some(Ok(EventOk::CertCacheStore))),
            "{event:?}"
        );
        let event = tokio::time::timeout(ALTERNATE_TIMEOUT + MIN, state.next()).await;
        event.ok().flatten()
    }

    /// Runs `state` until it waits for the renewal, and asserts that it reports nothing.
    async fn run_until_renewal_wait(state: &mut TestState) {
        let event = tokio::time::timeout(ALTERNATE_TIMEOUT + MIN, state.next()).await;
        assert!(event.is_err(), "unexpected event {event:?}");
        assert!(state.early_actions.is_empty());
    }

    /// A valid cached alternate is served after a restart, see the restart test.
    #[tokio::test(start_paused = true)]
    async fn invalid_cached_alternate_is_not_served() {
        let cases = [
            // Without the intermediate.
            chain(&[Cert::Leaf, Cert::EcRoot]).to_pem(),
            // With a key, which only the certificate's cache holds.
            fixture::bundle(CROSS_SIGNED_ROOT.alternate),
        ];
        for alternate in cases {
            let primary = fixture::bundle(CROSS_SIGNED_ROOT.primary);
            let cache = MemCertCache::new(Some(primary), Some(alternate), AlternateCache::Working);
            let mut state = start_cached(&cache).await;
            run_until_renewal_wait(&mut state).await;
            assert!(!state.resolver.serves_alternate_chain());
        }
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_alternate_cache_does_not_delay_the_certificate() {
        let cache = MemCertCache::new(
            Some(fixture::bundle(CROSS_SIGNED_ROOT.primary)),
            Some(chain(CROSS_SIGNED_ROOT.alternate).to_pem()),
            AlternateCache::StallingLoads,
        );
        let start = Instant::now();
        let mut state = start_cached(&cache).await;
        assert_eq!(start.elapsed(), Duration::ZERO);
        run_until_renewal_wait(&mut state).await;
        assert!(!state.resolver.serves_alternate_chain());
    }

    #[tokio::test(start_paused = true)]
    async fn failed_alternate_cache_load_is_reported() {
        let primary = fixture::bundle(CROSS_SIGNED_ROOT.primary);
        let cache = MemCertCache::new(Some(primary), None, AlternateCache::FailingLoads);
        let mut state = start_cached(&cache).await;
        let event = state.next().await;
        let failed = matches!(event, Some(Err(EventError::AltCertCacheLoad(LOAD_FAILED))));
        assert!(failed, "{event:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn new_alternate_is_served_stored_and_loaded_after_a_restart() {
        for hierarchy in HIERARCHIES {
            let cache = MemCertCache::new(None, None, AlternateCache::Working);
            let mut state = dual_chain_state(&cache);
            let alternate = chain(hierarchy.alternate);
            let download = future::ready(Some(alternate.clone()));
            let event = store_new(&mut state, hierarchy.primary, download).await;
            assert!(event.is_none(), "{event:?}");
            assert!(state.resolver.serves_alternate_chain());
            assert_eq!(cache.cert(), Some(fixture::bundle(hierarchy.primary)));
            assert_eq!(cache.alternate(), Some(alternate.to_pem()));

            let mut restarted = start_cached(&cache).await;
            run_until_renewal_wait(&mut restarted).await;
            assert!(restarted.resolver.serves_alternate_chain(), "{hierarchy:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn stalled_alternate_download_is_reported_after_the_timeout() {
        let stale = chain(CROSS_SIGNED_ROOT.alternate).to_pem();
        let cache = MemCertCache::new(None, Some(stale), AlternateCache::Working);
        let mut state = dual_chain_state(&cache);
        let start = Instant::now();
        let event = store_new(&mut state, CROSS_SIGNED_ROOT.primary, future::pending()).await;
        assert!(
            matches!(event, Some(Err(EventError::AltCertUnavailable))),
            "{event:?}"
        );
        assert_eq!(start.elapsed(), ALTERNATE_TIMEOUT);
        assert!(!state.resolver.serves_alternate_chain());
        let primary = Some(fixture::bundle(CROSS_SIGNED_ROOT.primary));
        assert_eq!(cache.cert(), primary);
        assert_eq!(cache.alternate(), None, "the stale alternate is removed");
    }

    #[tokio::test(start_paused = true)]
    async fn previous_alternate_is_served_until_a_new_one_arrives() {
        let cache = MemCertCache::new(None, None, AlternateCache::Working);
        let mut state = dual_chain_state(&cache);
        let download = future::ready(Some(chain(CROSS_SIGNED_ROOT.alternate)));
        store_new(&mut state, CROSS_SIGNED_ROOT.primary, download).await;
        let event = store_new(&mut state, CROSS_SIGNED_ROOT.primary, future::pending()).await;
        assert!(
            matches!(event, Some(Err(EventError::AltCertUnavailable))),
            "{event:?}"
        );
        assert!(state.resolver.serves_alternate_chain());
    }

    #[tokio::test(start_paused = true)]
    async fn failed_alternate_store_keeps_serving_the_alternate() {
        let cache = MemCertCache::new(None, None, AlternateCache::FailingStores);
        let mut state = dual_chain_state(&cache);
        let download = future::ready(Some(chain(CROSS_SIGNED_ROOT.alternate)));
        let event = store_new(&mut state, CROSS_SIGNED_ROOT.primary, download).await;
        let failed = matches!(
            event,
            Some(Err(EventError::AltCertCacheStore(STORE_FAILED)))
        );
        assert!(failed, "{event:?}");
        assert!(state.resolver.serves_alternate_chain());
        let primary = Some(fixture::bundle(CROSS_SIGNED_ROOT.primary));
        assert_eq!(cache.cert(), primary);
    }

    #[test]
    fn renewal_sleep_is_capped_at_max_renewal_sleep() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let cases = [
            (now - MIN, None),
            (now, None),
            (now + MIN, Some(MIN)),
            (now + MAX_RENEWAL_SLEEP, Some(MAX_RENEWAL_SLEEP)),
            (now + 30 * 24 * HOUR, Some(MAX_RENEWAL_SLEEP)),
        ];
        for (renew_at, expected) in cases {
            assert_eq!(
                renewal_sleep(renew_at, now),
                expected,
                "renew at {renew_at}"
            );
        }
    }

    #[test]
    fn stall_delay_doubles_until_the_round_limit() {
        let delays: Vec<_> = (0..=MAX_STALLED_ROUNDS).map(stall_delay).collect();
        let expected: Vec<_> = (0..MAX_STALLED_ROUNDS)
            .map(|round| Some(Duration::from_secs(1 << round)))
            .chain([None])
            .collect();
        assert_eq!(delays, expected);
    }
}

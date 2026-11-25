use std::convert::Infallible;
use std::fmt::{self, Debug};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use n0_future::{FutureExt, Stream, ready, try_join_all};
use rcgen::{CertificateParams, DistinguishedName, PKCS_ECDSA_P256_SHA256};
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer as RustlsCertificate, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use thiserror::Error;
use time::{Duration as TimeDuration, OffsetDateTime};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Sleep;
use tracing::{error, info, warn};
use x509_parser::parse_x509_certificate;

use crate::acceptor::AcmeAcceptor;
use crate::acme::{
    Account, AcmeError, Auth, AuthStatus, CreatedOrder, Directory, Identifier, InvalidIdentifier,
    Order, OrderStatus,
};
use crate::{AcmeConfig, Incoming, ResolvesServerCertAcme};

/// First delay of the order backoffs, which double it on each retry.
const BACKOFF_BASE_DELAY: Duration = Duration::from_secs(1);

/// Longest sleep toward a wall-clock deadline, since the monotonic timer misses host suspend.
const MAX_SLEEP: Duration = Duration::from_secs(60 * 60);

/// Number of order rounds that can fail to advance the order status before the order fails.
const MAX_STALLED_ROUNDS: u32 = 10;

/// Lifetime under which certificates renew at half their lifetime instead of two thirds.
const SHORT_LIFETIME: TimeDuration = TimeDuration::days(10);

/// Largest exponent of the backoff between failed orders, which doubles [`BACKOFF_BASE_DELAY`].
const MAX_BACKOFF_EXPONENT: u32 = 16;

/// Longest delay between failed orders, which the backoff reaches at [`MAX_BACKOFF_EXPONENT`].
const MAX_RETRY_DELAY: Duration = BACKOFF_BASE_DELAY.saturating_mul(1 << MAX_BACKOFF_EXPONENT);

/// Lower bound of the remaining-validity cap on the delay between failed orders.
const MIN_RETRY_DELAY_CAP: Duration = Duration::from_secs(10 * 60);

/// Part of the remaining validity that caps the delay between failed orders.
const RETRY_DELAY_VALIDITY_DIVISOR: u32 = 10;

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

pub(crate) fn after(d: Duration) -> Pin<Box<Sleep>> {
    Box::pin(tokio::time::sleep(d))
}

/// Returns the time left from `now` until `deadline`, or `None` once it is reached.
fn time_until(deadline: OffsetDateTime, now: OffsetDateTime) -> Option<Duration> {
    let left: Duration = (deadline - now).try_into().ok()?;
    (!left.is_zero()).then_some(left)
}

/// Returns how long to sleep before checking `deadline` again, or `None` once it is reached.
fn sleep_until(deadline: OffsetDateTime, now: OffsetDateTime) -> Option<Duration> {
    time_until(deadline, now).map(|left| left.min(MAX_SLEEP))
}

/// Returns when to renew a certificate valid from `not_before` to `not_after`.
///
/// At two thirds of the lifetime, or at half for lifetimes under [`SHORT_LIFETIME`], like certbot.
fn renewal_time(not_before: OffsetDateTime, not_after: OffsetDateTime) -> OffsetDateTime {
    let lifetime = not_after - not_before;
    if lifetime < SHORT_LIFETIME {
        not_before + lifetime / 2
    } else {
        not_before + lifetime * 2 / 3
    }
}

/// Returns the longest delay between failed orders for a certificate that expires at `expiry`.
///
/// A tenth of the remaining validity, within [`MIN_RETRY_DELAY_CAP`] and [`MAX_RETRY_DELAY`], and
/// at most half of it, so a retry comes before the expiry.
fn max_retry_delay(expiry: Option<OffsetDateTime>, now: OffsetDateTime) -> Duration {
    let Some(expiry) = expiry else {
        return MAX_RETRY_DELAY;
    };
    let Some(left) = time_until(expiry, now) else {
        return MIN_RETRY_DELAY_CAP;
    };
    (left / RETRY_DELAY_VALIDITY_DIVISOR)
        .clamp(MIN_RETRY_DELAY_CAP, MAX_RETRY_DELAY)
        .min((left / 2).max(BACKOFF_BASE_DELAY))
}

/// Returns the first of `identifiers` that the leaf of `cert` doesn't certify in its SANs.
fn uncertified_identifier<'a>(
    cert: &CertifiedKey,
    identifiers: &'a [Identifier],
) -> Option<&'a Identifier> {
    let leaf = cert.end_entity_cert().ok();
    let leaf = leaf.and_then(|leaf| parse_x509_certificate(leaf).ok());
    let san = leaf
        .as_ref()
        .and_then(|(_, leaf)| leaf.subject_alternative_name().ok().flatten());
    let names = san.map_or(&[][..], |san| &san.value.general_names[..]);
    identifiers
        .iter()
        .find(|identifier| !names.iter().any(|name| identifier.is_certified_by(name)))
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
    /// The identifiers of the config, validated once, since the config doesn't change.
    identifiers: Result<Arc<[Identifier]>, InvalidIdentifier>,
    resolver: Arc<ResolvesServerCertAcme>,
    account_key: Option<Vec<u8>>,

    early_action: Option<BoxFuture<Event<EC, EA>>>,
    load_cert: Option<BoxFuture<Result<Option<Vec<u8>>, EC>>>,
    load_account: Option<BoxFuture<Result<Option<Vec<u8>>, EA>>>,
    order: Option<BoxFuture<Result<Vec<u8>, OrderFailure>>>,
    backoff_cnt: u32,
    wait: Option<Pin<Box<Sleep>>>,
    renew_at: Option<OffsetDateTime>,
    /// When to retry after a failed order, on the wall clock like the renewal.
    retry_at: Option<OffsetDateTime>,
    /// Expiry of the deployed certificate.
    cert_expiry: Option<OffsetDateTime>,
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
    /// The newly issued certificate is unusable, so the deployed one stays.
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
    /// The configured identifiers can't be ordered, or an authorization names an invalid one.
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(#[from] InvalidIdentifier),
    /// The CA didn't confirm the profile of [`AcmeConfig::profile`] in the order it created.
    #[error("the CA selected profile {selected:?} instead of {requested:?}")]
    ProfileMismatch {
        /// The configured profile.
        requested: String,
        /// The profile the CA named in the order, if any.
        selected: Option<String>,
    },
    /// The order stayed `processing` or stopped advancing for too long.
    #[error("order did not reach a final status in time, last status {:?}", .0.status)]
    ProcessingTimeout(Order),
}

/// Why a PEM bundle of private key and certificate chain can't be served.
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
    /// The newly issued certificate doesn't certify an ordered identifier in its SANs.
    #[error("certificate does not certify {0}")]
    MissingIdentifier(Identifier),
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
    pub fn resolver(&self) -> Arc<ResolvesServerCertAcme> {
        self.resolver.clone()
    }

    /// Creates a state machine from `config`. Equivalent to
    /// [`AcmeConfig::state`].
    pub fn new(config: AcmeConfig<EC, EA>) -> Self {
        let config = Arc::new(config);
        let identifiers = config.validated_identifiers().map(Arc::from);
        // A config that can't order serves no cached certificate either.
        let load_cert = identifiers.is_ok().then(|| {
            let config = config.clone();
            Box::pin(async move {
                config
                    .cache
                    .load_cert(&config.cache_key(), &config.directory_url)
                    .await
            }) as BoxFuture<_>
        });
        Self {
            config: config.clone(),
            identifiers,
            resolver: ResolvesServerCertAcme::new(),
            account_key: None,
            early_action: None,
            load_cert,
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
            retry_at: None,
            cert_expiry: None,
        }
    }
    fn parse_cert(
        crypto_provider: &CryptoProvider,
        pem: &[u8],
    ) -> Result<(CertifiedKey, [OffsetDateTime; 2]), CertParseError> {
        let mut pems = pem::parse_many(pem).map_err(|err| CertParseError::Pem(err.into()))?;
        if pems.len() < 2 {
            return Err(CertParseError::TooFewPem(pems.len()));
        }
        let pk_bytes = pems.remove(0).into_contents();
        let pk_der: PrivatePkcs8KeyDer<'static> = pk_bytes.into();
        let cert_chain: Vec<RustlsCertificate> =
            pems.into_iter().map(|p| p.into_contents().into()).collect();
        let validity = match parse_x509_certificate(cert_chain[0].as_ref()) {
            Ok((_, cert)) => {
                let validity = cert.validity();
                [validity.not_before, validity.not_after].map(|t| t.to_datetime())
            }
            Err(err) => return Err(CertParseError::X509(err.into())),
        };
        let cert =
            CertifiedKey::from_der(cert_chain, pk_der.into(), crypto_provider).map_err(|err| {
                warn!(%err, "rejecting certificate and private key");
                CertParseError::InvalidPrivateKey
            })?;
        Ok((cert, validity))
    }

    #[allow(
        clippy::result_large_err,
        reason = "runs once per certificate, so the error size does not matter"
    )]
    fn process_cert(&mut self, pem: Vec<u8>, cached: bool) -> Event<EC, EA> {
        let provider = self.crypto_provider();
        let (cert, validity) = match (Self::parse_cert(&provider, &pem), cached) {
            (Ok(r), _) => r,
            (Err(err), cached) => {
                return match cached {
                    true => Err(EventError::CachedCertParse(err)),
                    false => Err(EventError::NewCertParse(err)),
                };
            }
        };
        let [not_before, not_after] = validity;
        // The deployed certificate may still be valid, so keep it and the cache.
        if !cached && not_after <= OffsetDateTime::now_utc() {
            warn!(%not_after, "the CA issued an expired certificate, keeping the deployed one");
            return Err(EventError::NewCertParse(CertParseError::Expired));
        }
        // Without one, clients that connect by it would fail after a successful deployment.
        if !cached
            && let Ok(identifiers) = &self.identifiers
            && let Some(missing) = uncertified_identifier(&cert, identifiers)
        {
            warn!(%missing, "the CA left an ordered identifier out, keeping the deployed one");
            let missing = missing.clone();
            return Err(EventError::NewCertParse(CertParseError::MissingIdentifier(
                missing,
            )));
        }
        self.resolver.set_cert(Arc::new(cert));
        self.renew_at = Some(renewal_time(not_before, not_after));
        self.cert_expiry = Some(not_after);
        if cached {
            return Ok(EventOk::DeployedCachedCert);
        }
        let config = self.config.clone();
        self.early_action = Some(Box::pin(async move {
            match config
                .cache
                .store_cert(&config.cache_key(), &config.directory_url, &pem)
                .await
            {
                Ok(()) => Ok(EventOk::CertCacheStore),
                Err(err) => Err(EventError::CertCacheStore(err)),
            }
        }));
        Event::Ok(EventOk::DeployedNewCert)
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
        identifiers: Arc<[Identifier]>,
    ) -> Result<Vec<u8>, OrderFailure> {
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
        Self::order_with_account(&config, &resolver, &account, &identifiers)
            .await
            .map_err(|error| OrderFailure {
                error,
                account_rejected: false,
            })
    }
    async fn order_with_account(
        config: &AcmeConfig<EC, EA>,
        resolver: &ResolvesServerCertAcme,
        account: &Account,
        identifiers: &[Identifier],
    ) -> Result<Vec<u8>, OrderError> {
        let has_ip = identifiers.iter().any(|id| matches!(id, Identifier::Ip(_)));
        if has_ip && config.profile.is_none() && config.is_lets_encrypt() {
            warn!("Let's Encrypt issues IP certificates only under the `shortlived` profile");
        }
        let mut params = CertificateParams::default();
        params.subject_alt_names = identifiers
            .iter()
            .map(Identifier::subject_alt_name)
            .collect::<Result<_, _>>()
            .map_err(rcgen_err)?;
        params.distinguished_name = DistinguishedName::new();
        let key_pair = rcgen::KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(rcgen_err)?;

        let CreatedOrder {
            url: order_url,
            mut order,
            profile,
        } = account
            .new_order(
                &config.client_config,
                identifiers,
                config.profile.as_deref(),
            )
            .await?;
        if let Some(requested) = &config.profile
            && profile.as_ref() != Some(requested)
        {
            return Err(OrderError::ProfileMismatch {
                requested: requested.clone(),
                selected: profile,
            });
        }
        info!(?profile, "created order");
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
                    let pem = [
                        &key_pair.serialize_pem(),
                        "\n",
                        &account
                            .certificate(&config.client_config, certificate)
                            .await?,
                    ]
                    .concat();
                    return Ok(pem.into_bytes());
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
    async fn authorize(
        config: &AcmeConfig<EC, EA>,
        resolver: &ResolvesServerCertAcme,
        account: &Account,
        url: &String,
    ) -> Result<(), OrderError> {
        let auth = account.auth(&config.client_config, url).await?;
        let (identifier, challenge_url) = match auth.status {
            AuthStatus::Pending => {
                // A CA may spell it otherwise, like `Example.COM.`, which would miss the SNI.
                let identifier = auth.identifier.validated()?;
                info!(%identifier, "trigger challenge");
                let (challenge, auth_key) =
                    account.tls_alpn_01(config.crypto_provider(), &auth.challenges, &identifier)?;
                resolver.set_auth_key(&identifier, Arc::new(auth_key));
                account
                    .challenge(&config.client_config, &challenge.url)
                    .await?;
                (identifier, challenge.url.clone())
            }
            AuthStatus::Valid => return Ok(()),
            _ => return Err(OrderError::BadAuth(auth)),
        };
        for i in 0u64..5 {
            after(Duration::from_secs(1u64 << i)).await;
            let auth = account.auth(&config.client_config, url).await?;
            match auth.status {
                AuthStatus::Pending => {
                    info!(%identifier, "authorization still pending");
                    account
                        .challenge(&config.client_config, &challenge_url)
                        .await?
                }
                AuthStatus::Valid => return Ok(()),
                _ => return Err(OrderError::BadAuth(auth)),
            }
        }
        Err(OrderError::TooManyAttemptsAuth(identifier.to_string()))
    }
    /// Delays the next order with an exponential backoff, capped by [`max_retry_delay`].
    fn back_off(&mut self) {
        let now = OffsetDateTime::now_utc();
        let cap = max_retry_delay(self.cert_expiry, now);
        let delay = (BACKOFF_BASE_DELAY * (1 << self.backoff_cnt)).min(cap);
        self.retry_at = Some(now + delay);
        self.backoff_cnt = (self.backoff_cnt + 1).min(MAX_BACKOFF_EXPONENT);
    }
    fn poll_next_infinite(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Event<EC, EA>> {
        loop {
            // queued early action
            if let Some(early_action) = &mut self.early_action {
                let result = ready!(early_action.poll(cx));
                self.early_action.take();
                return Poll::Ready(result);
            }

            // sleep
            if let Some(timer) = &mut self.wait {
                ready!(timer.poll(cx));
                self.wait.take();
            }

            // wait for the retry of a failed order
            if let Some(retry_at) = self.retry_at {
                match sleep_until(retry_at, OffsetDateTime::now_utc()) {
                    Some(sleep) => {
                        self.wait = Some(after(sleep));
                        continue;
                    }
                    None => self.retry_at = None,
                }
            }

            // wait for renewal
            if let Some(renew_at) = self.renew_at {
                match sleep_until(renew_at, OffsetDateTime::now_utc()) {
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
                    Ok(Some(pem)) => {
                        return Poll::Ready(self.process_cert(pem, true));
                    }
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
                    Ok(pem) => {
                        let event = self.process_cert(pem, false);
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
            let identifiers = match &self.identifiers {
                Ok(identifiers) => identifiers.clone(),
                // Fails before any request, so a typo doesn't reach the CA.
                Err(err) => {
                    let event = Err(EventError::Order(err.clone().into()));
                    self.back_off();
                    return Poll::Ready(event);
                }
            };
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
            self.order = Some(Box::pin(Self::order(
                config,
                resolver,
                account_key,
                identifiers,
            )));
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
    use rustls::crypto::ring;
    use rustls::{ClientConfig, DEFAULT_VERSIONS, RootCertStore};

    const SECOND: Duration = Duration::from_secs(1);
    const MIN: Duration = Duration::from_secs(60);
    const HOUR: Duration = Duration::from_secs(60 * 60);

    #[test]
    fn sleep_until_is_capped_at_max_sleep() {
        let now = OffsetDateTime::UNIX_EPOCH;
        let cases = [
            (now - MIN, None),
            (now, None),
            (now + MIN, Some(MIN)),
            (now + MAX_SLEEP, Some(MAX_SLEEP)),
            (now + 30 * 24 * HOUR, Some(MAX_SLEEP)),
        ];
        for (deadline, expected) in cases {
            assert_eq!(sleep_until(deadline, now), expected, "deadline {deadline}");
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

    #[test]
    fn renewal_time_is_half_the_lifetime_for_short_certificates() {
        let not_before = OffsetDateTime::UNIX_EPOCH;
        let cases = [
            // Let's Encrypt's `shortlived` profile, 160 hours.
            (TimeDuration::hours(160), TimeDuration::hours(80)),
            (TimeDuration::days(90), TimeDuration::days(60)),
            (SHORT_LIFETIME, SHORT_LIFETIME * 2 / 3),
        ];
        for (lifetime, renew_after) in cases {
            assert_eq!(
                renewal_time(not_before, not_before + lifetime),
                not_before + renew_after,
                "lifetime {lifetime}"
            );
        }
    }

    /// The state backs off from its certificate's expiry, also after many failed orders.
    #[test]
    fn back_off_caps_the_delay_by_the_remaining_validity() {
        let client_config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_protocol_versions(DEFAULT_VERSIONS)
            .expect("ring supports the default versions")
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        let config =
            AcmeConfig::new_with_client_tls_config(["example.com"], Arc::new(client_config));
        let mut state = config.state();
        let now = OffsetDateTime::now_utc();
        let cases = [
            (None, MAX_RETRY_DELAY),
            (Some(now + 4 * MIN), 2 * MIN),
            (Some(now - MIN), MIN_RETRY_DELAY_CAP),
        ];
        for (expiry, cap) in cases {
            state.cert_expiry = expiry;
            state.backoff_cnt = MAX_BACKOFF_EXPONENT;
            state.back_off();
            let retry_at = state.retry_at.expect("a backoff");
            let delay = (retry_at - OffsetDateTime::now_utc()).unsigned_abs();
            // The expiry nears while the test runs.
            assert!(
                delay <= cap && cap - delay < SECOND,
                "{expiry:?}: {delay:?}"
            );
        }
    }

    #[test]
    fn max_retry_delay_follows_the_remaining_validity() {
        const MINUTE: TimeDuration = TimeDuration::minutes(1);
        const HOUR: TimeDuration = TimeDuration::hours(1);
        let now = OffsetDateTime::UNIX_EPOCH;
        let cases = [
            (None, MAX_RETRY_DELAY),
            (Some(now + 80 * HOUR), Duration::from_secs(8 * 60 * 60)),
            (Some(now + 30 * 24 * HOUR), MAX_RETRY_DELAY),
            (Some(now + HOUR), MIN_RETRY_DELAY_CAP),
            // Half the remaining validity, so a retry happens before expiry.
            (Some(now + 4 * MINUTE), Duration::from_secs(2 * 60)),
            (
                Some(now + TimeDuration::milliseconds(100)),
                BACKOFF_BASE_DELAY,
            ),
            (Some(now - HOUR), MIN_RETRY_DELAY_CAP),
        ];
        for (expiry, expected) in cases {
            assert_eq!(max_retry_delay(expiry, now), expected, "expiry {expiry:?}");
        }
    }
}

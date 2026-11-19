use std::convert::Infallible;
use std::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::future::try_join_all;
use futures::{FutureExt, Stream, ready};
use rcgen::{CertificateParams, DistinguishedName, Error as RcgenError, PKCS_ECDSA_P256_SHA256};
use rustls::ServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer as RustlsCertificate, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;
use thiserror::Error;
use time::OffsetDateTime;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Sleep;
use x509_parser::error::X509Error;
use x509_parser::parse_x509_certificate;

use crate::acceptor::AcmeAcceptor;
use crate::acme::{
    Account, AcmeError, Auth, AuthStatus, Directory, Identifier, Order, OrderStatus,
};
use crate::{AcmeConfig, Incoming, ResolvesServerCertAcme};

type Timer = std::pin::Pin<Box<Sleep>>;
type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

pub fn after(d: std::time::Duration) -> Timer {
    Box::pin(tokio::time::sleep(d))
}

/// Longest renewal sleep, because the monotonic timer misses clock corrections and host suspend.
const MAX_RENEWAL_SLEEP: Duration = Duration::from_secs(60 * 60);

/// Number of order rounds that can fail to advance the order status before the order fails.
const MAX_STALLED_ROUNDS: u32 = 10;

/// Returns the position of `status` in the RFC 8555 order lifecycle.
fn order_progress(status: &OrderStatus) -> u8 {
    match status {
        OrderStatus::Pending => 0,
        OrderStatus::Ready => 1,
        OrderStatus::Processing => 2,
        OrderStatus::Valid { .. } | OrderStatus::Invalid => 3,
    }
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

/// Returns the delay after stalled order round `round`, or `None` once the order should fail.
fn stall_delay(round: u32) -> Option<Duration> {
    (round < MAX_STALLED_ROUNDS).then(|| Duration::from_secs(1 << round))
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
    load_cert: Option<BoxFuture<Result<Option<Vec<u8>>, EC>>>,
    load_account: Option<BoxFuture<Result<Option<Vec<u8>>, EA>>>,
    order: Option<BoxFuture<Result<Vec<u8>, OrderError>>>,
    backoff_cnt: usize,
    wait: Option<Timer>,
    renew_at: Option<OffsetDateTime>,
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
    /// The account cache could not be read, so this run orders with a new key that is not stored.
    ///
    /// Return `Ok(None)` from [`AccountCache::load_account`] when no key is stored.
    /// Otherwise every start uses a new account.
    ///
    /// [`AccountCache::load_account`]: crate::AccountCache::load_account
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
    /// The order stayed `processing` or stopped advancing for too long.
    #[error("order did not reach a final status in time, last status {:?}", .0.status)]
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
    ) -> Result<(CertifiedKey, [OffsetDateTime; 2]), CertParseError> {
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
        let validity = match parse_x509_certificate(cert_chain[0].as_ref()) {
            Ok((_, cert)) => {
                let validity = cert.validity();
                [validity.not_before, validity.not_after].map(|t| t.to_datetime())
            }
            Err(err) => return Err(CertParseError::X509(err)),
        };
        let cert = CertifiedKey::new(cert_chain, pk);
        Ok((cert, validity))
    }

    #[allow(clippy::result_large_err)]
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
            log::warn!(
                "the CA issued a certificate that expired at {not_after}, keeping the deployed one"
            );
            // A dedicated error variant needs the API break of #67, so reuse `InvalidDate`.
            let err = x509_parser::nom::Err::Error(X509Error::InvalidDate);
            return Err(EventError::NewCertParse(CertParseError::X509(err)));
        }
        self.resolver.set_cert(Arc::new(cert));
        self.renew_at = Some(not_after - (not_after - not_before) / 3_i32);
        if cached {
            return Ok(EventOk::DeployedCachedCert);
        }
        let config = self.config.clone();
        self.early_action = Some(Box::pin(async move {
            match config
                .cache
                .store_cert(&config.domains, &config.directory_url, &pem)
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
    ) -> Result<Vec<u8>, OrderError> {
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
        let mut stalled_rounds = 0;
        loop {
            let previous_progress = order_progress(&order.status);
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
            if order_progress(&order.status) <= previous_progress {
                let Some(delay) = stall_delay(stalled_rounds) else {
                    return Err(OrderError::ProcessingTimeout(order));
                };
                log::info!("order status did not advance, now {:?}", order.status);
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
    fn back_off(&mut self) {
        self.wait = Some(after(Duration::from_secs(1 << self.backoff_cnt)));
        self.backoff_cnt = (self.backoff_cnt + 1).min(16);
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

            // load from account cache
            if let Some(load_account) = &mut self.load_account {
                let result = ready!(load_account.poll_unpin(cx));
                self.load_account.take();
                // Never overwrite a stored key, it may be the only access to an account.
                match result {
                    Ok(Some(key_pair)) => match Account::check_key_pair(&key_pair) {
                        Ok(()) => self.account_key = Some(key_pair),
                        Err(err) => {
                            log::error!(
                                "cannot use the cached account key, fix or delete it. Ordering with a new key that is not stored: {err}"
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
                let result = ready!(order.poll_unpin(cx));
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
                    Err(err) => {
                        // TODO: replace key on some errors or high backoff_cnt?
                        self.back_off();
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

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: Duration = Duration::from_secs(60);
    const HOUR: Duration = Duration::from_secs(60 * 60);

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

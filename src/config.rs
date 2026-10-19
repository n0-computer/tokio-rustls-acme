use crate::acme::{
    ExternalAccountKey, LETS_ENCRYPT_PRODUCTION_DIRECTORY, LETS_ENCRYPT_STAGING_DIRECTORY,
};
use crate::caches::{BoxedErrCache, CompositeCache, NoCache};
use crate::{AccountCache, Cache, CertCache};
use crate::{AcmeState, Incoming};
use futures::Stream;
#[cfg(feature = "tls-webpki-roots")]
use rustls::DEFAULT_VERSIONS;
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, ServerConfig};
use std::convert::Infallible;
use std::fmt::Debug;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

const LETSENCRYPT_ISRG_ROOT_X2: &str = "ISRG Root X2";

/// Controls which certificate chain to serve to clients.
///
/// ACME servers like Let's Encrypt may offer multiple certificate chains with different root
/// certificates (RFC 8555 §7.4.2). This enum allows selecting which chain(s) to use.
///
/// A chain is identified by the issuer common name of its topmost certificate, i.e. the root it
/// chains to, like certbot's `--preferred-chain`. These names are chosen by the CA and change
/// when it rotates its hierarchy. If no offered chain matches, the default chain is used and a
/// warning is logged.
///
/// # DualChain and client capabilities
///
/// [`DualChain`](CertChainPreference::DualChain) picks the chain per connection from the
/// signature schemes in the client's TLS ClientHello. The alternate is served to clients that
/// can't verify every signature in the default chain but can verify the alternate. This helps
/// clients that leave out algorithms they can't verify, e.g. rustls clients built without RSA
/// support. A client that advertises a scheme it can't actually verify, or that doesn't trust
/// the alternate's root, gains nothing.
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub enum CertChainPreference {
    /// Use the default chain from the ACME server.
    #[default]
    Default,
    /// Use the alternate chain whose root issuer common name matches the given string. Falls
    /// back to the default chain if none matches, or if fetching the alternates fails.
    PreferredChain(String),
    /// Serve the default chain, plus the alternate whose root issuer common name matches the
    /// given string to clients that can only verify that one. See the type docs.
    DualChain(String),
}

impl CertChainPreference {
    /// Use Let's Encrypt's chain to ISRG Root X2, which is ECDSA-only.
    ///
    /// For ECDSA certificates, Let's Encrypt's default chain has its intermediate signed by
    /// ISRG Root X1 (RSA), with the X2-signed one offered as an alternate. Certificates from
    /// newer hierarchies (e.g. the 2026 Root YE for the `tlsserver` and `shortlived`
    /// profiles) may not offer an X2 chain, in which case the default chain is used.
    pub fn letsencrypt_x2() -> Self {
        Self::PreferredChain(LETSENCRYPT_ISRG_ROOT_X2.to_owned())
    }
    /// Serve Let's Encrypt's default chain (intermediate signed by ISRG Root X1, RSA) and the
    /// ISRG Root X2 chain (ECDSA-only) to clients without RSA. Same caveats as
    /// [`letsencrypt_x2`](Self::letsencrypt_x2).
    pub fn letsencrypt_dual_chain() -> Self {
        Self::DualChain(LETSENCRYPT_ISRG_ROOT_X2.to_owned())
    }
}

/// Configuration for an ACME resolver.
///
/// The type parameters represent the error types for the certificate cache and account cache.
pub struct AcmeConfig<EC: Debug, EA: Debug = EC> {
    pub(crate) client_config: Arc<ClientConfig>,
    pub(crate) directory_url: String,
    pub(crate) domains: Vec<String>,
    pub(crate) contact: Vec<String>,
    pub(crate) cache: Box<dyn Cache<EC = EC, EA = EA>>,
    pub(crate) eab: Option<ExternalAccountKey>,
    pub(crate) cert_chain: CertChainPreference,
}

impl AcmeConfig<Infallible, Infallible> {
    /// Creates an [`AcmeConfig`] backed by webpki-roots trust anchors.
    ///
    /// Picks aws-lc-rs when the `tls-aws-lc-rs` feature is enabled,
    /// otherwise ring (the default). The same provider is used for the HTTPS client,
    /// the TLS handshake, and key parsing. Use
    /// [`AcmeConfig::new_with_crypto_provider`] to pick a different provider.
    ///
    /// ```rust,no_run
    /// # use tokio_rustls_acme::AcmeConfig;
    /// use tokio_rustls_acme::caches::DirCache;
    /// let config = AcmeConfig::new(["example.com"]).cache(DirCache::new("./rustls_acme_cache"));
    /// ```
    ///
    /// Due to limited support for type parameter inference in Rust (see
    /// [RFC213](https://github.com/rust-lang/rfcs/blob/master/text/0213-defaulted-type-params.md)),
    /// [`AcmeConfig::new`] is not (yet) generic over the [`AcmeConfig`]'s type parameters.
    /// An uncached instance of [`AcmeConfig`] with particular type parameters can be created using
    /// [`NoCache`](crate::caches::NoCache).
    ///
    /// ```rust,no_run
    /// # use tokio_rustls_acme::AcmeConfig;
    /// use tokio_rustls_acme::caches::NoCache;
    /// # type EC = std::io::Error;
    /// # type EA = EC;
    /// let config: AcmeConfig<EC, EA> = AcmeConfig::new(["example.com"]).cache(NoCache::new());
    /// ```
    #[cfg(feature = "tls-webpki-roots")]
    pub fn new(domains: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        Self::new_with_crypto_provider(domains, Arc::new(crate::crypto::default_provider()))
    }

    /// Same as [`AcmeConfig::new`] but with an explicit [`CryptoProvider`].
    ///
    /// Lets the caller pick the provider regardless of which crate features
    /// are enabled. The same provider is used for the HTTPS client, the
    /// TLS handshake, and key parsing. ACME request signing and key
    /// generation still use the backend selected by the crate features.
    ///
    /// # Panics
    ///
    /// Panics if `crypto_provider` is unusable for TLS 1.2 and 1.3, i.e. it
    /// has no key exchange groups or no cipher suite for either version.
    /// This is the same check rustls's `ClientConfig::builder` performs.
    #[cfg(feature = "tls-webpki-roots")]
    pub fn new_with_crypto_provider(
        domains: impl IntoIterator<Item = impl AsRef<str>>,
        crypto_provider: Arc<CryptoProvider>,
    ) -> Self {
        let client_config = Arc::new(
            ClientConfig::builder_with_provider(crypto_provider)
                .with_protocol_versions(DEFAULT_VERSIONS)
                .expect("crypto provider has no usable cipher suites or key exchange groups")
                .with_root_certificates(Self::webpki_root_store())
                .with_no_client_auth(),
        );
        Self::new_with_client_tls_config(domains, client_config)
    }

    #[cfg(feature = "tls-webpki-roots")]
    fn webpki_root_store() -> rustls::RootCertStore {
        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            rustls::pki_types::TrustAnchor {
                subject: ta.subject.clone(),
                subject_public_key_info: ta.subject_public_key_info.clone(),
                name_constraints: ta.name_constraints.clone(),
            }
        }));
        root_store
    }

    /// Creates a config that uses `client_config` for ACME directory and
    /// order requests.
    ///
    /// The [`CryptoProvider`] is read from `client_config` and reused for
    /// the TLS handshake and key parsing, so the whole crate runs on the
    /// same provider as the HTTPS client.
    ///
    /// Use this when you need to control the trust store or crypto provider
    /// of the HTTPS client. Otherwise prefer [`AcmeConfig::new`] or
    /// [`AcmeConfig::new_with_crypto_provider`].
    pub fn new_with_client_tls_config(
        domains: impl IntoIterator<Item = impl AsRef<str>>,
        client_config: Arc<ClientConfig>,
    ) -> Self {
        AcmeConfig {
            client_config,
            directory_url: LETS_ENCRYPT_STAGING_DIRECTORY.into(),
            domains: domains.into_iter().map(|s| s.as_ref().into()).collect(),
            contact: vec![],
            cache: Box::new(NoCache::new()),
            eab: None,
            cert_chain: CertChainPreference::Default,
        }
    }
}

impl<EC: 'static + Debug, EA: 'static + Debug> AcmeConfig<EC, EA> {
    /// Sets a custom [`ClientConfig`] for ACME API calls.
    ///
    /// The [`CryptoProvider`] is read from `client_config` and reused for
    /// the TLS handshake and key parsing, keeping the whole crate on a
    /// single provider.
    pub fn client_tls_config(mut self, client_config: Arc<ClientConfig>) -> Self {
        self.client_config = client_config;
        self
    }
    pub fn directory(mut self, directory_url: impl AsRef<str>) -> Self {
        self.directory_url = directory_url.as_ref().into();
        self
    }
    pub fn directory_lets_encrypt(mut self, production: bool) -> Self {
        self.directory_url = match production {
            true => LETS_ENCRYPT_PRODUCTION_DIRECTORY,
            false => LETS_ENCRYPT_STAGING_DIRECTORY,
        }
        .into();
        self
    }
    pub fn domains(mut self, contact: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        self.domains = contact.into_iter().map(|s| s.as_ref().into()).collect();
        self
    }
    pub fn domains_push(mut self, contact: impl AsRef<str>) -> Self {
        self.domains.push(contact.as_ref().into());
        self
    }

    pub fn external_account_binding(mut self, kid: impl AsRef<str>, key: impl AsRef<[u8]>) -> Self {
        self.eab = Some(ExternalAccountKey::new(kid.as_ref().into(), key.as_ref()));
        self
    }

    /// Provide a list of contacts for the account.
    ///
    /// Note that email addresses must include a `mailto:` prefix.
    pub fn contact(mut self, contact: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        self.contact = contact.into_iter().map(|s| s.as_ref().into()).collect();
        self
    }

    /// Provide a contact for the account.
    ///
    /// Note that an email address must include a `mailto:` prefix.
    pub fn contact_push(mut self, contact: impl AsRef<str>) -> Self {
        self.contact.push(contact.as_ref().into());
        self
    }

    /// Set the certificate chain preference. See [`CertChainPreference`] for details.
    pub fn cert_chain(mut self, preference: CertChainPreference) -> Self {
        self.cert_chain = preference;
        self
    }
    pub fn cache<C: 'static + Cache>(self, cache: C) -> AcmeConfig<C::EC, C::EA> {
        AcmeConfig {
            client_config: self.client_config,
            directory_url: self.directory_url,
            domains: self.domains,
            contact: self.contact,
            cache: Box::new(cache),
            eab: self.eab,
            cert_chain: self.cert_chain,
        }
    }
    pub fn cache_compose<CC: 'static + CertCache, CA: 'static + AccountCache>(
        self,
        cert_cache: CC,
        account_cache: CA,
    ) -> AcmeConfig<CC::EC, CA::EA> {
        self.cache(CompositeCache::new(cert_cache, account_cache))
    }
    pub fn cache_with_boxed_err<C: 'static + Cache>(self, cache: C) -> AcmeConfig<Box<dyn Debug>> {
        self.cache(BoxedErrCache::new(cache))
    }
    pub fn cache_option<C: 'static + Cache>(self, cache: Option<C>) -> AcmeConfig<C::EC, C::EA> {
        match cache {
            Some(cache) => self.cache(cache),
            None => self.cache(NoCache::<C::EC, C::EA>::new()),
        }
    }

    /// The provider of the ACME client config, used for everything TLS.
    pub(crate) fn crypto_provider(&self) -> &Arc<CryptoProvider> {
        self.client_config.crypto_provider()
    }

    /// Returns the [`AcmeState`] that drives ordering, renewal, and caching.
    pub fn state(self) -> AcmeState<EC, EA> {
        AcmeState::new(self)
    }
    /// Turn a stream of TCP connections into a stream of TLS connections.
    ///
    /// Specify supported protocol names in `alpn_protocols`, most preferred first. If emtpy (`Vec::new()`), we don't do ALPN.
    pub fn incoming<
        TCP: AsyncRead + AsyncWrite + Unpin,
        ETCP,
        ITCP: Stream<Item = Result<TCP, ETCP>> + Unpin,
    >(
        self,
        tcp_incoming: ITCP,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> Incoming<TCP, ETCP, ITCP, EC, EA> {
        self.state().incoming(tcp_incoming, alpn_protocols)
    }
    /// Same as [AcmeConfig::incoming] but this version allows to specify a custom `rustls::ServerConfig`.
    pub fn incoming_with_server<
        TCP: AsyncRead + AsyncWrite + Unpin,
        ETCP,
        ITCP: Stream<Item = Result<TCP, ETCP>> + Unpin,
    >(
        self,
        tcp_incoming: ITCP,
        server_config: ServerConfig,
    ) -> Incoming<TCP, ETCP, ITCP, EC, EA> {
        self.state()
            .incoming_with_server(tcp_incoming, server_config)
    }
}

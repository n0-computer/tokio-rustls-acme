use crate::acme::{
    ExternalAccountKey, Identifier, InvalidIdentifier, LETS_ENCRYPT_PRODUCTION_DIRECTORY,
    LETS_ENCRYPT_STAGING_DIRECTORY,
};
use crate::caches::{BoxedErrCache, CompositeCache, NoCache};
use crate::{AccountCache, Cache, CertCache};
use crate::{AcmeState, Incoming};
use n0_future::Stream;
#[cfg(feature = "tls-webpki-roots")]
use rustls::DEFAULT_VERSIONS;
use rustls::crypto::CryptoProvider;
use rustls::{ClientConfig, ServerConfig};
use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::convert::Infallible;
use std::fmt::{self, Debug};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};

/// An identifier as configured: a string as given, or a typed [`Identifier`].
#[derive(Debug, Clone)]
enum ConfiguredIdentifier {
    Text(String),
    Typed(Identifier),
}

impl ConfiguredIdentifier {
    /// Returns the identifier to order, keeping the type of a typed identifier.
    fn to_identifier(&self) -> Result<Identifier, InvalidIdentifier> {
        match self {
            Self::Text(text) => text.parse(),
            Self::Typed(identifier) => identifier.clone().validated(),
        }
    }
}

/// The identifiers of a config, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Identifiers {
    /// The identifiers to order, without duplicates.
    pub(crate) order: Vec<Identifier>,
    /// The strings that key the certificate cache, see [`AcmeConfig::domains`].
    pub(crate) cache_key: Vec<String>,
}

/// Configuration for an ACME resolver.
///
/// The type parameters represent the error types for the certificate cache and account cache.
pub struct AcmeConfig<EC: Debug, EA: Debug = EC> {
    pub(crate) client_config: Arc<ClientConfig>,
    pub(crate) directory_url: String,
    identifiers: Vec<ConfiguredIdentifier>,
    pub(crate) contact: Vec<String>,
    pub(crate) cache: Box<dyn Cache<EC = EC, EA = EA>>,
    pub(crate) eab: Option<ExternalAccountKey>,
    pub(crate) profile: Option<String>,
}

impl<EC: Debug, EA: Debug> fmt::Debug for AcmeConfig<EC, EA> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcmeConfig")
            .field("directory_url", &self.directory_url)
            .field("identifiers", &self.identifiers)
            .field("contact", &self.contact)
            .finish_non_exhaustive()
    }
}

impl AcmeConfig<Infallible, Infallible> {
    /// Creates an [`AcmeConfig`] backed by webpki-roots trust anchors.
    ///
    /// Picks aws-lc-rs when the `tls-aws-lc-rs` feature is enabled,
    /// otherwise ring (the default). The same provider is used for the HTTPS client,
    /// the TLS handshake, and key parsing. Use
    /// [`AcmeConfig::new_with_crypto_provider`] to pick a different provider.
    ///
    /// `domains` are DNS names or IP addresses, see [`AcmeConfig::domains`].
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
            identifiers: Self::text_identifiers(domains),
            contact: vec![],
            cache: Box::new(NoCache::new()),
            eab: None,
            profile: None,
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
    /// Sets the URL of the ACME directory.
    ///
    /// RFC 8555 requires HTTPS. Plain HTTP works, but leaves the ACME traffic unprotected.
    ///
    /// Signed requests follow no redirects.
    pub fn directory(mut self, directory_url: impl AsRef<str>) -> Self {
        self.directory_url = directory_url.as_ref().into();
        self
    }
    /// Uses the Let's Encrypt production directory if `production` is true, else staging.
    pub fn directory_lets_encrypt(mut self, production: bool) -> Self {
        self.directory_url = match production {
            true => LETS_ENCRYPT_PRODUCTION_DIRECTORY,
            false => LETS_ENCRYPT_STAGING_DIRECTORY,
        }
        .into();
        self
    }
    /// Sets the identifiers to request a certificate for, DNS names or IP addresses.
    ///
    /// Invalid ones fail every order, see [`Identifier::validated`]. The strings, as given, key
    /// the certificate cache.
    pub fn domains(mut self, domains: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        self.identifiers = Self::text_identifiers(domains);
        self
    }
    /// Sets typed identifiers to request a certificate for, like [`IpAddr`](std::net::IpAddr)s.
    ///
    /// Each keeps its type. They key the certificate cache by their canonical text.
    pub fn identifiers(
        mut self,
        identifiers: impl IntoIterator<Item = impl Into<Identifier>>,
    ) -> Self {
        self.identifiers = identifiers
            .into_iter()
            .map(|identifier| ConfiguredIdentifier::Typed(identifier.into()))
            .collect();
        self
    }
    /// Adds an identifier (DNS name or IP address) to request a certificate for.
    pub fn domains_push(mut self, domain: impl AsRef<str>) -> Self {
        self.identifiers
            .push(ConfiguredIdentifier::Text(domain.as_ref().into()));
        self
    }

    /// Returns string identifiers as configured.
    fn text_identifiers(
        domains: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Vec<ConfiguredIdentifier> {
        domains
            .into_iter()
            .map(|domain| ConfiguredIdentifier::Text(domain.as_ref().into()))
            .collect()
    }

    /// Returns whether the directory is one of Let's Encrypt's.
    pub(crate) fn is_lets_encrypt(&self) -> bool {
        [
            LETS_ENCRYPT_PRODUCTION_DIRECTORY,
            LETS_ENCRYPT_STAGING_DIRECTORY,
        ]
        .contains(&self.directory_url.as_str())
    }

    /// Returns the validated identifiers, or why they can't be ordered.
    pub(crate) fn validated_identifiers(&self) -> Result<Identifiers, InvalidIdentifier> {
        if self.identifiers.is_empty() {
            return Err(InvalidIdentifier::NoIdentifiers);
        }
        let mut order = Vec::new();
        let mut cache_key = Vec::new();
        let mut challenge_names = BTreeMap::new();
        for configured in &self.identifiers {
            let identifier = configured.to_identifier()?;
            cache_key.push(match configured {
                // Strings stay as given, so existing cache entries keep matching.
                ConfiguredIdentifier::Text(text) => text.clone(),
                ConfiguredIdentifier::Typed(_) => identifier.to_string(),
            });
            match challenge_names.entry(identifier.tls_alpn_01_server_name()) {
                Entry::Vacant(entry) => {
                    entry.insert(identifier.clone());
                    order.push(identifier);
                }
                Entry::Occupied(entry) if *entry.get() == identifier => {}
                Entry::Occupied(entry) => {
                    return Err(InvalidIdentifier::ChallengeNameConflict(
                        entry.key().clone(),
                    ));
                }
            }
        }
        Ok(Identifiers { order, cache_key })
    }

    /// Requires the ACME profile `profile` (draft-ietf-acme-profiles) for new orders.
    ///
    /// The CA must confirm it in the order, or the order fails with
    /// [`OrderError::ProfileMismatch`](crate::OrderError::ProfileMismatch), so every order fails
    /// with a CA without profiles. Let's Encrypt issues IP certificates only under `shortlived`.
    pub fn profile(mut self, profile: impl AsRef<str>) -> Self {
        self.profile = Some(profile.as_ref().into());
        self
    }

    /// Binds the ACME account to an account at the CA with the key ID `kid` and HMAC `key`
    /// (RFC 8555 section 7.3.4). Some CAs require this.
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

    /// Stores certificates and account keys in `cache`.
    pub fn cache<C: 'static + Cache>(self, cache: C) -> AcmeConfig<C::EC, C::EA> {
        AcmeConfig {
            client_config: self.client_config,
            directory_url: self.directory_url,
            identifiers: self.identifiers,
            contact: self.contact,
            cache: Box::new(cache),
            eab: self.eab,
            profile: self.profile,
        }
    }
    /// Stores certificates in `cert_cache` and account keys in `account_cache`.
    pub fn cache_compose<CC: 'static + CertCache, CA: 'static + AccountCache>(
        self,
        cert_cache: CC,
        account_cache: CA,
    ) -> AcmeConfig<CC::EC, CA::EA> {
        self.cache(CompositeCache::new(cert_cache, account_cache))
    }
    /// Sets the cache and boxes its errors, so the config type does not depend on it.
    pub fn cache_with_boxed_err<C: 'static + Cache>(self, cache: C) -> AcmeConfig<Box<dyn Debug>> {
        self.cache(BoxedErrCache::new(cache))
    }
    /// Sets the cache if `cache` is `Some`, and disables caching otherwise.
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

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::ring;
    use rustls::{DEFAULT_VERSIONS, RootCertStore};
    use std::net::IpAddr;

    /// Returns a config for `domains` that needs no webpki roots, like the custom-root builds.
    fn config(domains: &[&str]) -> AcmeConfig<Infallible> {
        let client_config = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_protocol_versions(DEFAULT_VERSIONS)
            .expect("the provider supports the default versions")
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth();
        AcmeConfig::new_with_client_tls_config(domains, Arc::new(client_config))
    }

    /// Returns the identifiers to order of `config`.
    fn order(config: &AcmeConfig<Infallible>) -> Result<Vec<Identifier>, InvalidIdentifier> {
        config
            .validated_identifiers()
            .map(|identifiers| identifiers.order)
    }

    #[test]
    fn validated_identifiers_normalizes_and_deduplicates() {
        let config = config(&["Example.COM.", "example.com", "::1", "0:0::1"]);
        assert_eq!(
            order(&config),
            Ok(vec![
                Identifier::Dns("example.com".into()),
                Identifier::Ip("::1".parse().unwrap()),
            ])
        );
    }

    #[test]
    fn validated_identifiers_rejects_invalid_and_empty_lists() {
        let config = config(&["example.com", "*.example.com"]);
        assert_eq!(
            order(&config),
            Err(InvalidIdentifier::Wildcard("*.example.com".into()))
        );
        assert_eq!(
            order(&config.domains([""; 0])),
            Err(InvalidIdentifier::NoIdentifiers)
        );
    }

    #[test]
    fn validated_identifiers_rejects_identifiers_that_share_a_challenge_name() {
        let ipv6_reverse = format!("1.{}8.b.d.0.1.0.0.2.ip6.arpa", "0.".repeat(23));
        let cases = [
            ("192.0.2.1", "1.2.0.192.in-addr.arpa".to_string()),
            ("2001:db8::1", ipv6_reverse),
        ];
        for (ip, reverse) in cases {
            assert_eq!(
                order(&config(&[ip, &reverse])),
                Err(InvalidIdentifier::ChallengeNameConflict(reverse.clone())),
                "{ip}"
            );
        }
    }

    #[test]
    fn typed_identifiers_keep_their_type() {
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let typed_dns = config(&[]).identifiers([Identifier::Dns(ip.to_string())]);
        assert_eq!(
            order(&typed_dns),
            Err(InvalidIdentifier::InvalidDnsName(ip.to_string()))
        );
        let typed_ip = config(&[]).identifiers([ip]);
        assert_eq!(order(&typed_ip), Ok(vec![Identifier::Ip(ip)]));
    }

    #[test]
    fn cache_keys_are_strings_as_given_and_canonical_typed_identifiers() {
        let domains = ["Example.COM.", "0:0::1", "example.com"];
        let cache_key = |config: AcmeConfig<Infallible>| {
            config
                .validated_identifiers()
                .map(|identifiers| identifiers.cache_key)
        };
        assert_eq!(
            cache_key(config(&domains)),
            Ok(domains.map(String::from).to_vec())
        );
        let typed = domains.map(|domain| domain.parse::<Identifier>().unwrap());
        assert_eq!(
            cache_key(config(&[]).identifiers(typed)),
            Ok(vec![
                "example.com".into(),
                "::1".into(),
                "example.com".into()
            ])
        );
        let unvalidated = config(&[]).identifiers([Identifier::Dns("Example.COM.".into())]);
        assert_eq!(cache_key(unvalidated), Ok(vec!["example.com".into()]));
    }
}

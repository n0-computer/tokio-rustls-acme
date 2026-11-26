use std::fmt;
use std::net::{IpAddr, Ipv6Addr};
use std::str::FromStr;
use std::sync::Arc;

pub use crate::crypto::CryptoError;
use crate::crypto::hmac;
use crate::crypto::rand::SystemRandom;
use crate::crypto::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, EcdsaSigningAlgorithm,
};
pub use crate::https_helper::HttpsRequestError;
use crate::https_helper::{self, Method, Response, https};
pub use crate::jose::JoseError;
use crate::jose::{key_authorization_sha256, sign, sign_eab};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rcgen::{CertificateParams, CustomExtension, PKCS_ECDSA_P256_SHA256, SanType};
use rustls::sign::CertifiedKey;
use rustls::{
    ClientConfig,
    crypto::CryptoProvider,
    pki_types::{DnsName, PrivateKeyDer, PrivatePkcs8KeyDer},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use tracing::debug;
use x509_parser::extensions::GeneralName;

/// Directory URL of the Let's Encrypt staging environment.
pub const LETS_ENCRYPT_STAGING_DIRECTORY: &str =
    "https://acme-staging-v02.api.letsencrypt.org/directory";
/// Directory URL of the Let's Encrypt production environment.
pub const LETS_ENCRYPT_PRODUCTION_DIRECTORY: &str =
    "https://acme-v02.api.letsencrypt.org/directory";
/// ALPN protocol name that marks a `tls-alpn-01` validation handshake (RFC 8737).
pub const ACME_TLS_ALPN_NAME: &[u8] = b"acme-tls/1";

/// An account at an ACME server, with the key that signs its requests.
#[derive(Debug)]
pub(crate) struct Account {
    pub(crate) key_pair: EcdsaKeyPair,
    /// Directory of the ACME server that holds this account.
    pub(crate) directory: Directory,
    /// Account URL from the server, sent as `kid` in signed requests.
    pub(crate) kid: String,
}

static ALG: &EcdsaSigningAlgorithm = &ECDSA_P256_SHA256_FIXED_SIGNING;

impl Account {
    /// Generates a new P-256 ECDSA account key in PKCS#8 DER form.
    pub(crate) fn generate_key_pair() -> Vec<u8> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(ALG, &rng).expect("system RNG failed");
        pkcs8.as_ref().to_vec()
    }
    /// Returns an error if `key_pair` is not a PKCS#8 key that an account can use.
    pub(crate) fn check_key_pair(key_pair: &[u8]) -> Result<(), CryptoError> {
        crate::crypto::ecdsa_key_pair_from_pkcs8(ALG, key_pair).map(drop)
    }
    /// Registers the account for `key_pair` at the server, or looks up the existing one.
    pub(crate) async fn create_with_keypair<'a, S, I>(
        client_config: &Arc<ClientConfig>,
        directory: Directory,
        contact: I,
        key_pair: &[u8],
        eab: &Option<ExternalAccountKey>,
    ) -> Result<Self, AcmeError>
    where
        S: AsRef<str> + 'a,
        I: IntoIterator<Item = &'a S>,
    {
        let key_pair = crate::crypto::ecdsa_key_pair_from_pkcs8(ALG, key_pair)
            .map_err(AcmeError::KeyRejected)?;
        let contact: Vec<&'a str> = contact.into_iter().map(AsRef::<str>::as_ref).collect();

        let payload = if let Some(eab) = &eab.as_ref() {
            let eab_body = sign_eab(&key_pair, &eab.key, &eab.kid, &directory.new_account)?;

            json!({
                "termsOfServiceAgreed": true,
                "contact": contact,
                "externalAccountBinding": eab_body,
            })
        } else {
            json!({
                "termsOfServiceAgreed": true,
                "contact": contact,
            })
        }
        .to_string();

        let body = sign(
            &key_pair,
            None,
            directory.nonce(client_config).await?,
            &directory.new_account,
            &payload,
        )?;
        let response = https(
            client_config,
            &directory.new_account,
            Method::Post,
            Some(body),
            directory.https_only(),
        )
        .await?;
        let kid = get_header(&response, "Location")?;
        Ok(Account {
            key_pair,
            kid,
            directory,
        })
    }
    async fn request(
        &self,
        client_config: &Arc<ClientConfig>,
        url: impl AsRef<str>,
        payload: &str,
    ) -> Result<(Option<String>, String), AcmeError> {
        let body = sign(
            &self.key_pair,
            Some(&self.kid),
            self.directory.nonce(client_config).await?,
            url.as_ref(),
            payload,
        )?;
        let https_only = self.directory.https_only();
        let response = https(
            client_config,
            url.as_ref(),
            Method::Post,
            Some(body),
            https_only,
        )
        .await?;
        let location = get_header(&response, "Location").ok();
        let body = https_helper::text(response).await?;
        debug!(?body, "response");
        Ok((location, body))
    }
    /// Creates a new order for `identifiers`, with the certificate profile `profile` if set.
    pub(crate) async fn new_order(
        &self,
        client_config: &Arc<ClientConfig>,
        identifiers: &[Identifier],
        profile: Option<&str>,
    ) -> Result<CreatedOrder, AcmeError> {
        let payload = serde_json::to_string(&NewOrder {
            identifiers,
            profile,
        })
        .map_err(json_err)?;
        let (location, body) = self
            .request(client_config, &self.directory.new_order, &payload)
            .await?;
        let url = location.ok_or(AcmeError::MissingHeader("Location"))?;
        CreatedOrder::from_response(url, &body)
    }
    /// Fetches the authorization object at `url`.
    pub(crate) async fn auth(
        &self,
        client_config: &Arc<ClientConfig>,
        url: impl AsRef<str>,
    ) -> Result<Auth, AcmeError> {
        let payload = "".to_string();
        let response = self.request(client_config, url, &payload).await?;
        serde_json::from_str(&response.1).map_err(json_err)
    }
    /// Tells the server that the challenge at `url` is ready for validation.
    pub(crate) async fn challenge(
        &self,
        client_config: &Arc<ClientConfig>,
        url: impl AsRef<str>,
    ) -> Result<(), AcmeError> {
        self.request(client_config, &url, "{}").await?;
        Ok(())
    }
    /// Fetches the current state of the order at `url`.
    pub(crate) async fn order(
        &self,
        client_config: &Arc<ClientConfig>,
        url: impl AsRef<str>,
    ) -> Result<Order, AcmeError> {
        let response = self.request(client_config, &url, "").await?;
        serde_json::from_str(&response.1).map_err(json_err)
    }
    /// Sends the DER-encoded `csr` to the finalize `url` and returns the updated order.
    pub(crate) async fn finalize(
        &self,
        client_config: &Arc<ClientConfig>,
        url: impl AsRef<str>,
        csr: Vec<u8>,
    ) -> Result<Order, AcmeError> {
        let payload = format!("{{\"csr\":\"{}\"}}", URL_SAFE_NO_PAD.encode(csr),);
        let response = self.request(client_config, &url, &payload).await?;
        serde_json::from_str(&response.1).map_err(json_err)
    }
    /// Downloads the PEM certificate chain at `url`.
    pub(crate) async fn certificate(
        &self,
        client_config: &Arc<ClientConfig>,
        url: impl AsRef<str>,
    ) -> Result<String, AcmeError> {
        Ok(self.request(client_config, &url, "").await?.1)
    }
    /// Picks the `tls-alpn-01` challenge and builds its validation certificate for `domain`.
    pub(crate) fn tls_alpn_01<'a>(
        &self,
        crypto_provider: &CryptoProvider,
        challenges: &'a [Challenge],
        identifier: &Identifier,
    ) -> Result<(&'a Challenge, CertifiedKey), AcmeError> {
        let challenge = challenges
            .iter()
            .find(|c| c.typ == ChallengeType::TlsAlpn01);

        let challenge = match challenge {
            Some(challenge) => challenge,
            None => return Err(AcmeError::NoTlsAlpn01Challenge),
        };
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![identifier.subject_alt_name().map_err(rcgen_err)?];
        let key_auth = key_authorization_sha256(&self.key_pair, &challenge.token)?;
        params.custom_extensions = vec![CustomExtension::new_acme_identifier(key_auth.as_ref())];

        let key_pair = rcgen::KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).map_err(rcgen_err)?;
        let cert = params.self_signed(&key_pair).map_err(rcgen_err)?;

        let pk_bytes = key_pair.serialize_der();
        let pk_der: PrivatePkcs8KeyDer<'static> = pk_bytes.into();
        let pk_der: PrivateKeyDer<'static> = pk_der.into();
        let pk = crypto_provider
            .key_provider
            .load_private_key(pk_der)
            .map_err(|err| AcmeError::Crypto(CryptoError::new(err)))?;
        let certified_key = CertifiedKey::new(vec![cert.der().clone()], pk);
        Ok((challenge, certified_key))
    }
}

/// Endpoint URLs from the directory object of an ACME server (RFC 8555 section 7.1.1).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Directory {
    /// URL that hands out fresh replay nonces.
    pub(crate) new_nonce: String,
    /// URL to create an account or look up an existing one.
    pub(crate) new_account: String,
    /// URL to create a new order.
    pub(crate) new_order: String,
}

impl Directory {
    /// Fetches and parses the directory object at `url`.
    pub(crate) async fn discover(
        client_config: &Arc<ClientConfig>,
        url: impl AsRef<str>,
    ) -> Result<Self, AcmeError> {
        let https_only = https_helper::is_https(url.as_ref());
        let response = https(client_config, url, Method::Get, None, https_only).await?;
        let body = https_helper::bytes(response).await?;

        serde_json::from_slice(&body).map_err(json_err)
    }
    /// Fetches a fresh replay nonce from the `newNonce` URL.
    async fn nonce(&self, client_config: &Arc<ClientConfig>) -> Result<String, AcmeError> {
        let url = self.new_nonce.as_str();
        let response = &https(client_config, url, Method::Head, None, self.https_only()).await?;
        get_header(response, "replay-nonce")
    }

    /// Returns whether requests must refuse plain HTTP, which holds once any endpoint uses HTTPS.
    fn https_only(&self) -> bool {
        [&self.new_nonce, &self.new_account, &self.new_order]
            .iter()
            .any(|url| https_helper::is_https(url))
    }
}

/// A key that binds a new account to an external CA account (RFC 8555 section 7.3.4).
pub(crate) struct ExternalAccountKey {
    /// Key identifier that the CA assigned to the external account.
    pub(crate) kid: String,
    pub(crate) key: hmac::Key,
}

impl ExternalAccountKey {
    /// Creates a binding key from the CA-issued `kid` and the raw HMAC-SHA256 `key` bytes.
    pub(crate) fn new(kid: String, key: &[u8]) -> Self {
        Self {
            kid,
            key: hmac::Key::new(hmac::HMAC_SHA256, key),
        }
    }
}

/// The type of a challenge (RFC 8555 section 8).
#[derive(Debug, Deserialize, Eq, PartialEq)]
pub enum ChallengeType {
    /// The `http-01` challenge (RFC 8555 section 8.3), not supported by this crate.
    #[serde(rename = "http-01")]
    Http01,
    /// The `dns-01` challenge (RFC 8555 section 8.4), not supported by this crate.
    #[serde(rename = "dns-01")]
    Dns01,
    /// The `tls-alpn-01` challenge (RFC 8737), which this crate answers.
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
    /// A challenge type this crate does not know.
    #[serde(other)]
    Unknown,
}

/// An order object (RFC 8555 section 7.1.3).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Order {
    /// Status of the order, with the certificate URL once it is valid.
    #[serde(flatten)]
    pub status: OrderStatus,
    /// URLs of the authorizations that must be valid before finalization.
    pub authorizations: Vec<String>,
    /// URL to send the CSR to once the order is ready.
    pub finalize: String,
    /// Error that made the order fail, if any.
    pub error: Option<Problem>,
}

/// Status of an order (RFC 8555 section 7.1.6).
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "camelCase")]
#[non_exhaustive]
pub enum OrderStatus {
    /// Authorizations are not complete yet.
    Pending,
    /// All authorizations are valid, and the server waits for the CSR.
    Ready,
    /// The certificate is issued and can be downloaded.
    Valid {
        /// URL to download the certificate chain from.
        certificate: String,
    },
    /// The order failed or expired.
    Invalid,
    /// The server is issuing the certificate.
    Processing,
}

impl OrderStatus {
    /// Returns the position of this status in the RFC 8555 order lifecycle.
    pub(crate) fn progress(&self) -> u8 {
        match self {
            Self::Pending => 0,
            Self::Ready => 1,
            Self::Processing => 2,
            Self::Valid { .. } | Self::Invalid => 3,
        }
    }
}

/// An authorization object (RFC 8555 section 7.1.4).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Auth {
    /// Status of the authorization, `valid` once a challenge succeeded.
    pub status: AuthStatus,
    /// Identifier that this authorization proves control of.
    pub identifier: Identifier,
    /// Challenges the server offers to prove control of the identifier.
    pub challenges: Vec<Challenge>,
}

/// Status of an authorization (RFC 8555 section 7.1.6).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum AuthStatus {
    /// Validation has not succeeded yet.
    Pending,
    /// A challenge was validated.
    Valid,
    /// Validation failed.
    Invalid,
    /// The server revoked the authorization.
    Revoked,
    /// The authorization expired.
    Expired,
    /// The client deactivated the authorization.
    Deactivated,
}

/// An ACME identifier (RFC 8555 section 9.7.7, RFC 8738 for IP addresses).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
#[non_exhaustive]
pub enum Identifier {
    /// A DNS name.
    Dns(String),
    /// An IP address.
    Ip(IpAddr),
}

impl From<IpAddr> for Identifier {
    fn from(ip: IpAddr) -> Self {
        Identifier::Ip(ip)
    }
}

impl FromStr for Identifier {
    type Err = InvalidIdentifier;

    /// Parses `s` as an IP address, or else as a DNS name, see [`Identifier::validated`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_text(s).validated()
    }
}

/// Why an identifier, or the identifiers of a config, can't be ordered.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InvalidIdentifier {
    /// The config has no identifiers.
    #[error("no identifiers to order")]
    NoIdentifiers,
    /// Two identifiers share a challenge SNI, like `192.0.2.1` and `1.2.0.192.in-addr.arpa`.
    #[error("two identifiers share the challenge name {0:?}")]
    ChallengeNameConflict(String),
    /// The string is neither an IP address nor a valid DNS name.
    #[error("{0:?} is neither an IP address nor a valid DNS name")]
    InvalidDnsName(String),
    /// The name is not ASCII. Internationalized names need their punycode form (`xn--`).
    #[error("{0:?} is not ASCII, use the punycode form of the name")]
    NonAscii(String),
    /// The name is a wildcard, which tls-alpn-01 cannot validate.
    #[error("{0:?} is a wildcard, which tls-alpn-01 cannot validate")]
    Wildcard(String),
    /// The address is unspecified (`0.0.0.0` or `::`).
    #[error("{0} is the unspecified address")]
    UnspecifiedIp(IpAddr),
    /// The address is an IPv4-mapped IPv6 address. Use the IPv4 address instead.
    #[error("{0} is an IPv4-mapped IPv6 address, use the IPv4 address")]
    Ipv4MappedIp(Ipv6Addr),
}

impl fmt::Display for Identifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Identifier::Dns(name) => f.write_str(name),
            Identifier::Ip(ip) => ip.fmt(f),
        }
    }
}

impl Identifier {
    /// Returns `text` as an IP identifier if it is an IP address, else as a DNS one, unvalidated.
    pub(crate) fn from_text(text: &str) -> Self {
        match text.parse::<IpAddr>() {
            Ok(ip) => Identifier::Ip(ip),
            Err(_) => Identifier::Dns(text.to_owned()),
        }
    }
    /// Returns the identifier normalized for an order, or why it can't be ordered.
    ///
    /// DNS names are lowercased, lose one trailing dot, and must be valid ASCII names without a
    /// wildcard. IP addresses must not be unspecified or IPv4-mapped.
    pub fn validated(self) -> Result<Self, InvalidIdentifier> {
        match self {
            Identifier::Ip(ip) if ip.is_unspecified() => Err(InvalidIdentifier::UnspecifiedIp(ip)),
            Identifier::Ip(IpAddr::V6(v6)) if v6.to_ipv4_mapped().is_some() => {
                Err(InvalidIdentifier::Ipv4MappedIp(v6))
            }
            ip @ Identifier::Ip(_) => Ok(ip),
            Identifier::Dns(name) => Self::normalized_dns_name(name).map(Identifier::Dns),
        }
    }
    /// Returns `name` lowercased and without one trailing dot, or why it is no valid DNS name.
    fn normalized_dns_name(name: String) -> Result<String, InvalidIdentifier> {
        if !name.is_ascii() {
            return Err(InvalidIdentifier::NonAscii(name));
        }
        let normalized = name.strip_suffix('.').unwrap_or(&name).to_ascii_lowercase();
        if normalized.starts_with('*') {
            return Err(InvalidIdentifier::Wildcard(name));
        }
        // rustls accepts one trailing dot, so a second one would survive normalization.
        if normalized.ends_with('.') || DnsName::try_from(normalized.as_str()).is_err() {
            return Err(InvalidIdentifier::InvalidDnsName(name));
        }
        Ok(normalized)
    }
    /// Returns whether the subject alternative name `name` certifies this identifier.
    pub(crate) fn is_certified_by(&self, name: &GeneralName<'_>) -> bool {
        match (self, name) {
            // webpki rejects a SAN with a trailing dot, so it certifies nothing.
            (Identifier::Dns(dns), GeneralName::DNSName(name)) => name.eq_ignore_ascii_case(dns),
            (Identifier::Ip(ip), GeneralName::IPAddress(octets)) => match ip {
                IpAddr::V4(v4) => *octets == v4.octets(),
                IpAddr::V6(v6) => *octets == v6.octets(),
            },
            _ => false,
        }
    }
    /// Returns the subject alternative name that certifies this identifier.
    pub(crate) fn subject_alt_name(&self) -> Result<SanType, rcgen::Error> {
        Ok(match self {
            Identifier::Dns(name) => SanType::DnsName(name.clone().try_into()?),
            Identifier::Ip(ip) => SanType::IpAddress(*ip),
        })
    }
    /// Returns the SNI the CA sends to validate this validated identifier, see RFC 8738 for IPs.
    pub(crate) fn tls_alpn_01_server_name(&self) -> String {
        match self {
            Identifier::Dns(name) => name.clone(),
            Identifier::Ip(ip) => reverse_dns_name(*ip),
        }
    }
}

/// Returns the reverse-DNS name of `ip` (RFC 1035 section 3.5, RFC 3596 section 2.5).
fn reverse_dns_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa")
        }
        IpAddr::V6(v6) => {
            let nibbles: String = v6
                .octets()
                .iter()
                .rev()
                .map(|byte| format!("{:x}.{:x}.", byte & 0xf, byte >> 4))
                .collect();
            nibbles + "ip6.arpa"
        }
    }
}

/// An order that `newOrder` created.
#[derive(Debug)]
pub(crate) struct CreatedOrder {
    /// URL of the order, from the `Location` header.
    pub(crate) url: String,
    /// The order as created.
    pub(crate) order: Order,
    /// The profile the CA selected for the order (draft-ietf-acme-profiles), if it named one.
    pub(crate) profile: Option<String>,
}

impl CreatedOrder {
    /// Parses the `newOrder` response `body` of the order at `url`.
    ///
    /// A `profile` that is not a string counts as none.
    fn from_response(url: String, body: &str) -> Result<Self, AcmeError> {
        let value: serde_json::Value = serde_json::from_str(body).map_err(json_err)?;
        let profile = value
            .get("profile")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned);
        let order = Order::deserialize(value).map_err(json_err)?;
        Ok(Self {
            url,
            order,
            profile,
        })
    }
}

/// The payload of a `newOrder` request (RFC 8555 section 7.4).
#[derive(Debug, Serialize)]
struct NewOrder<'a> {
    identifiers: &'a [Identifier],
    /// The certificate profile (draft-ietf-acme-profiles), left out when unset.
    #[serde(skip_serializing_if = "Option::is_none")]
    profile: Option<&'a str>,
}

/// A challenge object (RFC 8555 section 8).
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct Challenge {
    /// Validation method of this challenge, such as `tls-alpn-01`.
    #[serde(rename = "type")]
    pub typ: ChallengeType,
    /// URL to post to when the client is ready for validation.
    #[serde(default)]
    pub url: String,
    /// Random token from the server, part of the key authorization.
    #[serde(default)]
    pub token: String,
    /// The error of a failed validation.
    pub error: Option<Problem>,
}

/// A problem document from the ACME server (RFC 8555 section 6.7, RFC 7807).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Problem {
    /// Problem type URI, such as `urn:ietf:params:acme:error:rateLimited`.
    #[serde(rename = "type")]
    pub typ: Option<String>,
    /// Human-readable explanation of the problem.
    pub detail: Option<String>,
}

/// An error from the ACME client.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum AcmeError {
    /// Generating the validation certificate or its key failed.
    ///
    /// Usually downcasts to `rcgen::Error`. The concrete type is not covered by semver.
    #[error("certificate generation error: {0}")]
    Rcgen(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// Signing a request or computing the key authorization failed.
    #[error("JOSE error: {0}")]
    Jose(#[from] JoseError),
    /// A request could not be serialized, or a response could not be parsed.
    ///
    /// Usually downcasts to `serde_json::Error`. The concrete type is not covered by semver.
    #[error("JSON error: {0}")]
    Json(#[source] Box<dyn std::error::Error + Send + Sync>),
    /// An HTTP request failed or returned a non-2xx status.
    #[error("http request error: {0}")]
    HttpRequest(#[from] HttpsRequestError),
    /// The account key is not a valid P-256 ECDSA PKCS#8 key.
    #[error("invalid key pair: {0}")]
    KeyRejected(CryptoError),
    /// The crypto provider could not load the validation key.
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    /// A server response lacks a required header.
    #[error("acme service response is missing {0} header")]
    MissingHeader(&'static str),
    /// The authorization offers no `tls-alpn-01` challenge.
    #[error("no tls-alpn-01 challenge found")]
    NoTlsAlpn01Challenge,
}

impl AcmeError {
    /// Returns whether a `newAccount` error shows a deactivated or unknown account.
    ///
    /// See RFC 8555 section 7.3.6.
    pub(crate) fn rejects_account(&self) -> bool {
        let AcmeError::HttpRequest(HttpsRequestError::Non2xxStatus { body, .. }) = self else {
            return false;
        };
        let typ = serde_json::from_str::<Problem>(body)
            .ok()
            .and_then(|p| p.typ);
        matches!(
            typ.as_deref(),
            Some(
                "urn:ietf:params:acme:error:unauthorized"
                    | "urn:ietf:params:acme:error:accountDoesNotExist"
            )
        )
    }
}

fn json_err(err: serde_json::Error) -> AcmeError {
    AcmeError::Json(err.into())
}

fn rcgen_err(err: rcgen::Error) -> AcmeError {
    AcmeError::Rcgen(err.into())
}

fn get_header(response: &Response, header: &'static str) -> Result<String, AcmeError> {
    let h = response
        .headers()
        .get_all(header)
        .iter()
        .next_back()
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    match h {
        None => Err(AcmeError::MissingHeader(header)),
        Some(value) => Ok(value),
    }
}

#[cfg(test)]
mod http_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::crypto::KeyProvider;
    use rustls::sign::SigningKey;

    /// Parses `s` as a valid identifier.
    fn id(s: &str) -> Identifier {
        s.parse()
            .unwrap_or_else(|err| panic!("{s:?} should parse: {err}"))
    }

    #[test]
    fn parsing_normalizes_identifiers() {
        let cases = [
            ("example.com", Identifier::Dns("example.com".into())),
            ("Example.COM.", Identifier::Dns("example.com".into())),
            // rustls accepts underscores, which private CAs may issue for.
            (
                "_svc.example.org",
                Identifier::Dns("_svc.example.org".into()),
            ),
            ("192.0.2.1", Identifier::Ip("192.0.2.1".parse().unwrap())),
            // RFC 5952: lowercase, longest zero run compressed, no leading zeros.
            (
                "2001:0DB8:0::0001",
                Identifier::Ip("2001:db8::1".parse().unwrap()),
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(id(input), expected, "{input:?}");
        }
        assert_eq!(id("0:0::1").to_string(), "::1");
    }

    #[test]
    fn invalid_identifiers_are_rejected() {
        let dns = |name: &str| InvalidIdentifier::InvalidDnsName(name.into());
        let cases = [
            ("", dns("")),
            (".", dns(".")),
            ("example.org..", dns("example.org..")),
            ("010.0.0.1", dns("010.0.0.1")),
            ("foo bar", dns("foo bar")),
            ("fe80::1%eth0", dns("fe80::1%eth0")),
            (
                "b\u{fc}cher.example",
                InvalidIdentifier::NonAscii("b\u{fc}cher.example".into()),
            ),
            (
                "*.example.com",
                InvalidIdentifier::Wildcard("*.example.com".into()),
            ),
            (
                "::",
                InvalidIdentifier::UnspecifiedIp("::".parse().unwrap()),
            ),
            (
                "::ffff:192.0.2.1",
                InvalidIdentifier::Ipv4MappedIp("::ffff:192.0.2.1".parse().unwrap()),
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(input.parse::<Identifier>(), Err(expected), "{input:?}");
        }
        // A typed DNS identifier keeps its type, so an IP literal is no valid DNS name.
        let typed = Identifier::Dns("192.0.2.1".into()).validated();
        assert_eq!(typed, Err(dns("192.0.2.1")));
    }

    #[test]
    fn challenge_server_names() {
        let cases = [
            (id("Example.COM"), "example.com".to_owned()),
            (id("192.0.2.1"), "1.2.0.192.in-addr.arpa".to_owned()),
            // Example from RFC 3596 section 2.5, lowercased.
            (
                id("4321:0:1:2:3:4:567:89ab"),
                "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.ip6.arpa"
                    .to_owned(),
            ),
            (id("::1"), format!("1.{}ip6.arpa", "0.".repeat(31))),
        ];
        for (identifier, name) in cases {
            assert_eq!(identifier.tls_alpn_01_server_name(), name, "{identifier}");
        }
    }

    #[test]
    fn is_certified_by_matches_the_san_type_and_value() {
        let v4 = [192, 0, 2, 1];
        let v6 = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets();
        let cases = [
            ("example.com", GeneralName::DNSName("Example.COM"), true),
            ("example.com", GeneralName::DNSName("example.com."), false),
            (
                "example.com",
                GeneralName::DNSName("www.example.com"),
                false,
            ),
            ("192.0.2.1", GeneralName::IPAddress(&v4), true),
            ("192.0.2.1", GeneralName::DNSName("192.0.2.1"), false),
            ("2001:db8::1", GeneralName::IPAddress(&v6), true),
            ("2001:db8::1", GeneralName::IPAddress(&v4), false),
        ];
        for (identifier, name, certified) in cases {
            let certifies = id(identifier).is_certified_by(&name);
            assert_eq!(certifies, certified, "{identifier} by {name:?}");
        }
    }

    #[test]
    fn new_order_payload_has_profile_only_when_set() {
        let identifiers = [id("example.com"), id("2001:DB8::1")];
        let payload = |profile| {
            let order = NewOrder {
                identifiers: &identifiers,
                profile,
            };
            serde_json::to_string(&order).unwrap()
        };
        let identifiers_json = concat!(
            r#""identifiers":[{"type":"dns","value":"example.com"},"#,
            r#"{"type":"ip","value":"2001:db8::1"}]"#,
        );
        assert_eq!(payload(None), format!("{{{identifiers_json}}}"));
        assert_eq!(
            payload(Some("shortlived")),
            format!(r#"{{{identifiers_json},"profile":"shortlived"}}"#)
        );
    }

    #[derive(Debug)]
    struct RejectingKeyProvider;

    impl KeyProvider for RejectingKeyProvider {
        fn load_private_key(
            &self,
            _key_der: PrivateKeyDer<'static>,
        ) -> Result<Arc<dyn SigningKey>, rustls::Error> {
            Err(rustls::Error::General("rejected".into()))
        }
    }

    /// A provider that can't load the challenge key must fail the order,
    /// not panic the task polling it.
    #[test]
    fn tls_alpn_01_reports_unloadable_key() {
        let provider = CryptoProvider {
            key_provider: &RejectingKeyProvider,
            ..rustls::crypto::ring::default_provider()
        };
        let account = Account {
            key_pair: crate::crypto::ecdsa_key_pair_from_pkcs8(ALG, &Account::generate_key_pair())
                .unwrap(),
            directory: Directory {
                new_nonce: String::new(),
                new_account: String::new(),
                new_order: String::new(),
            },
            kid: String::new(),
        };
        let challenges = [Challenge {
            typ: ChallengeType::TlsAlpn01,
            url: String::new(),
            token: "token".into(),
            error: None,
        }];

        let result = account.tls_alpn_01(&provider, &challenges, &id("example.com"));
        assert!(matches!(result, Err(AcmeError::Crypto(_))));
    }

    #[test]
    fn rejects_account_on_account_problems_only() {
        let non_2xx = |body: &str| {
            AcmeError::HttpRequest(HttpsRequestError::Non2xxStatus {
                status_code: 403,
                body: body.to_string(),
            })
        };
        let problem = |typ: &str| format!(r#"{{"type":"urn:ietf:params:acme:error:{typ}"}}"#);
        let cases = [
            (problem("unauthorized"), true),
            (problem("accountDoesNotExist"), true),
            (problem("rateLimited"), false),
            ("{}".to_string(), false),
            ("unauthorized".to_string(), false),
        ];
        for (body, expected) in cases {
            assert_eq!(non_2xx(&body).rejects_account(), expected, "{body}");
        }
        assert!(!AcmeError::MissingHeader("location").rejects_account());
    }

    #[test]
    fn directory_https_only() {
        let cases = [
            ("https://ca.test", "https://ca.test", true),
            ("HTTPS://ca.test", "http://ca.test", true),
            ("http://ca.test", "http://ca.test", false),
            ("http://https.test", "", false),
        ];
        for (new_nonce, new_order, expected) in cases {
            let directory = Directory {
                new_nonce: new_nonce.into(),
                new_account: new_nonce.into(),
                new_order: new_order.into(),
            };
            assert_eq!(directory.https_only(), expected, "{new_nonce} {new_order}");
        }
    }
}

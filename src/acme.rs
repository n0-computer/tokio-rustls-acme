use std::sync::Arc;

pub use crate::crypto::CryptoError;
use crate::crypto::hmac;
use crate::crypto::rand::SystemRandom;
use crate::crypto::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, EcdsaSigningAlgorithm,
};
pub use crate::https_helper::HttpsRequestError;
use crate::https_helper::{Method, Response, https};
pub use crate::jose::JoseError;
use crate::jose::{key_authorization_sha256, sign, sign_eab};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rcgen::{CustomExtension, Error as RcgenError, PKCS_ECDSA_P256_SHA256};
use rustls::sign::CertifiedKey;
use rustls::{
    ClientConfig,
    crypto::CryptoProvider,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

/// Directory URL of the Let's Encrypt staging environment.
pub const LETS_ENCRYPT_STAGING_DIRECTORY: &str =
    "https://acme-staging-v02.api.letsencrypt.org/directory";
/// Directory URL of the Let's Encrypt production environment.
pub const LETS_ENCRYPT_PRODUCTION_DIRECTORY: &str =
    "https://acme-v02.api.letsencrypt.org/directory";
/// ALPN protocol name that marks a `tls-alpn-01` validation handshake (RFC 8737).
pub const ACME_TLS_ALPN_NAME: &[u8] = b"acme-tls/1";

#[derive(Debug)]
pub struct Account {
    pub(crate) key_pair: EcdsaKeyPair,
    /// Directory of the ACME server that holds this account.
    pub directory: Directory,
    /// Account URL from the server, sent as `kid` in signed requests.
    pub kid: String,
}

static ALG: &EcdsaSigningAlgorithm = &ECDSA_P256_SHA256_FIXED_SIGNING;

impl Account {
    /// Generates a new P-256 ECDSA account key in PKCS#8 DER form.
    pub fn generate_key_pair() -> Vec<u8> {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(ALG, &rng).unwrap();
        pkcs8.as_ref().to_vec()
    }
    pub async fn create<'a, S, I>(
        client_config: &Arc<ClientConfig>,
        directory: Directory,
        contact: I,
        eab: &Option<ExternalAccountKey>,
    ) -> Result<Self, AcmeError>
    where
        S: AsRef<str> + 'a,
        I: IntoIterator<Item = &'a S>,
    {
        let key_pair = Self::generate_key_pair();
        Self::create_with_keypair(client_config, directory, contact, &key_pair, eab).await
    }
    /// Registers the account for `key_pair` at the server, or looks up the existing one.
    pub async fn create_with_keypair<'a, S, I>(
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
        let response = https(client_config, url.as_ref(), Method::Post, Some(body)).await?;
        let location = get_header(&response, "Location").ok();
        let body = response.text().await.map_err(HttpsRequestError::from)?;
        log::debug!("response: {body:?}");
        Ok((location, body))
    }
    pub async fn new_order(
        &self,
        client_config: &Arc<ClientConfig>,
        domains: Vec<String>,
    ) -> Result<(String, Order), AcmeError> {
        let domains: Vec<Identifier> = domains.into_iter().map(Identifier::Dns).collect();
        let payload = format!("{{\"identifiers\":{}}}", serde_json::to_string(&domains)?);
        let response = self
            .request(client_config, &self.directory.new_order, &payload)
            .await?;
        let url = response.0.ok_or(AcmeError::MissingHeader("Location"))?;
        let order = serde_json::from_str(&response.1)?;
        Ok((url, order))
    }
    /// Fetches the authorization object at `url`.
    pub async fn auth(
        &self,
        client_config: &Arc<ClientConfig>,
        url: impl AsRef<str>,
    ) -> Result<Auth, AcmeError> {
        let payload = "".to_string();
        let response = self.request(client_config, url, &payload).await?;
        Ok(serde_json::from_str(&response.1)?)
    }
    /// Tells the server that the challenge at `url` is ready for validation.
    pub async fn challenge(
        &self,
        client_config: &Arc<ClientConfig>,
        url: impl AsRef<str>,
    ) -> Result<(), AcmeError> {
        self.request(client_config, &url, "{}").await?;
        Ok(())
    }
    /// Fetches the current state of the order at `url`.
    pub async fn order(
        &self,
        client_config: &Arc<ClientConfig>,
        url: impl AsRef<str>,
    ) -> Result<Order, AcmeError> {
        let response = self.request(client_config, &url, "").await?;
        Ok(serde_json::from_str(&response.1)?)
    }
    /// Sends the DER-encoded `csr` to the finalize `url` and returns the updated order.
    pub async fn finalize(
        &self,
        client_config: &Arc<ClientConfig>,
        url: impl AsRef<str>,
        csr: Vec<u8>,
    ) -> Result<Order, AcmeError> {
        let payload = format!("{{\"csr\":\"{}\"}}", URL_SAFE_NO_PAD.encode(csr),);
        let response = self.request(client_config, &url, &payload).await?;
        Ok(serde_json::from_str(&response.1)?)
    }
    /// Downloads the PEM certificate chain at `url`.
    pub async fn certificate(
        &self,
        client_config: &Arc<ClientConfig>,
        url: impl AsRef<str>,
    ) -> Result<String, AcmeError> {
        Ok(self.request(client_config, &url, "").await?.1)
    }
    /// Picks the `tls-alpn-01` challenge and builds its validation certificate for `domain`.
    pub fn tls_alpn_01<'a>(
        &self,
        crypto_provider: &CryptoProvider,
        challenges: &'a [Challenge],
        domain: String,
    ) -> Result<(&'a Challenge, CertifiedKey), AcmeError> {
        let challenge = challenges
            .iter()
            .find(|c| c.typ == ChallengeType::TlsAlpn01);

        let challenge = match challenge {
            Some(challenge) => challenge,
            None => return Err(AcmeError::NoTlsAlpn01Challenge),
        };
        let mut params = rcgen::CertificateParams::new(vec![domain])?;
        let key_auth = key_authorization_sha256(&self.key_pair, &challenge.token)?;
        params.custom_extensions = vec![CustomExtension::new_acme_identifier(key_auth.as_ref())];

        let key_pair = rcgen::KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let cert = params.self_signed(&key_pair)?;

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
pub struct Directory {
    /// URL that hands out fresh replay nonces.
    pub new_nonce: String,
    /// URL to create an account or look up an existing one.
    pub new_account: String,
    /// URL to create a new order.
    pub new_order: String,
}

impl Directory {
    /// Fetches and parses the directory object at `url`.
    pub async fn discover(
        client_config: &Arc<ClientConfig>,
        url: impl AsRef<str>,
    ) -> Result<Self, AcmeError> {
        let response = https(client_config, url, Method::Get, None).await?;
        let body = response.bytes().await.map_err(HttpsRequestError::from)?;

        Ok(serde_json::from_slice(&body)?)
    }
    /// Fetches a fresh replay nonce from the `newNonce` URL.
    pub async fn nonce(&self, client_config: &Arc<ClientConfig>) -> Result<String, AcmeError> {
        let response = &https(client_config, &self.new_nonce.as_str(), Method::Head, None).await?;
        get_header(response, "replay-nonce")
    }
}

/// See RFC 8555 section 7.3.4 for more information.
pub struct ExternalAccountKey {
    /// Key identifier that the CA assigned to the external account.
    pub kid: String,
    pub(crate) key: hmac::Key,
}

impl ExternalAccountKey {
    /// Creates a binding key from the CA-issued `kid` and the raw HMAC-SHA256 `key` bytes.
    pub fn new(kid: String, key: &[u8]) -> Self {
        Self {
            kid,
            key: hmac::Key::new(hmac::HMAC_SHA256, key),
        }
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq)]
pub enum ChallengeType {
    /// The `http-01` challenge (RFC 8555 section 8.3), not supported by this crate.
    #[serde(rename = "http-01")]
    Http01,
    /// The `dns-01` challenge (RFC 8555 section 8.4), not supported by this crate.
    #[serde(rename = "dns-01")]
    Dns01,
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "camelCase")]
#[non_exhaustive]
pub enum Identifier {
    /// A DNS name.
    Dns(String),
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
    /// An I/O error, currently not produced by this crate.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// Generating the validation certificate or its key failed.
    #[error("certificate generation error: {0}")]
    Rcgen(#[from] RcgenError),
    /// Signing a request or computing the key authorization failed.
    #[error("JOSE error: {0}")]
    Jose(#[from] JoseError),
    /// A request could not be serialized, or a response could not be parsed.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
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
mod tests {
    use super::*;
    use rustls::crypto::KeyProvider;
    use rustls::sign::SigningKey;

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

        let result = account.tls_alpn_01(&provider, &challenges, "example.com".into());
        assert!(matches!(result, Err(AcmeError::Crypto(_))));
    }
}

//! Crypto backend for the ACME protocol itself: account keys, JWS signing,
//! external account binding, and digests.
//!
//! This is independent of the rustls [`CryptoProvider`](rustls::crypto::CryptoProvider)
//! used for TLS, but selected by the same crate features: aws-lc-rs when
//! `tls-aws-lc-rs` is enabled, otherwise ring. aws-lc-rs wins when both are
//! enabled because rcgen makes the same choice, so every layer agrees. Both
//! expose the same API, so the rest of the crate imports from here instead
//! of naming a backend.

#[cfg(not(any(feature = "tls-ring", feature = "tls-aws-lc-rs")))]
compile_error!("tokio-rustls-acme requires one of the `tls-ring` or `tls-aws-lc-rs` features");

#[cfg(feature = "tls-aws-lc-rs")]
pub(crate) use aws_lc_rs::{digest, hmac, rand, signature};
#[cfg(all(feature = "tls-ring", not(feature = "tls-aws-lc-rs")))]
pub(crate) use ring::{digest, hmac, rand, signature};

#[cfg(feature = "tls-webpki-roots")]
use rustls::crypto::CryptoProvider;
use signature::{EcdsaKeyPair, EcdsaSigningAlgorithm};

/// The rustls provider matching the selected backend, used by
/// `AcmeConfig::new`.
#[cfg(feature = "tls-webpki-roots")]
pub(crate) fn default_provider() -> CryptoProvider {
    #[cfg(all(feature = "tls-ring", not(feature = "tls-aws-lc-rs")))]
    let provider = rustls::crypto::ring::default_provider();
    #[cfg(feature = "tls-aws-lc-rs")]
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    provider
}

/// Error from the crypto backend.
///
/// Opaque so the public API stays the same whichever backend the crate
/// features select.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct CryptoError(String);

impl CryptoError {
    pub(crate) fn new(err: impl std::fmt::Display) -> Self {
        Self(err.to_string())
    }
}

/// Parses a PKCS#8 ECDSA key pair. ring needs an RNG for this, aws-lc-rs does not.
pub(crate) fn ecdsa_key_pair_from_pkcs8(
    alg: &'static EcdsaSigningAlgorithm,
    pkcs8: &[u8],
) -> Result<EcdsaKeyPair, CryptoError> {
    #[cfg(all(feature = "tls-ring", not(feature = "tls-aws-lc-rs")))]
    let key_pair = EcdsaKeyPair::from_pkcs8(alg, pkcs8, &rand::SystemRandom::new());
    #[cfg(feature = "tls-aws-lc-rs")]
    let key_pair = EcdsaKeyPair::from_pkcs8(alg, pkcs8);
    key_pair.map_err(CryptoError::new)
}

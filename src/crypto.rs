//! Crypto backend for the ACME protocol itself: account keys, JWS signing,
//! external account binding, and digests.
//!
//! This is independent of the rustls [`CryptoProvider`](rustls::crypto::CryptoProvider)
//! used for TLS, but selected by the same crate features: ring when
//! `tls-ring` is enabled, otherwise aws-lc-rs. Both expose the same API, so
//! the rest of the crate imports from here instead of naming a backend.

#[cfg(not(any(feature = "tls-ring", feature = "tls-aws-lc-rs")))]
compile_error!("tokio-rustls-acme requires one of the `tls-ring` or `tls-aws-lc-rs` features");

#[cfg(all(feature = "tls-aws-lc-rs", not(feature = "tls-ring")))]
pub(crate) use aws_lc_rs::{digest, error, hmac, rand, signature};
#[cfg(feature = "tls-ring")]
pub(crate) use ring::{digest, error, hmac, rand, signature};

use error::KeyRejected;
use signature::{EcdsaKeyPair, EcdsaSigningAlgorithm};

/// Parses a PKCS#8 ECDSA key pair. ring needs an RNG for this, aws-lc-rs does not.
pub(crate) fn ecdsa_key_pair_from_pkcs8(
    alg: &'static EcdsaSigningAlgorithm,
    pkcs8: &[u8],
) -> Result<EcdsaKeyPair, KeyRejected> {
    #[cfg(feature = "tls-ring")]
    {
        EcdsaKeyPair::from_pkcs8(alg, pkcs8, &rand::SystemRandom::new())
    }
    #[cfg(all(feature = "tls-aws-lc-rs", not(feature = "tls-ring")))]
    {
        EcdsaKeyPair::from_pkcs8(alg, pkcs8)
    }
}

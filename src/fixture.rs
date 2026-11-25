//! The private PKI of `tests/fixtures/alternate-chains.sh`, for unit tests.

use rustls::crypto::{WebPkiSupportedAlgorithms, ring};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;

use crate::chain::CertChain;

/// The fixture's PEM blocks: the leaf's key, then the certificates in the order of [`Cert`].
const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/alternate-chains.pem");

/// The DNS name of the leaf.
pub(crate) const LEAF_NAME: &str = "test.example.com";

/// The common name of the ECDSA root.
pub(crate) const EC_ROOT_CN: &str = "ec";

/// The common name of the RSA root.
pub(crate) const RSA_ROOT_CN: &str = "rsa";

/// The two hierarchies, see [`CROSS_SIGNED_ROOT`] and [`INTERMEDIATE_BY_EACH_ROOT`].
pub(crate) const HIERARCHIES: [Hierarchy; 2] = [CROSS_SIGNED_ROOT, INTERMEDIATE_BY_EACH_ROOT];

/// The ECDSA root cross-signed by the RSA root, like ISRG Root X2 by ISRG Root X1.
pub(crate) const CROSS_SIGNED_ROOT: Hierarchy = Hierarchy {
    primary: &[Cert::Leaf, Cert::Intermediate, Cert::EcByRsa],
    alternate: &[Cert::Leaf, Cert::Intermediate],
};

/// The intermediate's key signed by each root, like Let's Encrypt's E5 to E9 intermediates.
pub(crate) const INTERMEDIATE_BY_EACH_ROOT: Hierarchy = Hierarchy {
    primary: &[Cert::Leaf, Cert::IntermediateByRsa],
    alternate: &[Cert::Leaf, Cert::Intermediate],
};

/// A certificate of the fixture.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Cert {
    /// The leaf for [`LEAF_NAME`], issued by `CN=intermediate`.
    Leaf = 1,
    /// `CN=intermediate`, issued by the ECDSA root.
    Intermediate,
    /// The ECDSA root's key, issued by the RSA root.
    EcByRsa,
    /// The self-signed ECDSA root.
    EcRoot,
    /// The self-signed RSA root.
    RsaRoot,
    /// The intermediate's key, issued by the RSA root with RSA-PSS SHA-384.
    IntermediateByRsaPss,
    /// The intermediate's key, issued by the RSA root with RSA PKCS#1 SHA-256.
    IntermediateByRsa,
    /// The intermediate's key, issued by the ECDSA root, expired.
    IntermediateExpired,
    /// The intermediate's key, issued by the ECDSA root, but not as a CA.
    IntermediateNotCa,
    /// The intermediate's key, issued by the ECDSA root, but not to sign certificates.
    IntermediateWithoutCertSign,
}

impl Cert {
    /// Returns the DER of this certificate.
    pub(crate) fn der(self) -> CertificateDer<'static> {
        blocks()[self as usize].contents().to_vec().into()
    }
}

/// A primary chain to the RSA root, and an alternate to the ECDSA root, for the leaf.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Hierarchy {
    /// The chain to the RSA root, which the CA issues by default.
    pub(crate) primary: &'static [Cert],
    /// The chain to the ECDSA root.
    pub(crate) alternate: &'static [Cert],
}

/// Returns `certs` with the leaf's key.
pub(crate) fn certified_key(certs: &[Cert]) -> CertifiedKey {
    let key = PrivatePkcs8KeyDer::from(blocks()[0].contents().to_vec());
    let key = ring::default_provider()
        .key_provider
        .load_private_key(key.into())
        .expect("the fixture key is P-256");
    CertifiedKey::new(self::certs(certs), key)
}

/// Returns the signature verification algorithms of the tests.
pub(crate) fn algorithms() -> WebPkiSupportedAlgorithms {
    ring::default_provider().signature_verification_algorithms
}

/// Returns the DER of `certs`.
pub(crate) fn certs(certs: &[Cert]) -> Vec<CertificateDer<'static>> {
    certs.iter().map(|cert| cert.der()).collect()
}

/// Returns the chain of `certs`.
pub(crate) fn chain(certs: &[Cert]) -> CertChain {
    CertChain::new(self::certs(certs))
}

/// Returns the leaf's key followed by `certs`, as one PEM bundle.
pub(crate) fn bundle(certs: &[Cert]) -> Vec<u8> {
    let blocks = blocks();
    let picked: Vec<_> = [0]
        .into_iter()
        .chain(certs.iter().map(|&cert| cert as usize))
        .map(|i| blocks[i].clone())
        .collect();
    pem::encode_many(&picked).into_bytes()
}

/// Returns the fixture's PEM blocks.
fn blocks() -> Vec<pem::Pem> {
    pem::parse_many(FIXTURE).expect("the fixture is PEM")
}

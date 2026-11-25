//! Certificate chains a CA offers for one certificate, and the schemes that verifying them takes.

use rustls::SignatureScheme;
use rustls::pki_types::CertificateDer;
use x509_parser::asn1_rs::{Oid, oid};
use x509_parser::certificate::X509Certificate;
use x509_parser::oid_registry::{
    OID_EC_P256, OID_NIST_EC_P384, OID_NIST_EC_P521, OID_NIST_HASH_SHA256, OID_NIST_HASH_SHA384,
    OID_NIST_HASH_SHA512, OID_PKCS1_RSAENCRYPTION, OID_PKCS1_RSASSAPSS, OID_PKCS1_SHA256WITHRSA,
    OID_PKCS1_SHA384WITHRSA, OID_PKCS1_SHA512WITHRSA, OID_SIG_ECDSA_WITH_SHA256,
    OID_SIG_ECDSA_WITH_SHA384, OID_SIG_ECDSA_WITH_SHA512, OID_SIG_ED448, OID_SIG_ED25519,
};
use x509_parser::parse_x509_certificate;
use x509_parser::signature_algorithm::RsaSsaPssParams;

use crate::config::ChainRoot;

/// OID of the MGF1 mask generation function of RSA-PSS (RFC 8017 appendix B.2.1).
const OID_PKCS1_MGF1: Oid<'static> = oid!(1.2.840.113549.1.1.8);

/// The `trailerField` that RSA-PSS signatures use (RFC 4055 section 3.1).
const PSS_TRAILER_FIELD: u32 = 1;

/// The PEM tag of a certificate.
const CERTIFICATE_TAG: &str = "CERTIFICATE";

/// The signature schemes a client needs to verify a certificate chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RequiredSchemes {
    /// The schemes of all signatures in the chain.
    Known(Vec<SignatureScheme>),
    /// A signature in the chain has no scheme that it can be identified with.
    Unknown,
}

impl RequiredSchemes {
    /// Returns whether a client offering `offered` can verify the chain, or `None` if unknown.
    ///
    /// A TLS 1.3 client may list RSA PKCS#1 only in `signature_algorithms_cert`, which rustls
    /// doesn't expose, so RSA-PSS with the same hash counts for it.
    pub(crate) fn supported_by(&self, offered: &[SignatureScheme]) -> Option<bool> {
        match self {
            Self::Known(schemes) => Some(schemes.iter().all(|scheme| {
                offered.contains(scheme)
                    || pss_with_same_hash(*scheme).is_some_and(|pss| offered.contains(&pss))
            })),
            Self::Unknown => None,
        }
    }
}

/// Returns the RSA-PSS scheme with the hash of the RSA PKCS#1 scheme `scheme`.
fn pss_with_same_hash(scheme: SignatureScheme) -> Option<SignatureScheme> {
    match scheme {
        SignatureScheme::RSA_PKCS1_SHA256 => Some(SignatureScheme::RSA_PSS_SHA256),
        SignatureScheme::RSA_PKCS1_SHA384 => Some(SignatureScheme::RSA_PSS_SHA384),
        SignatureScheme::RSA_PKCS1_SHA512 => Some(SignatureScheme::RSA_PSS_SHA512),
        _ => None,
    }
}

/// How to treat an ECDSA signature whose signer's key is in neither chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnknownSigner {
    /// The schemes are unknown.
    Unknown,
    /// The signer's curve is the one TLS pairs with the signature's hash.
    ///
    /// Like P-384 for SHA-384, as in TLS 1.3's `ecdsa_secp384r1_sha384`.
    StandardCurve,
}

/// A certificate chain as a CA offers it, leaf first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CertChain {
    certs: Vec<CertificateDer<'static>>,
}

impl CertChain {
    /// Creates a chain from DER certificates, leaf first.
    pub(crate) fn new(certs: Vec<CertificateDer<'static>>) -> Self {
        Self { certs }
    }

    /// Parses a PEM chain, or returns `None` if it is empty or holds anything but certificates.
    pub(crate) fn from_pem(pem: &[u8]) -> Option<Self> {
        let certs = pem::parse_many(pem)
            .ok()?
            .into_iter()
            .map(|block| (block.tag() == CERTIFICATE_TAG).then(|| block.into_contents().into()))
            .collect::<Option<Vec<_>>>()?;
        (!certs.is_empty()).then_some(Self { certs })
    }

    /// Returns the chain as PEM, leaf first.
    pub(crate) fn to_pem(&self) -> Vec<u8> {
        let blocks: Vec<_> = self
            .certs
            .iter()
            .map(|der| pem::Pem::new(CERTIFICATE_TAG, der.to_vec()))
            .collect();
        pem::encode_many(&blocks).into_bytes()
    }

    /// Returns the leaf certificate.
    pub(crate) fn leaf(&self) -> &CertificateDer<'static> {
        &self.certs[0]
    }

    /// Returns the certificates, leaf first.
    pub(crate) fn into_certs(self) -> Vec<CertificateDer<'static>> {
        self.certs
    }

    /// Returns whether the topmost certificate is issued by `root`, so the chain ends there.
    pub(crate) fn ends_at(&self, root: &ChainRoot) -> bool {
        self.certs
            .last()
            .and_then(|der| parse(der))
            .is_some_and(|cert| issuer_name(&cert) == Some(root.common_name()))
    }

    /// Returns whether the chain is a valid alternate to `leaf` that ends at `root`.
    ///
    /// Each certificate must be issued and signed by the next, a CA certificate valid now. The
    /// root may be left out.
    pub(crate) fn is_alternate_for(&self, leaf: &CertificateDer<'_>, root: &ChainRoot) -> bool {
        if self.leaf() != leaf || !self.ends_at(root) {
            return false;
        }
        let Some(certs) = self.parse_all() else {
            return false;
        };
        certs.windows(2).all(|pair| {
            let [cert, issuer] = pair else {
                return false;
            };
            cert.issuer() == issuer.subject()
                && issuer.is_ca()
                && issuer.validity().is_valid()
                && issuer
                    .key_usage()
                    .is_ok_and(|usage| usage.is_none_or(|usage| usage.value.key_cert_sign()))
                && cert.verify_signature(Some(issuer.public_key())).is_ok()
        })
    }

    /// Returns the schemes a client needs to verify this chain.
    ///
    /// An ECDSA scheme depends on the signer's curve, so the topmost signer is looked up in
    /// `other`, the other chain for the leaf. A self-signed top is a trust anchor, not verified.
    pub(crate) fn required_schemes(&self, other: &CertChain) -> RequiredSchemes {
        self.schemes(other, UnknownSigner::Unknown)
    }

    /// Like [`CertChain::required_schemes`], but assumes standard curves for unknown signers.
    ///
    /// Only for the alternate, which goes only to clients that can't verify the primary, so a
    /// wrong guess only affects those.
    pub(crate) fn likely_required_schemes(&self, other: &CertChain) -> RequiredSchemes {
        self.schemes(other, UnknownSigner::StandardCurve)
    }

    /// Returns the schemes of this chain, see [`CertChain::required_schemes`].
    fn schemes(&self, other: &CertChain, unknown_signer: UnknownSigner) -> RequiredSchemes {
        let Some(certs) = self.parse_all() else {
            return RequiredSchemes::Unknown;
        };
        let others: Vec<_> = other.certs.iter().filter_map(|der| parse(der)).collect();
        let mut schemes = Vec::new();
        for (index, cert) in certs.iter().enumerate() {
            let issuer = match certs.get(index + 1) {
                Some(issuer) => Some(issuer),
                None if cert.subject() == cert.issuer() => continue,
                None => others.iter().find(|issuer| {
                    issuer.subject() == cert.issuer()
                        && cert.verify_signature(Some(issuer.public_key())).is_ok()
                }),
            };
            let Some(scheme) = signature_scheme(cert, issuer, unknown_signer) else {
                return RequiredSchemes::Unknown;
            };
            if !schemes.contains(&scheme) {
                schemes.push(scheme);
            }
        }
        RequiredSchemes::Known(schemes)
    }

    /// Parses all certificates, or returns `None` if one fails to parse.
    fn parse_all(&self) -> Option<Vec<X509Certificate<'_>>> {
        self.certs.iter().map(|der| parse(der)).collect()
    }
}

/// Parses a DER certificate without trailing data.
fn parse<'a>(der: &'a CertificateDer<'_>) -> Option<X509Certificate<'a>> {
    let (rest, cert) = parse_x509_certificate(der.as_ref()).ok()?;
    rest.is_empty().then_some(cert)
}

/// Returns the common name of the issuer of `cert`.
fn issuer_name<'a>(cert: &'a X509Certificate<'_>) -> Option<&'a str> {
    cert.issuer().iter_common_name().next()?.as_str().ok()
}

/// Returns the TLS scheme of the signature on `cert` by `issuer`, if it can be identified.
///
/// ECDSA needs the curve of the issuer's key, or `unknown_signer` decides.
fn signature_scheme(
    cert: &X509Certificate<'_>,
    issuer: Option<&X509Certificate<'_>>,
    unknown_signer: UnknownSigner,
) -> Option<SignatureScheme> {
    let algorithm = &cert.signature_algorithm;
    let oid = &algorithm.algorithm;
    if *oid == OID_PKCS1_SHA256WITHRSA {
        Some(SignatureScheme::RSA_PKCS1_SHA256)
    } else if *oid == OID_PKCS1_SHA384WITHRSA {
        Some(SignatureScheme::RSA_PKCS1_SHA384)
    } else if *oid == OID_PKCS1_SHA512WITHRSA {
        Some(SignatureScheme::RSA_PKCS1_SHA512)
    } else if *oid == OID_SIG_ED25519 {
        Some(SignatureScheme::ED25519)
    } else if *oid == OID_SIG_ED448 {
        Some(SignatureScheme::ED448)
    } else if *oid == OID_PKCS1_RSASSAPSS {
        if issuer.is_some_and(|issuer| {
            issuer.public_key().algorithm.algorithm != OID_PKCS1_RSAENCRYPTION
        }) {
            return None;
        }
        pss_scheme(&RsaSsaPssParams::try_from(algorithm.parameters()?).ok()?)
    } else {
        // The curve that TLS pairs with each ECDSA signature hash.
        let (scheme, standard_curve) = if *oid == OID_SIG_ECDSA_WITH_SHA256 {
            (SignatureScheme::ECDSA_NISTP256_SHA256, OID_EC_P256)
        } else if *oid == OID_SIG_ECDSA_WITH_SHA384 {
            (SignatureScheme::ECDSA_NISTP384_SHA384, OID_NIST_EC_P384)
        } else if *oid == OID_SIG_ECDSA_WITH_SHA512 {
            (SignatureScheme::ECDSA_NISTP521_SHA512, OID_NIST_EC_P521)
        } else {
            return None;
        };
        let curve_matches = match issuer {
            Some(issuer) => {
                issuer.public_key().algorithm.parameters()?.as_oid().ok()? == standard_curve
            }
            None => unknown_signer == UnknownSigner::StandardCurve,
        };
        curve_matches.then_some(scheme)
    }
}

/// Returns the TLS scheme of RSA-PSS `params`, if TLS allows them.
///
/// TLS requires MGF1 with the signature's hash and a salt as long as the hash (RFC 8446
/// section 4.2.3).
fn pss_scheme(params: &RsaSsaPssParams<'_>) -> Option<SignatureScheme> {
    let hash = params.hash_algorithm_oid();
    let mask = params.mask_gen_algorithm().ok()?;
    if mask.mgf != OID_PKCS1_MGF1
        || mask.hash != *hash
        || params.trailer_field() != PSS_TRAILER_FIELD
    {
        return None;
    }
    let (scheme, salt_length) = if *hash == OID_NIST_HASH_SHA256 {
        (SignatureScheme::RSA_PSS_SHA256, 32)
    } else if *hash == OID_NIST_HASH_SHA384 {
        (SignatureScheme::RSA_PSS_SHA384, 48)
    } else if *hash == OID_NIST_HASH_SHA512 {
        (SignatureScheme::RSA_PSS_SHA512, 64)
    } else {
        return None;
    };
    (params.salt_length() == salt_length).then_some(scheme)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{
        CROSS_SIGNED_ROOT, Cert, EC_ROOT_CN, INTERMEDIATE_BY_EACH_ROOT, RSA_ROOT_CN, chain,
    };

    #[test]
    fn accepts_a_linked_alternate_and_rejects_broken_ones() {
        let leaf = Cert::Leaf.der();
        let ec = ChainRoot::new(EC_ROOT_CN);
        let rsa = ChainRoot::new(RSA_ROOT_CN);
        let cases = [
            (CROSS_SIGNED_ROOT.alternate, &ec, true),
            (CROSS_SIGNED_ROOT.primary, &rsa, true),
            (INTERMEDIATE_BY_EACH_ROOT.primary, &rsa, true),
            (
                &[Cert::Leaf, Cert::IntermediateByRsaPss, Cert::RsaRoot],
                &rsa,
                true,
            ),
            (CROSS_SIGNED_ROOT.alternate, &rsa, false),
            // Without the leaf.
            (&[Cert::Intermediate], &ec, false),
            // Without the intermediate.
            (&[Cert::Leaf, Cert::EcRoot], &ec, false),
            // Issued by the name of the next certificate, but not signed by its key.
            (
                &[Cert::Leaf, Cert::Intermediate, Cert::RsaRoot],
                &rsa,
                false,
            ),
        ];
        for (certs, root, accepted) in cases {
            assert_eq!(
                chain(certs).is_alternate_for(&leaf, root),
                accepted,
                "{certs:?} to {root}"
            );
        }
    }

    #[test]
    fn required_schemes_follow_the_signer_keys() {
        let primary = chain(CROSS_SIGNED_ROOT.primary);
        let alternate = chain(CROSS_SIGNED_ROOT.alternate);
        // The cross-signature needs RSA, the ECDSA signatures are by P-256 keys.
        assert_eq!(
            primary.required_schemes(&alternate),
            RequiredSchemes::Known(vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA256,
            ])
        );
        // The intermediate's signer, the ECDSA root, is only in the other chain.
        assert_eq!(
            alternate.required_schemes(&primary),
            RequiredSchemes::Known(vec![SignatureScheme::ECDSA_NISTP256_SHA256])
        );
        // Without the other chain, the curve of the topmost signer is unknown.
        assert_eq!(
            alternate.required_schemes(&chain(&[])),
            RequiredSchemes::Unknown
        );
        // A self-signed root at the top is a trust anchor, so its signature doesn't count.
        assert_eq!(
            chain(&[Cert::Leaf, Cert::Intermediate, Cert::EcRoot]).required_schemes(&chain(&[])),
            RequiredSchemes::Known(vec![SignatureScheme::ECDSA_NISTP256_SHA256])
        );
    }

    #[test]
    fn likely_schemes_assume_the_standard_curve_for_a_missing_signer() {
        let primary = chain(INTERMEDIATE_BY_EACH_ROOT.primary);
        let alternate = chain(INTERMEDIATE_BY_EACH_ROOT.alternate);
        assert_eq!(
            primary.required_schemes(&alternate),
            RequiredSchemes::Known(vec![
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA256,
            ])
        );
        // The ECDSA root is in neither chain, so its curve is unknown.
        assert_eq!(
            alternate.required_schemes(&primary),
            RequiredSchemes::Unknown
        );
        assert_eq!(
            alternate.likely_required_schemes(&primary),
            RequiredSchemes::Known(vec![SignatureScheme::ECDSA_NISTP256_SHA256])
        );
        // A known signer decides, whatever the hash.
        assert_eq!(
            chain(CROSS_SIGNED_ROOT.alternate)
                .likely_required_schemes(&chain(CROSS_SIGNED_ROOT.primary)),
            RequiredSchemes::Known(vec![SignatureScheme::ECDSA_NISTP256_SHA256])
        );
    }

    #[test]
    fn rsa_pss_scheme_comes_from_its_parameters() {
        let pss_intermediate = Cert::IntermediateByRsaPss.der();
        let pss_intermediate = parse(&pss_intermediate).unwrap();
        let (rsa_root, ec_root) = (Cert::RsaRoot.der(), Cert::EcRoot.der());
        let (rsa_root, ec_root) = (parse(&rsa_root).unwrap(), parse(&ec_root).unwrap());
        for (issuer, scheme) in [
            (Some(&rsa_root), Some(SignatureScheme::RSA_PSS_SHA384)),
            // RSA-PSS is RSA only, so an unknown issuer is fine, but not an ECDSA one.
            (None, Some(SignatureScheme::RSA_PSS_SHA384)),
            (Some(&ec_root), None),
        ] {
            assert_eq!(
                signature_scheme(&pss_intermediate, issuer, UnknownSigner::Unknown),
                scheme
            );
        }
    }
}

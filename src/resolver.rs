use crate::acme::ACME_TLS_ALPN_NAME;
use crate::chain::{CertChain, RequiredSchemes};
use rustls::SignatureScheme;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use tracing::{debug, warn};

/// Cert resolver for the issued certificate and the `tls-alpn-01` validation certificates.
///
/// It serves only the default chain of [`CertChainPreference::DualChain`]: rustls hides some of
/// the client's signature schemes from resolvers, so
/// [`AcmeAcceptor::into_stream`](crate::AcmeAcceptor::into_stream) picks the alternate.
///
/// [`CertChainPreference::DualChain`]: crate::CertChainPreference::DualChain
#[derive(Debug)]
pub struct ResolvesServerCertAcme {
    inner: Mutex<Inner>,
}

/// An alternate chain for DualChain mode, with the schemes that verifying each chain takes.
#[derive(Debug)]
pub(crate) struct AlternateChain {
    /// The alternate chain with the primary's key.
    pub(crate) key: Arc<CertifiedKey>,
    /// The schemes a client needs to verify the primary chain.
    pub(crate) primary_schemes: RequiredSchemes,
    /// The schemes a client needs to verify the alternate chain.
    pub(crate) alternate_schemes: RequiredSchemes,
}

impl AlternateChain {
    /// Creates the alternate `chain` for `primary`, which signs with the primary's key.
    pub(crate) fn new(primary: &CertifiedKey, chain: CertChain) -> Self {
        let primary_chain = CertChain::new(primary.cert.clone());
        Self {
            primary_schemes: primary_chain.required_schemes(&chain),
            alternate_schemes: chain.likely_required_schemes(&primary_chain),
            key: Arc::new(CertifiedKey::new(chain.into_certs(), primary.key.clone())),
        }
    }

    /// Returns whether a client offering `offered` can verify only this alternate.
    fn serves(&self, offered: &[SignatureScheme]) -> bool {
        self.primary_schemes.supported_by(offered) == Some(false)
            && self.alternate_schemes.supported_by(offered) == Some(true)
    }
}

#[derive(Debug)]
struct Inner {
    cert: Option<Arc<CertifiedKey>>,
    /// Alternate chain for DualChain mode, for clients that can only verify this one.
    alt_cert: Option<AlternateChain>,
    auth_keys: BTreeMap<String, Arc<CertifiedKey>>,
}

impl ResolvesServerCertAcme {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                cert: None,
                alt_cert: None,
                auth_keys: Default::default(),
            }),
        })
    }
    /// Serves `cert`, without an alternate chain until [`ResolvesServerCertAcme::set_alternate`].
    pub(crate) fn set_cert(&self, cert: Arc<CertifiedKey>) {
        let mut inner = self.inner.lock().expect("poisoned");
        inner.cert = Some(cert);
        inner.alt_cert = None;
    }
    /// Serves `alternate` next to the certificate if it has the same leaf, and returns whether.
    pub(crate) fn set_alternate(&self, alternate: AlternateChain) -> bool {
        let mut inner = self.inner.lock().expect("poisoned");
        let matches = match (&inner.cert, alternate.key.end_entity_cert()) {
            (Some(cert), Ok(leaf)) => cert.end_entity_cert().ok() == Some(leaf),
            _ => false,
        };
        if matches {
            inner.alt_cert = Some(alternate);
        } else {
            warn!("alternate chain doesn't match the certificate, not serving it");
        }
        matches
    }
    /// Returns whether an alternate chain is set, which DualChain serves to some clients.
    pub fn serves_alternate_chain(&self) -> bool {
        self.inner.lock().expect("poisoned").alt_cert.is_some()
    }
    /// Returns the alternate chain for a client that offers `offered`, if it needs it.
    pub(crate) fn alternate_for(&self, offered: &[SignatureScheme]) -> Option<Arc<CertifiedKey>> {
        let inner = self.inner.lock().expect("poisoned");
        let alternate = inner.alt_cert.as_ref()?;
        alternate.serves(offered).then(|| alternate.key.clone())
    }
    pub(crate) fn set_auth_key(&self, domain: String, cert: Arc<CertifiedKey>) {
        self.inner
            .lock()
            .expect("poisoned")
            .auth_keys
            .insert(domain, cert);
    }
}

impl ResolvesServerCert for ResolvesServerCertAcme {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let is_acme_challenge = client_hello
            .alpn()
            .into_iter()
            .flatten()
            .eq([ACME_TLS_ALPN_NAME]);
        if is_acme_challenge {
            match client_hello.server_name() {
                None => {
                    debug!("client did not supply SNI");
                    None
                }
                Some(domain) => {
                    let domain = domain.to_owned();
                    let domain: String = AsRef::<str>::as_ref(&domain).into();
                    self.inner
                        .lock()
                        .expect("poisoned")
                        .auth_keys
                        .get(&domain)
                        .cloned()
                }
            }
        } else {
            self.inner.lock().expect("poisoned").cert.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixture::{self, CROSS_SIGNED_ROOT, Cert, chain};

    const P256: SignatureScheme = SignatureScheme::ECDSA_NISTP256_SHA256;
    const P384: SignatureScheme = SignatureScheme::ECDSA_NISTP384_SHA384;
    const RSA: SignatureScheme = SignatureScheme::RSA_PKCS1_SHA256;
    const RSA_PSS: SignatureScheme = SignatureScheme::RSA_PSS_SHA256;

    /// Returns a resolver that serves the primary of [`CROSS_SIGNED_ROOT`], and that primary.
    fn resolver() -> (Arc<ResolvesServerCertAcme>, Arc<CertifiedKey>) {
        let resolver = ResolvesServerCertAcme::new();
        let primary = Arc::new(fixture::certified_key(CROSS_SIGNED_ROOT.primary));
        resolver.set_cert(primary.clone());
        (resolver, primary)
    }

    #[test]
    fn set_alternate_needs_the_served_leaf() {
        let (resolver, primary) = resolver();
        let alternate = AlternateChain::new(&primary, chain(CROSS_SIGNED_ROOT.alternate));
        assert!(resolver.set_alternate(alternate));
        assert!(resolver.serves_alternate_chain());
        resolver.set_cert(primary.clone());
        assert!(
            !resolver.serves_alternate_chain(),
            "a new certificate drops it"
        );

        let other_leaf = AlternateChain::new(&primary, chain(&[Cert::Intermediate]));
        assert!(!resolver.set_alternate(other_leaf));
        assert!(!resolver.serves_alternate_chain());
        let alternate = AlternateChain::new(&primary, chain(CROSS_SIGNED_ROOT.alternate));
        assert!(
            !ResolvesServerCertAcme::new().set_alternate(alternate),
            "no certificate"
        );
    }

    #[test]
    fn alternate_goes_to_clients_that_can_verify_only_it() {
        let known = |schemes: &[SignatureScheme]| RequiredSchemes::Known(schemes.to_vec());
        let cases = [
            (known(&[P256, RSA]), known(&[P256]), &[P256][..], true),
            (known(&[P256, RSA]), known(&[P256]), &[P256, RSA], false),
            // TLS 1.3 clients may list RSA PKCS#1 only for certificates, out of rustls' sight.
            (known(&[P256, RSA]), known(&[P256]), &[P256, RSA_PSS], false),
            // The client can verify neither chain.
            (known(&[P256, RSA]), known(&[P384]), &[P256], false),
            (RequiredSchemes::Unknown, known(&[P256]), &[P256], false),
            (
                known(&[P256, RSA]),
                RequiredSchemes::Unknown,
                &[P256],
                false,
            ),
        ];
        let (_, primary) = resolver();
        for (primary_schemes, alternate_schemes, offered, served) in cases {
            let alternate = AlternateChain {
                primary_schemes,
                alternate_schemes,
                ..AlternateChain::new(&primary, chain(CROSS_SIGNED_ROOT.alternate))
            };
            assert_eq!(
                alternate.serves(offered),
                served,
                "{alternate:?} for {offered:?}"
            );
        }
    }
}

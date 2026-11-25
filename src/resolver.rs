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
/// It serves the issued certificate to application traffic, and the validation certificate of each
/// domain to `tls-alpn-01` clients. With
/// [`CertChainPreference::DualChain`](crate::CertChainPreference::DualChain), the resolver only
/// serves the primary chain. rustls filters the ClientHello's signature schemes by the cipher
/// suites before it calls a resolver, which hides schemes that clients can verify in certificates.
/// So [`AcmeAcceptor::into_stream`](crate::AcmeAcceptor::into_stream) picks the alternate from the
/// unfiltered ClientHello, as [`Incoming`](crate::Incoming) and the Axum acceptor do. A
/// `ServerConfig` that uses this resolver on its own serves the primary to every client.
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
    /// Creates the alternate `alternate` for the primary chain `primary`.
    ///
    /// The primary's schemes must be exact, while the alternate's may be guessed, see
    /// [`CertChain::likely_required_schemes`]: the alternate goes only to clients that can't
    /// verify the primary.
    pub(crate) fn new(primary: &CertChain, alternate: CertifiedKey) -> Self {
        let alternate_chain = CertChain::new(alternate.cert.clone());
        Self {
            primary_schemes: primary.required_schemes(&alternate_chain),
            alternate_schemes: alternate_chain.likely_required_schemes(primary),
            key: Arc::new(alternate),
        }
    }

    /// Returns whether a client offering `offered` should get this alternate.
    ///
    /// That is when the client can't verify the primary chain but can verify the alternate. If
    /// either is unknown, the client gets the primary.
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
    /// Replaces the certificate and the alternate chain, and returns whether the alternate is kept.
    ///
    /// The alternate must carry the same leaf certificate as `primary`: it is the same
    /// certificate, chained to a different root. An alternate with another leaf is dropped.
    /// Both are replaced under one lock, so no handshake sees a new primary with an old
    /// alternate.
    pub(crate) fn set_certs(
        &self,
        primary: Arc<CertifiedKey>,
        alternate: Option<AlternateChain>,
    ) -> bool {
        let alternate = alternate.filter(|alternate| {
            let matches = primary.end_entity_cert().ok() == alternate.key.end_entity_cert().ok();
            if !matches {
                warn!("alternate chain doesn't match the certificate, not serving it");
            }
            matches
        });
        let installed = alternate.is_some();
        let mut inner = self.inner.lock().expect("poisoned");
        inner.cert = Some(primary);
        inner.alt_cert = alternate;
        installed
    }
    /// Returns whether an alternate chain is set, which DualChain serves to some clients.
    pub fn serves_alternate_chain(&self) -> bool {
        self.inner.lock().expect("poisoned").alt_cert.is_some()
    }
    /// Returns the alternate chain for a client that offers the signature schemes `offered`.
    ///
    /// Returns `None` if the client should get the primary, see [`AlternateChain::serves`].
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
    use crate::fixture::{self, CROSS_SIGNED_ROOT, Cert};

    const P256: SignatureScheme = SignatureScheme::ECDSA_NISTP256_SHA256;
    const P384: SignatureScheme = SignatureScheme::ECDSA_NISTP384_SHA384;
    const RSA: SignatureScheme = SignatureScheme::RSA_PKCS1_SHA256;

    /// Returns the primary of [`CROSS_SIGNED_ROOT`] and the alternate `alternate` for it.
    fn certs(alternate: &[Cert]) -> (Arc<CertifiedKey>, AlternateChain) {
        let primary = fixture::certified_key(CROSS_SIGNED_ROOT.primary);
        let alternate = AlternateChain::new(
            &CertChain::new(primary.cert.clone()),
            fixture::certified_key(alternate),
        );
        (Arc::new(primary), alternate)
    }

    #[test]
    fn set_certs_keeps_only_an_alternate_for_the_same_leaf() {
        let resolver = ResolvesServerCertAcme::new();
        let (primary, alternate) = certs(CROSS_SIGNED_ROOT.alternate);
        assert!(resolver.set_certs(primary, Some(alternate)));
        assert!(resolver.serves_alternate_chain());

        let (primary, other_leaf) = certs(&[Cert::Intermediate]);
        assert!(!resolver.set_certs(primary.clone(), Some(other_leaf)));
        assert!(!resolver.serves_alternate_chain());

        let (_, alternate) = certs(CROSS_SIGNED_ROOT.alternate);
        resolver.set_certs(primary.clone(), Some(alternate));
        assert!(
            !resolver.set_certs(primary, None),
            "a new primary drops the alternate"
        );
        assert!(!resolver.serves_alternate_chain());
    }

    #[test]
    fn alternate_goes_to_clients_that_can_verify_only_it() {
        let known = |schemes: &[SignatureScheme]| RequiredSchemes::Known(schemes.to_vec());
        let cases = [
            (known(&[P256, RSA]), known(&[P256]), &[P256][..], true),
            (known(&[P256, RSA]), known(&[P256]), &[P256, RSA], false),
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
        for (primary_schemes, alternate_schemes, offered, served) in cases {
            let (_, alternate) = certs(CROSS_SIGNED_ROOT.alternate);
            let alternate = AlternateChain {
                primary_schemes,
                alternate_schemes,
                ..alternate
            };
            assert_eq!(
                alternate.serves(offered),
                served,
                "{alternate:?} for {offered:?}"
            );
        }
    }
}

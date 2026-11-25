use crate::acme::{ACME_TLS_ALPN_NAME, Identifier};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use tracing::debug;

/// Cert resolver that serves the issued certificate to application traffic
/// and per-domain validation certificates to `tls-alpn-01` clients.
#[derive(Debug)]
pub struct ResolvesServerCertAcme {
    inner: Mutex<Inner>,
}

#[derive(Debug)]
struct Inner {
    cert: Option<Arc<CertifiedKey>>,
    auth_keys: BTreeMap<String, Arc<CertifiedKey>>,
}

impl ResolvesServerCertAcme {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                cert: None,
                auth_keys: Default::default(),
            }),
        })
    }
    pub(crate) fn set_cert(&self, cert: Arc<CertifiedKey>) {
        self.inner.lock().expect("poisoned").cert = Some(cert);
    }
    /// Serves `cert` to tls-alpn-01 validation requests for `identifier`.
    ///
    /// The key is stored under the SNI the CA sends for the identifier, see
    /// [`Identifier::tls_alpn_01_server_name`].
    pub(crate) fn set_auth_key(&self, identifier: &Identifier, cert: Arc<CertifiedKey>) {
        let server_name = identifier.tls_alpn_01_server_name();
        self.inner
            .lock()
            .expect("poisoned")
            .auth_keys
            .insert(server_name, cert);
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
                Some(server_name) => self
                    .inner
                    .lock()
                    .expect("poisoned")
                    .auth_keys
                    .get(challenge_server_name(server_name))
                    .cloned(),
            }
        } else {
            self.inner.lock().expect("poisoned").cert.clone()
        }
    }
}

/// Returns the received SNI `server_name` without a trailing dot.
///
/// rustls lowercases the SNI it receives but keeps a trailing dot, which a CA may send. The
/// result matches [`Identifier::tls_alpn_01_server_name`].
fn challenge_server_name(server_name: &str) -> &str {
    server_name.strip_suffix('.').unwrap_or(server_name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::PKCS_ECDSA_P256_SHA256;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
    use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};

    #[test]
    fn challenge_server_name_strips_one_trailing_dot() {
        // The rustls client strips the dot before sending, so a handshake cannot test this.
        assert_eq!(
            challenge_server_name("1.2.0.192.in-addr.arpa."),
            "1.2.0.192.in-addr.arpa"
        );
        assert_eq!(challenge_server_name("example.org"), "example.org");
    }

    /// Accepts any server certificate, so the handshake only depends on the resolver.
    #[derive(Debug)]
    struct NoVerify;

    impl ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &CertificateDer<'_>,
            _: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    /// Returns the ring crypto provider.
    ///
    /// With both ring (dev-dependency) and aws-lc-rs enabled, rustls can't pick a process default.
    fn test_provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    /// Creates a self-signed certificate for `name`, as a key for the resolver and as DER.
    fn certified_key(name: &str) -> (Arc<CertifiedKey>, CertificateDer<'static>) {
        let key_pair = rcgen::KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec![name.to_string()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        let key = PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();
        let key = test_provider().key_provider.load_private_key(key).unwrap();
        let der = cert.der().clone();
        (Arc::new(CertifiedKey::new(vec![der.clone()], key)), der)
    }

    /// Runs a tls-alpn-01 validation handshake with `sni` and returns the served certificate.
    ///
    /// The client sends ALPN `acme-tls/1`, like an ACME server.
    async fn validation_handshake(
        resolver: Arc<ResolvesServerCertAcme>,
        sni: &str,
    ) -> Result<CertificateDer<'static>, std::io::Error> {
        let mut server_config = ServerConfig::builder_with_provider(test_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        server_config.alpn_protocols = vec![ACME_TLS_ALPN_NAME.to_vec()];
        let mut client_config = ClientConfig::builder_with_provider(test_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        client_config.alpn_protocols = vec![ACME_TLS_ALPN_NAME.to_vec()];

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let (client_io, server_io) = tokio::io::duplex(4096);
        let server_name = ServerName::try_from(sni.to_string()).unwrap();
        let (client, server) = tokio::join!(
            connector.connect(server_name, client_io),
            acceptor.accept(server_io),
        );
        server?;
        let client = client?;
        Ok(client.get_ref().1.peer_certificates().unwrap()[0].clone())
    }

    #[tokio::test]
    async fn resolves_ip_identifier_by_reverse_sni() {
        for (ip, sni) in [
            ("192.0.2.1", "1.2.0.192.in-addr.arpa".to_string()),
            (
                "2001:db8::1",
                format!("1.{}8.b.d.0.1.0.0.2.ip6.arpa", "0.".repeat(23)),
            ),
        ] {
            let resolver = ResolvesServerCertAcme::new();
            let (key, der) = certified_key(ip);
            resolver.set_auth_key(&Identifier::from(ip), key);
            let served = validation_handshake(resolver, &sni)
                .await
                .unwrap_or_else(|err| panic!("handshake for {ip} with SNI {sni} failed: {err}"));
            assert_eq!(served, der, "{ip}");
        }
    }

    #[tokio::test]
    async fn resolves_dns_identifier_by_sni() {
        let resolver = ResolvesServerCertAcme::new();
        let (key, der) = certified_key("example.org");
        resolver.set_auth_key(&Identifier::from("example.org"), key);
        let served = validation_handshake(resolver, "example.org").await.unwrap();
        assert_eq!(served, der);
    }

    #[tokio::test]
    async fn resolves_mixed_case_dns_identifier() {
        let resolver = ResolvesServerCertAcme::new();
        let (key, der) = certified_key("example.org");
        resolver.set_auth_key(&Identifier::from("Example.ORG"), key);
        let served = validation_handshake(resolver, "EXAMPLE.org").await.unwrap();
        assert_eq!(served, der);
    }

    #[tokio::test]
    async fn serves_no_challenge_certificate_for_unknown_names() {
        let resolver = ResolvesServerCertAcme::new();
        let (key, _) = certified_key("example.org");
        resolver.set_auth_key(&Identifier::from("example.org"), key);
        assert!(validation_handshake(resolver, "other.org").await.is_err());
    }
}

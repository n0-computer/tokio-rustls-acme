use crate::acme::{ACME_TLS_ALPN_NAME, Identifier};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;

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
        self.inner.lock().unwrap().cert = Some(cert);
    }
    /// Serve `cert` to tls-alpn-01 validation requests for `identifier`.
    ///
    /// The key is stored under the SNI the CA sends for the identifier, see
    /// [`tls_alpn_01_server_name`].
    pub(crate) fn set_auth_key(&self, identifier: &Identifier, cert: Arc<CertifiedKey>) {
        let server_name = tls_alpn_01_server_name(identifier);
        self.inner
            .lock()
            .unwrap()
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
                    log::debug!("client did not supply SNI");
                    None
                }
                Some(domain) => {
                    let domain = domain.to_owned();
                    let domain: String = AsRef::<str>::as_ref(&domain).into();
                    self.inner.lock().unwrap().auth_keys.get(&domain).cloned()
                }
            }
        } else {
            self.inner.lock().unwrap().cert.clone()
        }
    }
}

/// Returns the SNI an ACME server sends when validating `identifier` with tls-alpn-01.
///
/// For DNS identifiers this is the name itself (RFC 8737 §3). SNI cannot carry IP addresses, so
/// for IP identifiers it is the reverse-DNS name (RFC 8738 §6), e.g. `1.2.0.192.in-addr.arpa`
/// for `192.0.2.1`. rustls lowercases the received SNI and strips a trailing dot, so we produce
/// that form.
fn tls_alpn_01_server_name(identifier: &Identifier) -> String {
    match identifier {
        Identifier::Dns(name) => name.to_ascii_lowercase(),
        Identifier::Ip(ip) => match ip.parse::<IpAddr>() {
            Ok(ip) => reverse_dns_name(ip),
            Err(_) => ip.clone(),
        },
    }
}

/// Reverse-DNS name of `ip` under `in-addr.arpa` or `ip6.arpa` (RFC 1035 §3.5, RFC 3596 §2.5).
fn reverse_dns_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.in-addr.arpa")
        }
        IpAddr::V6(v6) => {
            let mut name = String::with_capacity(72);
            for byte in v6.octets().iter().rev() {
                write!(name, "{:x}.{:x}.", byte & 0xf, byte >> 4).unwrap();
            }
            name + "ip6.arpa"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::PKCS_ECDSA_P256_SHA256;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
    use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};

    #[test]
    fn reverse_dns_name_ipv4() {
        assert_eq!(
            reverse_dns_name("192.0.2.1".parse().unwrap()),
            "1.2.0.192.in-addr.arpa"
        );
    }

    #[test]
    fn reverse_dns_name_ipv6() {
        // Example from RFC 3596 §2.5, lowercased.
        assert_eq!(
            reverse_dns_name("4321:0:1:2:3:4:567:89ab".parse().unwrap()),
            "b.a.9.8.7.6.5.0.4.0.0.0.3.0.0.0.2.0.0.0.1.0.0.0.0.0.0.0.1.2.3.4.ip6.arpa"
        );
        assert_eq!(
            reverse_dns_name("::1".parse().unwrap()),
            format!("1.{}ip6.arpa", "0.".repeat(31))
        );
    }

    #[test]
    fn server_name_for_identifier() {
        assert_eq!(
            tls_alpn_01_server_name(&Identifier::from("Example.COM")),
            "example.com"
        );
        assert_eq!(
            tls_alpn_01_server_name(&Identifier::from("10.0.0.1")),
            "1.0.0.10.in-addr.arpa"
        );
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

    fn certified_key(name: &str) -> (Arc<CertifiedKey>, CertificateDer<'static>) {
        let key_pair = rcgen::KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = rcgen::CertificateParams::new(vec![name.to_string()])
            .unwrap()
            .self_signed(&key_pair)
            .unwrap();
        let key = PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into();
        let key = rustls::crypto::ring::sign::any_ecdsa_type(&key).unwrap();
        let der = cert.der().clone();
        (Arc::new(CertifiedKey::new(vec![der.clone()], key)), der)
    }

    /// Handshake like an ACME server doing tls-alpn-01 validation: ALPN `acme-tls/1` and the
    /// given SNI. Returns the certificate the resolver served.
    async fn validation_handshake(
        resolver: Arc<ResolvesServerCertAcme>,
        sni: &str,
    ) -> Result<CertificateDer<'static>, std::io::Error> {
        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);
        server_config.alpn_protocols = vec![ACME_TLS_ALPN_NAME.to_vec()];
        let mut client_config = ClientConfig::builder()
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
            // Pebble passes the reverse name with a trailing dot, which must not matter.
            ("192.0.2.1", "1.2.0.192.in-addr.arpa.".to_string()),
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
        let served = validation_handshake(resolver.clone(), "example.org")
            .await
            .unwrap();
        assert_eq!(served, der);
        // Unknown names are not served a challenge certificate.
        assert!(validation_handshake(resolver, "other.org").await.is_err());
    }
}

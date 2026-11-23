//! A Pebble ACME server and its DNS server, started for one test on free ports.
//!
//! The binaries come from `PEBBLE_BIN` and `CHALLTESTSRV_BIN`, or else from `target/pebble/`,
//! where `cargo make pebble-install` puts them.

use std::{
    env,
    fs::{self, File},
    io,
    net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use rustls::{ClientConfig, DEFAULT_VERSIONS, RootCertStore, pki_types::CertificateDer};
use serde_json::json;
use tempfile::TempDir;
use tokio::net::TcpStream;
use tokio_rustls_acme::{AcmeConfig, caches::NoCache};

use crate::test_crypto_provider;

const PEBBLE_BIN_ENV: &str = "PEBBLE_BIN";
const CHALLTESTSRV_BIN_ENV: &str = "CHALLTESTSRV_BIN";
const INSTALL_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/target/pebble");
const LOCALHOST: Ipv4Addr = Ipv4Addr::LOCALHOST;
/// How often to start Pebble on fresh ports when another process took one of them first.
const START_ATTEMPTS: usize = 3;
const READY_TIMEOUT: Duration = Duration::from_secs(10);
const READY_POLL_INTERVAL: Duration = Duration::from_millis(50);
/// Validity of certificates from the default profile, short enough to renew within a test.
const DEFAULT_VALIDITY: Duration = Duration::from_secs(20);
/// Validity of certificates from the `shortlived` profile.
const SHORTLIVED_VALIDITY: Duration = Duration::from_secs(10);
/// The `Retry-After` that Pebble sends while authorizations and orders are pending.
const RETRY_AFTER: Duration = Duration::from_secs(1);

/// A running Pebble whose validation authority resolves every name to `127.0.0.1`.
///
/// Stops both processes when dropped, and prints their logs if the test panicked.
pub struct Pebble {
    ports: Ports,
    client_config: Arc<ClientConfig>,
    processes: Vec<Process>,
    _dir: TempDir,
}

impl Pebble {
    /// Starts Pebble and `challtestsrv` and waits until both accept connections.
    pub async fn start() -> Self {
        let dir = tempfile::tempdir().expect("failed to create Pebble dir");
        let tls = WfeTls::generate(dir.path());
        let mut last_error = None;
        for _ in 0..START_ATTEMPTS {
            let ports = Ports::pick().expect("failed to pick free ports");
            let mut processes = ports
                .spawn(dir.path(), &tls)
                .unwrap_or_else(|err| panic!("failed to start Pebble: {err}"));
            match ports.wait_ready(&mut processes).await {
                Ok(()) => {
                    return Self {
                        ports,
                        client_config: tls.client_config,
                        processes,
                        _dir: dir,
                    };
                }
                Err(err) => {
                    print_logs(&processes);
                    last_error = Some(err);
                }
            }
        }
        panic!(
            "failed to start Pebble: {}",
            last_error.expect("no attempts")
        );
    }

    /// Returns the port that Pebble connects to for tls-alpn-01 validation.
    pub fn tls_alpn_port(&self) -> u16 {
        self.ports.tls_alpn
    }

    /// Returns the URL of the ACME directory.
    fn directory_url(&self) -> String {
        format!("https://localhost:{}/dir", self.ports.acme)
    }

    /// Returns a config for `domains` against this Pebble, without a cache.
    pub fn config(&self, domains: &[&str]) -> AcmeConfig<io::Error> {
        AcmeConfig::new_with_client_tls_config(domains, self.client_config.clone())
            .directory(self.directory_url())
            .cache(NoCache::new())
    }

    /// Fetches the roots of the ACME CA as a root store, without intermediates.
    pub async fn acme_root_store(&self) -> RootCertStore {
        let client = management_client();
        let mut root_store = RootCertStore::empty();

        // Index 1 only exists with PEBBLE_ALTERNATE_ROOTS, so a 404 there is expected.
        for index in 0..2 {
            let url = format!("https://localhost:{}/roots/{index}", self.ports.management);
            let resp =
                client.get(&url).send().await.unwrap_or_else(|e| {
                    panic!("failed to reach Pebble management API at {url}: {e}")
                });
            if resp.status().is_success() {
                let pem_text = resp.text().await.expect("failed to read Pebble root");
                for p in pem::parse_many(&pem_text).expect("failed to parse Pebble root PEM") {
                    root_store
                        .add(CertificateDer::from(p.into_contents()))
                        .expect("failed to add Pebble root to root store");
                }
            }
        }

        assert!(
            !root_store.is_empty(),
            "failed to fetch any roots from Pebble management API"
        );
        root_store
    }
}

impl Drop for Pebble {
    fn drop(&mut self) {
        if std::thread::panicking() {
            print_logs(&self.processes);
        }
    }
}

/// The ports of one Pebble and its `challtestsrv`, all on `127.0.0.1`.
#[derive(Debug, Clone, Copy)]
struct Ports {
    acme: u16,
    management: u16,
    tls_alpn: u16,
    /// The http-01 port. The tests do not use it, but Pebble needs one.
    http: u16,
    /// The DNS port of `challtestsrv`, over both UDP and TCP.
    dns: u16,
    challtestsrv_management: u16,
}

impl Ports {
    /// Picks distinct free ports.
    ///
    /// Another process can take a port before Pebble binds it, so callers retry on failure.
    fn pick() -> io::Result<Self> {
        // Hold every listener until all ports are picked, so that no port is picked twice.
        let mut held = Vec::new();
        let dns = loop {
            let port = take_free_port(&mut held)?;
            if UdpSocket::bind((LOCALHOST, port)).is_ok() {
                break port;
            }
        };
        Ok(Self {
            acme: take_free_port(&mut held)?,
            management: take_free_port(&mut held)?,
            tls_alpn: take_free_port(&mut held)?,
            http: take_free_port(&mut held)?,
            dns,
            challtestsrv_management: take_free_port(&mut held)?,
        })
    }

    /// Starts `challtestsrv` and Pebble on these ports, with logs and config in `dir`.
    fn spawn(&self, dir: &Path, tls: &WfeTls) -> io::Result<Vec<Process>> {
        let dns = SocketAddr::from((LOCALHOST, self.dns)).to_string();
        let challtestsrv_management =
            SocketAddr::from((LOCALHOST, self.challtestsrv_management)).to_string();
        let mut challtestsrv = Command::new(binary(CHALLTESTSRV_BIN_ENV, "pebble-challtestsrv"));
        challtestsrv.args(["-dnsserver", &dns]);
        challtestsrv.args(["-management", &challtestsrv_management]);
        challtestsrv.args(["-defaultIPv4", "127.0.0.1", "-defaultIPv6", ""]);
        // The tests serve the challenges themselves.
        for flag in ["-http01", "-https01", "-tlsalpn01", "-doh"] {
            challtestsrv.args([flag, ""]);
        }
        let challtestsrv = Process::spawn("challtestsrv", challtestsrv, dir)?;

        let config_path = dir.join("pebble-config.json");
        fs::write(&config_path, self.pebble_config(tls).to_string())?;
        let mut pebble = Command::new(binary(PEBBLE_BIN_ENV, "pebble"));
        pebble.arg("-config").arg(&config_path);
        pebble.args(["-dnsserver", &dns]);
        pebble.env("PEBBLE_VA_NOSLEEP", "1");
        pebble.env("PEBBLE_WFE_NONCEREJECT", "0");
        // Validate almost every order. Pebble still reuses about 1 in 100 authorizations.
        pebble.env("PEBBLE_AUTHZREUSE", "0");
        let pebble = Process::spawn("pebble", pebble, dir)?;

        Ok(vec![challtestsrv, pebble])
    }

    /// Returns the Pebble config file for these ports.
    ///
    /// Pebble picks a random profile for orders that do not name one, so every profile keeps the
    /// validity short enough to renew within a test.
    fn pebble_config(&self, tls: &WfeTls) -> serde_json::Value {
        json!({
            "pebble": {
                "listenAddress": SocketAddr::from((LOCALHOST, self.acme)),
                "managementListenAddress": SocketAddr::from((LOCALHOST, self.management)),
                "certificate": tls.cert_path,
                "privateKey": tls.key_path,
                "httpPort": self.http,
                "tlsPort": self.tls_alpn,
                "ocspResponderURL": "",
                "externalAccountBindingRequired": false,
                "retryAfter": {
                    "authz": RETRY_AFTER.as_secs(),
                    "order": RETRY_AFTER.as_secs()
                },
                "profiles": {
                    "default": {
                        "description": "Short-lived certs for testing renewal",
                        "validityPeriod": DEFAULT_VALIDITY.as_secs()
                    },
                    "shortlived": {
                        "description": "Second short-lived profile, for orders that name it",
                        "validityPeriod": SHORTLIVED_VALIDITY.as_secs()
                    }
                }
            }
        })
    }

    /// Waits until all servers accept connections and both processes still run.
    async fn wait_ready(&self, processes: &mut [Process]) -> io::Result<()> {
        let ports = [
            self.acme,
            self.management,
            self.dns,
            self.challtestsrv_management,
        ];
        let deadline = Instant::now() + READY_TIMEOUT;
        for port in ports {
            while TcpStream::connect((LOCALHOST, port)).await.is_err() {
                check_running(processes)?;
                if Instant::now() > deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        format!("nothing listens on port {port}"),
                    ));
                }
                tokio::time::sleep(READY_POLL_INTERVAL).await;
            }
        }
        // A port that another process took first also accepts connections, so check
        // that our processes did not exit because their bind failed.
        check_running(processes)
    }
}

/// Binds a free port on `127.0.0.1`, keeps the listener in `held` and returns the port.
fn take_free_port(held: &mut Vec<TcpListener>) -> io::Result<u16> {
    let listener = TcpListener::bind((LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    held.push(listener);
    Ok(port)
}

/// The TLS identity of Pebble's ACME and management API.
struct WfeTls {
    cert_path: PathBuf,
    key_path: PathBuf,
    client_config: Arc<ClientConfig>,
}

impl WfeTls {
    /// Generates a self-signed certificate for `localhost` and writes it to `dir`.
    fn generate(dir: &Path) -> Self {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("failed to generate key");
        let cert = CertificateParams::new(vec!["localhost".to_owned()])
            .expect("valid certificate params")
            .self_signed(&key)
            .expect("failed to self-sign");
        let cert_path = dir.join("wfe-cert.pem");
        let key_path = dir.join("wfe-key.pem");
        fs::write(&cert_path, cert.pem()).expect("failed to write Pebble cert");
        fs::write(&key_path, key.serialize_pem()).expect("failed to write Pebble key");

        let mut roots = RootCertStore::empty();
        roots
            .add(cert.der().clone())
            .expect("failed to add Pebble cert to root store");
        let client_config = ClientConfig::builder_with_provider(test_crypto_provider())
            .with_protocol_versions(DEFAULT_VERSIONS)
            .expect("provider should support the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        Self {
            cert_path,
            key_path,
            client_config: Arc::new(client_config),
        }
    }
}

/// A child process that is killed when dropped.
struct Process {
    name: &'static str,
    child: Child,
    log_path: PathBuf,
}

impl Process {
    /// Spawns `command` with its output in `<dir>/<name>.log`.
    fn spawn(name: &'static str, mut command: Command, dir: &Path) -> io::Result<Self> {
        let log_path = dir.join(format!("{name}.log"));
        let log = File::create(&log_path)?;
        let child = command
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()
            .map_err(|err| {
                io::Error::new(
                    err.kind(),
                    format!(
                        "failed to run {:?}, see `cargo make pebble-install`: {err}",
                        command.get_program()
                    ),
                )
            })?;
        Ok(Self {
            name,
            child,
            log_path,
        })
    }

    /// Returns an error if the process exited.
    fn check_running(&mut self) -> io::Result<()> {
        match self.child.try_wait()? {
            None => Ok(()),
            Some(status) => Err(io::Error::other(format!("{} exited: {status}", self.name))),
        }
    }

    /// Prints the output of the process to stderr.
    fn print_log(&self) {
        let log = fs::read_to_string(&self.log_path).unwrap_or_else(|e| format!("<{e}>"));
        eprintln!("--- {} log ---\n{log}", self.name);
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Returns an error if any of `processes` exited.
fn check_running(processes: &mut [Process]) -> io::Result<()> {
    processes.iter_mut().try_for_each(Process::check_running)
}

/// Prints the output of `processes` to stderr.
fn print_logs(processes: &[Process]) {
    for process in processes {
        process.print_log();
    }
}

/// Returns the path in the environment variable `var`, or else `name` in [`INSTALL_DIR`].
fn binary(var: &str, name: &str) -> PathBuf {
    env::var_os(var)
        .map(PathBuf::from)
        .unwrap_or_else(|| Path::new(INSTALL_DIR).join(name))
}

/// Returns a client for Pebble's management API, which serves the same certificate as the
/// ACME API.
///
/// Installs ring as the process-wide default `CryptoProvider` so reqwest's
/// `rustls-no-provider` build path can construct its own TLS config without
/// panicking. The pebble tests pin ring for TLS (via the `rustls`
/// dev-dependency) whatever backend the crate features select, and the
/// default only affects this test binary.
fn management_client() -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
}

//! A Pebble ACME server and its DNS server, started for one test on free ports.
//!
//! The binaries come from `PEBBLE_BIN` and `CHALLTESTSRV_BIN`, or else from `target/pebble/`,
//! where `cargo make pebble-install` puts them.

#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
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
pub(crate) struct Pebble {
    ports: Ports,
    /// The tls-alpn-01 listener, open for Pebble's lifetime so that no other process can take
    /// its port. Each [`Site`](crate::Site) serves on a clone of it.
    tls_alpn_listener: TcpListener,
    client_config: Arc<ClientConfig>,
    processes: Vec<Process>,
    _dir: TempDir,
}

impl Pebble {
    /// Starts Pebble and `challtestsrv` and waits until both accept connections.
    pub(crate) async fn start() -> Self {
        let dir = tempfile::tempdir().expect("failed to create Pebble dir");
        let tls = WfeTls::generate(dir.path());
        let tls_alpn_listener =
            TcpListener::bind((LOCALHOST, 0)).expect("failed to bind the tls-alpn-01 listener");
        let tls_alpn_port = tls_alpn_listener
            .local_addr()
            .expect("failed to read the tls-alpn-01 port")
            .port();
        let mut last_error = None;
        for _ in 0..START_ATTEMPTS {
            let ports = Ports::pick(tls_alpn_port).expect("failed to pick free ports");
            let mut processes = ports
                .spawn(dir.path(), &tls)
                .unwrap_or_else(|err| panic!("failed to start Pebble: {err}"));
            match ports.wait_ready(&mut processes).await {
                Ok(()) => {
                    return Self {
                        ports,
                        tls_alpn_listener,
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
    pub(crate) fn tls_alpn_port(&self) -> u16 {
        self.ports.tls_alpn
    }

    /// Returns a clone of the tls-alpn-01 listener for tokio.
    ///
    /// The listener stays open in [`Pebble`], so the port is never free for another process,
    /// also not between two sites that serve it in turn.
    pub(crate) fn tls_alpn_listener(&self) -> tokio::net::TcpListener {
        let listener = self
            .tls_alpn_listener
            .try_clone()
            .expect("failed to clone the tls-alpn-01 listener");
        listener
            .set_nonblocking(true)
            .expect("failed to make the tls-alpn-01 listener non-blocking");
        tokio::net::TcpListener::from_std(listener).expect("failed to register the listener")
    }

    /// Returns the URL of the ACME directory.
    fn directory_url(&self) -> String {
        format!("https://localhost:{}/dir", self.ports.acme)
    }

    /// Returns a config for `domains` against this Pebble, without a cache.
    pub(crate) fn config(&self, domains: &[&str]) -> AcmeConfig<io::Error> {
        AcmeConfig::new_with_client_tls_config(domains, self.client_config.clone())
            .directory(self.directory_url())
            .cache(NoCache::new())
    }

    /// Fetches the roots of the ACME CA as a root store, without intermediates.
    pub(crate) async fn acme_root_store(&self) -> RootCertStore {
        let mut root_store = RootCertStore::empty();
        for index in 0..2 {
            let root = self.management_cert(&format!("roots/{index}")).await;
            root_store
                .add(root)
                .expect("failed to add Pebble root to root store");
        }
        root_store
    }

    /// Returns the subject common name of root `index`, 0 for the default chain and 1 for the
    /// alternate.
    pub(crate) async fn root_cn(&self, index: usize) -> String {
        let root = self.management_cert(&format!("roots/{index}")).await;
        let (_, root) = x509_parser::parse_x509_certificate(&root).expect("failed to parse root");
        let common_name = root.subject().iter_common_name().next();
        common_name
            .and_then(|common_name| common_name.as_str().ok())
            .expect("root has no common name")
            .to_owned()
    }

    /// Returns the intermediate of chain `index`, 0 for the default chain and 1 for the
    /// alternate.
    ///
    /// Every chain has the same intermediate key, signed by a different root, so the DER
    /// identifies the chain.
    pub(crate) async fn intermediate(&self, index: usize) -> CertificateDer<'static> {
        self.management_cert(&format!("intermediates/{index}"))
            .await
    }

    /// Fetches the first certificate of the PEM at `path` of the management API.
    async fn management_cert(&self, path: &str) -> CertificateDer<'static> {
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(ClientConfig::clone(&self.client_config))
            .build()
            .expect("failed to build management API client");
        let url = format!("https://localhost:{}/{path}", self.ports.management);
        let pem_text = client
            .get(&url)
            .send()
            .await
            .and_then(|resp| resp.error_for_status())
            .unwrap_or_else(|e| panic!("failed to fetch {url}: {e}"))
            .text()
            .await
            .unwrap_or_else(|e| panic!("failed to read {url}: {e}"));
        let pems = pem::parse_many(&pem_text).expect("failed to parse Pebble PEM");
        let first = pems
            .into_iter()
            .next()
            .expect("no certificate in Pebble PEM");
        CertificateDer::from(first.into_contents())
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
    /// Picks distinct free ports, with `tls_alpn` as the tls-alpn-01 port.
    ///
    /// Another process can take a port before Pebble binds it, so callers retry on failure.
    /// The tls-alpn-01 port is held by its listener, so it can't be picked again.
    fn pick(tls_alpn: u16) -> io::Result<Self> {
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
            tls_alpn,
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
        // Offers a second chain to another root, for the chain preference tests.
        pebble.env("PEBBLE_ALTERNATE_ROOTS", "1");
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

/// The TLS identity of Pebble's ACME and management API, which share one certificate.
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
        #[cfg(target_os = "linux")]
        kill_with_parent(&mut command);
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

/// Makes the kernel kill the process that `command` starts once the calling thread exits.
///
/// This stops Pebble also when the test process is killed and cannot run [`Process`]'s drop.
/// Each test runs on its own thread, which ends only after the test dropped its [`Pebble`].
#[cfg(target_os = "linux")]
fn kill_with_parent(command: &mut Command) {
    let parent = std::process::id();
    // SAFETY: The closure runs between fork and exec. It only calls `prctl` and `getppid`, which
    // are async-signal-safe, and does not allocate.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(io::Error::last_os_error());
            }
            // No signal comes if the parent exited before `prctl`.
            if libc::getppid() as u32 != parent {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            Ok(())
        });
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

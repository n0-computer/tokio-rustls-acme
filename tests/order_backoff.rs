//! Tests that the client backs off when orders stall or yield unusable certificates.

mod support;

use std::{
    convert::Infallible,
    io,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use futures::StreamExt;
use support::{MockAcme, MockCa, OrderScript, Validity};
use tokio::task::JoinHandle;
use tokio_rustls_acme::{AccountCache, AcmeConfig, AcmeState, CertCache};

const DOMAIN: &str = "example.com";
/// Upper bound on the real time that one test waits for the client.
const LIMIT: Duration = Duration::from_secs(30);
/// Shortest accepted delay before the first retry, which the client sets to one second.
const MIN_RETRY_DELAY: Duration = Duration::from_millis(900);
/// Interval at which the tests check for new events.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// The events of a state machine, formatted with `Debug`.
type Events = Arc<Mutex<Vec<Result<String, String>>>>;

/// Polls `state` in the background and records its events.
fn drive<EC, EA>(mut state: AcmeState<EC, EA>) -> (JoinHandle<()>, Events)
where
    EC: std::fmt::Debug + Send + 'static,
    EA: std::fmt::Debug + Send + 'static,
{
    let events = Events::default();
    let driver = tokio::spawn({
        let events = events.clone();
        async move {
            while let Some(event) = state.next().await {
                let event = event
                    .map(|ok| format!("{ok:?}"))
                    .map_err(|err| format!("{err:?}"));
                events.lock().expect("poisoned").push(event);
            }
        }
    });
    (driver, events)
}

/// Returns a state machine without a cache that orders from `mock`.
fn state(mock: &MockAcme) -> AcmeState<Infallible> {
    AcmeConfig::new_with_client_tls_config([DOMAIN], mock.client_config.clone())
        .directory(&mock.directory_url)
        .state()
}

/// Panics if the state machine reported an error that `expected` does not accept.
fn assert_only_expected_errors(events: &Events, expected: impl Fn(&str) -> bool) {
    let events = events.lock().expect("poisoned");
    let unexpected: Vec<_> = events
        .iter()
        .filter_map(|event| event.as_ref().err())
        .filter(|err| !expected(err))
        .collect();
    assert!(unexpected.is_empty(), "unexpected errors: {unexpected:#?}");
}

/// Panics if the client never sent a request to `route`.
fn assert_reached(mock: &MockAcme, route: &str) {
    assert!(
        mock.state().hits(route) > 0,
        "the client never sent {route}, so the test did not exercise the backoff"
    );
}

/// Waits for the second request to `route`, and panics if it came too soon after the first.
async fn assert_retry_delay(mock: &MockAcme, route: &str) {
    mock.wait_for_hits(route, 2, LIMIT).await;
    let delay = {
        let state = mock.state();
        let arrivals = state.arrivals(route);
        arrivals[1].duration_since(arrivals[0])
    };
    assert!(
        delay >= MIN_RETRY_DELAY,
        "the client retried {route} after {delay:?}, expected at least {MIN_RETRY_DELAY:?}"
    );
}

/// Returns whether any recorded event matches `wanted`.
fn has_event(events: &Events, wanted: impl Fn(&Result<String, String>) -> bool) -> bool {
    events.lock().expect("poisoned").iter().any(wanted)
}

/// Waits for an event that matches `wanted`, and panics after [`LIMIT`].
async fn wait_for_event(events: &Events, wanted: impl Fn(&Result<String, String>) -> bool) {
    let reached = tokio::time::timeout(LIMIT, async {
        while !has_event(events, &wanted) {
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    })
    .await;
    assert!(
        reached.is_ok(),
        "the expected event did not come in {LIMIT:?}: {:#?}",
        events.lock().expect("poisoned")
    );
}

/// Returns whether `err` is the `Debug` output of an expired new certificate error.
fn is_expired_error(err: &str) -> bool {
    err == "NewCertParse(Expired)"
}

#[tokio::test]
async fn order_round_backs_off_while_order_status_does_not_advance() {
    let cases = [
        (OrderScript::AlwaysPending, "POST /order/1"),
        (OrderScript::RevertsOnFinalize, "POST /finalize/1"),
    ];
    for (script, route) in cases {
        let mock = MockAcme::start().await;
        mock.state().order_script = script;
        let (driver, events) = drive(state(&mock));

        assert_retry_delay(&mock, route).await;
        driver.abort();

        assert_only_expected_errors(&events, |_| false);
    }
}

#[tokio::test]
async fn renewal_backs_off_when_new_certificate_is_already_due() {
    let mock = MockAcme::start().await;
    mock.state().issue_validity = Validity::Due;
    let (driver, events) = drive(state(&mock));

    assert_retry_delay(&mock, "POST /order").await;
    driver.abort();

    assert_only_expected_errors(&events, |_| false);
    assert!(
        has_event(&events, |event| event.as_deref() == Ok("DeployedNewCert")),
        "the client never deployed the issued certificate"
    );
}

#[tokio::test]
async fn renewal_keeps_previous_certificate_when_new_certificate_is_expired() {
    let mock = MockAcme::start().await;
    mock.state().issue_validity = Validity::Expired;
    // The cached certificate is still valid but due for renewal, so an order starts at once.
    let cached = MockCa::new().issue_with_key(DOMAIN, Validity::Due);
    let cache = RecordingCache::new(cached);
    let stored_certs = cache.stored_certs.clone();
    let state = AcmeConfig::new_with_client_tls_config([DOMAIN], mock.client_config.clone())
        .directory(&mock.directory_url)
        .cache(cache)
        .state();
    let (driver, events) = drive(state);

    wait_for_event(&events, |event| {
        event.as_ref().is_err_and(|err| is_expired_error(err))
    })
    .await;
    assert_retry_delay(&mock, "POST /order").await;
    driver.abort();

    assert_only_expected_errors(&events, is_expired_error);
    assert_reached(&mock, "POST /cert/1");
    {
        let events = events.lock().expect("poisoned");
        assert_eq!(
            events.first().map(Result::as_deref),
            Some(Ok("DeployedCachedCert")),
            "the client did not start from the cached certificate: {events:#?}"
        );
        assert!(
            !events
                .iter()
                .any(|event| event.as_deref() == Ok("DeployedNewCert")),
            "the client deployed the expired certificate: {events:#?}"
        );
    }
    assert!(
        stored_certs.lock().expect("poisoned").is_empty(),
        "the client cached the expired certificate"
    );
}

/// A cache that starts with one certificate and records what the client stores.
struct RecordingCache {
    cert: Vec<u8>,
    stored_certs: Arc<Mutex<Vec<Vec<u8>>>>,
}

impl RecordingCache {
    fn new(cert: Vec<u8>) -> Self {
        Self {
            cert,
            stored_certs: Arc::default(),
        }
    }
}

#[async_trait]
impl CertCache for RecordingCache {
    type EC = io::Error;

    async fn load_cert(&self, _: &[String], _: &str) -> io::Result<Option<Vec<u8>>> {
        Ok(Some(self.cert.clone()))
    }

    async fn store_cert(&self, _: &[String], _: &str, cert: &[u8]) -> io::Result<()> {
        self.stored_certs
            .lock()
            .expect("poisoned")
            .push(cert.to_vec());
        Ok(())
    }
}

#[async_trait]
impl AccountCache for RecordingCache {
    type EA = io::Error;

    async fn load_account(&self, _: &[String], _: &str) -> io::Result<Option<Vec<u8>>> {
        Ok(None)
    }

    async fn store_account(&self, _: &[String], _: &str, _: &[u8]) -> io::Result<()> {
        Ok(())
    }
}

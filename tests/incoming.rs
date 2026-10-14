#![cfg(feature = "tls-webpki-roots")]

use std::{io, sync::mpsc, time::Duration};

use futures::StreamExt;
use tokio::io::DuplexStream;
use tokio_rustls_acme::{AcmeConfig, caches::TestCache};

/// `Incoming` must end once the TCP stream ends and nothing is in flight.
///
/// Runs on its own thread: a `poll_next` that never yields would block a
/// runtime-based timeout too.
#[test]
fn ends_when_tcp_stream_ends() {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let next = rt.block_on(async {
            let tcp = futures::stream::empty::<io::Result<DuplexStream>>();
            let mut incoming = AcmeConfig::new(["example.com"])
                .cache(TestCache::<io::Error, io::Error>::new())
                .state()
                .incoming(tcp, Vec::new());
            incoming.next().await.map(|_| ())
        });
        tx.send(next).unwrap();
    });
    let next = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("Incoming did not end after the TCP stream ended");
    assert!(next.is_none());
}

//! Tests for the timeouts, body limit and redirect policy of the ACME HTTP client.

#[path = "../../tests/support/mod.rs"]
mod support;

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use crate::acme::{Account, Directory};
use crate::https_helper::{CONNECT_TIMEOUT, REQUEST_TIMEOUT};
use serde_json::{Value, json};
use support::{Request, Response, Server};
use tokio::{io::AsyncWriteExt, net::TcpListener, sync::oneshot, time::Instant};

/// Paused-clock bound far above any client timeout, so hitting it means no timeout exists.
const STALL_LIMIT: Duration = Duration::from_secs(3600);

/// Real-clock limit for instant steps, below [`CONNECT_TIMEOUT`] to catch connect attempts.
const QUICK_LIMIT: Duration = Duration::from_secs(5);

/// Unroutable IPv4 address from TEST-NET-1 (RFC 5737).
const UNREACHABLE_HTTP: &str = "http://192.0.2.1/dir";

fn directory_json(base: &str) -> Value {
    json!({
        "newNonce": format!("{base}/nonce"),
        "newAccount": format!("{base}/acct"),
        "newOrder": format!("{base}/order"),
    })
}

fn counting_server(
    listener: TcpListener,
    tls: Option<tokio_rustls::TlsAcceptor>,
    handler: impl Fn(Request) -> Response + Send + Sync + 'static,
) -> (Server, Arc<AtomicUsize>) {
    let requests = Arc::new(AtomicUsize::new(0));
    let server = Server::start(listener, tls, {
        let requests = requests.clone();
        move |request| {
            requests.fetch_add(1, Ordering::SeqCst);
            handler(request)
        }
    });
    (server, requests)
}

#[tokio::test(start_paused = true)]
async fn stalled_tls_handshake_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // Holds connections open without sending a byte.
    let server = tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            if let Ok((connection, _)) = listener.accept().await {
                held.push(connection);
            }
        }
    });

    let client_config = support::local_tls().client_config;
    let request = Directory::discover(&client_config, format!("https://{addr}/dir"));
    let start = Instant::now();
    let finished = tokio::time::timeout(STALL_LIMIT, request).await;
    let elapsed = start.elapsed();
    server.abort();

    let result =
        finished.unwrap_or_else(|_| panic!("the request was still pending after {STALL_LIMIT:?}"));
    assert!(result.is_err(), "the request succeeded without a handshake");
    assert!(
        elapsed >= CONNECT_TIMEOUT && elapsed < REQUEST_TIMEOUT / 2,
        "the request failed after {elapsed:?}, not after the connect timeout of {CONNECT_TIMEOUT:?}"
    );
}

#[tokio::test]
async fn stalled_response_times_out() {
    let tls = support::local_tls();
    let (listener, addr) = Server::bind().await;
    let (received_tx, received_rx) = oneshot::channel();
    let received_tx = Arc::new(Mutex::new(Some(received_tx)));
    let _server = Server::start_raw(listener, Some(tls.acceptor), move |mut stream| {
        let received_tx = received_tx.clone();
        Box::pin(async move {
            if support::read_request(&mut stream).await.is_err() {
                return;
            }
            if let Some(tx) = received_tx.lock().expect("poisoned").take() {
                let _ = tx.send(());
            }
            std::future::pending::<()>().await;
            drop(stream);
        })
    });

    let client_config = tls.client_config;
    let mut request = tokio::spawn(async move {
        Directory::discover(&client_config, format!("https://{addr}/dir")).await
    });
    // Connect and handshake run on the real clock, before the pause below.
    tokio::select! {
        received = received_rx => received.expect("the server dropped the sender"),
        result = &mut request => {
            panic!("the request ended before the server received it: {result:?}")
        }
        _ = tokio::time::sleep(QUICK_LIMIT) => {
            panic!("the server did not receive the request within {QUICK_LIMIT:?}")
        }
    }
    // Paused, the clock jumps to the request timeout, or to the stall limit if there is none.
    tokio::time::pause();
    let finished = tokio::time::timeout(STALL_LIMIT, request).await;

    let result =
        finished.unwrap_or_else(|_| panic!("the request was still pending after {STALL_LIMIT:?}"));
    assert!(
        result.expect("the request task panicked").is_err(),
        "the request succeeded without a response"
    );
}

#[tokio::test(start_paused = true)]
async fn plain_http_to_other_host_is_attempted() {
    let client_config = support::client_config_without_roots();
    let request = Directory::discover(&client_config, UNREACHABLE_HTTP);
    let directory = tokio::time::timeout(STALL_LIMIT, request)
        .await
        .unwrap_or_else(|_| panic!("the request was still pending after {STALL_LIMIT:?}"));

    // Only a connect error proves the client tried the URL instead of refusing it.
    let err = directory.expect_err("the unreachable host answered");
    let debug = format!("{err:?}");
    assert!(
        debug.starts_with("HttpRequest(Http(reqwest::Error { kind: Request")
            && debug.contains("ConnectError"),
        "the client did not try to connect: {err:?}"
    );
}

#[tokio::test]
async fn signed_request_is_not_redirected() {
    let tls = support::local_tls();
    let (listener, target_addr) = Server::bind().await;
    let (_target, target_requests) = counting_server(listener, Some(tls.acceptor.clone()), |_| {
        Response::json(201, &json!({"status": "valid"}))
    });

    let (listener, addr) = Server::bind().await;
    let source_posts = Arc::new(AtomicUsize::new(0));
    let _source = Server::start(listener, Some(tls.acceptor), {
        let source_posts = source_posts.clone();
        move |request| match request.method.as_str() {
            "HEAD" => Response::new(200).header("replay-nonce", "bW9jay1ub25jZQ"),
            _ => {
                source_posts.fetch_add(1, Ordering::SeqCst);
                Response::new(307).header("location", format!("https://{target_addr}/acct"))
            }
        }
    });

    let directory = Directory {
        new_nonce: format!("https://{addr}/nonce"),
        new_account: format!("https://{addr}/acct"),
        new_order: format!("https://{addr}/order"),
        meta: Default::default(),
    };
    let contact: [&str; 0] = [];
    let account = Account::create_with_keypair(
        &tls.client_config,
        directory,
        &contact,
        &Account::generate_key_pair(),
        &None,
    )
    .await;

    assert!(
        account.is_err(),
        "the account creation succeeded: {account:?}"
    );
    assert_eq!(
        source_posts.load(Ordering::SeqCst),
        1,
        "the source did not send exactly one redirect"
    );
    assert_eq!(
        target_requests.load(Ordering::SeqCst),
        0,
        "the client followed the redirect of a signed request"
    );
}

#[tokio::test]
async fn plain_http_object_url_is_refused_for_https_directory() {
    let tls = support::local_tls();
    let (listener, plain_addr) = Server::bind().await;
    let (_plain, plain_requests) = counting_server(listener, None, |_| {
        Response::json(200, &json!({"status": "valid"}))
    });

    let (listener, addr) = Server::bind().await;
    let _ca = Server::start(listener, Some(tls.acceptor), move |request| {
        match request.method.as_str() {
            "HEAD" => Response::new(200).header("replay-nonce", "bW9jay1ub25jZQ"),
            _ => Response::json(201, &json!({"status": "valid"}))
                .header("location", format!("https://{addr}/acct/1")),
        }
    });

    let directory = Directory {
        new_nonce: format!("https://{addr}/nonce"),
        new_account: format!("https://{addr}/acct"),
        new_order: format!("https://{addr}/order"),
        meta: Default::default(),
    };
    let contact: [&str; 0] = [];
    let account = Account::create_with_keypair(
        &tls.client_config,
        directory,
        &contact,
        &Account::generate_key_pair(),
        &None,
    )
    .await
    .expect("the account creation failed");
    let order = account
        .order(&tls.client_config, format!("http://{plain_addr}/order/1"))
        .await;

    assert!(order.is_err(), "the client accepted a plain HTTP order URL");
    assert_eq!(
        plain_requests.load(Ordering::SeqCst),
        0,
        "the client sent a request to the plain HTTP URL"
    );
}

#[tokio::test]
async fn directory_redirect_to_https_is_followed() {
    let tls = support::local_tls();
    let (listener, target_addr) = Server::bind().await;
    let target_base = format!("https://{target_addr}");
    let (_target, target_requests) = counting_server(listener, Some(tls.acceptor.clone()), {
        let target_base = target_base.clone();
        move |_| Response::json(200, &directory_json(&target_base))
    });

    let (listener, addr) = Server::bind().await;
    let (_source, source_requests) = counting_server(listener, Some(tls.acceptor), move |_| {
        Response::new(307).header("location", format!("https://{target_addr}/dir"))
    });

    let directory = Directory::discover(&tls.client_config, format!("https://{addr}/dir"))
        .await
        .expect("the client did not follow the redirect");

    assert_eq!(directory.new_nonce, format!("{target_base}/nonce"));
    assert_eq!(source_requests.load(Ordering::SeqCst), 1);
    assert_eq!(target_requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn directory_redirect_to_plain_http_is_not_followed() {
    let tls = support::local_tls();
    let (listener, addr) = Server::bind().await;
    let (_source, source_requests) = counting_server(listener, Some(tls.acceptor), |_| {
        Response::new(307).header("location", UNREACHABLE_HTTP)
    });

    let request = Directory::discover(&tls.client_config, format!("https://{addr}/dir"));
    let directory = tokio::time::timeout(QUICK_LIMIT, request)
        .await
        .expect("the client tried to reach the plain HTTP target");

    assert_eq!(
        source_requests.load(Ordering::SeqCst),
        1,
        "the source did not send the redirect"
    );
    let err = directory.expect_err("the client followed the redirect to plain HTTP");
    assert!(
        format!("{err:?}").contains("BadScheme"),
        "the request failed for another reason: {err:?}"
    );
}

#[tokio::test]
async fn oversized_response_body_is_rejected() {
    const PADDING: usize = 16 * 1024 * 1024;

    let tls = support::local_tls();
    let (listener, addr) = Server::bind().await;
    let base = format!("https://{addr}");
    let _server = Server::start_raw(listener, Some(tls.acceptor), {
        let base = base.clone();
        move |mut stream| {
            let base = base.clone();
            Box::pin(async move {
                if support::read_request(&mut stream).await.is_err() {
                    return;
                }
                // JSON allows leading whitespace, so the padded body is a valid directory.
                let head = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\nconnection: close\r\n\r\n";
                if stream.write_all(head.as_bytes()).await.is_err() {
                    return;
                }
                let chunk = [b' '; 64 * 1024];
                for _ in 0..PADDING / chunk.len() {
                    if stream.write_all(&chunk).await.is_err() {
                        return;
                    }
                }
                let directory = directory_json(&base).to_string();
                let _ = stream.write_all(directory.as_bytes()).await;
                let _ = stream.shutdown().await;
            })
        }
    });

    let directory = Directory::discover(&tls.client_config, format!("{base}/dir")).await;

    assert!(
        directory.is_err(),
        "the client buffered a response body of more than {PADDING} bytes"
    );
}

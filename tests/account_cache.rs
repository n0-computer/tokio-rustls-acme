mod support;

use std::{
    io,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use futures::StreamExt;
use rcgen::{KeyPair, PKCS_ECDSA_P384_SHA384};
use support::{MockAcme, jwk_public_point};
use tokio_rustls_acme::{
    AccountCache, AcmeConfig, AcmeState, CertCache, EventError, EventOk, acme::Account,
};

const DOMAIN: &str = "example.com";
/// Upper bound on the real time that one test waits for a certificate.
const LIMIT: Duration = Duration::from_secs(30);

/// A cache that returns `account` from every account load and records the stored keys.
struct FixedCache {
    account: Result<Option<Vec<u8>>, ()>,
    stored_accounts: Arc<Mutex<Vec<Vec<u8>>>>,
}

#[async_trait]
impl CertCache for FixedCache {
    type EC = io::Error;

    async fn load_cert(&self, _: &[String], _: &str) -> Result<Option<Vec<u8>>, io::Error> {
        Ok(None)
    }

    async fn store_cert(&self, _: &[String], _: &str, _: &[u8]) -> Result<(), io::Error> {
        Ok(())
    }
}

#[async_trait]
impl AccountCache for FixedCache {
    type EA = io::Error;

    async fn load_account(&self, _: &[String], _: &str) -> Result<Option<Vec<u8>>, io::Error> {
        self.account
            .clone()
            .map_err(|()| io::Error::other("read error"))
    }

    async fn store_account(&self, _: &[String], _: &str, key: &[u8]) -> Result<(), io::Error> {
        self.stored_accounts
            .lock()
            .expect("poisoned")
            .push(key.to_vec());
        Ok(())
    }
}

/// Drives `state` until it deploys a new certificate, and returns whether an account load failed.
async fn deploy_new_cert(state: &mut AcmeState<io::Error, io::Error>) -> bool {
    let mut load_failed = false;
    let deployed = tokio::time::timeout(LIMIT, async {
        loop {
            match state.next().await.expect("event") {
                Ok(EventOk::DeployedNewCert) => break,
                Ok(_) => {}
                Err(EventError::AccountCacheLoad(_)) => load_failed = true,
                Err(err) => panic!("unexpected error: {err:?}"),
            }
        }
    })
    .await;
    assert!(deployed.is_ok(), "no certificate in {LIMIT:?}");
    load_failed
}

/// Only a missing key is stored. Any other load result orders with a key kept in memory.
#[tokio::test]
async fn account_key_is_stored_only_when_missing() {
    let p384 = KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).expect("generate key");
    // (case, load result, key stored)
    let cases = [
        ("missing", Ok(None), true),
        ("corrupt", Ok(Some(Vec::new())), false),
        ("P-384", Ok(Some(p384.serialize_der())), false),
        ("load error", Err(()), false),
    ];
    for (name, account, stores) in cases {
        let mock = MockAcme::start().await;
        let load_fails = account.is_err();
        let stored_accounts = Arc::default();
        let cache = FixedCache {
            account,
            stored_accounts: Arc::clone(&stored_accounts),
        };
        let mut state =
            AcmeConfig::new_with_client_tls_config([DOMAIN], mock.client_config.clone())
                .directory(&mock.directory_url)
                .cache(cache)
                .state();

        assert_eq!(deploy_new_cert(&mut state).await, load_fails, "{name}");

        let stored = stored_accounts.lock().expect("poisoned").clone();
        let jwk = mock.state().account_jwk.clone().expect("newAccount JWK");
        if stores {
            assert_eq!(stored.len(), 1, "{name}");
            let key = KeyPair::try_from(stored[0].as_slice()).expect("P-256 key");
            assert_eq!(jwk_public_point(&jwk), key.public_key_raw(), "{name}");
        } else {
            assert!(stored.is_empty(), "{name}: the cached key was overwritten");
        }
    }
}

/// A CA rejecting `newAccount` switches to a new unstored key. Other rejections keep the key.
#[tokio::test]
async fn account_rejection_switches_to_unstored_key() {
    // (case, newAccount rejected, finalize rejected)
    let cases = [("newAccount", true, false), ("finalize", false, true)];
    for (name, reject_account, reject_finalize) in cases {
        let mock = MockAcme::start().await;
        let key = Account::generate_key_pair();
        let point = KeyPair::try_from(key.as_slice())
            .expect("P-256 key")
            .public_key_raw()
            .to_vec();
        mock.state().deactivated_key = reject_account.then(|| point.clone());
        mock.state().reject_finalize = reject_finalize;
        let stored_accounts = Arc::default();
        let cache = FixedCache {
            account: Ok(Some(key)),
            stored_accounts: Arc::clone(&stored_accounts),
        };
        let mut state =
            AcmeConfig::new_with_client_tls_config([DOMAIN], mock.client_config.clone())
                .directory(&mock.directory_url)
                .cache(cache)
                .state();

        let first = state.next().await.expect("event");
        assert!(
            matches!(first, Err(EventError::Order(_))),
            "{name}: {first:?}"
        );
        deploy_new_cert(&mut state).await;

        assert!(
            stored_accounts.lock().expect("poisoned").is_empty(),
            "{name}"
        );
        let jwk = mock.state().account_jwk.clone().expect("newAccount JWK");
        assert_eq!(jwk_public_point(&jwk) != point, reject_account, "{name}");
    }
}

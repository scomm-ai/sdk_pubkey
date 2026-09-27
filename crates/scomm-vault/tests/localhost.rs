//! Vault client against a host on localhost.
//!
//! Set `SCOMM_LOCALHOST=1` while the vault host is listening (default
//! `http://127.0.0.1:3001`).

use serde_json::json;
use scomm_vault_client::{VaultHostApi, VaultHostClient};

fn enabled() -> bool {
    std::env::var("SCOMM_LOCALHOST").ok().as_deref() == Some("1")
}

fn vault_url() -> String {
    std::env::var("VAULT_URL").unwrap_or_else(|_| "http://127.0.0.1:3001".into())
}

#[tokio::test]
async fn oprf_key_pepper_keys_and_stable_identity() {
    if !enabled() {
        return;
    }
    let host = VaultHostClient::new(vault_url()).expect("client");
    let key = host.identity_oprf_key().await.expect("oprf key");
    assert_eq!(key.len(), 32, "identity OPRF public key");

    let peppers = host.pepper_keys().await.expect("pepper keys");
    assert!(
        !peppers.keys.is_empty(),
        "pepper key set must be published"
    );
    assert!(!peppers.current_kid.is_empty());

    let mailbox = "localhost-vault@example.test";
    let first = host.identity_id(mailbox, Some(&key)).await.expect("identity");
    let second = host.identity_id(mailbox, Some(&key)).await.expect("identity");
    assert_eq!(first, second, "identity_id must be stable for one mailbox");
    assert!(!first.is_empty());
}

#[tokio::test]
async fn open_without_grant_is_rejected() {
    if !enabled() {
        return;
    }
    let host = VaultHostClient::new(vault_url()).expect("client");
    let err = host
        .open_vault(
            &"ab".repeat(32),
            "AAAAAAAAAAAAAAAAAAAAAA",
            "",
            json!({ "algorithm": "ed25519", "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" }),
            json!({}),
        )
        .await
        .expect_err("open without a grant must fail");
    let status = err.status.expect("http status");
    assert!(
        status == 400 || status == 401,
        "expected 400 or 401, got {status}: {err}"
    );
}

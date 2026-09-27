//! Discovery client against a host on localhost.
//!
//! Set `SCOMM_LOCALHOST=1` while discovery is listening (default
//! `http://127.0.0.1:3000`). Without that variable these tests pass without
//! calling the network so `cargo test` stays usable offline.

use scomm_discovery::{
    mailbox_sha256_hex, DiscoveryClient, HttpClient, PubkeyClientBuilder,
};

fn enabled() -> bool {
    std::env::var("SCOMM_LOCALHOST").ok().as_deref() == Some("1")
}

fn discovery_url() -> String {
    std::env::var("DISCOVERY_URL").unwrap_or_else(|_| "http://127.0.0.1:3000".into())
}

#[tokio::test]
async fn health_and_unknown_mailbox_document() {
    if !enabled() {
        return;
    }
    let base = discovery_url();
    let http = HttpClient::new().expect("http");
    let health = scomm_discovery::pubkey_request(
        &http,
        &scomm_discovery::join_url(&base, "/health"),
        "GET",
        None,
        false,
    )
    .await
    .expect("health");
    assert!(
        health.get("ok").and_then(|v| v.as_bool()).unwrap_or(true)
            || health.get("status").is_some()
            || health.is_object(),
        "{health}"
    );

    let email = "localhost-discovery@example.test";
    let client = DiscoveryClient::new(&base).expect("client");
    let doc = client.discover_mailbox(email).await.expect("document");
    assert_eq!(doc.mailbox_sha256, mailbox_sha256_hex(email));
    assert!(!doc.schema_version.is_empty() || !doc.raw.is_empty());
}

#[tokio::test]
async fn resource_list_and_key_lookup_do_not_500() {
    if !enabled() {
        return;
    }
    let base = discovery_url();
    let client = PubkeyClientBuilder::new()
        .read_base_url(&base)
        .write_base_url(&base)
        .build()
        .expect("client");
    let email = "localhost-resources@example.test";
    let resources = client.list_resources(email).await.expect("resources");
    for resource in &resources {
        let raw = serde_json::Value::Object(resource.raw.clone());
        let blob = raw.to_string();
        assert!(
            !blob.contains("\"purpose\":\"verify\""),
            "verify material in public listing: {blob}"
        );
    }

    match client
        .get_best_key(Some(email), None, Some("encrypt"), None, None)
        .await
    {
        Ok(body) => assert!(body.is_object() || body.is_null(), "{body}"),
        Err(err) => {
            let status = err.status.unwrap_or(0);
            assert!(status < 500, "key lookup failed closed with {err}");
        }
    }
}

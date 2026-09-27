//! Pure unit tests ported from Dart discovery/grant/identity tests.

use serde_json::json;
use scomm_discovery::*;

fn fixtures_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/fixtures")
}

#[test]
fn discovery_document_preserves_unknown_extensions() {
    let doc = DiscoveryDocument::from_json(&json!({
        "schemaVersion": "1.0",
        "mailboxSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "capabilities": {
            "crypto": {
                "encryption": { "keys": [{ "family": "openpgp", "keyId": "1" }] },
                "verification": { "keys": [{ "family": "openpgp", "keyId": "3" }] }
            }
        },
        "extensions": {
            "https://example.org/discovery/appointment/v1": { "bookingRequired": true }
        },
        "futureRoot": true
    }));
    assert_eq!(doc.encryption_keys().len(), 1);
    assert_eq!(doc.verification_keys().len(), 1);
    assert_eq!(doc.raw.get("futureRoot"), Some(&json!(true)));
    assert!(doc
        .extensions
        .get("https://example.org/discovery/appointment/v1")
        .unwrap()
        .is_object());
}

#[test]
fn mailbox_path_hashes_and_accepts_digest() {
    let client = PubkeyClientBuilder::new()
        .read_base_url("https://pubkey.test")
        .write_base_url("https://api.pubkey.test")
        .build()
        .unwrap();
    let hashed = client
        .encode_mailbox_sha256_path("Alice+tag@Example.COM")
        .unwrap();
    assert_eq!(hashed.len(), 64);
    let digest = "ab".repeat(32);
    assert_eq!(
        client.encode_mailbox_sha256_path(&digest).unwrap(),
        digest
    );
}

#[test]
fn pubkey_exception_parses_nested_error_envelope() {
    let ex = PubkeyError::from_response(
        400,
        &json!({
            "error": {
                "code": "challenge_expired",
                "message": "The challenge has expired.",
                "details": {}
            }
        }),
    );
    assert_eq!(ex.code, "challenge_expired");
    assert!(ex.message.contains("expired"));
}

#[test]
fn signing_vectors_match_canonicalization() {
    let path = fixtures_dir().join("discovery/signing-vectors.json");
    let fixture: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let vector = &fixture["vectors"][0];
    let envelope = &vector["envelope"];
    assert_eq!(
        payload_sha256_hex(&envelope["payload"]).unwrap(),
        vector["payload_sha256"].as_str().unwrap()
    );
    let canonical = canonical_signed_utf8(
        envelope["protocol_version"].as_i64().unwrap(),
        envelope["operation"].as_str().unwrap(),
        envelope["principal"].as_str().unwrap(),
        envelope["timestamp"].as_i64().unwrap(),
        envelope["nonce"].as_str().unwrap(),
        &envelope["payload"],
    )
    .unwrap();
    assert_eq!(canonical, vector["canonical_utf8"].as_str().unwrap());
}

#[test]
fn mailbox_discovery_fixture_parses() {
    let path = fixtures_dir().join("discovery/mailbox-discovery.json");
    let json: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let doc = DiscoveryDocument::from_json(&json);
    assert_eq!(doc.schema_version, "1.0");
    assert!(!doc.mailbox_sha256.is_empty());
    assert!(!doc.encryption_keys().is_empty());
    assert!(doc.verification_keys().is_empty());
}

#[test]
fn encryption_selection_classical_only() {
    let doc = dual_publish_doc();
    let selected = doc
        .select_best_encryption_key(
            &json!({ "families": { "pgp": ["openpgp-cv25519"] } }),
            None,
        )
        .unwrap();
    assert_eq!(
        selected.get("algorithm").and_then(|v| v.as_str()),
        Some("openpgp-cv25519")
    );
    assert_eq!(
        selected.get("public_material").and_then(|v| v.as_str()),
        Some("classical-material")
    );
    assert_eq!(
        selected.get("published_key_id").and_then(|v| v.as_str()),
        Some("AAAA-0001")
    );
}

#[test]
fn encryption_selection_prefers_pqc() {
    let doc = dual_publish_doc();
    let selected = doc
        .select_best_encryption_key(
            &json!({
                "families": {
                    "pgp": ["openpgp-cv25519", "openpgp-mlkem768-x25519"]
                }
            }),
            None,
        )
        .unwrap();
    assert_eq!(
        selected.get("algorithm").and_then(|v| v.as_str()),
        Some("openpgp-mlkem768-x25519")
    );
}

#[test]
fn encryption_selection_unsupported_yields_none() {
    let doc = dual_publish_doc();
    let selected = doc.select_best_encryption_key(
        &json!({ "families": { "smime": ["smime-rsa-oaep-sha256"] } }),
        None,
    );
    assert!(selected.is_none());
}

#[test]
fn maps_openpgp_family_to_wire_pgp() {
    let artifacts = dual_publish_doc().encryption_artifacts_for_selection();
    assert_eq!(artifacts.len(), 2);
    assert!(artifacts.iter().all(|a| {
        a.get("family").and_then(|v| v.as_str()) == Some(families::PGP)
            && a.get("purpose").and_then(|v| v.as_str()) == Some(purposes::ENCRYPTION)
    }));
}

fn dual_publish_doc() -> DiscoveryDocument {
    DiscoveryDocument::from_json(&json!({
        "schemaVersion": "1.0",
        "mailboxSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "capabilities": {
            "crypto": {
                "encryption": {
                    "keys": [
                        {
                            "family": "openpgp",
                            "keyId": "AAAA-0001",
                            "publicKey": "classical-material",
                            "algorithms": ["openpgp-cv25519"]
                        },
                        {
                            "family": "openpgp",
                            "keyId": "BBBB-0002",
                            "publicKey": "pqc-material",
                            "algorithms": ["openpgp-mlkem768-x25519"]
                        }
                    ]
                }
            }
        }
    }))
}

#[test]
fn mailbox_otp_normalize() {
    assert_eq!(mailbox_otp::LENGTH, 11);
    assert_eq!(mailbox_otp::BITS, 64);
    assert_eq!(mailbox_otp::PUBLIC_PRODUCT_NAME, "Scomm.AI");
    assert_eq!(mailbox_otp::FROM_DISPLAY_NAME, "SComm.AI NoReply OTP");
    assert_eq!(mailbox_otp::normalize("AbC1-2DeF-345"), "AbC12DeF345");
    assert_eq!(mailbox_otp::normalize("123456"), "");
}

#[test]
fn grant_v1_parses_shared_vectors() {
    let path = fixtures_dir().join("grant-vectors.json");
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let now_ms = doc["now_ms"].as_i64().unwrap();
    for vector in doc["valid"].as_array().unwrap() {
        let claims = &vector["claims"];
        let parsed = parse_grant_v1(vector["token"].as_str().unwrap()).unwrap();
        assert_eq!(parsed.iss, claims["iss"].as_str().unwrap());
        assert_eq!(parsed.aud.join(" "), claims["aud"].as_str().unwrap());
        assert_eq!(parsed.kid, claims["kid"].as_str().unwrap());
        assert_eq!(parsed.purpose, claims["purpose"].as_str().unwrap());
        assert_eq!(parsed.identity_id, claims["identity_id"].as_str().unwrap());
        assert_eq!(
            parsed.msk_fingerprint,
            claims["msk_fingerprint"].as_str().unwrap()
        );
        assert_eq!(parsed.amr, claims["amr"].as_str().unwrap());
        assert_eq!(parsed.idp, claims["idp"].as_str().unwrap());
        assert_eq!(
            parsed.exp_ms,
            claims["exp"].as_str().unwrap().parse::<i64>().unwrap()
        );
        assert_eq!(parsed.jti, claims["jti"].as_str().unwrap());
        assert!(!parsed.is_expired(Some(now_ms)));
    }
}

#[test]
fn grant_v1_rejects_reordered() {
    let path = fixtures_dir().join("grant-vectors.json");
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    let format = doc["invalid"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["reason"].as_str() == Some("format"))
        .unwrap();
    assert!(parse_grant_v1(format["token"].as_str().unwrap()).is_none());
}

#[test]
fn grant_v1_opaque_directory_grant() {
    assert!(parse_grant_v1("AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-abcde").is_none());
}

#[test]
fn identity_wire_asserts() {
    assert!(assert_no_mailbox_address("https://x/v1/keys", None).is_ok());
    assert!(assert_no_mailbox_address("https://x/alice@example.com", None).is_err());
    assert!(assert_no_mailbox_address(
        "https://x/v1",
        Some(&json!({ "email": "a@b.com" }))
    )
    .is_err());
    require_mailbox_sha256(&"ab".repeat(32)).unwrap();
    assert!(require_identity_id("short").is_err());
}

#[test]
fn locator_compatible_with_existing_api() {
    let hex = mailbox_sha256_hex("alice@example.com");
    assert_eq!(hex.len(), 64);
    assert_eq!(mailbox_path(&hex), format!("/v1/mailboxes/{hex}"));
    assert!(keys_path(&hex, "verify", Some("A1B2-C3D4")).contains("key_id=A1B2-C3D4"));
}

#[test]
fn join_url_trims_slashes() {
    assert_eq!(
        join_url("https://example.com/", "/v1/keys"),
        "https://example.com/v1/keys"
    );
}

#[tokio::test]
async fn get_best_key_builds_query() {
    // Path/query construction only — no live server.
    let client = PubkeyClientBuilder::new()
        .read_base_url("https://pubkey.test")
        .write_base_url("https://api.pubkey.test")
        .build()
        .unwrap();
    let sha = "ab".repeat(32);
    // Will fail to connect; we only check encode path helpers here.
    let path = client.encode_mailbox_sha256_path(&sha).unwrap();
    assert_eq!(path, sha);
    let _ = client; // keep async test harness linked
}

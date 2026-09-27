mod common;

use std::sync::Arc;
use std::time::Duration;

use scomm_vault::base64url_encode;
use common::FakeVaultHost;
use scomm_vault_client::{
    approve_pairing, cpace_finish, cpace_respond, cpace_start, fetch_pairing_request,
    start_pairing, KeyVault, MemoryLocalVaultStore, PairingProtocol, PairingUri, StaticAuthorizer,
    VaultAuthorization, VaultClientError, VaultDevice, VaultHostBinding, PAIRING_TYPED_PASSWORD_LENGTH,
};

const IDENTITY_ID: &str =
    "abababababababababababababababababababababababababababababababab";

fn bind(host: Arc<FakeVaultHost>) -> VaultHostBinding {
    VaultHostBinding::new(
        host,
        IDENTITY_ID,
        Arc::new(StaticAuthorizer {
            authorization: VaultAuthorization::device("test"),
        }),
    )
}

#[test]
fn cpace_and_tek_match_pubkey_sdk_v2_pairing_bytes() {
    let session = "00112233445566778899aabbccddeeff";
    let password: Vec<u8> = (1..=16).collect();
    let sid = PairingProtocol::sid(session, IDENTITY_ID);
    let ci = PairingProtocol::ci(IDENTITY_ID);
    let a = cpace_start(
        &password,
        &sid,
        &ci,
        &(0u8..64).collect::<Vec<_>>(),
    )
    .unwrap();
    let r = cpace_respond(
        &password,
        &sid,
        &ci,
        &a.ya,
        &(0u8..64).map(|i| 255 - i).collect::<Vec<_>>(),
    )
    .unwrap();
    assert_eq!(
        base64url_encode(&sid),
        "SbfR8pRSVdhHYQ98z3fNphvbEu0OlJXPtLzsa6euWlc"
    );
    assert_eq!(
        base64url_encode(&a.ya),
        "-uy2n2V4XupURljlMHqqVgfc2kXork1iM0gICnX2KR4"
    );
    assert_eq!(
        base64url_encode(&r.yb),
        "BB8od_SmIPWRzh_xvQ4NM3ryYp16XR2R_NpzKAwj8So"
    );
    assert_eq!(
        base64url_encode(&r.isk),
        "o0CknlXcaZskEW6UmK0u-yhZcGWpnbSaaNADTAWtWOlw0cZuXkUvjO-3lFJvm1S9Rgd2YI-hCBzOv60RREzXzg"
    );
    assert_eq!(cpace_finish(&a, &r.yb).unwrap(), r.isk);
    assert_eq!(
        base64url_encode(&PairingProtocol::tek(
            &r.isk, session, &a.ya, &r.yb, IDENTITY_ID
        )),
        "G1cUDjJ4GdmndkSeW205zVLUKfuJ0hA65q5SH6KJZJ8"
    );
}

#[test]
fn pairing_uri_and_typed_passwords_round_trip() {
    let pw = PairingProtocol::generate_high_entropy_password();
    let uri = PairingUri {
        session_id: "abc".into(),
        password: pw.clone(),
    }
    .to_uri_string();
    let parsed = PairingUri::try_parse(&uri).unwrap();
    assert_eq!(parsed.session_id, "abc");
    assert_eq!(parsed.password, pw);
    assert!(PairingUri::try_parse("scomm-pair:v1?sid=a&pw=b").is_none());

    let typed = PairingProtocol::generate_typed_password();
    assert_eq!(typed.len(), PAIRING_TYPED_PASSWORD_LENGTH);
    assert_eq!(
        PairingProtocol::typed_password_bytes(&typed.to_lowercase()).unwrap(),
        PairingProtocol::typed_password_bytes(&typed).unwrap()
    );
    assert!(matches!(
        PairingProtocol::typed_password_bytes("short"),
        Err(VaultClientError { code, .. }) if code == "pairing_password_mismatch"
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn new_device_receives_vek_and_joins() {
    let host = Arc::new(FakeVaultHost::new());
    let store = Arc::new(MemoryLocalVaultStore::new());
    let mut laptop = KeyVault::with_binding(store, bind(host.clone()));
    laptop
        .create(
            "alice@example.com",
            VaultDevice::new("dev-laptop", "Laptop"),
            None,
            None,
        )
        .await
        .unwrap();

    let offer = start_pairing(
        host.clone(),
        IDENTITY_ID,
        "Phone",
        "dev-phone",
        false,
        Duration::from_millis(5),
        300,
    )
    .await
    .unwrap();
    let parsed = PairingUri::try_parse(&offer.uri()).unwrap();
    let request = fetch_pairing_request(host.as_ref(), &parsed.session_id)
        .await
        .unwrap();
    assert_eq!(request.device_name, "Phone");

    let completed = tokio::spawn(offer.completed);
    approve_pairing(
        &mut laptop,
        &request,
        &parsed.password,
        Duration::from_millis(5),
        Duration::from_secs(30),
    )
    .await
    .unwrap();
    let opened = completed.await.unwrap().unwrap();

    let phone_store = Arc::new(MemoryLocalVaultStore::new());
    let mut phone = KeyVault::with_binding(phone_store, bind(host.clone()));
    phone
        .adopt(
            opened,
            VaultDevice::new("dev-phone", "Phone"),
            true,
            None,
        )
        .await
        .unwrap();
    phone.push().await.unwrap();
    laptop.pull().await.unwrap();
    let names: Vec<_> = laptop
        .devices()
        .unwrap()
        .into_iter()
        .map(|d| d.name)
        .collect();
    assert!(names.contains(&"Laptop".to_string()));
    assert!(names.contains(&"Phone".to_string()));
    assert_eq!(
        phone.msk_public_key().unwrap(),
        laptop.msk_public_key().unwrap()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn wrong_password_fails_confirmation() {
    let host = Arc::new(FakeVaultHost::new());
    let store = Arc::new(MemoryLocalVaultStore::new());
    let mut laptop = KeyVault::with_binding(store, bind(host.clone()));
    laptop
        .create(
            "alice@example.com",
            VaultDevice::new("dev-laptop", "Laptop"),
            None,
            None,
        )
        .await
        .unwrap();

    let offer = start_pairing(
        host.clone(),
        IDENTITY_ID,
        "Phone",
        "dev-phone",
        true,
        Duration::from_millis(5),
        300,
    )
    .await
    .unwrap();
    let request = fetch_pairing_request(host.as_ref(), &offer.session_id)
        .await
        .unwrap();
    let wrong = PairingProtocol::typed_password_bytes(&PairingProtocol::generate_typed_password())
        .unwrap();
    let completed = tokio::spawn(offer.completed);
    approve_pairing(
        &mut laptop,
        &request,
        &wrong,
        Duration::from_millis(5),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let err = completed.await.unwrap().unwrap_err();
    assert_eq!(err.code, "pairing_password_mismatch");
}

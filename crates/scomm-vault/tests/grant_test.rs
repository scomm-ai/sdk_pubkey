use base64::Engine;
use scomm_vault::{parse_grant_v1, GrantV1Claims};

fn b64url(s: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s.as_bytes())
}

#[test]
fn parse_grant_v1_round_trip() {
    let body = "\
Scomm/grant/v1\n\
iss=https://vault.scomm.ai\n\
aud=vault_backup recovery_generation\n\
kid=msk1\n\
purpose=vault_backup\n\
identity_id=abababababababababababababababababababababababababababababababab\n\
msk_fingerprint=deadbeef\n\
amr=otp\n\
idp=microsoft\n\
exp=1893456000000\n\
jti=jti-1\n";
    let token = format!("{}.sig", b64url(body));
    let claims = parse_grant_v1(&token).unwrap();
    assert_eq!(
        claims,
        GrantV1Claims {
            iss: "https://vault.scomm.ai".into(),
            aud: vec!["vault_backup".into(), "recovery_generation".into()],
            purpose: "vault_backup".into(),
            identity_id: "abababababababababababababababababababababababababababababababab"
                .into(),
            msk_fingerprint: "deadbeef".into(),
            exp: 1893456000000,
            jti: "jti-1".into(),
        }
    );
    assert!(!claims.is_expired(Some(1_000)));
    assert!(claims.is_expired(Some(1893456000000)));
}

#[test]
fn parse_grant_v1_rejects_malformed() {
    assert!(parse_grant_v1("not-a-grant").is_none());
    assert!(parse_grant_v1(&format!("{}.x", b64url("hello\n"))).is_none());
}

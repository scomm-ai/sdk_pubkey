use std::fs;

use base64::Engine;
use scomm_vault_client::{
    identity_blind, identity_finalize, identity_id_from_output, oprf_public_key, pepper_info,
    poprf_blind, poprf_blind_evaluate, poprf_finalize, VaultClientError,
};

fn fixture(name: &str) -> serde_json::Value {
    let path = format!("tests/fixtures/{name}");
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

fn b64(s: &str) -> Vec<u8> {
    let mut t = s.to_string();
    while t.len() % 4 != 0 {
        t.push('=');
    }
    base64::engine::general_purpose::URL_SAFE
        .decode(t)
        .unwrap()
}

fn flip(b: &[u8], i: usize) -> Vec<u8> {
    let mut out = b.to_vec();
    out[i] ^= 0x01;
    out
}

#[test]
fn pepper_poprf_vectors() {
    let v = fixture("pepper-poprf.json");
    let key = &v["key"];
    let public_key = b64(key["public_key"].as_str().unwrap());
    assert_eq!(
        oprf_public_key(&b64(key["secret_key"].as_str().unwrap())).unwrap(),
        public_key
    );

    for c in v["cases"].as_array().unwrap() {
        let info = pepper_info(v["vault_id"].as_str().unwrap(), c["slot_id"].as_str().unwrap());
        let input = c["secret"].as_str().unwrap().as_bytes();
        assert_eq!(info, b64(c["info"].as_str().unwrap()));

        let state = poprf_blind(input, &info, &public_key, Some(&b64(c["blind"].as_str().unwrap())))
            .unwrap();
        assert_eq!(state.blinded, b64(c["blinded"].as_str().unwrap()));
        assert_eq!(state.tweaked_key, b64(c["tweaked_key"].as_str().unwrap()));
        let rwd = poprf_finalize(
            &state,
            &b64(c["evaluated"].as_str().unwrap()),
            &b64(c["proof"].as_str().unwrap()),
        )
        .unwrap();
        assert_eq!(rwd, b64(c["rwd"].as_str().unwrap()));

        let (evaluated, proof) = poprf_blind_evaluate(
            &b64(key["secret_key"].as_str().unwrap()),
            &info,
            &b64(c["blinded"].as_str().unwrap()),
            None,
        )
        .unwrap();
        assert_eq!(evaluated, b64(c["evaluated"].as_str().unwrap()));
        assert_eq!(
            poprf_finalize(&state, &evaluated, &proof).unwrap(),
            b64(c["rwd"].as_str().unwrap())
        );

        let evaluated = b64(c["evaluated"].as_str().unwrap());
        let proof = b64(c["proof"].as_str().unwrap());
        let err = poprf_finalize(&state, &evaluated, &flip(&proof, 3)).unwrap_err();
        assert_eq!(err.code, "invalid_evaluation");

        let mut other_sk = vec![0u8; 32];
        other_sk[0] = 9;
        let other_key = oprf_public_key(&other_sk).unwrap();
        let wrong = poprf_blind(
            input,
            &info,
            &other_key,
            Some(&b64(c["blind"].as_str().unwrap())),
        )
        .unwrap();
        assert!(matches!(
            poprf_finalize(&wrong, &evaluated, &proof),
            Err(VaultClientError { .. })
        ));
    }
}

#[test]
fn identity_voprf_vectors() {
    let v = fixture("identity-voprf.json");
    let public_key = b64(v["public_key"].as_str().unwrap());
    let state = identity_blind(
        v["input"].as_str().unwrap().as_bytes(),
        Some(&b64(v["blind"].as_str().unwrap())),
    )
    .unwrap();
    assert_eq!(state.blinded, b64(v["blinded"].as_str().unwrap()));
    let out = identity_finalize(
        &state,
        &b64(v["evaluated"].as_str().unwrap()),
        &b64(v["proof"].as_str().unwrap()),
        &public_key,
    )
    .unwrap();
    assert_eq!(out, b64(v["output"].as_str().unwrap()));
    assert_eq!(identity_id_from_output(&out), v["identity_id"].as_str().unwrap());

    let mut other_sk = vec![0u8; 32];
    other_sk[0] = 9;
    let other_key = oprf_public_key(&other_sk).unwrap();
    assert!(identity_finalize(
        &state,
        &b64(v["evaluated"].as_str().unwrap()),
        &b64(v["proof"].as_str().unwrap()),
        &other_key,
    )
    .is_err());
}

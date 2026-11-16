//! The checks over a genuine Confidential Space token (see
//! [`fixture::REAL_PKI_TOKEN`]), so what the enclave and the guest accept is
//! known to include what Google really issues, in the shapes it really uses.
//!
//! The token is a BotStadia testnet enclave's boot token, requested for our
//! own audience with our nonce rule, so it passes the full [`verify`] and
//! gives back exactly the journal its published boot proof committed.
//!
//! There is no genuine OIDC token here: production asks only for PKI tokens,
//! and we hold no OIDC token issued for our own relying party. The OIDC path
//! (a JWKS key by `kid`) stays covered by the synthetic tokens signed under
//! the fixture's test key, beside Google's published keys.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde_json::Value;

use super::super::*;
use crate::fixture::{self, REAL_PKI_EXP, REAL_PKI_IAT, real_binding, real_input};

fn token() -> &'static str {
    fixture::REAL_PKI_TOKEN.trim()
}

/// The real token's claims, decoded without checking anything.
fn real_claims() -> Value {
    let payload = token().split('.').nth(1).unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
}

fn header_of(token: &str) -> Value {
    let header = token.split('.').next().unwrap();
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).unwrap()).unwrap()
}

#[test]
fn the_real_token_passes_verify_and_gives_back_the_published_journal() {
    let published = hex::decode(fixture::REAL_JOURNAL).unwrap();
    for now in [REAL_PKI_IAT, REAL_PKI_IAT + 60, REAL_PKI_EXP - 1] {
        let journal = verify(&real_input(now)).unwrap();
        assert_eq!(journal.encode().as_slice(), published.as_slice());
        assert_eq!(Journal::decode(&published), Some(journal));
        assert_eq!(
            hex::encode(journal.image_digest),
            fixture::REAL_IMAGE_DIGEST.trim_start_matches("sha256:")
        );
        assert_eq!(journal.project_id, project_id(fixture::REAL_PROJECT));
        assert_eq!(journal.issued_at, REAL_PKI_IAT);
        assert_eq!(journal.root_hash, confidential_space_root_hash());
        assert_eq!(journal.chain_id, fixture::REAL_CHAIN_ID);
        assert_eq!(journal.instruction, fixture::REAL_INSTRUCTION);
    }
}

#[test]
fn the_real_token_passes_every_signature_chain_and_claim_check_inside_its_hour() {
    for now in [REAL_PKI_IAT, REAL_PKI_IAT + 60, REAL_PKI_EXP - 1] {
        let token = verify_token(token(), &[], now).unwrap();
        assert_eq!(
            hex::encode(token.image_digest),
            fixture::REAL_IMAGE_DIGEST.trim_start_matches("sha256:")
        );
        assert_eq!(token.project, fixture::REAL_PROJECT);
        assert_eq!(token.issued_at, REAL_PKI_IAT);
        assert!(token.stable);
        assert_eq!(token.audiences, vec![fixture::REAL_AUDIENCE.to_string()]);
        assert_eq!(token.nonces, vec![fixture::REAL_NONCE.to_string()]);
        assert_eq!(token.root_hash, confidential_space_root_hash());
        assert!(!token.swversion.is_empty());
    }
}

#[test]
fn the_real_token_is_refused_for_any_other_binding() {
    let others = [
        Binding {
            submit_key: [0; 20],
            ..real_binding()
        },
        Binding {
            bundle_key: [0; 32],
            ..real_binding()
        },
        Binding {
            chain_id: 8_453,
            ..real_binding()
        },
        Binding {
            results: [0; 20],
            ..real_binding()
        },
        Binding {
            instruction: fixture::REAL_INSTRUCTION + 1,
            ..real_binding()
        },
    ];
    for binding in others {
        let input = Input {
            binding,
            ..real_input(REAL_PKI_IAT + 60)
        };
        assert_eq!(verify(&input), Err(Error::Nonce));
    }
}

#[test]
fn the_real_token_is_refused_at_its_expiry_and_before_its_issue() {
    for now in [REAL_PKI_EXP, REAL_PKI_EXP + 1, REAL_PKI_IAT - 1] {
        assert_eq!(verify_token(token(), &[], now), Err(Error::NotFresh));
        assert_eq!(verify(&real_input(now)), Err(Error::NotFresh));
    }
}

#[test]
fn the_real_token_s_times_and_nonce_are_the_fixture_s() {
    let claims = real_claims();
    assert_eq!(claims["iat"].as_u64(), Some(REAL_PKI_IAT));
    assert_eq!(claims["nbf"].as_u64(), Some(REAL_PKI_IAT));
    assert_eq!(claims["exp"].as_u64(), Some(REAL_PKI_EXP));
    // One nonce comes back as a plain string, not a one-element array.
    assert_eq!(claims["eat_nonce"].as_str(), Some(fixture::REAL_NONCE));
    assert_eq!(real_binding().nonce(), fixture::REAL_NONCE);
}

#[test]
fn the_real_token_overrides_only_the_launch_variables_and_carries_a_tdx_object() {
    let claims = real_claims();
    assert!(claims.pointer("/submods/container/cmd_override").is_none());
    // The launch sets the chain binding and the api's URL, and nothing else;
    // the binding it sets is the one the nonce commits to.
    let env = claims
        .pointer("/submods/container/env_override")
        .and_then(Value::as_object)
        .unwrap();
    assert!(env.keys().all(|name| LAUNCH_VARS.contains(&name.as_str())));
    assert_eq!(
        env["BOTSTADIA_CHAIN_ID"].as_str(),
        Some(fixture::REAL_CHAIN_ID.to_string().as_str())
    );
    assert_eq!(
        env["BOTSTADIA_RESULTS"].as_str().map(str::to_lowercase),
        Some(format!("0x{}", fixture::REAL_RESULTS))
    );
    // `tdx` is an object (the documentation shows an array); nothing checked
    // depends on its shape.
    assert!(claims["tdx"].is_object());
    assert_eq!(claims["hwmodel"].as_str(), Some(HARDWARE));
    assert_eq!(claims["swname"].as_str(), Some(SOFTWARE));
    assert_eq!(claims["dbgstat"].as_str(), Some(DEBUG_DISABLED));
    assert_eq!(claims["iss"].as_str(), Some(ISSUER));
}

#[test]
fn the_real_token_is_a_pki_token_chained_to_google_s_root_with_no_jwks_key() {
    let header = header_of(token());
    assert_eq!(header["alg"].as_str(), Some("RS256"));
    assert_eq!(header["x5c"].as_array().map(Vec::len), Some(3));
    let kid = header["kid"].as_str().unwrap();
    let google = Jwk::from_jwks(PINNED_GOOGLE_JWKS).unwrap();
    assert!(google.iter().all(|key| key.kid != kid));
    assert_eq!(
        hex::encode(confidential_space_root_hash()),
        fixture::CONFIDENTIAL_SPACE_ROOT_HASH
    );
    // Given Google's published keys, the chain is still what is checked.
    let token = verify_token(token(), &google, REAL_PKI_IAT + 60).unwrap();
    assert_eq!(token.root_hash, confidential_space_root_hash());
}

#[test]
fn the_real_token_s_chain_ends_in_the_root_google_publishes() {
    let chain = fixture::chain::x5c_of(token());
    assert_eq!(chain.len(), 3);
    let published = pki::pem_der(CONFIDENTIAL_SPACE_ROOT).unwrap();
    assert_eq!(chain[2], published);
}

#[test]
fn the_real_token_s_signature_covers_its_claims() {
    let parts: Vec<&str> = token().split('.').collect();
    for (pointer, value) in [
        (
            "/submods/container/image_digest",
            Value::from(format!("sha256:{}", "00".repeat(32))),
        ),
        ("/submods/gce/project_id", Value::from("another-project")),
        ("/eat_nonce", Value::from("00".repeat(32))),
    ] {
        let mut claims = real_claims();
        *claims.pointer_mut(pointer).unwrap() = value;
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let forged = format!("{}.{}.{}", parts[0], payload, parts[2]);
        assert_eq!(
            verify_token(&forged, &[], REAL_PKI_IAT + 60),
            Err(Error::BadSignature)
        );
    }
}

#[test]
fn the_real_token_with_its_root_swapped_for_another_is_refused() {
    let parts: Vec<&str> = token().split('.').collect();
    let mut header = header_of(token());
    let mut chain = fixture::chain::x5c_of(token());
    chain[2] = fixture::chain::chain(REAL_PKI_IAT).pop().unwrap();
    header["x5c"] = Value::from(
        chain
            .iter()
            .map(|der| Value::from(STANDARD.encode(der)))
            .collect::<Vec<_>>(),
    );
    let forged = format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        parts[1],
        parts[2]
    );
    assert_eq!(
        verify_token(&forged, &[], REAL_PKI_IAT + 60),
        Err(Error::Chain("issuer"))
    );
}

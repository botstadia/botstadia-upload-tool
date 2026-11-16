use serde_json::{Value, json};

use super::*;
use crate::fixture::{self, binding, claims, header, input, sign, sign_with, test_private_key};

const IAT: u64 = 1_790_000_000;
const NOW: u64 = IAT + 60;

fn passes(claims: &Value) -> Result<Journal, Error> {
    let mut input = input(&binding(), IAT, NOW);
    input.token = sign(claims);
    verify(&input)
}

fn with(mut claims: Value, pointer: &str, value: Value) -> Value {
    *claims.pointer_mut(pointer).expect("the claim exists") = value;
    claims
}

fn without(mut claims: Value, parent: &str, field: &str) -> Value {
    claims
        .pointer_mut(parent)
        .and_then(Value::as_object_mut)
        .expect("the parent exists")
        .remove(field);
    claims
}

#[test]
fn a_production_token_yields_the_journal_of_its_image_project_keys_and_time() {
    let journal = verify(&input(&binding(), IAT, NOW)).unwrap();
    assert_eq!(
        hex::encode(journal.image_digest),
        fixture::IMAGE_DIGEST.trim_start_matches("sha256:")
    );
    assert_eq!(journal.project_id, project_id(fixture::PROJECT));
    assert_eq!(journal.submit_key, binding().submit_key);
    assert_eq!(journal.bundle_key, binding().bundle_key);
    assert_eq!(journal.chain_id, binding().chain_id);
    assert_eq!(journal.results, binding().results);
    assert_eq!(journal.instruction, binding().instruction);
    assert_eq!(journal.issued_at, IAT);
    assert_eq!(journal.root_hash, fixture::test_jwk().key_hash());
}

#[test]
fn a_token_signed_by_a_key_not_given_is_refused() {
    let mut input = input(&binding(), IAT, NOW);
    input.keys.retain(|key| key.kid != fixture::TEST_KID);
    assert_eq!(verify(&input), Err(Error::UnknownKey));
}

#[test]
fn a_token_whose_signature_was_made_by_another_key_under_the_same_kid_is_refused() {
    let other = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
    let mut input = input(&binding(), IAT, NOW);
    input.token = sign_with(&other, &header(fixture::TEST_KID), &claims(&binding(), IAT));
    assert_eq!(verify(&input), Err(Error::BadSignature));
}

#[test]
fn a_claim_changed_after_signing_breaks_the_signature() {
    let mut input = input(&binding(), IAT, NOW);
    let parts: Vec<&str> = input.token.split('.').collect();
    let forged = with(
        claims(&binding(), IAT),
        "/dbgstat",
        json!(DEBUG_DISABLED.to_uppercase()),
    );
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&forged).unwrap());
    input.token = format!("{}.{}.{}", parts[0], payload, parts[2]);
    assert_eq!(verify(&input), Err(Error::BadSignature));
}

#[test]
fn only_rs256_is_accepted() {
    for alg in ["none", "HS256", "RS512", "PS256", "ES256"] {
        let mut input = input(&binding(), IAT, NOW);
        let header = json!({"alg": alg, "kid": fixture::TEST_KID});
        input.token = sign_with(&test_private_key(), &header, &claims(&binding(), IAT));
        assert_eq!(verify(&input), Err(Error::Algorithm), "{alg}");
    }
}

#[test]
fn a_key_smaller_than_2048_bits_is_refused() {
    let small = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024).unwrap();
    let public = rsa::RsaPublicKey::from(&small);
    let mut input = input(&binding(), IAT, NOW);
    input.keys = vec![Jwk {
        kid: "small".into(),
        n: rsa::traits::PublicKeyParts::n(&public).to_bytes_be(),
        e: rsa::traits::PublicKeyParts::e(&public).to_bytes_be(),
    }];
    input.token = sign_with(&small, &header("small"), &claims(&binding(), IAT));
    assert_eq!(verify(&input), Err(Error::WeakKey));
}

#[test]
fn a_debug_image_is_refused() {
    let claims = with(claims(&binding(), IAT), "/dbgstat", json!("enabled"));
    assert_eq!(passes(&claims), Err(Error::Claim("/dbgstat")));
}

#[test]
fn only_the_confidential_space_launcher_is_accepted() {
    let claims = with(claims(&binding(), IAT), "/swname", json!("GCE"));
    assert_eq!(passes(&claims), Err(Error::Claim("/swname")));
}

#[test]
fn only_intel_tdx_hardware_is_accepted() {
    for model in ["GCP_SHIELDED_VM", "GCP_AMD_SEV", "GCP_AMD_SEV_ES"] {
        let claims = with(claims(&binding(), IAT), "/hwmodel", json!(model));
        assert_eq!(passes(&claims), Err(Error::Claim("/hwmodel")), "{model}");
    }
}

#[test]
fn secure_boot_must_be_on() {
    let claims = with(claims(&binding(), IAT), "/secboot", json!(false));
    assert_eq!(passes(&claims), Err(Error::Claim("/secboot")));
}

#[test]
fn a_launcher_version_google_no_longer_marks_stable_is_refused() {
    let claims = with(
        claims(&binding(), IAT),
        "/submods/confidential_space/support_attributes",
        json!(["EXPERIMENTAL"]),
    );
    assert_eq!(
        passes(&claims),
        Err(Error::Claim(
            "/submods/confidential_space/support_attributes"
        ))
    );
}

#[test]
fn another_issuer_is_refused() {
    let claims = with(
        claims(&binding(), IAT),
        "/iss",
        json!("https://accounts.google.com"),
    );
    assert_eq!(passes(&claims), Err(Error::Claim("/iss")));
}

#[test]
fn a_token_for_another_audience_or_for_several_is_refused() {
    for aud in [
        json!("https://sts.googleapis.com"),
        json!([AUDIENCE, "https://example.com"]),
        json!([]),
    ] {
        let claims = with(claims(&binding(), IAT), "/aud", aud.clone());
        assert_eq!(passes(&claims), Err(Error::Claim("/aud")), "{aud}");
    }
    let one = with(claims(&binding(), IAT), "/aud", json!([AUDIENCE]));
    assert!(passes(&one).is_ok());
}

#[test]
fn a_token_is_accepted_only_from_its_issue_until_its_expiry() {
    let at = |now| {
        let mut input = input(&binding(), IAT, now);
        input.now = now;
        verify(&input).map(|_| ())
    };
    assert_eq!(at(IAT - 1), Err(Error::NotFresh));
    assert_eq!(at(IAT), Ok(()));
    assert_eq!(at(IAT + 3599), Ok(()));
    assert_eq!(at(IAT + 3600), Err(Error::NotFresh));
}

#[test]
fn a_token_not_yet_valid_is_refused() {
    let claims = with(claims(&binding(), IAT), "/nbf", json!(NOW + 1));
    assert_eq!(passes(&claims), Err(Error::NotFresh));
}

#[test]
fn an_operator_override_of_the_image_s_arguments_or_environment_is_refused() {
    let base = claims(&binding(), IAT);
    let cmd = with(base.clone(), "/submods/container", {
        let mut container = base.pointer("/submods/container").unwrap().clone();
        container["cmd_override"] = json!(["--unsafe"]);
        container
    });
    assert_eq!(
        passes(&cmd),
        Err(Error::Claim("/submods/container/cmd_override"))
    );
    let env = with(base.clone(), "/submods/container", {
        let mut container = base.pointer("/submods/container").unwrap().clone();
        container["env_override"] = json!({"RUST_LOG": "trace"});
        container
    });
    assert_eq!(
        passes(&env),
        Err(Error::Claim("/submods/container/env_override"))
    );
    // The launch variables may be set, and only those.
    let launch = with(base.clone(), "/submods/container", {
        let mut container = base.pointer("/submods/container").unwrap().clone();
        container["env_override"] = json!({
            "BOTSTADIA_API_URL": "https://api.example",
            "BOTSTADIA_CHAIN_ID": "84532",
            "BOTSTADIA_RESULTS": "0x40b96dF6D229d984Bc1400fA7A151c3423792E00",
        });
        container
    });
    assert!(passes(&launch).is_ok());
    let keys = with(base.clone(), "/submods/container", {
        let mut container = base.pointer("/submods/container").unwrap().clone();
        container["env_override"] =
            json!({"BOTSTADIA_CHAIN_ID": "84532", "BOTSTADIA_RPC_KEYS": "alchemy=x"});
        container
    });
    assert_eq!(
        passes(&keys),
        Err(Error::Claim("/submods/container/env_override"))
    );
    // Empty overrides override nothing.
    let empty = with(base.clone(), "/submods/container", {
        let mut container = base.pointer("/submods/container").unwrap().clone();
        container["cmd_override"] = json!([]);
        container["env_override"] = json!({});
        container
    });
    assert!(passes(&empty).is_ok());
}

#[test]
fn an_image_digest_that_is_not_a_sha256_digest_is_refused() {
    for digest in [
        "sha256:3b9e",
        "sha512:3b9e5f2a6c1d4e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7",
        "3b9e5f2a6c1d4e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7",
        "sha256:zz9e5f2a6c1d4e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7",
    ] {
        let claims = with(
            claims(&binding(), IAT),
            "/submods/container/image_digest",
            json!(digest),
        );
        assert_eq!(
            passes(&claims),
            Err(Error::Claim("/submods/container/image_digest")),
            "{digest}"
        );
    }
}

#[test]
fn a_token_with_no_project_is_refused() {
    let claims = without(claims(&binding(), IAT), "/submods/gce", "project_id");
    assert_eq!(
        passes(&claims),
        Err(Error::Claim("/submods/gce/project_id"))
    );
}

#[test]
fn a_token_whose_nonce_binds_other_keys_or_another_chain_binding_is_refused() {
    let theirs = Binding {
        submit_key: [0xBA; 20],
        ..binding()
    };
    let mut theirs_input = input(&binding(), IAT, NOW);
    theirs_input.token = sign(&claims(&theirs, IAT));
    assert_eq!(verify(&theirs_input), Err(Error::Nonce));

    for changed in [
        Binding {
            bundle_key: [1; 32],
            ..binding()
        },
        Binding {
            chain_id: 84_532,
            ..binding()
        },
        Binding {
            results: [2; 20],
            ..binding()
        },
        Binding {
            instruction: 2,
            ..binding()
        },
    ] {
        let mut input = input(&binding(), IAT, NOW);
        input.binding = changed;
        assert_eq!(verify(&input), Err(Error::Nonce));
    }
}

#[test]
fn a_handover_nonce_binds_the_peer_s_challenge_and_never_passes_as_a_boot_nonce() {
    let b = binding();
    assert_ne!(b.handover_nonce(&[1; 32]), b.handover_nonce(&[2; 32]));
    assert_ne!(b.handover_nonce(&[0; 32]), b.nonce());
    let claims = with(
        claims(&b, IAT),
        "/eat_nonce",
        json!([b.handover_nonce(&[7; 32])]),
    );
    assert_eq!(passes(&claims), Err(Error::Nonce));
    let token = verify_token(&sign(&claims), &input(&b, IAT, NOW).keys, NOW).unwrap();
    assert_eq!(token.nonces, vec![b.handover_nonce(&[7; 32])]);
}

#[test]
fn verify_token_reports_stable_and_the_os_version_for_the_caller_to_judge() {
    let unsupported = with(
        claims(&binding(), IAT),
        "/submods/confidential_space/support_attributes",
        json!(["USABLE"]),
    );
    let token = verify_token(&sign(&unsupported), &input(&binding(), IAT, NOW).keys, NOW).unwrap();
    assert!(!token.stable);
    assert_eq!(token.swversion, vec!["25090100".to_string()]);
    assert_eq!(
        passes(&unsupported),
        Err(Error::Claim(
            "/submods/confidential_space/support_attributes"
        ))
    );
}

#[test]
fn the_nonce_may_be_one_of_several() {
    let claims = with(
        claims(&binding(), IAT),
        "/eat_nonce",
        json!(["an-unrelated-nonce", binding().nonce()]),
    );
    assert!(passes(&claims).is_ok());
    let single = with(claims.clone(), "/eat_nonce", json!(binding().nonce()));
    assert!(passes(&single).is_ok());
}

#[test]
fn a_token_that_is_not_three_parts_is_refused() {
    let mut input = input(&binding(), IAT, NOW);
    input.token.push_str(".extra");
    assert_eq!(verify(&input), Err(Error::Malformed("structure")));
}

#[test]
fn the_pinned_key_set_is_one_of_the_dated_sets() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata");
    let dated: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .filter(|name| name.starts_with("google-jwks-") && name.ends_with(".json"))
        .map(|name| std::fs::read_to_string(format!("{dir}/{name}")).unwrap())
        .collect();
    assert!(dated.iter().any(|set| set == PINNED_GOOGLE_JWKS));
    assert!(!Jwk::from_jwks(PINNED_GOOGLE_JWKS).unwrap().is_empty());
}

#[test]
fn google_s_published_keys_parse_and_hash_by_their_material_alone() {
    let keys = Jwk::from_jwks(fixture::GOOGLE_JWKS_2026_10_06).unwrap();
    assert_eq!(keys.len(), 2);
    for key in &keys {
        assert_eq!(key.n.len(), 256, "2048-bit keys");
        assert_eq!(key.e, vec![1, 0, 1]);
    }
    assert_ne!(keys[0].key_hash(), keys[1].key_hash());
    let relabelled = Jwk {
        kid: "another".into(),
        ..keys[0].clone()
    };
    assert_eq!(relabelled.key_hash(), keys[0].key_hash());
    let padded = Jwk {
        n: [&[0u8][..], &keys[0].n].concat(),
        ..keys[0].clone()
    };
    assert_eq!(padded.key_hash(), keys[0].key_hash());
}

#[test]
fn the_journal_is_the_results_contract_s_abi_encoding() {
    let journal = verify(&input(&binding(), IAT, NOW)).unwrap();
    let bytes = journal.encode();
    assert_eq!(bytes.len(), 288);
    assert_eq!(&bytes[0..32], &journal.image_digest);
    assert_eq!(&bytes[32..64], &journal.project_id);
    assert_eq!(&bytes[64..76], &[0u8; 12]);
    assert_eq!(&bytes[76..96], &journal.submit_key);
    assert_eq!(&bytes[96..128], &journal.bundle_key);
    assert_eq!(
        u64::from_be_bytes(bytes[152..160].try_into().unwrap()),
        31_337
    );
    assert_eq!(&bytes[172..192], &journal.results);
    assert_eq!(u64::from_be_bytes(bytes[216..224].try_into().unwrap()), 1);
    assert_eq!(u64::from_be_bytes(bytes[248..256].try_into().unwrap()), IAT);
    assert_eq!(&bytes[256..288], &journal.root_hash);
    assert_eq!(Journal::decode(&bytes), Some(journal));
    assert_eq!(Journal::decode(&bytes[..287]), None);
    let mut dirty = bytes;
    dirty[64] = 1;
    assert_eq!(Journal::decode(&dirty), None, "padding must be zero");
}

#[test]
fn the_nonce_is_64_hex_characters_within_confidential_space_s_limits() {
    let nonce = binding().nonce();
    assert_eq!(nonce.len(), 64);
    assert!((8..=88).contains(&nonce.len()));
    assert!(nonce.bytes().all(|b| b.is_ascii_hexdigit()));
}

mod pki;
mod real_token;

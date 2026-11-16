//! Mock attestation, for the local target only (PLAN: the runner as a native
//! process with mock attestation).
//!
//! A local runner has no TEE, so it asks this module for its tokens instead
//! of Confidential Space's launcher. They are real PKI tokens in Google's
//! format, checked by the same [`crate::verify_token`] as Google's, but
//! chained to a fixed mock root CA (keys from public seeds, the test
//! fixture's). Their trust root is [`root_hash`] and their image is
//! [`IMAGE_DIGEST`]: only the local deploy approves either, so a mock token
//! can approve a key on Anvil and nowhere else.
//!
//! It refuses to compile into an enclave image: the image build sets
//! `--cfg botstadia_image`.

#[cfg(botstadia_image)]
compile_error!("mock attestation can never be built into an enclave image");

use alloc::string::String;
use serde_json::{Value, json};

use crate::fixture::chain::{self, Spec};

/// The GCP project local enclaves claim.
pub const PROJECT: &str = "botstadia-local";
/// The image digest local enclaves claim: `sha256("botstadia-local-enclave")`.
pub const IMAGE_DIGEST: &str =
    "sha256:7007511271e94f24cde3d1c6933c623138ad763715109d1d8f91a2e54d15a33e";
/// The OS version local enclaves claim.
pub const SWVERSION: &str = "25090100";

/// The mock CA's validity: 2025 to the end of 2049 (the last year UTCTime
/// can say), fixed so its root hash never changes.
const CA_FROM: u64 = 1_735_689_600;
const CA_UNTIL: u64 = 2_524_607_999;

fn mock_chain(iat: u64) -> alloc::vec::Vec<alloc::vec::Vec<u8>> {
    let root = Spec {
        not_before: CA_FROM,
        not_after: CA_UNTIL,
        ..Spec::root(iat)
    };
    let intermediate = Spec {
        not_before: CA_FROM,
        not_after: CA_UNTIL,
        ..Spec::intermediate(iat)
    };
    chain::chain_of(&Spec::leaf(iat), &intermediate, &root)
}

/// The mock root's hash: the local results contract's GoogleRootCert.
pub fn root_hash() -> [u8; 32] {
    crate::pki::root_hash(mock_chain(CA_FROM + 86_400).last().expect("a root"))
}

/// A token issued at `iat`, carrying `nonces`, as Confidential Space would
/// issue one to the local image.
pub fn issue(nonces: &[String], iat: u64) -> String {
    let mut claims: Value = crate::fixture::claims(&crate::fixture::binding(), iat);
    claims["eat_nonce"] = json!(nonces);
    claims["submods"]["container"]["image_digest"] = json!(IMAGE_DIGEST);
    claims["submods"]["gce"]["project_id"] = json!(PROJECT);
    claims["swversion"] = json!([SWVERSION]);
    chain::token(&mock_chain(iat), &chain::key(chain::LEAF_SEED), &claims)
}

/// The local prover: what the testnet and prod prover does with a zkVM, done
/// natively. It runs the guest's own check ([`crate::verify`]) and returns
/// the journal with a seal RISC Zero's mock verifier accepts for
/// `guest_image_id` under `selector`. Local target only: no verifier but the
/// local mock accepts the seal.
pub fn prove_local(
    input: &crate::Input,
    selector: &[u8; 4],
    guest_image_id: &[u8; 32],
) -> Result<(crate::Journal, alloc::vec::Vec<u8>), crate::Error> {
    let journal = crate::verify(input)?;
    let seal = crate::receipt::mock_seal(selector, guest_image_id, &journal.digest());
    Ok((journal, seal))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Binding, Input, project_id, verify};

    #[test]
    fn a_mock_token_passes_verify_chained_to_the_fixed_mock_root() {
        let binding = Binding {
            submit_key: [1; 20],
            bundle_key: [2; 32],
            chain_id: 31_337,
            results: [3; 20],
            instruction: 1,
        };
        let iat = 1_800_000_000;
        let journal = verify(&Input {
            token: issue(&[binding.nonce()], iat),
            keys: alloc::vec::Vec::new(),
            now: iat + 60,
            binding,
        })
        .unwrap();
        assert_eq!(journal.root_hash, root_hash());
        assert_eq!(journal.project_id, project_id(PROJECT));
        assert_eq!(
            hex::encode(journal.image_digest),
            IMAGE_DIGEST.trim_start_matches("sha256:")
        );
        // The same root hash whenever a token is issued.
        let later = crate::verify_token(
            &issue(&[binding.nonce()], iat + 86_400 * 300),
            &[],
            iat + 86_400 * 300 + 1,
        )
        .unwrap();
        assert_eq!(later.root_hash, root_hash());
    }

    #[test]
    fn the_local_prover_refuses_what_the_guest_would_and_seals_what_it_passes() {
        let binding = Binding {
            submit_key: [1; 20],
            bundle_key: [2; 32],
            chain_id: 31_337,
            results: [3; 20],
            instruction: 1,
        };
        let iat = 1_800_000_000;
        let input = Input {
            token: issue(&[binding.nonce()], iat),
            keys: alloc::vec::Vec::new(),
            now: iat + 60,
            binding,
        };
        let (journal, seal) = prove_local(&input, &[0xb0; 4], &[9; 32]).unwrap();
        assert_eq!(seal.len(), 36);
        assert_eq!(&seal[..4], &[0xb0; 4]);
        assert_eq!(
            &seal[4..],
            &crate::receipt::ok_claim_digest(&[9; 32], &journal.digest())
        );
        let mut other = input.clone();
        other.binding.chain_id = 8453;
        assert_eq!(
            prove_local(&other, &[0xb0; 4], &[9; 32]),
            Err(crate::Error::Nonce)
        );
    }

    #[test]
    fn the_exported_mock_root_hash_is_the_mock_root_s() {
        assert_eq!(crate::LOCAL_MOCK_ROOT_HASH, root_hash());
    }

    #[test]
    fn the_mock_image_digest_is_the_hash_it_says() {
        use sha2::{Digest, Sha256};
        assert_eq!(
            hex::encode(Sha256::digest(b"botstadia-local-enclave")),
            IMAGE_DIGEST.trim_start_matches("sha256:")
        );
    }

    #[test]
    fn print_the_local_trust_anchors_for_config() {
        std::println!("CHAIN_LOCAL_ROOT_HASH: 0x{}", hex::encode(root_hash()));
        std::println!(
            "CHAIN_LOCAL_IMAGE_DIGEST: 0x{}",
            IMAGE_DIGEST.trim_start_matches("sha256:")
        );
    }
}

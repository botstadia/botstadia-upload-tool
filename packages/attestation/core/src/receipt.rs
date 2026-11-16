//! RISC Zero's receipt-claim digest for a successful run, as risc0-ethereum's
//! `ReceiptClaimLib.ok(imageId, journalDigest).digest()` computes it. A
//! verifier checks a seal against this digest; RISC Zero's mock verifier
//! accepts exactly `selector ‖ digest`, which is how local enclaves are
//! approved without a real proof ([`mock_seal`]).

use alloc::vec::Vec;

use sha2::{Digest, Sha256};

/// `SystemStateLib.digest(SystemState(0, bytes32(0)))`.
pub const SYSTEM_STATE_ZERO_DIGEST: [u8; 32] = [
    0xa3, 0xac, 0xc2, 0x71, 0x17, 0x41, 0x89, 0x96, 0x34, 0x0b, 0x84, 0xe5, 0xa9, 0x0f, 0x3e, 0xf4,
    0xc4, 0x9d, 0x22, 0xc7, 0x9e, 0x44, 0xaa, 0xd8, 0x22, 0xec, 0x9c, 0x31, 0x3e, 0x1e, 0xb8, 0xe2,
];

fn tag(name: &str) -> [u8; 32] {
    Sha256::digest(name.as_bytes()).into()
}

/// The digest of the claim that `image_id` ran to a halt with exit code 0
/// and committed a journal with this `sha256`.
pub fn ok_claim_digest(image_id: &[u8; 32], journal_digest: &[u8; 32]) -> [u8; 32] {
    let mut output = Sha256::new();
    output.update(tag("risc0.Output"));
    output.update(journal_digest);
    output.update([0u8; 32]); // no assumptions
    output.update(2u16.to_le_bytes());
    let output: [u8; 32] = output.finalize().into();

    let mut claim = Sha256::new();
    claim.update(tag("risc0.ReceiptClaim"));
    claim.update([0u8; 32]); // input
    claim.update(image_id); // pre-state
    claim.update(SYSTEM_STATE_ZERO_DIGEST); // post-state
    claim.update(output);
    claim.update([0u8; 4]); // system exit code: halted
    claim.update([0u8; 4]); // user exit code: 0
    claim.update(4u16.to_le_bytes());
    claim.finalize().into()
}

/// The seal RISC Zero's mock verifier accepts for this run, under its
/// `selector`. Local target only: no deployed verifier but the local mock
/// accepts it.
pub fn mock_seal(selector: &[u8; 4], image_id: &[u8; 32], journal_digest: &[u8; 32]) -> Vec<u8> {
    let mut seal = selector.to_vec();
    seal.extend_from_slice(&ok_claim_digest(image_id, journal_digest));
    seal
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_zero_system_state_digest_is_risc_zero_s() {
        let mut h = Sha256::new();
        h.update(tag("risc0.SystemState"));
        h.update([0u8; 32]);
        h.update(0u32.to_be_bytes());
        h.update(1u16.to_le_bytes());
        let d: [u8; 32] = h.finalize().into();
        assert_eq!(d, SYSTEM_STATE_ZERO_DIGEST);
    }
}

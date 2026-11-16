//! The session spec (TRUST.md#what-the-enclave-signs).
//!
//! What a session is: its entrants' bundle digests in strictly ascending
//! order, each builder's payout address, the arena digest, the chain id and
//! results contract (so a testnet result can never count on mainnet), a
//! random nonce and the budget version. Its hash is the post entry's spec
//! hash, and the first bet carries it in full.

use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_sol_types::SolValue;
use serde::{Deserialize, Serialize};

use crate::abi::Settlement;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Spec {
    pub digests: Vec<B256>,
    pub payouts: Vec<Address>,
    pub arena: B256,
    pub chain_id: u64,
    pub results: Address,
    pub nonce: B256,
    pub budget_version: u32,
}

impl Spec {
    /// `keccak256(abi.encode(spec))`, as the settlement contract computes it.
    pub fn hash(&self) -> B256 {
        keccak256(self.to_sol().abi_encode())
    }

    pub fn to_sol(&self) -> Settlement::Spec {
        Settlement::Spec {
            digests: self.digests.clone(),
            payouts: self.payouts.clone(),
            arena: self.arena,
            chainId: U256::from(self.chain_id),
            results: self.results,
            nonce: self.nonce,
            budgetVersion: self.budget_version,
        }
    }

    /// Entrants must be strictly ascending by digest (so none appears twice)
    /// and each must have a payout address (the zero address is valid).
    pub fn check(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.digests.len() >= 2,
            "a session needs at least two entrants"
        );
        anyhow::ensure!(self.digests.len() <= 224, "at most 224 entrants");
        anyhow::ensure!(
            self.payouts.len() == self.digests.len(),
            "one payout address per entrant"
        );
        anyhow::ensure!(
            self.digests.windows(2).all(|pair| pair[0] < pair[1]),
            "entrants must be in strictly ascending digest order"
        );
        Ok(())
    }
}

/// A bundle digest as BotStadia writes it (`sha256-<hex>`), as the 32 bytes
/// specs and the contracts carry.
pub fn digest_bytes(digest: &str) -> anyhow::Result<B256> {
    let hex = digest
        .strip_prefix("sha256-")
        .ok_or_else(|| anyhow::anyhow!("a digest starts with sha256-: {digest}"))?;
    Ok(hex.parse::<B256>()?)
}

/// The 32 bytes back as `sha256-<hex>`.
pub fn digest_string(bytes: &B256) -> String {
    format!("sha256-{}", alloy_primitives::hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digests_round_trip() {
        let s = "sha256-00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        assert_eq!(digest_string(&digest_bytes(s).unwrap()), s);
        assert!(digest_bytes("md5-00").is_err());
    }

    #[test]
    fn entrants_out_of_order_are_refused() {
        let mut spec = Spec {
            digests: vec![B256::repeat_byte(2), B256::repeat_byte(1)],
            payouts: vec![Address::ZERO; 2],
            arena: B256::ZERO,
            chain_id: 31337,
            results: Address::ZERO,
            nonce: B256::ZERO,
            budget_version: 1,
        };
        assert!(spec.check().is_err());
        spec.digests.reverse();
        assert!(spec.check().is_ok());
    }
}

//! The zk guest's journal (TRUST.md#the-tee-and-the-zk-proof), ABI-encoded
//! as the results contract decodes it. The guest commits these bytes, and
//! the verifier checks a proof against their sha256.

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::SolValue;
use serde::{Deserialize, Serialize};

alloy_sol_types::sol! {
    /// `Results.Journal`, which no function signature names, so the ABI
    /// doesn't carry it. The Anvil test checks the contract decodes it.
    #[derive(Debug, PartialEq, Eq)]
    struct SolJournal {
        bytes32 imageDigest;
        bytes32 projectId;
        address submitKey;
        bytes32 bundleKey;
        uint256 chainId;
        address results;
        uint64 instruction;
        uint64 issuedAt;
        bytes32 rootHash;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Journal {
    /// The container image digest (`sha256:<hex>` as bytes).
    pub image_digest: B256,
    /// keccak256 of the GCP project id.
    pub project_id: B256,
    pub submit_key: Address,
    /// The BundleKey's public half (X25519).
    pub bundle_key: B256,
    /// The chain binding: this chain and this results contract.
    pub chain_id: u64,
    pub results: Address,
    /// The new-key instruction the BundleKey belongs to.
    pub instruction: u64,
    /// The attestation token's issue time.
    pub issued_at: u64,
    /// The GoogleRootCert the token chained to (sha256 of its DER).
    pub root_hash: B256,
}

impl Journal {
    pub fn to_sol(&self) -> SolJournal {
        SolJournal {
            imageDigest: self.image_digest,
            projectId: self.project_id,
            submitKey: self.submit_key,
            bundleKey: self.bundle_key,
            chainId: U256::from(self.chain_id),
            results: self.results,
            instruction: self.instruction,
            issuedAt: self.issued_at,
            rootHash: self.root_hash,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        self.to_sol().abi_encode()
    }

    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let j = SolJournal::abi_decode(bytes)?;
        Ok(Self {
            image_digest: j.imageDigest,
            project_id: j.projectId,
            submit_key: j.submitKey,
            bundle_key: j.bundleKey,
            chain_id: u64::try_from(j.chainId)?,
            results: j.results,
            instruction: j.instruction,
            issued_at: j.issuedAt,
            root_hash: j.rootHash,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_journal_is_nine_words_and_round_trips() {
        let j = Journal {
            image_digest: B256::repeat_byte(1),
            project_id: B256::repeat_byte(2),
            submit_key: Address::repeat_byte(3),
            bundle_key: B256::repeat_byte(4),
            chain_id: 31337,
            results: Address::repeat_byte(5),
            instruction: 1,
            issued_at: 1_800_000_000,
            root_hash: B256::repeat_byte(6),
        };
        assert_eq!(j.encode().len(), 9 * 32);
        assert_eq!(Journal::decode(&j.encode()).unwrap(), j);
    }
}

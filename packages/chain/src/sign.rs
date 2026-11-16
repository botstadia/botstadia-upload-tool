//! SubmitKey signing: standard prefixed ECDSA over opaque bytes (EIP-191),
//! as TRUST.md#what-the-enclave-signs says, so anyone can verify one result,
//! final rating or upload report without the chain.

use alloy_primitives::{Address, B256, Bytes, Signature, U256, keccak256};
use alloy_sol_types::SolType;
use alloy_sol_types::sol_data::{self, FixedBytes};
use k256::ecdsa::SigningKey;

/// A secp256k1 key: an enclave's SubmitKey, the keeper's operator key, or a
/// test account.
#[derive(Clone)]
pub struct Key(SigningKey);

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Key({})", self.address())
    }
}

impl Key {
    pub fn from_bytes(secret: &[u8; 32]) -> anyhow::Result<Self> {
        Ok(Self(SigningKey::from_bytes(secret.into())?))
    }

    /// From `0x`-prefixed or bare hex.
    pub fn from_hex(hex: &str) -> anyhow::Result<Self> {
        let bytes: B256 = hex.trim().parse()?;
        Self::from_bytes(&bytes.0)
    }

    pub fn address(&self) -> Address {
        Address::from_public_key(self.0.verifying_key())
    }

    pub fn secret(&self) -> [u8; 32] {
        self.0.to_bytes().into()
    }

    /// Sign a 32-byte hash as is.
    pub fn sign_hash(&self, hash: B256) -> anyhow::Result<Signature> {
        let (sig, recid) = self.0.sign_prehash_recoverable(hash.as_slice())?;
        let r = U256::from_be_slice(&sig.r().to_bytes());
        let s = U256::from_be_slice(&sig.s().to_bytes());
        Ok(Signature::new(r, s, recid.is_y_odd()))
    }

    /// EIP-191 over opaque bytes: 65 bytes, r ‖ s ‖ v (27 or 28).
    pub fn sign_message(&self, message: &[u8]) -> anyhow::Result<Bytes> {
        let sig = self.sign_hash(eip191_hash(message))?;
        Ok(Bytes::from(sig.as_bytes().to_vec()))
    }
}

/// `keccak256("\x19Ethereum Signed Message:\n" ‖ len ‖ message)`.
pub fn eip191_hash(message: &[u8]) -> B256 {
    let mut bytes = format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
    bytes.extend_from_slice(message);
    keccak256(bytes)
}

/// Who signed `message` (EIP-191), from a 65-byte signature.
pub fn recover(message: &[u8], signature: &[u8]) -> anyhow::Result<Address> {
    let sig = Signature::try_from(signature)?;
    Ok(sig.recover_address_from_prehash(&eip191_hash(message))?)
}

/// [`recover`], refusing a signature in its high-s form. Every ECDSA
/// signature has a twin, `s` replaced by `n − s` with the parity flipped,
/// that recovers the same signer; only the low-s one is accepted (EIP-2), so
/// one signing is one accepted string.
pub fn recover_low_s(message: &[u8], signature: &[u8]) -> anyhow::Result<Address> {
    let sig = Signature::try_from(signature)?;
    anyhow::ensure!(sig.normalize_s().is_none(), "a high-s signature");
    Ok(sig.recover_address_from_prehash(&eip191_hash(message))?)
}

/// What an enclave signs for a session's result
/// (TRUST.md#what-the-enclave-signs).
#[derive(Debug, Clone)]
pub struct ResultMessage {
    pub chain_id: u64,
    pub results: Address,
    pub session: B256,
    pub outcome: Vec<u8>,
    pub anchor: B256,
    pub anchor_block: u64,
    pub seed: B256,
    pub spec_hash: B256,
    pub archive_hash: B256,
}

impl ResultMessage {
    pub fn encode(&self) -> Vec<u8> {
        type Message = (
            FixedBytes<32>,
            sol_data::Uint<256>,
            sol_data::Address,
            FixedBytes<32>,
            sol_data::Bytes,
            FixedBytes<32>,
            sol_data::Uint<64>,
            FixedBytes<32>,
            FixedBytes<32>,
            FixedBytes<32>,
        );
        Message::abi_encode_params(&(
            keccak256("botstadia-result-v1"),
            U256::from(self.chain_id),
            self.results,
            self.session,
            Bytes::from(self.outcome.clone()),
            self.anchor,
            self.anchor_block,
            self.seed,
            self.spec_hash,
            self.archive_hash,
        ))
    }
}

/// What an enclave signs for a warm-up's final rating (TRUST.md#the-result).
#[derive(Debug, Clone)]
pub struct RatingMessage {
    pub chain_id: u64,
    pub results: Address,
    pub bot: B256,
    pub ladder: B256,
    pub mu: i64,
    pub sigma: i64,
    pub rating_version: u32,
    pub arena_digest: B256,
    pub budget_version: u32,
    pub opponent_list_hash: B256,
}

impl RatingMessage {
    pub fn encode(&self) -> Vec<u8> {
        type Message = (
            FixedBytes<32>,
            sol_data::Uint<256>,
            sol_data::Address,
            FixedBytes<32>,
            FixedBytes<32>,
            sol_data::Int<64>,
            sol_data::Int<64>,
            sol_data::Uint<32>,
            FixedBytes<32>,
            sol_data::Uint<32>,
            FixedBytes<32>,
        );
        Message::abi_encode_params(&(
            keccak256("botstadia-final-rating-v1"),
            U256::from(self.chain_id),
            self.results,
            self.bot,
            self.ladder,
            self.mu,
            self.sigma,
            self.rating_version,
            self.arena_digest,
            self.budget_version,
            self.opponent_list_hash,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signed_message_recovers_its_signer() {
        let key = Key::from_bytes(&[7u8; 32]).unwrap();
        let sig = key.sign_message(b"hello").unwrap();
        assert_eq!(sig.len(), 65);
        assert_eq!(recover(b"hello", &sig).unwrap(), key.address());
        assert_ne!(recover(b"hellp", &sig).unwrap(), key.address());
    }

    #[test]
    fn anvil_s_first_key_has_its_well_known_address() {
        let key =
            Key::from_hex("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
                .unwrap();
        assert_eq!(
            key.address(),
            "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
                .parse::<Address>()
                .unwrap()
        );
    }
}

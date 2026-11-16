//! User operations for EntryPoint v0.7, and what a Safe's owner signs for
//! one through Safe4337Module 0.3.0.
//!
//! The owner signs the module's SafeOp, an EIP-712 struct over the
//! operation's fields with the module as the verifying contract. The
//! operation's signature is `validAfter ‖ validUntil ‖ Safe signatures`.

use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_sol_types::{SolCall, SolValue, sol};
use serde::{Deserialize, Serialize};

use super::Contracts;
use super::safe::multi_send_tx;

sol! {
    #[allow(missing_docs)]
    function executeUserOpWithErrorString(address to, uint256 value, bytes data, uint8 operation);

    #[allow(missing_docs)]
    function getNonce(address sender, uint192 key) returns (uint256 nonce);
}

/// One call an operation makes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Call {
    pub to: Address,
    pub value: U256,
    pub data: Bytes,
}

/// The operation's `callData`: one call straight from the Safe, or several
/// batched through MultiSendCallOnly (delegatecalled, so each runs as the
/// Safe).
pub fn call_data(c: &Contracts, calls: &[Call]) -> anyhow::Result<Bytes> {
    let (to, value, data, operation) = match calls {
        [] => anyhow::bail!("an operation makes at least one call"),
        [one] => (one.to, one.value, one.data.clone(), 0u8),
        many => {
            let mut txs = Vec::new();
            for call in many {
                multi_send_tx(&mut txs, false, call.to, call.value, &call.data);
            }
            let batch = super::safe::multiSendCall {
                transactions: txs.into(),
            }
            .abi_encode();
            (c.multi_send_call_only, U256::ZERO, batch.into(), 1u8)
        }
    };
    Ok(executeUserOpWithErrorStringCall {
        to,
        value,
        data,
        operation,
    }
    .abi_encode()
    .into())
}

/// A v0.7 user operation, unpacked, as bundlers' JSON-RPC takes it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserOp {
    pub sender: Address,
    pub nonce: U256,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub factory: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub factory_data: Option<Bytes>,
    pub call_data: Bytes,
    pub call_gas_limit: U256,
    pub verification_gas_limit: U256,
    pub pre_verification_gas: U256,
    pub max_fee_per_gas: U256,
    pub max_priority_fee_per_gas: U256,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paymaster: Option<Address>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paymaster_verification_gas_limit: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paymaster_post_op_gas_limit: Option<U256>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paymaster_data: Option<Bytes>,
    pub signature: Bytes,
}

fn pack128(hi: U256, lo: U256) -> B256 {
    B256::from((hi << 128) | (lo & U256::from(u128::MAX)))
}

impl UserOp {
    pub fn init_code(&self) -> Vec<u8> {
        match (self.factory, &self.factory_data) {
            (Some(f), Some(d)) => [f.as_slice(), d.as_ref()].concat(),
            (Some(f), None) => f.to_vec(),
            _ => Vec::new(),
        }
    }

    pub fn paymaster_and_data(&self) -> Vec<u8> {
        let Some(pm) = self.paymaster else {
            return Vec::new();
        };
        let mut out = pm.to_vec();
        let v = self.paymaster_verification_gas_limit.unwrap_or_default();
        let p = self.paymaster_post_op_gas_limit.unwrap_or_default();
        out.extend_from_slice(&v.to_be_bytes::<32>()[16..]);
        out.extend_from_slice(&p.to_be_bytes::<32>()[16..]);
        if let Some(d) = &self.paymaster_data {
            out.extend_from_slice(d);
        }
        out
    }

    /// The EntryPoint's `getUserOpHash`: what bundlers and receipts name it by.
    pub fn hash(&self, c: &Contracts) -> B256 {
        let inner = (
            self.sender,
            self.nonce,
            keccak256(self.init_code()),
            keccak256(&self.call_data),
            pack128(self.verification_gas_limit, self.call_gas_limit),
            self.pre_verification_gas,
            pack128(self.max_priority_fee_per_gas, self.max_fee_per_gas),
            keccak256(self.paymaster_and_data()),
        )
            .abi_encode();
        keccak256((keccak256(inner), c.entry_point, U256::from(c.chain_id)).abi_encode())
    }

    /// The SafeOp digest the Safe's owners sign (EIP-712, Safe4337Module
    /// 0.3.0's `getOperationHash`).
    pub fn safe_op_hash(&self, c: &Contracts, valid_after: u64, valid_until: u64) -> B256 {
        let type_hash = keccak256(
            "SafeOp(address safe,uint256 nonce,bytes initCode,bytes callData,uint128 verificationGasLimit,uint128 callGasLimit,uint256 preVerificationGas,uint128 maxPriorityFeePerGas,uint128 maxFeePerGas,bytes paymasterAndData,uint48 validAfter,uint48 validUntil,address entryPoint)",
        );
        let lo = |v: U256| v & U256::from(u128::MAX);
        let fields = (
            type_hash,
            self.sender,
            self.nonce,
            keccak256(self.init_code()),
            keccak256(&self.call_data),
            lo(self.verification_gas_limit),
            lo(self.call_gas_limit),
            self.pre_verification_gas,
            lo(self.max_priority_fee_per_gas),
            lo(self.max_fee_per_gas),
            keccak256(self.paymaster_and_data()),
            U256::from(valid_after),
            U256::from(valid_until),
            c.entry_point,
        )
            .abi_encode();
        eip712(domain_separator(c, c.safe_4337_module), keccak256(fields))
    }
}

/// `EIP712Domain(uint256 chainId,address verifyingContract)`, the domain
/// Safe uses for its own messages and the module for SafeOps.
pub fn domain_separator(c: &Contracts, verifying: Address) -> B256 {
    let type_hash = keccak256("EIP712Domain(uint256 chainId,address verifyingContract)");
    keccak256((type_hash, U256::from(c.chain_id), verifying).abi_encode())
}

pub fn eip712(domain: B256, struct_hash: B256) -> B256 {
    let mut bytes = vec![0x19, 0x01];
    bytes.extend_from_slice(domain.as_slice());
    bytes.extend_from_slice(struct_hash.as_slice());
    keccak256(bytes)
}

/// One owner's signature, in Safe's `checkSignatures` layout.
#[derive(Clone, Debug)]
pub enum OwnerSignature {
    /// An address owner's ECDSA signature: r ‖ s ‖ v, with v 27 or 28 over
    /// the digest itself (a key in the page, `eth_signTypedData_v4`), or 31
    /// or 32 over its EIP-191 hash (`personal_sign` of the digest, which
    /// Safe reads as eth_sign).
    Address { owner: Address, rsv: Bytes },
    /// A contract owner (the shared signer, a passkey's own signer): its
    /// ERC-1271 signature bytes.
    Contract { owner: Address, signature: Bytes },
}

impl OwnerSignature {
    fn owner(&self) -> Address {
        match self {
            Self::Address { owner, .. } | Self::Contract { owner, .. } => *owner,
        }
    }
}

/// Safe signatures for a threshold of one, or several sorted by owner, as
/// `checkSignatures` wants: 65-byte static parts, then contract signatures'
/// dynamic parts.
pub fn safe_signatures(mut sigs: Vec<OwnerSignature>) -> anyhow::Result<Bytes> {
    sigs.sort_by_key(OwnerSignature::owner);
    let mut stat = Vec::new();
    let mut dynamic = Vec::new();
    let base = 65 * sigs.len();
    for sig in &sigs {
        match sig {
            OwnerSignature::Address { rsv, .. } => {
                anyhow::ensure!(rsv.len() == 65, "an address owner's signature is 65 bytes");
                anyhow::ensure!(
                    matches!(rsv[64], 27 | 28 | 31 | 32),
                    "v is 27, 28, 31 or 32"
                );
                stat.extend_from_slice(rsv);
            }
            OwnerSignature::Contract { owner, signature } => {
                stat.extend_from_slice(&U256::from_be_slice(owner.as_slice()).to_be_bytes::<32>());
                stat.extend_from_slice(&U256::from(base + dynamic.len()).to_be_bytes::<32>());
                stat.push(0);
                dynamic.extend_from_slice(&U256::from(signature.len()).to_be_bytes::<32>());
                dynamic.extend_from_slice(signature);
            }
        }
    }
    stat.extend_from_slice(&dynamic);
    Ok(stat.into())
}

/// The operation's signature: `validAfter ‖ validUntil ‖ Safe signatures`.
pub fn op_signature(valid_after: u64, valid_until: u64, safe_sigs: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(12 + safe_sigs.len());
    out.extend_from_slice(&valid_after.to_be_bytes()[2..]);
    out.extend_from_slice(&valid_until.to_be_bytes()[2..]);
    out.extend_from_slice(safe_sigs);
    out.into()
}

/// A placeholder passkey signature of realistic size for gas estimation,
/// so the bundler prices validation as it will run.
pub fn dummy_signature(c: &Contracts, passkey: bool) -> Bytes {
    let sig = if passkey {
        OwnerSignature::Contract {
            owner: c.webauthn_shared_signer,
            signature: super::webauthn::dummy(),
        }
    } else {
        let mut rsv = vec![0xff; 64];
        rsv.push(27);
        OwnerSignature::Address {
            owner: Address::ZERO,
            rsv: rsv.into(),
        }
    };
    op_signature(0, 0, &safe_signatures(vec![sig]).expect("a valid dummy"))
}

/// The Safe's own EIP-712 message hash (`SafeMessage(bytes message)`), what
/// its ERC-1271 check asks the owners to have signed for `hash`.
pub fn safe_message_hash(c: &Contracts, safe: Address, hash: B256) -> B256 {
    let type_hash = keccak256("SafeMessage(bytes message)");
    let struct_hash = keccak256((type_hash, keccak256(hash.as_slice())).abi_encode());
    eip712(domain_separator(c, safe), struct_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_contract_signature_points_past_the_static_part() {
        let owner = Address::repeat_byte(0x11);
        let sig = safe_signatures(vec![OwnerSignature::Contract {
            owner,
            signature: vec![0xab; 3].into(),
        }])
        .unwrap();
        assert_eq!(sig.len(), 65 + 32 + 3);
        assert_eq!(&sig[12..32], owner.as_slice());
        assert_eq!(U256::from_be_slice(&sig[32..64]), U256::from(65));
        assert_eq!(sig[64], 0);
        assert_eq!(U256::from_be_slice(&sig[65..97]), U256::from(3));
    }

    #[test]
    fn the_signature_carries_validity_first() {
        let s = op_signature(1, 2, &[9]);
        assert_eq!(s.as_ref(), &[0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 2, 9]);
    }
}

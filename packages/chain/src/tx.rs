//! EIP-1559 transactions, signed by a [`Key`]. The caller chooses the nonce:
//! the keeper's one sender and each enclave keep their own, so a held
//! transaction can be replaced at the same nonce by a smaller one
//! (TRUST.md#submitting-results).

use alloy_consensus::{SignableTransaction, TxEip1559, TxEnvelope};
use alloy_eips::eip2718::Encodable2718;
use alloy_primitives::{Address, B256, Bytes, TxKind, U256};

use crate::sign::Key;

#[derive(Debug, Clone)]
pub struct Call {
    pub to: Address,
    pub data: Vec<u8>,
    pub value: U256,
}

#[derive(Debug, Clone, Copy)]
pub struct Fees {
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
}

/// A signed transaction, ready for `eth_sendRawTransaction`.
#[derive(Debug, Clone)]
pub struct Signed {
    pub raw: Bytes,
    pub hash: B256,
    pub nonce: u64,
}

pub fn sign(
    key: &Key,
    chain_id: u64,
    nonce: u64,
    gas_limit: u64,
    fees: Fees,
    call: &Call,
) -> anyhow::Result<Signed> {
    let tx = TxEip1559 {
        chain_id,
        nonce,
        gas_limit,
        max_fee_per_gas: fees.max_fee_per_gas,
        max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
        to: TxKind::Call(call.to),
        value: call.value,
        access_list: Default::default(),
        input: Bytes::from(call.data.clone()),
    };
    let signature = key.sign_hash(tx.signature_hash())?;
    let envelope = TxEnvelope::from(tx.into_signed(signature));
    let hash = *envelope.tx_hash();
    Ok(Signed {
        raw: Bytes::from(envelope.encoded_2718()),
        hash,
        nonce,
    })
}

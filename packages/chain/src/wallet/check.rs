//! An account wallet's signature, checked through ERC-1271 whether or not
//! the wallet is deployed yet (MONEY.md#stolen-sign-ins).
//!
//! The call runs `WalletSignatureCheck`'s creation code in `eth_call`: it
//! deploys the wallet from its setup data inside the call if it has no code,
//! then asks it. Nothing is deployed for real, and any RPC can run it.

use alloy_primitives::{Address, B256, Bytes};
use alloy_sol_types::SolValue;

use super::Contracts;
use crate::rpc::{BlockTag, Client, Transport};

/// `contracts/src/wallet/WalletSignatureCheck.sol`'s creation code, copied by
/// `task chain:abi` and checked against `contracts/out` by the drift test.
pub const BYTECODE: &str = include_str!("../../abi/WalletSignatureCheck.bytecode");

/// The `eth_call` data: creation code, then the constructor's arguments.
/// `setup` is the wallet's setup data, used only if it isn't deployed.
pub fn call_data(
    c: &Contracts,
    wallet: Address,
    hash: B256,
    signature: &[u8],
    setup: Option<&[u8]>,
) -> Vec<u8> {
    let mut data =
        alloy_primitives::hex::decode(BYTECODE.trim()).expect("the check's bytecode is hex");
    let (factory, factory_data) = match setup {
        Some(init) => (c.proxy_factory, super::safe::deploy_call(c, init)),
        None => (Address::ZERO, Vec::new()),
    };
    data.extend_from_slice(
        &(
            wallet,
            hash,
            Bytes::from(signature.to_vec()),
            factory,
            Bytes::from(factory_data),
        )
            .abi_encode_params(),
    );
    data
}

/// Whether `wallet` signed `hash` (its ERC-1271 answer).
pub async fn is_valid<T: Transport>(
    rpc: &Client<T>,
    c: &Contracts,
    wallet: Address,
    hash: B256,
    signature: &[u8],
    setup: Option<&[u8]>,
) -> anyhow::Result<bool> {
    is_valid_at(rpc, c, wallet, hash, signature, setup, BlockTag::Latest).await
}

/// [`is_valid`] at one block, where anyone can ask again: owners change.
pub async fn is_valid_at<T: Transport>(
    rpc: &Client<T>,
    c: &Contracts,
    wallet: Address,
    hash: B256,
    signature: &[u8],
    setup: Option<&[u8]>,
    at: BlockTag,
) -> anyhow::Result<bool> {
    let data = call_data(c, wallet, hash, signature, setup);
    let v = rpc
        .request(
            "eth_call",
            serde_json::json!([{ "data": Bytes::from(data) }, at.json()]),
        )
        .await?;
    let out: Bytes = serde_json::from_value(v)?;
    Ok(out.as_ref() == [1])
}

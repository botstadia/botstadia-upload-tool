//! Circle's Paymaster (MONEY.md#currency): gas paid in USDC from the
//! wallet's own balance, plus Circle's surcharge.
//!
//! The paymaster takes its charge with `transferFrom`, so it needs an
//! allowance. The first operation carries a USDC permit for a small
//! standing allowance, signed by the wallet through ERC-1271 with USDC's
//! maximum deadline, since validation can't read the clock (ERC-7562).
//! Later operations renew it with an `approve` inside the operation itself
//! (MONEY.md#accounts-and-wallets).

use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_sol_types::SolValue;

use super::Contracts;
use super::op::{UserOp, eip712};

/// Paymaster validation and post-op gas, as Circle documents them. Its
/// post-op refuses less than 35,000, the gas it charges for itself.
pub const VERIFICATION_GAS: u64 = 200_000;
pub const POST_OP_GAS: u64 = 35_000;

/// The standing allowance a permit or renewal gives the paymaster: about a
/// dollar of gas, small because the paymaster is Circle's upgradeable
/// contract.
pub const ALLOWANCE: u64 = 1_000_000;

/// `paymasterData`: mode 0, the token, the permit's amount and its
/// signature. Without a permit there's no data at all, and the paymaster
/// uses the allowance already in place.
pub fn data(c: &Contracts, permit_amount: U256, permit_signature: &[u8]) -> Bytes {
    if permit_signature.is_empty() {
        return Bytes::new();
    }
    let mut out = vec![0u8];
    out.extend_from_slice(c.usdc.as_slice());
    out.extend_from_slice(&permit_amount.to_be_bytes::<32>());
    out.extend_from_slice(permit_signature);
    out.into()
}

/// Point `op` at the paymaster with this data.
pub fn attach(op: &mut UserOp, c: &Contracts, data: Bytes) {
    op.paymaster = Some(c.paymaster);
    op.paymaster_verification_gas_limit = Some(U256::from(VERIFICATION_GAS));
    op.paymaster_post_op_gas_limit = Some(U256::from(POST_OP_GAS));
    op.paymaster_data = Some(data);
}

/// USDC's EIP-2612 permit digest for the paymaster as spender.
pub fn permit_digest(
    c: &Contracts,
    owner: Address,
    value: U256,
    nonce: U256,
    deadline: U256,
) -> B256 {
    let domain_type = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );
    let domain = keccak256(
        (
            domain_type,
            keccak256(c.usdc_name.as_bytes()),
            keccak256("2"),
            U256::from(c.chain_id),
            c.usdc,
        )
            .abi_encode(),
    );
    let permit_type = keccak256(
        "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)",
    );
    let s = keccak256((permit_type, owner, c.paymaster, value, nonce, deadline).abi_encode());
    eip712(domain, s)
}

/// The most gas the paymaster may charge for `op`, in wei: what the wallet
/// keeps back so it can always claim (MONEY.md#placing-bets) is this, priced
/// in USDC with the surcharge.
pub fn max_cost_wei(op: &UserOp) -> U256 {
    let gas = op.verification_gas_limit
        + op.call_gas_limit
        + op.pre_verification_gas
        + op.paymaster_verification_gas_limit.unwrap_or_default()
        + op.paymaster_post_op_gas_limit.unwrap_or_default();
    gas * op.max_fee_per_gas
}

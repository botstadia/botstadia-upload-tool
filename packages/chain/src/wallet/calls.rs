//! The calls an account wallet's operations batch (MONEY.md#placing-bets):
//! claiming whatever is claimable first, so its money can be used, then
//! approving exactly the amount, the eligibility statement if not yet made,
//! and the bets. A withdrawal claims first too.

use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::{SolCall, sol};

use super::Contracts;
use super::op::Call;
use crate::abi::Settlement;

sol! {
    #[allow(missing_docs)]
    function approve(address spender, uint256 amount) returns (bool);
    #[allow(missing_docs)]
    function transfer(address to, uint256 amount) returns (bool);
    #[allow(missing_docs)]
    function allowance(address owner, address spender) returns (uint256);
    #[allow(missing_docs)]
    function balanceOf(address who) returns (uint256);
    #[allow(missing_docs)]
    function nonces(address owner) returns (uint256);
}

fn call(to: Address, data: Vec<u8>) -> Call {
    Call {
        to,
        value: U256::ZERO,
        data: data.into(),
    }
}

pub fn claim(c: &Contracts, sessions: Vec<B256>) -> Call {
    call(
        c.settlement,
        Settlement::claimCall { sessions }.abi_encode(),
    )
}

pub fn approve(c: &Contracts, spender: Address, amount: U256) -> Call {
    call(c.usdc, approveCall { spender, amount }.abi_encode())
}

/// The paymaster's standing allowance, renewed inside an operation.
pub fn approve_paymaster(c: &Contracts) -> Call {
    approve(c, c.paymaster, U256::from(super::paymaster::ALLOWANCE))
}

/// The eligibility statement, made by the wallet calling the contract
/// itself: no signature, since only the wallet can be the caller.
pub fn make_statement(c: &Contracts) -> Call {
    call(c.settlement, Settlement::makeStatementCall {}.abi_encode())
}

pub fn bets(c: &Contracts, items: Vec<Settlement::BetItem>) -> Call {
    call(c.settlement, Settlement::betManyCall { items }.abi_encode())
}

pub fn transfer(c: &Contracts, to: Address, amount: U256) -> Call {
    call(c.usdc, transferCall { to, amount }.abi_encode())
}

/// A first bet's whole batch: claim, approve exactly the stake, the
/// statement if not yet made, the bets, then the paymaster's allowance
/// renewed.
pub fn bet_batch(
    c: &Contracts,
    claims: Vec<B256>,
    items: Vec<Settlement::BetItem>,
    needs_statement: bool,
    renew_paymaster: bool,
) -> Vec<Call> {
    let total = items.iter().fold(U256::ZERO, |t, i| t + i.amount);
    let mut out = Vec::new();
    if !claims.is_empty() {
        out.push(claim(c, claims));
    }
    out.push(approve(c, c.settlement, total));
    if needs_statement {
        out.push(make_statement(c));
    }
    out.push(bets(c, items));
    if renew_paymaster {
        out.push(approve_paymaster(c));
    }
    out
}

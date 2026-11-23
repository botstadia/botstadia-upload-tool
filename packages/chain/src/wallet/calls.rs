//! The calls an account wallet's operations batch (MONEY.md#placing-bets):
//! claiming whatever is claimable first, so its money can be used, then
//! approving exactly the amount, the eligibility statement if not yet made,
//! and the bets. A withdrawal claims first too.

use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_sol_types::{SolCall, sol};

use super::Contracts;
use super::op::Call;
use crate::abi::{Settlement, StandingOrders};

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

/// A week's claim carries its bound final's entry, or nothing while no
/// result decides it (a refund).
pub fn claim_weeks(c: &Contracts, weeks: Vec<(B256, Bytes)>) -> Call {
    let (weeks_, entries) = weeks.into_iter().unzip();
    call(
        c.settlement,
        Settlement::claimWeeksCall {
            weeks_,
            finalEntries: entries,
        }
        .abi_encode(),
    )
}

/// The entry whose hash is `id` among one `Posted` event's data: a post
/// carries its entries whole, so a week's claim needs nobody's index.
pub fn posted_entry(data: &[u8], id: B256) -> Option<Bytes> {
    let (_, entries) = <(
        alloy_sol_types::sol_data::FixedBytes<32>,
        alloy_sol_types::sol_data::Array<alloy_sol_types::sol_data::Bytes>,
    ) as alloy_sol_types::SolType>::abi_decode_params(data)
    .ok()?;
    entries
        .into_iter()
        .find(|entry| alloy_primitives::keccak256(entry) == id)
}

/// The most pools one operation claims: the rest wait for the next.
pub const CLAIMS_AT_ONCE: usize = 40;

/// What one pool pays a wallet, as the chain answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claimable {
    pub id: B256,
    /// `Some` for a week, with the entry its claim passes.
    pub week: Option<Bytes>,
    pub amount: U256,
}

/// The claims one operation makes first.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Claims {
    pub sessions: Vec<B256>,
    pub weeks: Vec<(B256, Bytes)>,
    /// What they pay together.
    pub total: U256,
}

impl Claims {
    /// The largest first, as many as one operation takes.
    pub fn from_claimable(list: &[Claimable]) -> Self {
        let mut list: Vec<&Claimable> = list.iter().filter(|x| !x.amount.is_zero()).collect();
        list.sort_by_key(|x| std::cmp::Reverse(x.amount));
        let mut out = Self::default();
        for x in list.into_iter().take(CLAIMS_AT_ONCE) {
            match &x.week {
                Some(entry) => out.weeks.push((x.id, entry.clone())),
                None => out.sessions.push(x.id),
            }
            out.total += x.amount;
        }
        out
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty() && self.weeks.is_empty()
    }

    pub fn calls(&self, c: &Contracts) -> Vec<Call> {
        let mut out = Vec::new();
        if !self.sessions.is_empty() {
            out.push(claim(c, self.sessions.clone()));
        }
        if !self.weeks.is_empty() {
            out.push(claim_weeks(c, self.weeks.clone()));
        }
        out
    }
}

pub fn approve(c: &Contracts, spender: Address, amount: U256) -> Call {
    call(c.usdc, approveCall { spender, amount }.abi_encode())
}

/// The paymaster's standing allowance, renewed inside an operation.
pub fn approve_paymaster(c: &Contracts) -> Call {
    approve(c, c.paymaster, U256::from(super::paymaster::ALLOWANCE))
}

/// A builder's shares whose transfer failed, claimed by the payout address.
pub fn claim_builder_owed(c: &Contracts) -> Call {
    call(
        c.settlement,
        Settlement::claimBuilderOwedCall {}.abi_encode(),
    )
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

fn orders(c: &Contracts) -> anyhow::Result<Address> {
    c.standing_orders
        .ok_or_else(|| anyhow::anyhow!("no standing orders on this target"))
}

/// Set, change or clear one auto-back, with `deposit` more set aside for it
/// (MONEY.md#standing-orders): approving exactly the deposit, depositing it,
/// the statement if not yet made (fills need it, as any bet does), then the
/// order itself. An amount of zero clears it.
pub fn order_set(
    c: &Contracts,
    bot: B256,
    amount: U256,
    daily_cap: u32,
    deposit: U256,
    needs_statement: bool,
) -> anyhow::Result<Vec<Call>> {
    let to = orders(c)?;
    let mut out = Vec::new();
    if !deposit.is_zero() {
        out.push(approve(c, to, deposit));
        out.push(call(
            to,
            StandingOrders::depositCall { amount: deposit }.abi_encode(),
        ));
    }
    if needs_statement && !amount.is_zero() {
        out.push(make_statement(c));
    }
    out.push(call(
        to,
        StandingOrders::setOrderCall {
            bot,
            amount,
            dailyCap: daily_cap,
        }
        .abi_encode(),
    ));
    Ok(out)
}

/// More set aside, the orders left as they are.
pub fn order_top_up(c: &Contracts, deposit: U256) -> anyhow::Result<Vec<Call>> {
    let to = orders(c)?;
    Ok(vec![
        approve(c, to, deposit),
        call(
            to,
            StandingOrders::depositCall { amount: deposit }.abi_encode(),
        ),
    ])
}

/// Every order cleared and what's set aside taken back to the wallet, in one
/// operation: what a timeout or exclusion asks the wallet to sign.
pub fn orders_stop(c: &Contracts, bots: Vec<B256>, balance: U256) -> anyhow::Result<Vec<Call>> {
    let to = orders(c)?;
    let mut out: Vec<Call> = bots
        .into_iter()
        .map(|bot| {
            call(
                to,
                StandingOrders::setOrderCall {
                    bot,
                    amount: U256::ZERO,
                    dailyCap: 0,
                }
                .abi_encode(),
            )
        })
        .collect();
    if !balance.is_zero() {
        out.push(call(
            to,
            StandingOrders::withdrawCall { amount: balance }.abi_encode(),
        ));
    }
    Ok(out)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn contracts(orders: Option<Address>) -> Contracts {
        let mut c: Contracts = serde_json::from_value(serde_json::json!({
            "chain_id": 84532,
            "entry_point": Address::repeat_byte(1),
            "safe_singleton": Address::repeat_byte(2),
            "proxy_factory": Address::repeat_byte(3),
            "safe_4337_module": Address::repeat_byte(4),
            "safe_module_setup": Address::repeat_byte(5),
            "multi_send": Address::repeat_byte(6),
            "multi_send_call_only": Address::repeat_byte(7),
            "webauthn_shared_signer": Address::repeat_byte(8),
            "webauthn_signer_factory": Address::repeat_byte(9),
            "p256_verifiers": "0x100",
            "usdc": Address::repeat_byte(10),
            "paymaster": Address::repeat_byte(11),
            "settlement": Address::repeat_byte(12),
        }))
        .unwrap();
        assert_eq!(c.standing_orders, None, "an older setup still reads");
        c.standing_orders = orders;
        c
    }

    #[test]
    fn an_order_is_set_with_exactly_its_deposit_approved() {
        let orders = Address::repeat_byte(13);
        let c = contracts(Some(orders));
        let bot = B256::repeat_byte(14);
        let calls = order_set(
            &c,
            bot,
            U256::from(5_000_000),
            3,
            U256::from(20_000_000),
            true,
        )
        .unwrap();
        let targets: Vec<Address> = calls.iter().map(|x| x.to).collect();
        assert_eq!(
            targets,
            [c.usdc, orders, c.settlement, orders],
            "approve, deposit, statement, order"
        );
        assert_eq!(
            approveCall::abi_decode(&calls[0].data).unwrap().amount,
            U256::from(20_000_000)
        );
        let set = StandingOrders::setOrderCall::abi_decode(&calls[3].data).unwrap();
        assert_eq!(
            (set.bot, set.amount, set.dailyCap),
            (bot, U256::from(5_000_000), 3)
        );
        // A change with no more money: the order alone; clearing needs no statement.
        assert_eq!(
            order_set(&c, bot, U256::from(2_000_000), 3, U256::ZERO, false)
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            order_set(&c, bot, U256::ZERO, 0, U256::ZERO, true)
                .unwrap()
                .len(),
            1
        );
        assert!(order_set(&contracts(None), bot, U256::from(1), 1, U256::ZERO, false).is_err());
    }

    #[test]
    fn stopping_clears_each_order_and_takes_the_money_back_at_once() {
        let orders = Address::repeat_byte(13);
        let c = contracts(Some(orders));
        let calls = orders_stop(
            &c,
            vec![B256::repeat_byte(1), B256::repeat_byte(2)],
            U256::from(7),
        )
        .unwrap();
        assert_eq!(calls.len(), 3);
        assert!(calls.iter().all(|x| x.to == orders));
        assert_eq!(
            StandingOrders::withdrawCall::abi_decode(&calls[2].data)
                .unwrap()
                .amount,
            U256::from(7)
        );
    }

    #[test]
    fn a_finals_entry_is_found_in_its_post() {
        use alloy_sol_types::SolEvent;
        let entry = Bytes::from(vec![5u8; 130]);
        let posted = crate::abi::Results::Posted {
            post: 9,
            root: B256::ZERO,
            entries: vec![Bytes::from(vec![1u8; 33]), entry.clone()],
        };
        let data = posted.encode_data();
        let id = alloy_primitives::keccak256(&entry);
        assert_eq!(posted_entry(&data, id), Some(entry));
        assert_eq!(posted_entry(&data, B256::ZERO), None);
    }

    #[test]
    fn one_operation_claims_the_largest_first_weeks_included() {
        let mut list: Vec<Claimable> = (1..=50u64)
            .map(|i| Claimable {
                id: B256::from(U256::from(i)),
                week: None,
                amount: U256::from(i),
            })
            .collect();
        let entry = Bytes::from(vec![0xe1]);
        list.push(Claimable {
            id: B256::repeat_byte(7),
            week: Some(entry.clone()),
            amount: U256::from(1_000u64),
        });
        let claims = Claims::from_claimable(&list);
        assert_eq!(claims.sessions.len(), CLAIMS_AT_ONCE - 1);
        assert_eq!(claims.weeks, vec![(B256::repeat_byte(7), entry)]);
        assert!(!claims.sessions.contains(&B256::from(U256::from(1u64))));
        let sessions: u64 = (12..=50).sum();
        assert_eq!(claims.total, U256::from(1_000 + sessions));
    }
}

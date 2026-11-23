//! A wallet's money at one block: its USDC and what each of its pools pays
//! it, read together through Multicall3, so a balance is never added to a
//! claim it already holds, and a refresh costs a call or a few however many
//! pools there are.

use alloy_primitives::{Address, B256, Bytes, U256, address};
use alloy_sol_types::{SolCall, sol};

use super::Contracts;
use super::calls::{Claimable, balanceOfCall};
use crate::abi::Settlement;
use crate::rpc::{BlockTag, Client, Transport};

/// Multicall3, at the same address on Base and Base Sepolia.
pub const MULTICALL3: Address = address!("cA11bde05977b3631167028862bE2a173976CA11");

/// The pools one `eth_call` reads.
pub const POOLS_A_CALL: usize = 200;

sol! {
    #[allow(missing_docs)]
    struct Call3 { address target; bool allowFailure; bytes callData; }
    #[allow(missing_docs)]
    struct Returned { bool success; bytes returnData; }
    #[allow(missing_docs)]
    function aggregate3(Call3[] calls) payable returns (Returned[] returnData);
    #[allow(missing_docs)]
    function getBlockNumber() returns (uint256 blockNumber);
}

/// A pool to ask about.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pool {
    pub id: B256,
    /// `Some` for a week, with the entry its claim passes.
    pub week: Option<Bytes>,
}

impl From<&Claimable> for Pool {
    fn from(x: &Claimable) -> Self {
        Self {
            id: x.id,
            week: x.week.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Money {
    pub usdc: U256,
    /// Only what pays.
    pub claimable: Vec<Claimable>,
    /// Pools the chain wouldn't answer for, left out.
    pub unread: usize,
}

/// The wallet's USDC and what `pools` pay it, all at one block.
pub async fn read<T: Transport>(
    rpc: &Client<T>,
    c: &Contracts,
    wallet: Address,
    pools: &[Pool],
) -> anyhow::Result<Money> {
    let ask = |pool: &Pool| Call3 {
        target: c.settlement,
        allowFailure: true,
        callData: match &pool.week {
            Some(entry) => Settlement::weekClaimableCall {
                week: pool.id,
                bettor: wallet,
                finalEntry: entry.clone(),
            }
            .abi_encode(),
            None => Settlement::claimableCall {
                session: pool.id,
                bettor: wallet,
            }
            .abi_encode(),
        }
        .into(),
    };
    let mut first = vec![
        Call3 {
            target: MULTICALL3,
            allowFailure: false,
            callData: getBlockNumberCall {}.abi_encode().into(),
        },
        Call3 {
            target: c.usdc,
            allowFailure: false,
            callData: balanceOfCall { who: wallet }.abi_encode().into(),
        },
    ];
    let head = pools.len().min(POOLS_A_CALL);
    first.extend(pools[..head].iter().map(ask));
    let answers = rpc
        .call_typed(
            MULTICALL3,
            &aggregate3Call { calls: first },
            BlockTag::Latest,
        )
        .await?;
    anyhow::ensure!(answers.len() == head + 2, "a short multicall answer");
    let block = getBlockNumberCall::abi_decode_returns(&answers[0].returnData)?;
    let usdc = balanceOfCall::abi_decode_returns(&answers[1].returnData)?;
    let mut claimable = Vec::new();
    let mut unread = answers[2..].iter().filter(|a| !a.success).count();
    take(&pools[..head], &answers[2..], &mut claimable);

    // The rest at that same block.
    let at = BlockTag::Number(u64::try_from(block)?);
    for chunk in pools[head..].chunks(POOLS_A_CALL) {
        let call = aggregate3Call {
            calls: chunk.iter().map(ask).collect(),
        };
        let answers = rpc.call_typed(MULTICALL3, &call, at).await?;
        anyhow::ensure!(answers.len() == chunk.len(), "a short multicall answer");
        unread += answers.iter().filter(|a| !a.success).count();
        take(chunk, &answers, &mut claimable);
    }
    Ok(Money {
        usdc,
        claimable,
        unread,
    })
}

fn take(pools: &[Pool], answers: &[Returned], out: &mut Vec<Claimable>) {
    for (pool, answer) in pools.iter().zip(answers) {
        if !answer.success {
            continue;
        }
        let amount = match &pool.week {
            Some(_) => Settlement::weekClaimableCall::abi_decode_returns(&answer.returnData)
                .map(|r| r.amount),
            None => {
                Settlement::claimableCall::abi_decode_returns(&answer.returnData).map(|r| r.amount)
            }
        };
        if let Ok(amount) = amount
            && !amount.is_zero()
        {
            out.push(Claimable {
                id: pool.id,
                week: pool.week.clone(),
                amount,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_sol_types::SolValue;
    use serde_json::{Value, json};
    use std::cell::RefCell;

    /// Answers a multicall: block 77, $9, every pool paying 5 but the third,
    /// which reverts. Notes the block each call named.
    struct Node(RefCell<Vec<Value>>);

    impl Transport for &Node {
        async fn post(&self, body: String) -> anyhow::Result<String> {
            let req: Value = serde_json::from_str(&body)?;
            self.0.borrow_mut().push(req["params"][1].clone());
            let data: Bytes = req["params"][0]["data"].as_str().unwrap().parse()?;
            let out: Vec<Returned> = aggregate3Call::abi_decode(&data)?
                .calls
                .iter()
                .map(|call| {
                    let (success, value) = if call.target == MULTICALL3 {
                        (true, U256::from(77u64).abi_encode())
                    } else if call.callData.starts_with(&balanceOfCall::SELECTOR) {
                        (true, U256::from(9_000_000u64).abi_encode())
                    } else if call.callData[4..36] == B256::from(U256::from(2u64)).0 {
                        (false, Vec::new())
                    } else {
                        (true, (U256::from(5u64), false).abi_encode())
                    };
                    Returned {
                        success,
                        returnData: value.into(),
                    }
                })
                .collect();
            let result = Bytes::from(aggregate3Call::abi_encode_returns(&out));
            Ok(json!({"jsonrpc": "2.0", "id": 1, "result": result}).to_string())
        }
    }

    #[tokio::test]
    async fn money_is_read_at_one_block_however_many_pools() {
        let a = format!("{:#x}", Address::repeat_byte(1));
        let c: Contracts = serde_json::from_value(json!({
            "chain_id": 84532,
            "entry_point": a, "safe_singleton": a, "proxy_factory": a,
            "safe_4337_module": a, "safe_module_setup": a, "multi_send": a,
            "multi_send_call_only": a, "webauthn_shared_signer": a,
            "webauthn_signer_factory": a,
            "p256_verifiers": "0x1000000000000000000000000000000000000000000",
            "usdc": format!("{:#x}", Address::repeat_byte(2)),
            "usdc_name": "USDC", "paymaster": a,
            "settlement": format!("{:#x}", Address::repeat_byte(3)),
        }))
        .unwrap();
        let pools: Vec<Pool> = (0..450u64)
            .map(|i| Pool {
                id: B256::from(U256::from(i)),
                week: (i % 7 == 0).then(Bytes::new),
            })
            .collect();
        let node = Node(RefCell::new(Vec::new()));
        let money = read(&Client::new(&node), &c, Address::repeat_byte(4), &pools)
            .await
            .unwrap();
        assert_eq!(money.usdc, U256::from(9_000_000u64));
        assert_eq!(
            money.claimable.len(),
            449,
            "the one that reverts pays nothing"
        );
        assert_eq!(money.unread, 1, "the one that reverts is said to be unread");
        assert_eq!(
            *node.0.borrow(),
            vec![json!("latest"), json!("0x4d"), json!("0x4d")]
        );
    }
}

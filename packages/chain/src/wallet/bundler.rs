//! ERC-4337 bundlers over JSON-RPC (TRUST.md#deploying-a-wallet).
//!
//! Operations go to one bundler at a time, failing over to the next, never
//! to both at once: a bundler that refuses an operation on its merits (a
//! validation failure, a rule broken) is the operation's answer, and only a
//! bundler that can't be reached, or errors on its own side, passes it on.

use alloy_primitives::{B256, U256};
use serde::Deserialize;
use serde_json::{Value, json};

use super::Contracts;
use super::op::UserOp;
use crate::rpc::{Client, NodeError, Transport};

/// Which gas-price method a bundler answers: each runs its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flavor {
    /// `pimlico_getUserOperationGasPrice`.
    Pimlico,
    /// Alchemy's Rundler: `rundler_maxPriorityFeePerGas` plus the base fee.
    Alchemy,
    /// Anything else: the node's own fee methods.
    Generic,
}

pub struct Bundler<T> {
    pub name: String,
    pub flavor: Flavor,
    pub rpc: Client<T>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GasPrice {
    pub max_fee_per_gas: U256,
    pub max_priority_fee_per_gas: U256,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Estimate {
    pub pre_verification_gas: U256,
    pub verification_gas_limit: U256,
    pub call_gas_limit: U256,
    #[serde(default)]
    pub paymaster_verification_gas_limit: Option<U256>,
    #[serde(default)]
    pub paymaster_post_op_gas_limit: Option<U256>,
}

/// What a receipt says about an included operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpReceipt {
    pub success: bool,
    pub actual_gas_used: U256,
    pub actual_gas_cost: U256,
    pub transaction_hash: B256,
    pub block_number: u64,
    pub reason: Option<String>,
}

fn u256(v: &Value) -> anyhow::Result<U256> {
    let s = v
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("not a hex quantity: {v}"))?;
    Ok(U256::from_str_radix(s.trim_start_matches("0x"), 16)?)
}

impl<T: Transport> Bundler<T> {
    pub fn new(name: impl Into<String>, flavor: Flavor, transport: T) -> Self {
        Self {
            name: name.into(),
            flavor,
            rpc: Client::new(transport),
        }
    }

    pub async fn supported_entry_points(&self) -> anyhow::Result<Vec<String>> {
        let v = self
            .rpc
            .request("eth_supportedEntryPoints", json!([]))
            .await?;
        Ok(serde_json::from_value(v)?)
    }

    pub async fn gas_price(&self) -> anyhow::Result<GasPrice> {
        match self.flavor {
            Flavor::Pimlico => {
                let v = self
                    .rpc
                    .request("pimlico_getUserOperationGasPrice", json!([]))
                    .await?;
                Ok(GasPrice {
                    max_fee_per_gas: u256(&v["fast"]["maxFeePerGas"])?,
                    max_priority_fee_per_gas: u256(&v["fast"]["maxPriorityFeePerGas"])?,
                })
            }
            Flavor::Alchemy | Flavor::Generic => {
                let tip = if self.flavor == Flavor::Alchemy {
                    u256(
                        &self
                            .rpc
                            .request("rundler_maxPriorityFeePerGas", json!([]))
                            .await?,
                    )?
                } else {
                    u256(
                        &self
                            .rpc
                            .request("eth_maxPriorityFeePerGas", json!([]))
                            .await?,
                    )?
                };
                let block = self
                    .rpc
                    .request("eth_getBlockByNumber", json!(["latest", false]))
                    .await?;
                let base = u256(&block["baseFeePerGas"])?;
                // Headroom for two full blocks of base-fee rises, as wallets do.
                let tip = tip + tip / U256::from(4);
                Ok(GasPrice {
                    max_fee_per_gas: base * U256::from(2) + tip,
                    max_priority_fee_per_gas: tip,
                })
            }
        }
    }

    pub async fn estimate(&self, c: &Contracts, op: &UserOp) -> anyhow::Result<Estimate> {
        let v = self
            .rpc
            .request(
                "eth_estimateUserOperationGas",
                json!([op, format!("{:#x}", c.entry_point)]),
            )
            .await?;
        Ok(serde_json::from_value(v)?)
    }

    pub async fn send(&self, c: &Contracts, op: &UserOp) -> anyhow::Result<B256> {
        let v = self
            .rpc
            .request(
                "eth_sendUserOperation",
                json!([op, format!("{:#x}", c.entry_point)]),
            )
            .await?;
        Ok(serde_json::from_value(v)?)
    }

    /// The receipt once included, `None` while pending.
    pub async fn receipt(&self, hash: B256) -> anyhow::Result<Option<OpReceipt>> {
        let v = self
            .rpc
            .request("eth_getUserOperationReceipt", json!([hash]))
            .await?;
        if v.is_null() {
            return Ok(None);
        }
        let receipt = &v["receipt"];
        Ok(Some(OpReceipt {
            success: v["success"].as_bool().unwrap_or(false),
            actual_gas_used: u256(&v["actualGasUsed"])?,
            actual_gas_cost: u256(&v["actualGasCost"])?,
            transaction_hash: serde_json::from_value(receipt["transactionHash"].clone())?,
            block_number: u256(&receipt["blockNumber"])?.to::<u64>(),
            reason: v["reason"]
                .as_str()
                .filter(|r| !r.is_empty() && *r != "0x")
                .map(str::to_string),
        }))
    }

    /// Whether this bundler knows the operation (pending or included).
    pub async fn knows(&self, hash: B256) -> anyhow::Result<bool> {
        let v = self
            .rpc
            .request("eth_getUserOperationByHash", json!([hash]))
            .await?;
        Ok(!v.is_null())
    }
}

/// Whether an error is the bundler refusing the operation itself (its
/// answer, final) rather than the bundler failing (pass it on).
pub fn is_refusal(e: &anyhow::Error) -> bool {
    e.downcast_ref::<NodeError>().is_some_and(|n| {
        // JSON-RPC's own invalid-params, ERC-7769's -32500..=-32508 and the
        // estimate's revert (-32521) are verdicts on the operation; a
        // throttle (-32504), -32603 and transport errors are the bundler's
        // own trouble, passed on.
        n.code == -32602
            || n.code == -32521
            || ((-32508..=-32500).contains(&n.code) && n.code != -32504)
    })
}

/// Bundlers in failover order.
pub struct Bundlers<T> {
    pub list: Vec<Bundler<T>>,
}

impl<T: Transport> Bundlers<T> {
    /// Run `f` on the first bundler that answers, moving on only when one
    /// fails on its own side. A refusal is returned as is.
    pub async fn first<R>(
        &self,
        mut f: impl AsyncFnMut(&Bundler<T>) -> anyhow::Result<R>,
    ) -> anyhow::Result<(usize, R)> {
        let mut errors = Vec::new();
        for (i, b) in self.list.iter().enumerate() {
            match f(b).await {
                Ok(r) => return Ok((i, r)),
                Err(e) if is_refusal(&e) => return Err(e.context(format!("{} refused it", b.name))),
                Err(e) => errors.push(format!("{}: {e:#}", b.name)),
            }
        }
        anyhow::bail!("no bundler answered: {}", errors.join("; "))
    }

    /// Send to one bundler at a time. Before passing an operation on after a
    /// failure, ask the failed bundler whether it holds it anyway, so it's
    /// never with two at once.
    pub async fn send(&self, c: &Contracts, op: &UserOp) -> anyhow::Result<(usize, B256)> {
        let hash = op.hash(c);
        let mut errors = Vec::new();
        for (i, b) in self.list.iter().enumerate() {
            match b.send(c, op).await {
                Ok(h) => return Ok((i, h)),
                Err(e) if is_refusal(&e) => return Err(e.context(format!("{} refused it", b.name))),
                Err(e) => {
                    // Only a bundler known not to hold it passes it on: one
                    // that can't say might yet include it.
                    match b.knows(hash).await {
                        Ok(true) => return Ok((i, hash)),
                        Ok(false) => errors.push(format!("{}: {e:#}", b.name)),
                        Err(k) => anyhow::bail!(
                            "{} failed and can't say whether it holds the operation ({e:#}; {k:#}): not sending it elsewhere",
                            b.name
                        ),
                    }
                }
            }
        }
        anyhow::bail!("no bundler took the operation: {}", errors.join("; "))
    }
}

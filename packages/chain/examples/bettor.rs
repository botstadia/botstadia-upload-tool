//! A test bettor on the testnet (README "The testnet"), since the site's wallets
//! aren't wired yet. Each bettor is a plain key holding testnet USDC.
//!
//! - `bettor setup`: approve the settlement contract for USDC, and record
//!   the eligibility statement, signed;
//! - `bettor bet <session id> <entrant position> <usdc>`: back an entrant,
//!   opening the pool with the session's post entry if it isn't open yet;
//! - `bettor bet-week <week id> <field index> <usdc>`: back a field bot to
//!   win the week, opening the week-winner pool if needed;
//! - `bettor claim <session id>...` and `bettor claim-week <week id>
//!   <final entry hex>`;
//! - `bettor balance`.
//!
//! The key (`SEND_KEY`), the RPC URL (`SEND_RPC`), the api (`API_URL`), the
//! settlement contract (`SETTLEMENT`) and USDC (`TOKEN`) come from the
//! environment, never the command line. `task chain:bettor-testnet` sets
//! them for one of the three test bettors (`CHAIN_TESTNET_BETTOR_n_KEY`).

use std::time::Duration;

use alloy_sol_types::SolCall;
use anyhow::{Context, bail, ensure};
use botstadia_chain::abi::Settlement;
use botstadia_chain::rpc::{BlockTag, Client, Http};
use botstadia_chain::sign::Key;
use botstadia_chain::{Address, B256, Bytes, U256, tx};
use serde_json::Value;

alloy_sol_types::sol! {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

struct Env {
    key: Key,
    rpc: Client<Http>,
    api: String,
    settlement: Address,
    token: Address,
}

fn var(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("{name} isn't set"))
}

fn usdc(amount: &str) -> anyhow::Result<U256> {
    let v: f64 = amount.parse().context("an amount in USDC")?;
    ensure!(v > 0.0, "an amount above zero");
    Ok(U256::from((v * 1_000_000.0).round() as u64))
}

fn get(url: &str) -> anyhow::Result<Value> {
    let body = reqwest_blocking(url)?;
    Ok(serde_json::from_str(&body)?)
}

fn reqwest_blocking(url: &str) -> anyhow::Result<String> {
    let rt = tokio::runtime::Handle::current();
    let url = url.to_string();
    tokio::task::block_in_place(|| {
        rt.block_on(async move {
            let r = reqwest::get(&url).await?;
            ensure!(r.status().is_success(), "{url}: {}", r.status());
            Ok(r.text().await?)
        })
    })
}

impl Env {
    async fn send(&self, to: Address, data: Vec<u8>) -> anyhow::Result<B256> {
        let chain_id = self.rpc.chain_id().await?;
        let from = self.key.address();
        let nonce = self.rpc.nonce(from, BlockTag::Latest).await?;
        let gas = self.rpc.estimate_gas(from, to, &data).await?;
        let price = self.rpc.gas_price().await?.max(1);
        let signed = tx::sign(
            &self.key,
            chain_id,
            nonce,
            gas * 3 / 2,
            tx::Fees {
                max_fee_per_gas: price * 2,
                max_priority_fee_per_gas: price,
            },
            &tx::Call {
                to,
                data,
                value: U256::ZERO,
            },
        )?;
        self.rpc.send_raw(&signed.raw).await?;
        for _ in 0..120 {
            if let Some(r) = self.rpc.receipt(signed.hash).await? {
                ensure!(r.succeeded(), "transaction {} reverted", signed.hash);
                return Ok(signed.hash);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        bail!("transaction {} not included after two minutes", signed.hash)
    }

    async fn balance(&self) -> anyhow::Result<U256> {
        self.rpc
            .call_typed(
                self.token,
                &balanceOfCall {
                    who: self.key.address(),
                },
                BlockTag::Latest,
            )
            .await
    }
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let e = Env {
        key: Key::from_hex(&var("SEND_KEY")?)?,
        rpc: Client::new(Http::new(var("SEND_RPC")?)),
        api: var("API_URL")?.trim_end_matches('/').to_string(),
        settlement: var("SETTLEMENT")?.parse()?,
        token: var("TOKEN")?.parse()?,
    };
    let me = e.key.address();
    match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        ["setup"] => {
            e.send(
                e.token,
                approveCall {
                    spender: e.settlement,
                    amount: U256::MAX,
                }
                .abi_encode(),
            )
            .await?;
            let digest = e
                .rpc
                .call_typed(
                    e.settlement,
                    &Settlement::statementDigestCall { wallet: me },
                    BlockTag::Latest,
                )
                .await?;
            let signature = e.key.sign_hash(digest)?;
            let hash = e
                .send(
                    e.settlement,
                    Settlement::recordStatementCall {
                        wallet: me,
                        signature: Bytes::from(signature.as_bytes().to_vec()),
                    }
                    .abi_encode(),
                )
                .await?;
            println!("{me:#x}: approved and statement recorded ({hash})");
        }
        ["balance"] => println!("{me:#x}: {} USDC (millionths)", e.balance().await?),
        ["bet", session, position, amount] => {
            let s = get(&format!("{}/public/session?id={session}", e.api))?;
            let id: B256 = session.parse()?;
            let pos: usize = position.parse()?;
            let spec: botstadia_chain::spec::Spec = serde_json::from_value(s["spec"].clone())?;
            let bot = *spec
                .digests
                .get(pos)
                .context("no entrant at that position")?;
            let amount = usdc(amount)?;
            let open = e
                .rpc
                .call_typed(
                    e.settlement,
                    &Settlement::poolOpenCall { session: id },
                    BlockTag::Latest,
                )
                .await?;
            let data = if open {
                Settlement::betForCall {
                    session: id,
                    bot,
                    amount,
                    bettor: me,
                }
                .abi_encode()
            } else {
                let entry = hex::decode(
                    s["entry"]
                        .as_str()
                        .context("entry")?
                        .trim_start_matches("0x"),
                )?;
                let proof: Vec<B256> = serde_json::from_value(s["proof"].clone())?;
                Settlement::openAndBetForCall {
                    opening: Settlement::Opening {
                        post: s["post_number"].as_u64().context("post")?,
                        entry: entry.into(),
                        proof,
                        spec: spec.to_sol(),
                    },
                    bot,
                    amount,
                    bettor: me,
                }
                .abi_encode()
            };
            let hash = e.send(e.settlement, data).await?;
            println!(
                "{me:#x}: bet on entrant {pos} of {session} ({hash}{})",
                if open { "" } else { ", opening the pool" }
            );
        }
        ["bet-week", week, index, amount] => {
            let w = get(&format!("{}/public/week?id={week}", e.api))?;
            let field = &w["field"][index.parse::<usize>()?];
            let bytes = hex::decode(
                field["leaf"]
                    .as_str()
                    .context("leaf")?
                    .trim_start_matches("0x"),
            )?;
            let l = botstadia_chain::entry::FieldLeaf::decode(&bytes)?;
            let leaf = Settlement::FieldLeaf {
                digest: l.digest,
                payout: l.payout,
                mu: l.mu,
                sigma: l.sigma,
                group: l.group,
            };
            let proof: Vec<B256> = serde_json::from_value(field["proof"].clone())?;
            let id: B256 = week.parse()?;
            let amount = usdc(amount)?;
            let open = e
                .rpc
                .call_typed(
                    e.settlement,
                    &Settlement::weekPoolOpenCall { week: id },
                    BlockTag::Latest,
                )
                .await?;
            let data = if open {
                Settlement::betWeekForCall {
                    week: id,
                    leaf,
                    leafProof: proof,
                    amount,
                    bettor: me,
                }
                .abi_encode()
            } else {
                Settlement::openAndBetWeekForCall {
                    opening: Settlement::WeekOpening {
                        week: id,
                        entry: w["field_entry"].as_str().context("field entry")?.parse()?,
                    },
                    leaf,
                    leafProof: proof,
                    amount,
                    bettor: me,
                }
                .abi_encode()
            };
            let hash = e.send(e.settlement, data).await?;
            println!("{me:#x}: backed field bot {index} to win {week} ({hash})");
        }
        ["claim", sessions @ ..] if !sessions.is_empty() => {
            let ids: Vec<B256> = sessions
                .iter()
                .map(|s| s.parse())
                .collect::<Result<_, _>>()?;
            let before = e.balance().await?;
            let hash = e
                .send(
                    e.settlement,
                    Settlement::claimCall { sessions: ids }.abi_encode(),
                )
                .await?;
            println!(
                "{me:#x}: claimed {} (millionths) ({hash})",
                e.balance().await? - before
            );
        }
        ["claim-week", week, final_entry] => {
            let entry = hex::decode(final_entry.trim_start_matches("0x"))?;
            let before = e.balance().await?;
            let hash = e
                .send(
                    e.settlement,
                    Settlement::claimWeeksCall {
                        weeks_: vec![week.parse()?],
                        finalEntries: vec![entry.into()],
                    }
                    .abi_encode(),
                )
                .await?;
            println!(
                "{me:#x}: claimed {} (millionths) from {week} ({hash})",
                e.balance().await? - before
            );
        }
        _ => bail!(
            "usage: bettor setup | balance | bet <session> <position> <usdc> | bet-week <week> <index> <usdc> | claim <session>... | claim-week <week> <final entry>"
        ),
    }
    Ok(())
}

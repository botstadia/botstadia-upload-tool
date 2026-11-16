//! Measures the Base facts BEFORE-PROD's "prove first" #6 asks for, on
//! whichever chain `FACTS_RPC` serves: the block rate, the finality lag,
//! `P256VERIFY` and, when `SEND_KEY` is set, the transaction size limit.
//!
//! The size probe sends two zero-filled self-transfers to the sequencer,
//! one just under the clients' default limit (128 KiB of encoded
//! transaction), which should land, and one just over, which should be
//! refused before it costs anything. Zero bytes keep the landed one cheap.
//! Throttling of large transactions can't be provoked on purpose; it's read
//! from the size a sequencer holds back when it happens.
//!
//! Keys and RPC URLs come from the environment, never the command line:
//! `task chain:base-facts-testnet`.

use std::time::Duration;

use anyhow::{Context, bail};
use botstadia_chain::rpc::{BlockTag, Client, Http};
use botstadia_chain::sign::Key;
use botstadia_chain::{U256, tx};
use serde_json::json;

/// A throwaway P-256 key's signature over sha256("botstadia p256verify
/// probe"): hash, r, s, x, y (RIP-7212's input).
const P256_VECTOR: &str = concat!(
    "b786f4677da9a2dd4902318a784452f6e44e82ef58df85b76af0f5cf12419287",
    "2aa21963d87ddb501e7b873eb1858a112b07712e540d1a7c4a3d77ec502b4a9b",
    "32770460fc047390dec26e7817163ff53e11bc03362cc02513350fe0aac270fe",
    "a06db1c0d9f1d7755df8e9ebc263a33a33d538b5d6d4874dd5dcbb1eebc483fe",
    "6aab4af502406ba0bc05918dce37edebedb66c44ff820af8796b61f77c9ccef2",
);
const P256VERIFY: &str = "0x0000000000000000000000000000000000000100";

/// The clients' default limit on one encoded transaction.
const DEFAULT_LIMIT: usize = 128 * 1024;

async fn p256(rpc: &Client<Http>, input: &str) -> anyhow::Result<String> {
    let v = rpc
        .request(
            "eth_call",
            json!([{"to": P256VERIFY, "data": format!("0x{input}")}, "latest"]),
        )
        .await?;
    Ok(v.as_str().unwrap_or_default().to_string())
}

/// A zero-filled self-transfer whose encoded size is close to `target`.
async fn sized(
    rpc: &Client<Http>,
    key: &Key,
    nonce: u64,
    target: usize,
) -> anyhow::Result<tx::Signed> {
    let chain_id = rpc.chain_id().await?;
    let price = rpc.gas_price().await?.max(1);
    let sign = |len: usize| {
        let data = vec![0u8; len];
        // 4 gas a zero byte, but the calldata floor (EIP-7623) is 10.
        let gas = 21_000 + 12 * len as u64;
        tx::sign(
            key,
            chain_id,
            nonce,
            gas,
            tx::Fees {
                max_fee_per_gas: price * 2,
                max_priority_fee_per_gas: price,
            },
            &tx::Call {
                to: key.address(),
                data,
                value: U256::ZERO,
            },
        )
    };
    let overhead = sign(0)?.raw.len() + 8;
    sign(target.saturating_sub(overhead))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let rpc = Client::new(Http::new(std::env::var("FACTS_RPC").context("FACTS_RPC")?));
    let chain_id = rpc.chain_id().await?;
    println!("chain {chain_id}");

    // Block rate, over the last thousand blocks.
    let head = rpc.block(BlockTag::Latest).await?;
    let back = rpc.block(BlockTag::Number(head.number - 1000)).await?;
    println!(
        "block rate: {:.3} s a block over the last 1000 (head {})",
        (head.timestamp - back.timestamp) as f64 / 1000.0,
        head.number
    );

    // Finality: how far the finalized block trails the head, sampled.
    let mut lags = Vec::new();
    for i in 0..5 {
        if i > 0 {
            tokio::time::sleep(Duration::from_secs(20)).await;
        }
        let head = rpc.block(BlockTag::Latest).await?;
        let fin = rpc.block(BlockTag::Finalized).await?;
        lags.push((head.timestamp - fin.timestamp, head.number - fin.number));
    }
    let (min, max) = (
        lags.iter().map(|l| l.0).min().unwrap_or(0),
        lags.iter().map(|l| l.0).max().unwrap_or(0),
    );
    println!(
        "finality lag: {min}–{max} s ({:.1}–{:.1} min) over 5 samples, {} blocks at the last",
        min as f64 / 60.0,
        max as f64 / 60.0,
        lags.last().map(|l| l.1).unwrap_or(0)
    );

    // P256VERIFY: a good signature returns 1; a bad one returns nothing,
    // as does a chain without the precompile, so only the 1 proves it.
    let good = p256(&rpc, P256_VECTOR).await?;
    let mut bad = P256_VECTOR.to_string();
    bad.replace_range(0..2, "b8");
    let bad = p256(&rpc, &bad).await?;
    let one = format!("0x{:064x}", 1);
    println!(
        "P256VERIFY: {} (good signature {}, tampered {})",
        if good == one && bad == "0x" {
            "present"
        } else {
            "ABSENT OR WRONG"
        },
        if good == one { "1" } else { good.as_str() },
        if bad == "0x" { "empty" } else { bad.as_str() },
    );

    // The size limit, if a key is given.
    let Ok(key) = std::env::var("SEND_KEY") else {
        println!("size limit: not probed (no SEND_KEY)");
        return Ok(());
    };
    let key = Key::from_hex(&key)?;
    let nonce = rpc.nonce(key.address(), BlockTag::Latest).await?;
    let over = sized(&rpc, &key, nonce, DEFAULT_LIMIT + 1024).await?;
    match rpc.send_raw(&over.raw).await {
        Ok(_) => println!(
            "size limit: a {}-byte transaction was ACCEPTED (over the default)",
            over.raw.len()
        ),
        Err(e) => println!(
            "size limit: a {}-byte transaction refused: {e:#}",
            over.raw.len()
        ),
    }
    let under = sized(&rpc, &key, nonce, DEFAULT_LIMIT - 1024).await?;
    rpc.send_raw(&under.raw)
        .await
        .with_context(|| format!("a {}-byte transaction", under.raw.len()))?;
    for _ in 0..120 {
        if let Some(r) = rpc.receipt(under.hash).await? {
            println!(
                "size limit: a {}-byte transaction landed in block {} ({} gas, {})",
                under.raw.len(),
                r.block_number,
                r.gas_used,
                under.hash
            );
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!(
        "the {}-byte transaction wasn't included after two minutes",
        under.raw.len()
    )
}

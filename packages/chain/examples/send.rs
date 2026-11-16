//! Sends one transaction and waits for it: `send <to> <calldata hex>`.
//!
//! The key (`SEND_KEY`) and the RPC URL (`SEND_RPC`, which may carry a
//! provider key) come from the environment, never the command line, where
//! any process could read them. The testnet's admin tasks use it with its hot
//! admin key (`task chain:admin-testnet`).

use std::time::Duration;

use anyhow::{Context, bail, ensure};
use botstadia_chain::rpc::{BlockTag, Client, Http};
use botstadia_chain::sign::Key;
use botstadia_chain::{Address, U256, tx};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [to, data] = args.as_slice() else {
        bail!("usage: send <to> <calldata hex>");
    };
    let to: Address = to.parse().context("the recipient")?;
    let data = hex::decode(data.trim_start_matches("0x")).context("the calldata")?;
    let key = Key::from_hex(&std::env::var("SEND_KEY").context("SEND_KEY")?)?;
    let rpc = Client::new(Http::new(std::env::var("SEND_RPC").context("SEND_RPC")?));
    let chain_id = rpc.chain_id().await?;
    let nonce = rpc.nonce(key.address(), BlockTag::Latest).await?;
    let gas = rpc.estimate_gas(key.address(), to, &data).await?;
    let price = rpc.gas_price().await?.max(1);
    let signed = tx::sign(
        &key,
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
    rpc.send_raw(&signed.raw).await?;
    for _ in 0..120 {
        if let Some(r) = rpc.receipt(signed.hash).await? {
            ensure!(r.succeeded(), "transaction {} reverted", signed.hash);
            println!("{} included, from {}", signed.hash, key.address());
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    bail!("transaction {} not included after two minutes", signed.hash)
}

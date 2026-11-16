//! JSON-RPC behind one transport trait, so the same reads and sends work
//! natively (HTTP, feature `native`) and in Workers (fetch, feature
//! `worker`), and tests can stand in a fake.
//!
//! Reads that a decision rests on name a block ([`BlockTag`]), so two
//! providers' answers compare directly (TRUST.md#how-the-enclave-talks-to-the-chain).

use alloy_primitives::{Address, B256, Bytes, U256};
use serde::Deserialize;
use serde_json::{Value, json};

/// Sends one JSON-RPC request body and returns the response body.
#[allow(async_fn_in_trait)]
pub trait Transport {
    async fn post(&self, body: String) -> anyhow::Result<String>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockTag {
    Latest,
    /// Base's `safe` head: derived from data posted to Ethereum, not yet
    /// final there. A minute or two behind the head.
    Safe,
    Finalized,
    Number(u64),
}

impl BlockTag {
    /// The head a decision waits on before it counts as settled
    /// (TRUST.md#how-the-enclave-talks-to-the-chain): `finalized`, about
    /// twenty minutes behind, on prod and the public testnet alike. A devnet
    /// build (`--cfg botstadia_devnet`: the devnet's image and its CLI,
    /// never a release) waits on `safe` instead, so no check there waits on
    /// Ethereum's finality (OPERATIONS.md#the-devnet).
    #[cfg(not(botstadia_devnet))]
    pub const SETTLED: Self = Self::Finalized;
    #[cfg(botstadia_devnet)]
    pub const SETTLED: Self = Self::Safe;

    /// About how long [`Self::SETTLED`] trails the head, for messages.
    #[cfg(not(botstadia_devnet))]
    pub const SETTLED_LAG: &'static str = "about twenty minutes";
    #[cfg(botstadia_devnet)]
    pub const SETTLED_LAG: &'static str = "a few minutes";

    pub(crate) fn json(&self) -> Value {
        match self {
            Self::Latest => json!("latest"),
            Self::Safe => json!("safe"),
            Self::Finalized => json!("finalized"),
            Self::Number(n) => json!(format!("0x{n:x}")),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Block {
    #[serde(deserialize_with = "hex_u64")]
    pub number: u64,
    pub hash: B256,
    #[serde(deserialize_with = "hex_u64")]
    pub timestamp: u64,
    #[serde(default, deserialize_with = "hex_u128_opt")]
    pub base_fee_per_gas: Option<u128>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Log {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
    #[serde(default, deserialize_with = "hex_u64_opt")]
    pub block_number: Option<u64>,
    #[serde(default)]
    pub transaction_hash: Option<B256>,
    #[serde(default, deserialize_with = "hex_u64_opt")]
    pub log_index: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Receipt {
    pub transaction_hash: B256,
    #[serde(deserialize_with = "hex_u64")]
    pub block_number: u64,
    #[serde(deserialize_with = "hex_u64")]
    pub status: u64,
    #[serde(deserialize_with = "hex_u64")]
    pub gas_used: u64,
    pub logs: Vec<Log>,
}

impl Receipt {
    pub fn succeeded(&self) -> bool {
        self.status == 1
    }
}

fn parse_u64(s: &str) -> Result<u64, String> {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).map_err(|e| e.to_string())
}

fn hex_u64<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    let s = String::deserialize(d)?;
    parse_u64(&s).map_err(serde::de::Error::custom)
}

fn hex_u64_opt<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
    Option::<String>::deserialize(d)?
        .map(|s| parse_u64(&s))
        .transpose()
        .map_err(serde::de::Error::custom)
}

fn hex_u128_opt<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<u128>, D::Error> {
    Option::<String>::deserialize(d)?
        .map(|s| u128::from_str_radix(s.trim_start_matches("0x"), 16))
        .transpose()
        .map_err(serde::de::Error::custom)
}

/// A JSON-RPC client over any transport.
pub struct Client<T> {
    transport: T,
}

/// An error the node returned, kept apart from transport failures so callers
/// can tell a revert from an outage.
#[derive(Debug)]
pub struct NodeError {
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
}

impl std::fmt::Display for NodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "node error {}: {}", self.code, self.message)
    }
}

impl std::error::Error for NodeError {}

impl<T: Transport> Client<T> {
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    pub async fn request(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        let body =
            json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
        let text = self
            .transport
            .post(body)
            .await
            .map_err(|e| anyhow::anyhow!("{method}: {e:#}"))?;
        let mut reply: Value = serde_json::from_str(&text)
            .map_err(|e| anyhow::anyhow!("{method}: not JSON ({e}): {text}"))?;
        if let Some(error) = reply.get("error") {
            return Err(NodeError {
                code: error["code"].as_i64().unwrap_or(0),
                message: error["message"].as_str().unwrap_or("").to_string(),
                data: error.get("data").cloned(),
            }
            .into());
        }
        Ok(reply["result"].take())
    }

    async fn hex_u64(&self, method: &str, params: Value) -> anyhow::Result<u64> {
        let v = self.request(method, params).await?;
        parse_u64(v.as_str().unwrap_or_default()).map_err(|e| anyhow::anyhow!("{method}: {e}"))
    }

    pub async fn chain_id(&self) -> anyhow::Result<u64> {
        self.hex_u64("eth_chainId", json!([])).await
    }

    pub async fn block_number(&self) -> anyhow::Result<u64> {
        self.hex_u64("eth_blockNumber", json!([])).await
    }

    pub async fn block(&self, tag: BlockTag) -> anyhow::Result<Block> {
        let v = self
            .request("eth_getBlockByNumber", json!([tag.json(), false]))
            .await?;
        anyhow::ensure!(!v.is_null(), "no such block: {tag:?}");
        Ok(serde_json::from_value(v)?)
    }

    pub async fn nonce(&self, address: Address, tag: BlockTag) -> anyhow::Result<u64> {
        self.hex_u64("eth_getTransactionCount", json!([address, tag.json()]))
            .await
    }

    pub async fn balance(&self, address: Address, tag: BlockTag) -> anyhow::Result<U256> {
        let v = self
            .request("eth_getBalance", json!([address, tag.json()]))
            .await?;
        Ok(v.as_str().unwrap_or("0x0").parse()?)
    }

    pub async fn gas_price(&self) -> anyhow::Result<u128> {
        let v = self.request("eth_gasPrice", json!([])).await?;
        Ok(u128::from_str_radix(
            v.as_str().unwrap_or("0x0").trim_start_matches("0x"),
            16,
        )?)
    }

    pub async fn max_priority_fee(&self) -> anyhow::Result<u128> {
        let v = self.request("eth_maxPriorityFeePerGas", json!([])).await?;
        Ok(u128::from_str_radix(
            v.as_str().unwrap_or("0x0").trim_start_matches("0x"),
            16,
        )?)
    }

    /// `eth_call` at a block, returning the raw return data.
    pub async fn call(&self, to: Address, data: &[u8], tag: BlockTag) -> anyhow::Result<Bytes> {
        let v = self
            .request(
                "eth_call",
                json!([{"to": to, "data": Bytes::from(data.to_vec())}, tag.json()]),
            )
            .await?;
        Ok(v.as_str().unwrap_or("0x").parse()?)
    }

    /// Call a contract function by its generated call type and decode the
    /// return.
    pub async fn call_typed<C: alloy_sol_types::SolCall>(
        &self,
        to: Address,
        call: &C,
        tag: BlockTag,
    ) -> anyhow::Result<C::Return> {
        let out = self.call(to, &call.abi_encode(), tag).await?;
        Ok(C::abi_decode_returns(&out)?)
    }

    pub async fn estimate_gas(
        &self,
        from: Address,
        to: Address,
        data: &[u8],
    ) -> anyhow::Result<u64> {
        self.hex_u64(
            "eth_estimateGas",
            json!([{"from": from, "to": to, "data": Bytes::from(data.to_vec())}]),
        )
        .await
    }

    pub async fn send_raw(&self, raw: &[u8]) -> anyhow::Result<B256> {
        let v = self
            .request("eth_sendRawTransaction", json!([Bytes::from(raw.to_vec())]))
            .await?;
        Ok(v.as_str().unwrap_or_default().parse()?)
    }

    pub async fn receipt(&self, hash: B256) -> anyhow::Result<Option<Receipt>> {
        let v = self
            .request("eth_getTransactionReceipt", json!([hash]))
            .await?;
        if v.is_null() {
            return Ok(None);
        }
        Ok(Some(serde_json::from_value(v)?))
    }

    pub async fn logs(
        &self,
        addresses: &[Address],
        from_block: u64,
        to_block: u64,
    ) -> anyhow::Result<Vec<Log>> {
        let v = self
            .request(
                "eth_getLogs",
                json!([{
                    "address": addresses,
                    "fromBlock": format!("0x{from_block:x}"),
                    "toBlock": format!("0x{to_block:x}"),
                }]),
            )
            .await?;
        Ok(serde_json::from_value(v)?)
    }
}

/// JSON-RPC over HTTP, for native callers.
#[cfg(feature = "native")]
pub struct Http {
    url: String,
    client: reqwest::Client,
}

#[cfg(feature = "native")]
impl Http {
    /// With connect and overall timeouts, so a provider that stops answering
    /// fails the call (and its caller moves to the next provider) rather than
    /// hanging it.
    pub fn new(url: impl Into<String>) -> Self {
        Self::with_timeout(url, std::time::Duration::from_secs(30))
    }

    pub fn with_timeout(url: impl Into<String>, timeout: std::time::Duration) -> Self {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10).min(timeout))
            .timeout(timeout)
            .build()
            .expect("an HTTP client with timeouts");
        Self {
            url: url.into(),
            client,
        }
    }
}

#[cfg(feature = "native")]
impl Transport for Http {
    async fn post(&self, body: String) -> anyhow::Result<String> {
        let response = self
            .client
            .post(&self.url)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await?;
        anyhow::ensure!(
            response.status().is_success(),
            "RPC returned HTTP {}",
            response.status()
        );
        Ok(response.text().await?)
    }
}

/// JSON-RPC over the Workers runtime's fetch.
/// JSON-RPC over the Workers runtime's fetch. The URL may list several,
/// comma-separated: each request goes to the first that answers, the next
/// taking over when one can't be reached or refuses with an HTTP error (a
/// provider rate-limiting Workers' shared egress, found on the testnet).
/// A node's own JSON-RPC error is an answer, and isn't passed on.
#[cfg(feature = "worker")]
pub struct Fetch {
    url: String,
}

#[cfg(feature = "worker")]
impl Fetch {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }
}

#[cfg(feature = "worker")]
impl Transport for Fetch {
    async fn post(&self, body: String) -> anyhow::Result<String> {
        let mut errors = Vec::new();
        for url in self.url.split(',').map(str::trim).filter(|u| !u.is_empty()) {
            match fetch_one(url, &body).await {
                Ok(text) => return Ok(text),
                Err(e) => errors.push(e.to_string()),
            }
        }
        anyhow::bail!("{}", errors.join("; then "))
    }
}

#[cfg(feature = "worker")]
async fn fetch_one(url: &str, body: &str) -> anyhow::Result<String> {
    let body = body.to_string();
    let headers = worker::Headers::new();
    headers
        .set("content-type", "application/json")
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_headers(headers)
        .with_body(Some(body.into()));
    let request = worker::Request::new_with_init(url, &init).map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut response = worker::Fetch::Request(request)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    anyhow::ensure!(
        (200..300).contains(&response.status_code()),
        "RPC returned HTTP {}",
        response.status_code()
    );
    response.text().await.map_err(|e| anyhow::anyhow!("{e}"))
}

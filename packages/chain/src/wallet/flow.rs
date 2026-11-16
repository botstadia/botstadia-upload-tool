//! One account-wallet operation from calls to receipt, shared by the site
//! (through the api's relays), the exit page (through public endpoints) and
//! the proof driver, so they build and sign exactly the same thing.
//!
//! - The paymaster's allowance must be in place before validation: a wallet
//!   without one carries a permit, signed first (the first action's second
//!   prompt), and every operation renews it inside itself for the next.
//! - The owner signs only once the gas is final, since the SafeOp covers it.
//! - Circle's post-op takes at least 35,000 gas; paymaster verification is
//!   set from measurement (a bundler may echo the limit it's given, and
//!   Alchemy's refuses limits used less than a quarter).

use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_sol_types::SolCall;

use super::Contracts;
use super::bundler::{Estimate, GasPrice, OpReceipt};
use super::op::{self, Call, OwnerSignature, UserOp};
use super::{calls, paymaster};
use crate::rpc::{BlockTag, Client, Transport};

/// Paymaster verification gas: with a permit, whose ERC-1271 check runs the
/// passkey's verification inside the paymaster (about 150k measured on Base
/// Sepolia), and without.
pub const PAYMASTER_GAS_WITH_PERMIT: u64 = 250_000;
pub const PAYMASTER_GAS: u64 = 120_000;

/// An owner that can sign a digest for the wallet.
#[allow(async_fn_in_trait)]
pub trait Signer {
    /// Whether it's a passkey (for the estimate's placeholder signature).
    fn passkey(&self) -> bool;
    /// Sign `digest` as this owner, ready for Safe's signature layout.
    async fn sign(&self, digest: B256) -> anyhow::Result<OwnerSignature>;
}

/// Where operations go: a bundler directly, or the api's relay.
#[allow(async_fn_in_trait)]
pub trait Bundle {
    async fn gas_price(&self) -> anyhow::Result<GasPrice>;
    async fn estimate(&self, c: &Contracts, op: &UserOp) -> anyhow::Result<Estimate>;
    async fn send(&self, c: &Contracts, op: &UserOp) -> anyhow::Result<B256>;
    async fn receipt(&self, hash: B256) -> anyhow::Result<Option<OpReceipt>>;
    /// Pimlico's ERC-20 paymaster's fields for `op` (a stub for the
    /// estimate, or the signed data), where this bundle reaches it.
    async fn erc20_paymaster(
        &self,
        _c: &Contracts,
        _op: &UserOp,
        _stub: bool,
    ) -> anyhow::Result<Option<PaymasterFields>> {
        Ok(None)
    }
}

/// A paymaster's part of an operation, as its service hands it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PaymasterFields {
    pub data: Bytes,
    pub verification_gas: Option<U256>,
    pub post_op_gas: Option<U256>,
}

impl PaymasterFields {
    /// From `pm_getPaymasterStubData` / `pm_getPaymasterData`'s answer.
    pub fn from_json(v: &serde_json::Value) -> anyhow::Result<Self> {
        let num = |k: &str| -> anyhow::Result<Option<U256>> {
            match v.get(k).filter(|x| !x.is_null()) {
                Some(x) => Ok(Some(serde_json::from_value(x.clone())?)),
                None => Ok(None),
            }
        };
        Ok(Self {
            data: serde_json::from_value(v["paymasterData"].clone())?,
            verification_gas: num("paymasterVerificationGasLimit")?,
            post_op_gas: num("paymasterPostOpGasLimit")?,
        })
    }
}

/// The ERC-20 paymaster methods' parameters: the operation, the
/// EntryPoint, the chain, and the token gas is paid in.
pub fn erc20_paymaster_params(c: &Contracts, op: &UserOp) -> serde_json::Value {
    serde_json::json!([
        op,
        format!("{:#x}", c.entry_point),
        format!("0x{:x}", c.chain_id),
        { "token": format!("{:#x}", c.usdc) }
    ])
}

impl<T: Transport> Bundle for super::bundler::Bundler<T> {
    async fn gas_price(&self) -> anyhow::Result<GasPrice> {
        super::bundler::Bundler::gas_price(self).await
    }
    async fn estimate(&self, c: &Contracts, op: &UserOp) -> anyhow::Result<Estimate> {
        super::bundler::Bundler::estimate(self, c, op).await
    }
    async fn send(&self, c: &Contracts, op: &UserOp) -> anyhow::Result<B256> {
        super::bundler::Bundler::send(self, c, op).await
    }
    async fn receipt(&self, hash: B256) -> anyhow::Result<Option<OpReceipt>> {
        super::bundler::Bundler::receipt(self, hash).await
    }
    async fn erc20_paymaster(
        &self,
        c: &Contracts,
        op: &UserOp,
        stub: bool,
    ) -> anyhow::Result<Option<PaymasterFields>> {
        if self.flavor != super::bundler::Flavor::Pimlico {
            return Ok(None);
        }
        let method = if stub {
            "pm_getPaymasterStubData"
        } else {
            "pm_getPaymasterData"
        };
        let v = self
            .rpc
            .request(method, erc20_paymaster_params(c, op))
            .await?;
        Ok(Some(PaymasterFields::from_json(&v)?))
    }
}

/// What the wallet needs before an operation: whether it carries a permit,
/// and whether the eligibility statement is still to make.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Needs {
    pub permit: bool,
    pub statement: bool,
}

pub async fn needs<T: Transport>(
    rpc: &Client<T>,
    c: &Contracts,
    wallet: Address,
) -> anyhow::Result<Needs> {
    let allowance = rpc
        .call_typed(
            c.usdc,
            &calls::allowanceCall {
                owner: wallet,
                spender: c.paymaster,
            },
            BlockTag::Latest,
        )
        .await?;
    let statement = rpc
        .call_typed(
            c.settlement,
            &crate::abi::Settlement::statementsCall(wallet),
            BlockTag::Latest,
        )
        .await?;
    Ok(Needs {
        permit: allowance < U256::from(paymaster::ALLOWANCE / 2),
        statement: !statement,
    })
}

/// The digest a permit signature signs, for the wallet as owner (its
/// SafeMessage over USDC's permit digest).
pub async fn permit_digest<T: Transport>(
    rpc: &Client<T>,
    c: &Contracts,
    wallet: Address,
) -> anyhow::Result<B256> {
    let nonce = rpc
        .call_typed(
            c.usdc,
            &calls::noncesCall { owner: wallet },
            BlockTag::Latest,
        )
        .await?;
    let d = paymaster::permit_digest(
        c,
        wallet,
        U256::from(paymaster::ALLOWANCE),
        nonce,
        U256::MAX,
    );
    Ok(op::safe_message_hash(c, wallet, d))
}

/// Build, sign and send one operation making `calls`, renewing the
/// paymaster's allowance unless the operation carries a permit. Returns
/// once included, or fails with what refused it.
pub async fn send<T: Transport, B: Bundle, S: Signer>(
    rpc: &Client<T>,
    bundle: &B,
    signer: &S,
    c: &Contracts,
    wallet: Address,
    calls: Vec<Call>,
    sleep: impl AsyncFn(u32),
) -> anyhow::Result<OpReceipt> {
    send_built(rpc, bundle, signer, c, wallet, |_| calls.clone(), sleep).await
}

/// USDC per ETH that a sweep prices the paymaster's deposit at: well above
/// any rate it charges, so the deposit always fits. What's left over is
/// refunded to the wallet after the operation.
pub const SWEEP_USDC_PER_ETH: u64 = 20_000;

/// [`send`], with the calls built once the operation's most gas cost (in
/// USDC, at [`SWEEP_USDC_PER_ETH`]) is known: how a "send everything"
/// leaves room for the paymaster's deposit, which it takes before the calls
/// run. The calls are built first with `U256::MAX` (not known yet) for the
/// estimate, so a sweep moves a placeholder of the same shape.
pub async fn send_built<T: Transport, B: Bundle, S: Signer>(
    rpc: &Client<T>,
    bundle: &B,
    signer: &S,
    c: &Contracts,
    wallet: Address,
    build: impl Fn(U256) -> Vec<Call>,
    sleep: impl AsyncFn(u32),
) -> anyhow::Result<OpReceipt> {
    match send_circle(rpc, bundle, signer, c, wallet, &build, &sleep).await {
        // Circle's Paymaster refused it, or can't be reached: Pimlico's
        // ERC-20 paymaster, where this bundle reaches it (MONEY.md#currency).
        Err(e) if c.fallback_paymaster.is_some() && paymaster_refused(&e) => {
            match send_fallback(rpc, bundle, signer, c, wallet, &build, &sleep).await {
                Ok(r) => Ok(r),
                Err(f) => Err(e.context(format!("and the fallback paymaster: {f:#}"))),
            }
        }
        other => other,
    }
}

/// Whether an operation failed on the paymaster's side: its validation
/// (AA3x) or its post-op, rather than the calls or the account.
fn paymaster_refused(e: &anyhow::Error) -> bool {
    let t = format!("{e:#}");
    t.contains("AA3") || t.contains("AA50") || t.to_lowercase().contains("paymaster")
}

/// One operation through Pimlico's ERC-20 paymaster: an approve for it in
/// the operation itself, since it charges in its post-op, and its own
/// signed data. Its prices come from Pimlico's service, so it's a fallback.
async fn send_fallback<T: Transport, B: Bundle, S: Signer>(
    rpc: &Client<T>,
    bundle: &B,
    signer: &S,
    c: &Contracts,
    wallet: Address,
    build: &impl Fn(U256) -> Vec<Call>,
    sleep: &impl AsyncFn(u32),
) -> anyhow::Result<OpReceipt> {
    let pm = c
        .fallback_paymaster
        .ok_or_else(|| anyhow::anyhow!("no fallback paymaster"))?;
    let approve = calls::approve(c, pm, U256::from(paymaster::ALLOWANCE));
    let with_approve = |max: U256| {
        std::iter::once(approve.clone())
            .chain(build(max))
            .collect::<Vec<_>>()
    };
    let nonce = rpc
        .call_typed(
            c.entry_point,
            &op::getNonceCall {
                sender: wallet,
                key: Default::default(),
            },
            BlockTag::Latest,
        )
        .await?;
    let mut uo = UserOp {
        sender: wallet,
        nonce,
        call_data: op::call_data(c, &with_approve(U256::MAX))?,
        signature: op::dummy_signature(c, signer.passkey()),
        ..Default::default()
    };
    let price = bundle.gas_price().await?;
    uo.max_fee_per_gas = price.max_fee_per_gas;
    uo.max_priority_fee_per_gas = price.max_priority_fee_per_gas;
    let fields = |uo: &mut UserOp, f: PaymasterFields| {
        uo.paymaster = Some(pm);
        uo.paymaster_data = Some(f.data);
        if let Some(v) = f.verification_gas {
            uo.paymaster_verification_gas_limit = Some(v);
        }
        if let Some(v) = f.post_op_gas {
            uo.paymaster_post_op_gas_limit = Some(v);
        }
    };
    let stub = bundle
        .erc20_paymaster(c, &uo, true)
        .await?
        .ok_or_else(|| anyhow::anyhow!("this bundler doesn't reach the fallback paymaster"))?;
    uo.paymaster_verification_gas_limit = Some(U256::from(PAYMASTER_GAS));
    fields(&mut uo, stub);
    let est = bundle.estimate(c, &uo).await?;
    uo.pre_verification_gas = est.pre_verification_gas;
    uo.verification_gas_limit = est.verification_gas_limit;
    uo.call_gas_limit = est.call_gas_limit;
    if let Some(v) = est.paymaster_post_op_gas_limit {
        uo.paymaster_post_op_gas_limit =
            Some(v.max(uo.paymaster_post_op_gas_limit.unwrap_or_default()));
    }
    // A sweep leaves room for the most the gas can cost, as with Circle's.
    uo.call_data = op::call_data(c, &with_approve(max_cost_usdc(&uo, SWEEP_USDC_PER_ETH)))?;
    let signed = bundle
        .erc20_paymaster(c, &uo, false)
        .await?
        .ok_or_else(|| anyhow::anyhow!("this bundler doesn't reach the fallback paymaster"))?;
    fields(&mut uo, signed);
    let digest = uo.safe_op_hash(c, 0, 0);
    let sigs = op::safe_signatures(vec![signer.sign(digest).await?])?;
    uo.signature = op::op_signature(0, 0, &sigs);
    let hash = bundle.send(c, &uo).await?;
    wait(bundle, hash, sleep).await
}

async fn wait<B: Bundle>(
    bundle: &B,
    hash: B256,
    sleep: &impl AsyncFn(u32),
) -> anyhow::Result<OpReceipt> {
    for _ in 0..120 {
        if let Some(r) = bundle.receipt(hash).await? {
            anyhow::ensure!(
                r.success,
                "the operation reverted: {}",
                r.reason.unwrap_or_default()
            );
            return Ok(r);
        }
        sleep(1000).await;
    }
    anyhow::bail!("the operation {hash} wasn't included in two minutes")
}

async fn send_circle<T: Transport, B: Bundle, S: Signer>(
    rpc: &Client<T>,
    bundle: &B,
    signer: &S,
    c: &Contracts,
    wallet: Address,
    build: &impl Fn(U256) -> Vec<Call>,
    sleep: &impl AsyncFn(u32),
) -> anyhow::Result<OpReceipt> {
    let mut calls = build(U256::MAX);
    let n = needs(rpc, c, wallet).await?;
    let permit = if n.permit {
        let d = permit_digest(rpc, c, wallet).await?;
        op::safe_signatures(vec![signer.sign(d).await?])?
    } else {
        calls.push(calls::approve_paymaster(c));
        Bytes::new()
    };
    let nonce = rpc
        .call_typed(
            c.entry_point,
            &op::getNonceCall {
                sender: wallet,
                key: Default::default(),
            },
            BlockTag::Latest,
        )
        .await?;
    let mut uo = UserOp {
        sender: wallet,
        nonce,
        call_data: op::call_data(c, &calls)?,
        signature: op::dummy_signature(c, signer.passkey()),
        ..Default::default()
    };
    paymaster::attach(
        &mut uo,
        c,
        paymaster::data(c, U256::from(paymaster::ALLOWANCE), &permit),
    );
    let pm_gas = if n.permit {
        PAYMASTER_GAS_WITH_PERMIT
    } else {
        PAYMASTER_GAS
    };
    uo.paymaster_verification_gas_limit = Some(U256::from(pm_gas));
    let price = bundle.gas_price().await?;
    uo.max_fee_per_gas = price.max_fee_per_gas;
    uo.max_priority_fee_per_gas = price.max_priority_fee_per_gas;
    let est = bundle.estimate(c, &uo).await?;
    uo.pre_verification_gas = est.pre_verification_gas;
    uo.verification_gas_limit = est.verification_gas_limit;
    uo.call_gas_limit = est.call_gas_limit;
    uo.paymaster_post_op_gas_limit = Some(
        est.paymaster_post_op_gas_limit
            .unwrap_or_default()
            .max(U256::from(paymaster::POST_OP_GAS)),
    );
    // Rebuilt with the most the gas can cost, for a sweep; the calls keep
    // their shape, so the estimate still holds.
    let max_cost = max_cost_usdc(&uo, SWEEP_USDC_PER_ETH);
    if max_cost > U256::ZERO {
        let mut rebuilt = build(max_cost);
        if !n.permit {
            rebuilt.push(calls::approve_paymaster(c));
        }
        uo.call_data = op::call_data(c, &rebuilt)?;
    }
    let digest = uo.safe_op_hash(c, 0, 0);
    let sigs = op::safe_signatures(vec![signer.sign(digest).await?])?;
    uo.signature = op::op_signature(0, 0, &sigs);
    let hash = bundle.send(c, &uo).await?;
    wait(bundle, hash, sleep).await
}

/// What an operation can cost at most in USDC (6 decimals) at Circle's
/// rate: what the wallet keeps back so it can always claim.
pub fn max_cost_usdc(op: &UserOp, usdc_per_eth: u64) -> U256 {
    paymaster::max_cost_wei(op) * U256::from(usdc_per_eth) / U256::from(1_000_000_000_000u64)
}

/// The Safe's owners in its list order (deployed), or the first owners from
/// the setup data (not yet).
pub async fn owners<T: Transport>(
    rpc: &Client<T>,
    c: &Contracts,
    wallet: Address,
    setup: &[u8],
) -> anyhow::Result<Vec<Address>> {
    let code = rpc
        .request(
            "eth_getCode",
            serde_json::json!([format!("{wallet:#x}"), "latest"]),
        )
        .await?;
    if code.as_str().is_some_and(|s| s.len() > 2) {
        let out = rpc
            .call(
                wallet,
                &super::safe::getOwnersCall {}.abi_encode(),
                BlockTag::Latest,
            )
            .await?;
        return Ok(super::safe::getOwnersCall::abi_decode_returns(&out)?);
    }
    Ok(super::safe::parse_owners(c, setup)?.owners(c))
}

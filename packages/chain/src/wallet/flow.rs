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
use crate::rpc::{BlockTag, Client, NodeError, Transport};

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

/// The operation was handed over and what became of it isn't known. It may
/// still land, so nothing builds another in its place: that could bet or
/// withdraw twice.
#[derive(Debug)]
pub struct Unconfirmed {
    pub hash: Option<B256>,
    /// What the send answered, where it didn't say. Shown last: whatever it
    /// says, the warning is what's read first.
    pub cause: Option<String>,
}

impl std::fmt::Display for Unconfirmed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sent, not yet confirmed")?;
        if let Some(hash) = self.hash {
            write!(f, " (operation {hash})")?;
        }
        write!(f, ": check your balance and bets before trying again")?;
        if let Some(cause) = &self.cause {
            write!(f, ". The send's answer was: {cause}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Unconfirmed {}

/// Whether what failed may still land, so mustn't be built again.
pub fn may_have_landed(e: &anyhow::Error) -> bool {
    e.downcast_ref::<Unconfirmed>().is_some()
}

/// Refused before it reached a bundler (a rate limit of ours, say).
#[derive(Debug)]
pub struct NotSent(pub String);

impl std::fmt::Display for NotSent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "not sent: {}", self.0)
    }
}

impl std::error::Error for NotSent {}

/// Whether a send's failure says for sure that it wasn't taken: refused
/// before any bundler, or the bundler's own verdict on the operation.
/// Never a transport's error, whatever its text, nor an answer that means
/// the operation, or another at its nonce, is already known.
fn not_taken(e: &anyhow::Error) -> bool {
    if e.downcast_ref::<NotSent>().is_some() {
        return true;
    }
    let Some(node) = e.downcast_ref::<NodeError>() else {
        return false;
    };
    let said = node.message.to_lowercase();
    super::bundler::is_refusal(e)
        && ![
            "aa25",
            "already known",
            "already exists",
            "replacement underpriced",
        ]
        .iter()
        .any(|known| said.contains(known))
}

/// Hand a signed operation over, and wait for it. Where the answer doesn't
/// say it wasn't taken, its own hash, known before sending, is what's asked.
async fn hand_over<B: Bundle>(
    bundle: &B,
    c: &Contracts,
    uo: &UserOp,
    sleep: &impl AsyncFn(u32),
) -> anyhow::Result<OpReceipt> {
    match bundle.send(c, uo).await {
        Ok(hash) => wait(bundle, hash, sleep).await,
        Err(e) if not_taken(&e) => Err(e),
        Err(e) => wait(bundle, uo.hash(c), sleep).await.map_err(|unknown| {
            match unknown.downcast::<Unconfirmed>() {
                // Why, kept: it may be why nothing ever arrives.
                Ok(sent) => Unconfirmed {
                    cause: Some(format!("{e:#}")),
                    ..sent
                }
                .into(),
                Err(other) => other,
            }
        }),
    }
}

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
        Err(e)
            if c.fallback_paymaster.is_some() && !may_have_landed(&e) && paymaster_refused(&e) =>
        {
            match send_fallback(rpc, bundle, signer, c, wallet, &build, &sleep).await {
                Ok(r) => Ok(r),
                Err(f) if may_have_landed(&f) => Err(f),
                Err(f) => Err(e.context(format!("and the fallback paymaster: {f:#}"))),
            }
        }
        other => other,
    }
}

/// Whether an operation failed on the paymaster's side: its validation
/// (AA3x) or its post-op, rather than the calls or the account.
fn paymaster_refused(e: &anyhow::Error) -> bool {
    // The node's own answer only: a transport's error carries URLs and bodies.
    e.downcast_ref::<NodeError>().is_some_and(|node| {
        let t = &node.message;
        t.contains("AA3") || t.contains("AA50") || t.to_lowercase().contains("paymaster")
    })
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
    hand_over(bundle, c, &uo, sleep).await
}

async fn wait<B: Bundle>(
    bundle: &B,
    hash: B256,
    sleep: &impl AsyncFn(u32),
) -> anyhow::Result<OpReceipt> {
    let mut waited = 0;
    while waited < 120 {
        // A poll that fails says nothing about the operation: ask again.
        if let Ok(Some(r)) = bundle.receipt(hash).await {
            anyhow::ensure!(
                r.success,
                "the operation reverted: {}",
                r.reason.unwrap_or_default()
            );
            return Ok(r);
        }
        // Often at first, then sparingly: the relay counts every poll.
        let pause = if waited < 5 { 1 } else { 4 };
        sleep(pause * 1000).await;
        waited += pause;
    }
    Err(Unconfirmed {
        hash: Some(hash),
        cause: None,
    }
    .into())
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
    hand_over(bundle, c, &uo, sleep).await
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    /// A bundler answering receipt polls from a script, then with nothing.
    struct Scripted {
        polls: RefCell<Vec<anyhow::Result<Option<OpReceipt>>>>,
        asked: Cell<usize>,
    }

    impl Bundle for Scripted {
        async fn gas_price(&self) -> anyhow::Result<GasPrice> {
            unreachable!()
        }
        async fn estimate(&self, _: &Contracts, _: &UserOp) -> anyhow::Result<Estimate> {
            unreachable!()
        }
        async fn send(&self, _: &Contracts, _: &UserOp) -> anyhow::Result<B256> {
            unreachable!()
        }
        async fn receipt(&self, _: B256) -> anyhow::Result<Option<OpReceipt>> {
            self.asked.set(self.asked.get() + 1);
            self.polls.borrow_mut().pop().unwrap_or(Ok(None))
        }
    }

    fn landed(success: bool) -> OpReceipt {
        OpReceipt {
            success,
            actual_gas_used: U256::from(1u64),
            actual_gas_cost: U256::from(1u64),
            transaction_hash: B256::repeat_byte(9),
            block_number: 1,
            reason: None,
        }
    }

    fn contracts() -> Contracts {
        let a = format!("{:#x}", Address::ZERO);
        serde_json::from_value(serde_json::json!({
            "chain_id": 84532,
            "entry_point": a, "safe_singleton": a, "proxy_factory": a,
            "safe_4337_module": a, "safe_module_setup": a, "multi_send": a,
            "multi_send_call_only": a, "webauthn_shared_signer": a,
            "webauthn_signer_factory": a,
            "p256_verifiers": "0x1000000000000000000000000000000000000000000",
            "usdc": a, "usdc_name": "USDC", "paymaster": a,
            "fallback_paymaster": a, "settlement": a,
        }))
        .unwrap()
    }

    /// Refuses, or loses, what's handed to it, and never has a receipt.
    struct Send(fn() -> anyhow::Error);

    impl Bundle for Send {
        async fn gas_price(&self) -> anyhow::Result<GasPrice> {
            unreachable!()
        }
        async fn estimate(&self, _: &Contracts, _: &UserOp) -> anyhow::Result<Estimate> {
            unreachable!()
        }
        async fn send(&self, _: &Contracts, _: &UserOp) -> anyhow::Result<B256> {
            Err((self.0)())
        }
        async fn receipt(&self, _: B256) -> anyhow::Result<Option<OpReceipt>> {
            Ok(None)
        }
    }

    fn node(code: i64, message: &str) -> anyhow::Error {
        NodeError {
            code,
            message: message.into(),
            data: None,
        }
        .into()
    }

    #[tokio::test]
    async fn only_a_refusal_says_a_send_didnt_happen() {
        let sleep = async |_: u32| {};
        let (c, uo) = (contracts(), UserOp::default());
        let refusals: [fn() -> anyhow::Error; 5] = [
            || node(-32501, "AA33 reverted"),
            || node(-32501, "AA33 reverted").context("pimlico refused it"),
            || node(-32602, "preVerificationGas is too low"),
            || node(-32500, "AA21 didn't pay prefund"),
            || NotSent("too many attempts".into()).into(),
        ];
        for refused in refusals {
            let e = hand_over(&Send(refused), &c, &uo, &sleep)
                .await
                .unwrap_err();
            assert!(!may_have_landed(&e), "{e:#}");
        }
        let unknowns: [fn() -> anyhow::Error; 6] = [
            || anyhow::anyhow!("the connection dropped"),
            || anyhow::anyhow!("https://x.example/rpc?apikey=pim_xAA3q answered 502"),
            || anyhow::anyhow!("https://paymaster.example/rpc answered 504"),
            || node(-32603, "internal error in the paymaster"),
            || node(-32500, "AA25 invalid account nonce"),
            || node(-32602, "already known"),
        ];
        for unknown in unknowns {
            let e = hand_over(&Send(unknown), &c, &uo, &sleep)
                .await
                .unwrap_err();
            assert!(may_have_landed(&e), "{e:#}");
            let cause = format!("{:#}", unknown());
            let said = format!("{e:#}");
            assert!(said.starts_with("sent, not yet confirmed"), "{said}");
            assert!(
                said.ends_with(&cause),
                "the cause is kept, and last: {said}"
            );
        }
    }

    #[tokio::test]
    async fn a_failed_poll_is_asked_again_and_silence_is_never_a_failure() {
        let sleep = async |_: u32| {};
        let hash = B256::repeat_byte(1);
        let blip = Scripted {
            polls: RefCell::new(vec![Ok(Some(landed(true))), Err(anyhow::anyhow!("429"))]),
            asked: Cell::new(0),
        };
        assert!(wait(&blip, hash, &sleep).await.unwrap().success);
        assert_eq!(blip.asked.get(), 2);

        let silent = Scripted {
            polls: RefCell::new(Vec::new()),
            asked: Cell::new(0),
        };
        let e = wait(&silent, hash, &sleep).await.unwrap_err();
        assert!(may_have_landed(&e), "nothing may be built in its place");
        assert!(may_have_landed(&e.context("claiming")));

        // Included and reverted: nothing moved, so it may be built again.
        let reverted = Scripted {
            polls: RefCell::new(vec![Ok(Some(landed(false)))]),
            asked: Cell::new(0),
        };
        assert!(!may_have_landed(
            &wait(&reverted, hash, &sleep).await.unwrap_err()
        ));
    }
}

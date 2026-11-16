//! Proving the account-wallet stack on Base Sepolia (BEFORE-PROD.md, "What
//! to prove first" #2), and driving a test wallet afterwards.
//!
//! - `wallet new passkey|address`: a wallet whose first owners are a
//!   software passkey (standing in for WebAuthn, signing exactly what a
//!   browser's assertion does) and a recovery key, or a single address
//!   owner (a browser wallet with no ETH)
//! - `wallet fund <usdc>`: send it USDC from `FUND_KEY`
//! - `wallet deploy`: deploy it from the canonical setup data with
//!   `DEPLOY_KEY`, standing in for the keeper
//! - `wallet op <bundler> <signer> first|bet|withdraw …`: one user
//!   operation, signed by `passkey`, `recovery` or `owner`, gas paid in USDC
//!   through Circle's Paymaster, sent to bundler `0` or `1` of `BUNDLERS`
//! - `wallet show`: address, owners, balances
//!
//! The wallet's keys live in the JSON file at `WALLET_STATE`. Contracts come
//! from `CHAIN_ID`, `TOKEN` and `SETTLEMENT`; the RPC from `SEND_RPC`.

use std::time::Duration;

use alloy_sol_types::{SolCall, SolValue};
use anyhow::{Context, bail, ensure};
use botstadia_chain::abi::Settlement;
use botstadia_chain::rpc::{BlockTag, Client, Http};
use botstadia_chain::sign::Key;
use botstadia_chain::wallet::bundler::{Bundler, Bundlers, Flavor};
use botstadia_chain::wallet::op::{self, OwnerSignature, UserOp};
use botstadia_chain::wallet::safe::{self, FirstOwners, Passkey, Setup};
use botstadia_chain::wallet::{Contracts, calls, paymaster, webauthn};
use botstadia_chain::{Address, B256, Bytes, U256, tx};
use p256::ecdsa::signature::Signer;
use serde::{Deserialize, Serialize};
use sha2::Digest;

#[derive(Serialize, Deserialize)]
struct State {
    passkey: Option<String>,
    recovery: Option<String>,
    owner: Option<String>,
    setup: Setup,
}

fn var(name: &str) -> anyhow::Result<String> {
    std::env::var(name).with_context(|| format!("{name} isn't set"))
}

fn usdc(amount: &str) -> anyhow::Result<U256> {
    let v: f64 = amount.parse().context("an amount in USDC")?;
    Ok(U256::from((v * 1_000_000.0).round() as u64))
}

fn fmt_usdc(v: U256) -> String {
    format!("{:.6}", v.to::<u128>() as f64 / 1e6)
}

/// A software passkey: what a platform authenticator does, for an RP ID
/// and origin.
struct SoftPasskey {
    key: p256::ecdsa::SigningKey,
    rp_id: String,
    origin: String,
}

impl SoftPasskey {
    fn public(&self) -> Passkey {
        let point = self.key.verifying_key().to_encoded_point(false);
        Passkey {
            x: U256::from_be_slice(point.x().unwrap()),
            y: U256::from_be_slice(point.y().unwrap()),
        }
    }

    /// `navigator.credentials.get` over `challenge`, user verified.
    fn assert(&self, challenge: B256) -> anyhow::Result<Bytes> {
        let mut auth = sha2::Sha256::digest(self.rp_id.as_bytes()).to_vec();
        auth.push(0x05); // user present, user verified
        auth.extend_from_slice(&[0, 0, 0, 0]);
        let client = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{}","crossOrigin":false}}"#,
            webauthn::challenge_b64(challenge),
            self.origin
        );
        let mut msg = auth.clone();
        msg.extend_from_slice(&sha2::Sha256::digest(client.as_bytes()));
        let sig: p256::ecdsa::Signature = self.key.sign(&msg);
        let (r, s) = webauthn::der_to_rs(sig.to_der().as_bytes())?;
        let fields = webauthn::client_data_fields(&client, challenge)?;
        Ok(webauthn::signature(&auth, &fields, r, s))
    }
}

struct Env {
    c: Contracts,
    rpc: Client<Http>,
    bundlers: Bundlers<Http>,
    path: String,
}

impl Env {
    fn load(&self) -> anyhow::Result<State> {
        Ok(serde_json::from_str(&std::fs::read_to_string(&self.path)?)?)
    }

    async fn send_tx(&self, key: &Key, to: Address, data: Vec<u8>) -> anyhow::Result<(B256, u64)> {
        let from = key.address();
        let nonce = self.rpc.nonce(from, BlockTag::Latest).await?;
        let gas = self.rpc.estimate_gas(from, to, &data).await?;
        let price = self.rpc.gas_price().await?.max(1);
        let signed = tx::sign(
            key,
            self.c.chain_id,
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
                return Ok((signed.hash, r.gas_used));
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        bail!("transaction {} not included after two minutes", signed.hash)
    }

    async fn usdc_of(&self, who: Address) -> anyhow::Result<U256> {
        self.rpc
            .call_typed(self.c.usdc, &calls::balanceOfCall { who }, BlockTag::Latest)
            .await
    }

    async fn deployed(&self, who: Address) -> anyhow::Result<bool> {
        let code = self
            .rpc
            .request("eth_getCode", serde_json::json!([who, "latest"]))
            .await?;
        Ok(code.as_str().is_some_and(|c| c.len() > 2))
    }

    /// The Safe signature over `digest` from the chosen signer.
    fn sign(&self, st: &State, signer: &str, digest: B256) -> anyhow::Result<Bytes> {
        let sig = match signer {
            "passkey" => {
                let pk = soft_passkey(st)?;
                OwnerSignature::Contract {
                    owner: self.c.webauthn_shared_signer,
                    signature: pk.assert(digest)?,
                }
            }
            "recovery" | "owner" => {
                let hex = if signer == "recovery" {
                    &st.recovery
                } else {
                    &st.owner
                };
                let key = Key::from_hex(hex.as_deref().context("no such key")?)?;
                let s = key.sign_hash(digest)?;
                OwnerSignature::Address {
                    owner: key.address(),
                    rsv: Bytes::from(s.as_bytes().to_vec()),
                }
            }
            other => bail!("signer is passkey, recovery or owner, not {other}"),
        };
        op::safe_signatures(vec![sig])
    }
}

struct FlowSigner<'a> {
    e: &'a Env,
    st: &'a State,
    who: &'a str,
}

impl botstadia_chain::wallet::flow::Signer for FlowSigner<'_> {
    fn passkey(&self) -> bool {
        self.who == "passkey"
    }
    async fn sign(&self, digest: B256) -> anyhow::Result<OwnerSignature> {
        Ok(match self.who {
            "passkey" => OwnerSignature::Contract {
                owner: self.e.c.webauthn_shared_signer,
                signature: soft_passkey(self.st)?.assert(digest)?,
            },
            // What a browser wallet's personal_sign of the digest gives,
            // which Safe reads as eth_sign (v + 4): the site's own-wallet path.
            "owner-ethsign" => {
                let key = Key::from_hex(self.st.owner.as_deref().context("no owner key")?)?;
                let mut rsv = key.sign_message(digest.as_slice())?.to_vec();
                rsv[64] += 4;
                OwnerSignature::Address {
                    owner: key.address(),
                    rsv: rsv.into(),
                }
            }
            who => {
                let hex = if who == "recovery" {
                    &self.st.recovery
                } else {
                    &self.st.owner
                };
                let key = Key::from_hex(hex.as_deref().context("no such key")?)?;
                OwnerSignature::Address {
                    owner: key.address(),
                    rsv: Bytes::from(key.sign_hash(digest)?.as_bytes().to_vec()),
                }
            }
        })
    }
}

fn soft_passkey(st: &State) -> anyhow::Result<SoftPasskey> {
    let hex = st
        .passkey
        .as_deref()
        .context("this wallet has no passkey")?;
    let bytes: B256 = hex.parse()?;
    Ok(SoftPasskey {
        key: p256::ecdsa::SigningKey::from_bytes(&bytes.0.into())?,
        rp_id: std::env::var("RP_ID").unwrap_or_else(|_| "localhost".into()),
        origin: std::env::var("ORIGIN").unwrap_or_else(|_| "http://localhost:28081".into()),
    })
}

fn random32() -> [u8; 32] {
    let k = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
    k.to_bytes().into()
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut c = Contracts::base(
        var("CHAIN_ID")?.parse()?,
        var("TOKEN")?.parse()?,
        var("SETTLEMENT")?.parse()?,
    );
    // A drill: Circle's Paymaster replaced by an address that isn't one, so
    // the flow falls back to the ERC-20 paymaster.
    if let Ok(pm) = std::env::var("PAYMASTER_OVERRIDE")
        && !pm.is_empty()
    {
        c.paymaster = pm.parse()?;
    }
    let bundlers = var("BUNDLERS")?
        .split(',')
        .map(|entry| {
            let (name, url) = entry.split_once('=').context("BUNDLERS is name=url,…")?;
            let flavor = match name {
                n if n.starts_with("pimlico") => Flavor::Pimlico,
                n if n.starts_with("alchemy") => Flavor::Alchemy,
                _ => Flavor::Generic,
            };
            Ok(Bundler::new(name, flavor, Http::new(url)))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let e = Env {
        c,
        rpc: Client::new(Http::new(var("SEND_RPC")?)),
        bundlers: Bundlers { list: bundlers },
        path: var("WALLET_STATE")?,
    };
    let a: Vec<&str> = args.iter().map(String::as_str).collect();
    match a.as_slice() {
        ["new", kind] => {
            let st = match *kind {
                "passkey" => {
                    let secret = random32();
                    let recovery = Key::from_bytes(&random32())?;
                    let pk = SoftPasskey {
                        key: p256::ecdsa::SigningKey::from_bytes(&secret.into())?,
                        rp_id: String::new(),
                        origin: String::new(),
                    };
                    let owners = FirstOwners {
                        passkey: Some(pk.public()),
                        addresses: vec![recovery.address()],
                    };
                    State {
                        passkey: Some(format!("0x{}", hex::encode(secret))),
                        recovery: Some(format!("0x{}", hex::encode(recovery.secret()))),
                        owner: None,
                        setup: Setup::new(&e.c, owners)?,
                    }
                }
                "address" => {
                    let owner = Key::from_bytes(&random32())?;
                    State {
                        passkey: None,
                        recovery: None,
                        owner: Some(format!("0x{}", hex::encode(owner.secret()))),
                        setup: Setup::new(
                            &e.c,
                            FirstOwners {
                                passkey: None,
                                addresses: vec![owner.address()],
                            },
                        )?,
                    }
                }
                _ => bail!("new passkey|address"),
            };
            ensure!(
                !std::path::Path::new(&e.path).exists(),
                "{} exists; move it aside first",
                e.path
            );
            std::fs::write(&e.path, serde_json::to_string_pretty(&st)?)?;
            println!("{:#x}", st.setup.address);
        }
        ["show"] => {
            let st = e.load()?;
            let w = st.setup.address;
            println!("address  {w:#x}");
            println!("deployed {}", e.deployed(w).await?);
            println!("usdc     {}", fmt_usdc(e.usdc_of(w).await?));
            println!("eth      {}", e.rpc.balance(w, BlockTag::Latest).await?);
            if e.deployed(w).await? {
                let owners = e
                    .rpc
                    .call_typed(w, &safe::getOwnersCall {}, BlockTag::Latest)
                    .await?;
                println!("owners   {owners:?}");
            }
        }
        ["verify", signer] => {
            // ERC-1271 through the check contract, deployed or not: a
            // message hash signed as the Safe's owners sign (SafeMessage).
            let st = e.load()?;
            let w = st.setup.address;
            let hash = botstadia_chain::sign::eip191_hash(b"BotStadia check");
            let sig = e.sign(&st, signer, op::safe_message_hash(&e.c, w, hash))?;
            let deployed = e.deployed(w).await?;
            let ok = botstadia_chain::wallet::check::is_valid(
                &e.rpc,
                &e.c,
                w,
                hash,
                &sig,
                Some(&st.setup.initializer),
            )
            .await?;
            let wrong = botstadia_chain::wallet::check::is_valid(
                &e.rpc,
                &e.c,
                w,
                botstadia_chain::sign::eip191_hash(b"other"),
                &sig,
                Some(&st.setup.initializer),
            )
            .await?;
            println!("deployed {deployed}: valid {ok}, other message {wrong}");
        }
        ["send", bundler, signer, "withdraw", to, amount] => {
            // The shared flow (wallet::flow), as the site and exit page run it.
            let st = e.load()?;
            let w = st.setup.address;
            let b: usize = bundler.parse()?;
            let bundler = e.bundlers.list.get(b).context("no such bundler")?;
            let s = FlowSigner {
                e: &e,
                st: &st,
                who: signer,
            };
            let calls = vec![calls::transfer(&e.c, to.parse()?, usdc(amount)?)];
            let before = e.usdc_of(w).await?;
            let r = botstadia_chain::wallet::flow::send(
                &e.rpc,
                bundler,
                &s,
                &e.c,
                w,
                calls,
                async |ms| tokio::time::sleep(Duration::from_millis(ms as u64)).await,
            )
            .await?;
            let after = e.usdc_of(w).await?;
            println!(
                "{}: tx {} gas {} USDC moved {}",
                bundler.name,
                r.transaction_hash,
                r.actual_gas_used,
                fmt_usdc(before - after)
            );
        }
        ["sign-message", key, wallet, message] => {
            // A Safe signature over an EIP-191 message (what the api checks
            // through ERC-1271), signed by a recovery key as written down.
            let k = botstadia_chain::wallet::recovery::decode(key)
                .map_err(|r| anyhow::anyhow!("not a recovery key: {r:?}"))?;
            let w: Address = wallet.parse()?;
            let message = message.replace("\\n", "\n");
            let hash = botstadia_chain::sign::eip191_hash(message.as_bytes());
            let d = op::safe_message_hash(&e.c, w, hash);
            let s = k.sign_hash(d)?;
            let sigs = op::safe_signatures(vec![OwnerSignature::Address {
                owner: k.address(),
                rsv: Bytes::from(s.as_bytes().to_vec()),
            }])?;
            println!("{sigs}");
        }
        ["fund", amount] => {
            let st = e.load()?;
            let key = Key::from_hex(&var("FUND_KEY")?)?;
            let (h, gas) = e
                .send_tx(
                    &key,
                    e.c.usdc,
                    calls::transferCall {
                        to: st.setup.address,
                        amount: usdc(amount)?,
                    }
                    .abi_encode(),
                )
                .await?;
            println!("funded {amount} USDC: {h} ({gas} gas)");
        }
        ["deploy"] => {
            let st = e.load()?;
            // The keeper's check: only the canonical template.
            Setup::check_canonical(&e.c, st.setup.address, &st.setup.initializer)?;
            let key = Key::from_hex(&var("DEPLOY_KEY")?)?;
            let data = safe::deploy_call(&e.c, &st.setup.initializer);
            let (h, gas) = e.send_tx(&key, e.c.proxy_factory, data).await?;
            ensure!(
                e.deployed(st.setup.address).await?,
                "nothing at the address"
            );
            println!("deployed {:#x}: {h} ({gas} gas)", st.setup.address);
        }
        ["op", bundler, signer, rest @ ..] => {
            let st = e.load()?;
            let w = st.setup.address;
            let b: usize = bundler.parse()?;
            let one = Bundlers {
                list: vec![
                    e.bundlers
                        .list
                        .into_iter()
                        .nth(b)
                        .context("no such bundler")?,
                ],
            };
            let e = Env { bundlers: one, ..e };
            let allowance = e
                .rpc
                .call_typed(
                    e.c.usdc,
                    &calls::allowanceCall {
                        owner: w,
                        spender: e.c.paymaster,
                    },
                    BlockTag::Latest,
                )
                .await?;
            let needs_permit = allowance < U256::from(paymaster::ALLOWANCE / 2);
            let statement = e
                .rpc
                .call_typed(
                    e.c.settlement,
                    &Settlement::statementsCall(w),
                    BlockTag::Latest,
                )
                .await?;
            let calls = match rest {
                ["first"] | ["bet"] => {
                    // A bet that can't be placed (no such session) is
                    // skipped with an event, and a claim with nothing to
                    // pay likewise: the whole shape of a first bet, without
                    // a live session.
                    let bogus = B256::repeat_byte(0x42);
                    calls::bet_batch(
                        &e.c,
                        vec![bogus],
                        vec![Settlement::BetItem {
                            session: bogus,
                            bot: B256::repeat_byte(0x43),
                            amount: U256::from(1_000_000),
                            bettor: w,
                            opening: Bytes::new(),
                        }],
                        !statement,
                        !needs_permit,
                    )
                }
                ["bet", session, bot, amount] => {
                    let item = Settlement::BetItem {
                        session: session.parse()?,
                        bot: bot.parse()?,
                        amount: usdc(amount)?,
                        bettor: w,
                        opening: std::env::var("OPENING")
                            .ok()
                            .map(|h| h.parse::<Bytes>())
                            .transpose()?
                            .unwrap_or_default(),
                    };
                    calls::bet_batch(&e.c, vec![], vec![item], !statement, !needs_permit)
                }
                ["withdraw", to, amount] => {
                    let mut v = vec![calls::transfer(&e.c, to.parse()?, usdc(amount)?)];
                    if !needs_permit {
                        v.push(calls::approve_paymaster(&e.c));
                    }
                    v
                }
                _ => bail!(
                    "op <bundler> <signer> first | bet <session> <bot> <usdc> | withdraw <to> <usdc>"
                ),
            };
            ensure!(e.deployed(w).await?, "deploy the wallet first");
            // The fallback paymaster: Pimlico's ERC-20 paymaster, which
            // charges in post-op, so an approve in the operation itself pays.
            let pimlico_pm: Option<Address> = std::env::var("PM_PIMLICO")
                .ok()
                .filter(|v| !v.is_empty())
                .map(|v| v.parse())
                .transpose()?;
            let mut calls = calls;
            if let Some(pm) = pimlico_pm {
                calls.retain(|c| c.data.get(16..36) != Some(e.c.paymaster.as_slice()));
                calls.insert(0, calls::approve(&e.c, pm, U256::from(1_000_000)));
            }
            let needs_permit = needs_permit && pimlico_pm.is_none();
            let permit_sig = if needs_permit {
                let nonce = e
                    .rpc
                    .call_typed(e.c.usdc, &calls::noncesCall { owner: w }, BlockTag::Latest)
                    .await?;
                let digest = paymaster::permit_digest(
                    &e.c,
                    w,
                    U256::from(paymaster::ALLOWANCE),
                    nonce,
                    U256::MAX,
                );
                let safe_hash = op::safe_message_hash(&e.c, w, digest);
                println!("permit: a second signature (first operation only)");
                e.sign(&st, signer, safe_hash)?
            } else {
                Bytes::new()
            };
            let nonce = e
                .rpc
                .call_typed(
                    e.c.entry_point,
                    &op::getNonceCall {
                        sender: w,
                        key: Default::default(),
                    },
                    BlockTag::Latest,
                )
                .await?;
            let mut uo = UserOp {
                sender: w,
                nonce,
                call_data: op::call_data(&e.c, &calls)?,
                signature: op::dummy_signature(&e.c, signer == &"passkey"),
                ..Default::default()
            };
            paymaster::attach(
                &mut uo,
                &e.c,
                paymaster::data(&e.c, U256::from(paymaster::ALLOWANCE), &permit_sig),
            );
            // Room for the estimate: some bundlers echo the limit they're
            // given rather than measure it.
            uo.paymaster_verification_gas_limit = Some(U256::from(
                std::env::var("PMV")
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(1_000_000),
            ));
            let bundler = &e.bundlers.list[0];
            let price = if bundler.flavor == Flavor::Generic {
                // A bundler with no fee method of its own: price from the RPC.
                let tip = U256::from(e.rpc.max_priority_fee().await?.max(1_000_000));
                let base = U256::from(e.rpc.gas_price().await?);
                botstadia_chain::wallet::bundler::GasPrice {
                    max_fee_per_gas: base * U256::from(2) + tip,
                    max_priority_fee_per_gas: tip,
                }
            } else {
                bundler.gas_price().await?
            };
            uo.max_fee_per_gas = price.max_fee_per_gas;
            uo.max_priority_fee_per_gas = price.max_priority_fee_per_gas;
            let pm_ctx = serde_json::json!({ "token": format!("{:#x}", e.c.usdc) });
            let chain_hex = format!("0x{:x}", e.c.chain_id);
            if let Some(pm) = pimlico_pm {
                let stub = bundler
                    .rpc
                    .request(
                        "pm_getPaymasterStubData",
                        serde_json::json!([
                            uo,
                            format!("{:#x}", e.c.entry_point),
                            chain_hex,
                            pm_ctx
                        ]),
                    )
                    .await
                    .context("stub")?;
                println!("pimlico stub: {stub}");
                uo.paymaster = Some(pm);
                uo.paymaster_data = Some(serde_json::from_value(stub["paymasterData"].clone())?);
                if let Some(v) = stub
                    .get("paymasterVerificationGasLimit")
                    .filter(|v| !v.is_null())
                {
                    uo.paymaster_verification_gas_limit = Some(serde_json::from_value(v.clone())?);
                }
                if let Some(v) = stub.get("paymasterPostOpGasLimit").filter(|v| !v.is_null()) {
                    uo.paymaster_post_op_gas_limit = Some(serde_json::from_value(v.clone())?);
                }
            }
            let est = bundler.estimate(&e.c, &uo).await.context("estimate")?;
            uo.pre_verification_gas = est.pre_verification_gas;
            uo.verification_gas_limit = est.verification_gas_limit;
            uo.call_gas_limit = est.call_gas_limit;
            if let Some(v) = est.paymaster_verification_gas_limit {
                uo.paymaster_verification_gas_limit = Some(v);
            }
            if let Some(v) = est.paymaster_post_op_gas_limit {
                // Circle's post-op refuses less than its own charge.
                uo.paymaster_post_op_gas_limit = Some(v.max(U256::from(paymaster::POST_OP_GAS)));
            }
            if pimlico_pm.is_some() {
                let d = bundler
                    .rpc
                    .request(
                        "pm_getPaymasterData",
                        serde_json::json!([
                            uo,
                            format!("{:#x}", e.c.entry_point),
                            chain_hex,
                            pm_ctx
                        ]),
                    )
                    .await
                    .context("paymaster data")?;
                uo.paymaster_data = Some(serde_json::from_value(d["paymasterData"].clone())?);
                if let Some(v) = d
                    .get("paymasterVerificationGasLimit")
                    .filter(|v| !v.is_null())
                {
                    uo.paymaster_verification_gas_limit = Some(serde_json::from_value(v.clone())?);
                }
                if let Some(v) = d.get("paymasterPostOpGasLimit").filter(|v| !v.is_null()) {
                    uo.paymaster_post_op_gas_limit = Some(serde_json::from_value(v.clone())?);
                }
            }
            let digest = uo.safe_op_hash(&e.c, 0, 0);
            // Check our SafeOp hash against the module's own.
            let packed = (
                w,
                uo.nonce,
                Bytes::from(uo.init_code()),
                uo.call_data.clone(),
                B256::from((uo.verification_gas_limit << 128) | uo.call_gas_limit),
                uo.pre_verification_gas,
                B256::from((uo.max_priority_fee_per_gas << 128) | uo.max_fee_per_gas),
                Bytes::from(uo.paymaster_and_data()),
                op::op_signature(0, 0, &[]),
            );
            let mut q = alloy_primitives::keccak256(
                "getOperationHash((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes))",
            )[..4]
                .to_vec();
            q.extend_from_slice(&(packed,).abi_encode_params());
            let theirs = e
                .rpc
                .call(e.c.safe_4337_module, &q, BlockTag::Latest)
                .await?;
            ensure!(
                theirs.as_ref() == digest.as_slice(),
                "SafeOp hash differs from the module's"
            );
            let sigs = e.sign(&st, signer, digest)?;
            uo.signature = op::op_signature(0, 0, &sigs);
            println!(
                "gas: pvg {} vgl {} cgl {} pmv {:?} pmp {:?}; max fee {} prio {}",
                uo.pre_verification_gas,
                uo.verification_gas_limit,
                uo.call_gas_limit,
                uo.paymaster_verification_gas_limit,
                uo.paymaster_post_op_gas_limit,
                uo.max_fee_per_gas,
                uo.max_priority_fee_per_gas
            );
            let before = e.usdc_of(w).await?;
            let (_, hash) = e.bundlers.send(&e.c, &uo).await?;
            println!("sent to {}: {hash}", bundler.name);
            let started = std::time::Instant::now();
            let receipt = loop {
                if let Some(r) = bundler.receipt(hash).await? {
                    break r;
                }
                ensure!(
                    started.elapsed() < Duration::from_secs(120),
                    "not included in 2 minutes"
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
            };
            let after = e.usdc_of(w).await?;
            println!(
                "included in {:.1}s, block {}, tx {}: success {} {:?}",
                started.elapsed().as_secs_f64(),
                receipt.block_number,
                receipt.transaction_hash,
                receipt.success,
                receipt.reason
            );
            println!(
                "gas used {}, cost {} wei; USDC {} -> {} (moved {})",
                receipt.actual_gas_used,
                receipt.actual_gas_cost,
                fmt_usdc(before),
                fmt_usdc(after),
                fmt_usdc(before - after)
            );
        }
        _ => bail!("wallet new|show|fund|deploy|op …"),
    }
    Ok(())
}

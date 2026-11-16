//! Checking the BundleKey before wrapping to it (TRUST.md#bundle-encryption).
//!
//! The CLI checks the attestation token behind a published boot proof
//! itself, not the zk proof, as enclaves do at handover: Google's signature
//! chain, our project id, and the nonce binding the keys, as of the token's
//! issue time. It reads the chain itself through two RPC providers, acting
//! only on what they agree on, never through our api: the image and root are
//! approved and not revoked, the SubmitKey the token binds is approved and
//! not revoked, the token's binding is the results contract it's configured
//! for, and its BundleKey is the one the chain holds for the newest filled
//! new-key instruction. It refuses to wrap at all while a newer instruction
//! is pending or in effect but unfilled.
//!
//! So we can't hand builders a key of our own, and bundle secrecy never rests
//! on the zk verifier's soundness.

use alloy_sol_types::SolCall;
use botstadia_attestation_core::{Binding, Journal, verify_token};
use botstadia_chain::abi::Results;
use botstadia_chain::rpc::{BlockTag, Client, Http};
use botstadia_chain::{Address, B256};

/// What a check needs to know, from the CLI's own config.
pub struct Expect {
    pub chain_id: u64,
    pub results: Address,
    pub project: String,
}

/// The BundleKey a builder may wrap to, once checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    pub bundle_key: [u8; 32],
    pub instruction: u64,
}

async fn agree<C: SolCall>(
    a: &Client<Http>,
    b: &Client<Http>,
    to: Address,
    call: &C,
    at: u64,
) -> anyhow::Result<C::Return>
where
    C::Return: PartialEq + std::fmt::Debug,
{
    let x = a.call_typed(to, call, BlockTag::Number(at)).await?;
    let y = b.call_typed(to, call, BlockTag::Number(at)).await?;
    anyhow::ensure!(x == y, "the two RPC providers disagree; not wrapping");
    Ok(x)
}

/// A yes/no getter that must hold at the finalized block `at`. When it holds
/// only at the head, it was approved too recently to be final (Base's
/// finalized block trails by about twenty minutes): `fresh` says so, rather
/// than the plain refusal `refused`.
async fn final_yes<C: SolCall<Return = bool>>(
    a: &Client<Http>,
    b: &Client<Http>,
    to: Address,
    call: &C,
    at: u64,
    refused: &str,
    fresh: &str,
) -> anyhow::Result<()> {
    if agree(a, b, to, call, at).await? {
        return Ok(());
    }
    if a.call_typed(to, call, BlockTag::Latest)
        .await
        .unwrap_or(false)
    {
        anyhow::bail!(
            "{fresh}: not final on-chain yet, so not trusted; try again in {}",
            BlockTag::SETTLED_LAG
        );
    }
    anyhow::bail!("{refused}")
}

/// Check one published boot proof (its token and journal) and return the
/// BundleKey to wrap to.
pub async fn check(
    rpc: (&Client<Http>, &Client<Http>),
    expect: &Expect,
    token: &str,
    journal_hex: &str,
) -> anyhow::Result<Checked> {
    let (a, b) = rpc;
    let journal_bytes = hex::decode(journal_hex.trim_start_matches("0x"))?;
    let journal =
        Journal::decode(&journal_bytes).ok_or_else(|| anyhow::anyhow!("not a journal"))?;
    // The token as of its own issue time.
    let t = verify_token(token, &[], journal.issued_at)
        .map_err(|e| anyhow::anyhow!("the attestation token is refused: {e}"))?;
    anyhow::ensure!(
        t.project == expect.project,
        "the token names another project"
    );
    anyhow::ensure!(
        journal.chain_id == expect.chain_id && journal.results == expect.results.0.0,
        "the token's chain binding isn't the results contract this CLI is configured for"
    );
    let binding = Binding {
        submit_key: journal.submit_key,
        bundle_key: journal.bundle_key,
        chain_id: journal.chain_id,
        results: journal.results,
        instruction: journal.instruction,
    };
    anyhow::ensure!(
        t.nonces.contains(&binding.nonce()),
        "the token's nonce doesn't bind this BundleKey"
    );
    anyhow::ensure!(
        t.image_digest == journal.image_digest && t.root_hash == journal.root_hash,
        "the journal isn't the token's"
    );

    // Read the chain at a finalized block both providers have.
    let fa = a.block(BlockTag::SETTLED).await?;
    let fb = b.block(BlockTag::SETTLED).await?;
    let at = fa.number.min(fb.number);
    let block_time = a.block(BlockTag::Number(at)).await?.timestamp;
    let r = expect.results;
    final_yes(
        a,
        b,
        r,
        &Results::imageApprovedCall {
            digest: B256::from(journal.image_digest),
        },
        at,
        "the token's image isn't approved",
        "the enclave's image was approved moments ago",
    )
    .await?;
    anyhow::ensure!(
        agree(
            a,
            b,
            r,
            &Results::rootApprovedCall {
                rootHash: B256::from(journal.root_hash)
            },
            at
        )
        .await?,
        "the token's root isn't an approved GoogleRootCert"
    );
    final_yes(
        a,
        b,
        r,
        &Results::keyActiveCall {
            key: Address::from(journal.submit_key),
        },
        at,
        "the SubmitKey the token binds isn't approved, or is revoked",
        "the enclave's key was approved moments ago",
    )
    .await?;
    let count = agree(a, b, r, &Results::instructionCountCall {}, at).await?;
    let mut n = count;
    while n > 0 {
        let i = agree(a, b, r, &Results::instructionsCall(n), at).await?;
        if i.readyAt == 0 {
            n -= 1; // withdrawn
            continue;
        }
        anyhow::ensure!(
            i.readyAt <= block_time,
            "a newer new-key instruction is pending: not wrapping until it's filled"
        );
        anyhow::ensure!(
            i.bundleKey != B256::ZERO,
            "the newest new-key instruction isn't filled yet: not wrapping"
        );
        anyhow::ensure!(
            n == journal.instruction && i.bundleKey == B256::from(journal.bundle_key),
            "this boot proof's BundleKey isn't the one the chain holds for the newest instruction"
        );
        return Ok(Checked {
            bundle_key: journal.bundle_key,
            instruction: n,
        });
    }
    anyhow::bail!("no new-key instruction is in effect: uploads are paused")
}

/// Pick a boot proof from the api's list and check it; the api only serves
/// them, and is trusted for nothing.
pub async fn check_any(
    rpc: (&Client<Http>, &Client<Http>),
    expect: &Expect,
    proofs: &[(String, String)],
) -> anyhow::Result<Checked> {
    // The newest proof's refusal is the one worth saying: older ones are
    // older machines' (often a retired image's), and saying theirs hid "not
    // final yet" for a key approved moments ago (found on the testnet).
    let mut newest: Option<anyhow::Error> = None;
    for (token, journal) in proofs.iter().rev() {
        match check(rpc, expect, token, journal).await {
            Ok(c) => return Ok(c),
            Err(e) => {
                newest.get_or_insert(e);
            }
        }
    }
    Err(newest.unwrap_or_else(|| anyhow::anyhow!("the api published no boot proof")))
}

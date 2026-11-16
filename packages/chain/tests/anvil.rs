//! The chain SDK against the real contracts on a local Anvil
//! (`task chain:test-sdk` deploys them, runs this, and stops Anvil). Rust and
//! Solidity must agree exactly on spec hashes, entries, Merkle roots,
//! journals and signed results.
//!
//! Ignored unless run by that task, since it needs the chain.

use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_sol_types::SolCall;
use botstadia_chain::abi::{Results, Settlement};
use botstadia_chain::entry::{Entry, FieldEntry, FieldLeaf, field_root, ladder_id};
use botstadia_chain::events::{Contracts, Event, decode};
use botstadia_chain::journal::Journal;
use botstadia_chain::outcome::Outcome;
use botstadia_chain::rpc::{BlockTag, Client, Http, Receipt};
use botstadia_chain::sign::{Key, ResultMessage, recover};
use botstadia_chain::spec::Spec;
use botstadia_chain::{merkle, tx};
use serde_json::json;
use sha2::{Digest, Sha256};

alloy_sol_types::sol! {
    struct Receipt0 { bytes seal; bytes32 claimDigest; }
    function mockProve(bytes32 imageId, bytes32 journalDigest) external view returns (Receipt0 memory);
}

/// Anvil's well-known keys for the test mnemonic: index 2 is the operator.
const OPERATOR: &str = "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a";

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is set by `task chain:test-sdk`"))
}

struct Chain {
    rpc: Client<Http>,
    chain_id: u64,
    results: Address,
    settlement: Address,
}

impl Chain {
    async fn send(&self, key: &Key, to: Address, data: Vec<u8>) -> Receipt {
        let nonce = self
            .rpc
            .nonce(key.address(), BlockTag::Latest)
            .await
            .unwrap();
        let gas = self
            .rpc
            .estimate_gas(key.address(), to, &data)
            .await
            .unwrap();
        let price = self.rpc.gas_price().await.unwrap();
        let signed = tx::sign(
            key,
            self.chain_id,
            nonce,
            gas * 2,
            tx::Fees {
                max_fee_per_gas: price * 2,
                max_priority_fee_per_gas: price,
            },
            &tx::Call {
                to,
                data,
                value: U256::ZERO,
            },
        )
        .unwrap();
        let hash = self.rpc.send_raw(&signed.raw).await.unwrap();
        assert_eq!(hash, signed.hash, "the SDK computes the hash the node does");
        let mut receipt = None;
        for _ in 0..50 {
            receipt = self.rpc.receipt(hash).await.unwrap();
            if receipt.is_some() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let receipt = receipt.expect("Anvil mines within a second");
        assert!(receipt.succeeded(), "transaction to {to} reverted");
        receipt
    }

    async fn warp(&self, seconds: u64) {
        self.rpc
            .request("evm_increaseTime", json!([seconds]))
            .await
            .unwrap();
        self.rpc.request("evm_mine", json!([])).await.unwrap();
    }

    fn contracts(&self) -> Contracts {
        Contracts {
            results: self.results,
            settlement: self.settlement,
            standing_orders: Address::ZERO,
        }
    }
}

#[tokio::test]
#[ignore = "needs the local chain: run `task chain:test-sdk`"]
async fn rust_and_solidity_agree_from_post_to_signed_result() {
    let chain = Chain {
        rpc: Client::new(Http::new(env("BOTSTADIA_ANVIL_URL"))),
        chain_id: 0,
        results: env("BOTSTADIA_RESULTS").parse().unwrap(),
        settlement: env("BOTSTADIA_SETTLEMENT").parse().unwrap(),
    };
    let chain = Chain {
        chain_id: chain.rpc.chain_id().await.unwrap(),
        ..chain
    };
    let operator = Key::from_hex(OPERATOR).unwrap();

    // A spec, hashed by Rust and by the settlement contract.
    let now = chain.rpc.block(BlockTag::Latest).await.unwrap().timestamp;
    let close = now + 2 * 3600;
    let spec = Spec {
        digests: vec![
            B256::repeat_byte(0x11),
            B256::repeat_byte(0x22),
            B256::repeat_byte(0x33),
        ],
        payouts: vec![
            Address::repeat_byte(0xA1),
            Address::ZERO,
            Address::repeat_byte(0xA3),
        ],
        arena: B256::repeat_byte(0x44),
        chain_id: chain.chain_id,
        results: chain.results,
        nonce: keccak256("anvil-test"),
        budget_version: 1,
    };
    spec.check().unwrap();
    let on_chain = chain
        .rpc
        .call_typed(
            chain.settlement,
            &Settlement::specHashCall {
                spec: spec.to_sol(),
            },
            BlockTag::Latest,
        )
        .await
        .unwrap();
    assert_eq!(on_chain, spec.hash(), "spec hash");

    // A post: the contract's root is the SDK's.
    let session = Entry::Session {
        spec_hash: spec.hash(),
        digests: spec.digests.clone(),
        close,
        week: B256::repeat_byte(0x77),
        round: 1,
    };
    let leaves: Vec<FieldLeaf> = spec
        .digests
        .iter()
        .enumerate()
        .map(|(i, d)| FieldLeaf {
            digest: *d,
            payout: spec.payouts[i],
            mu: 25_000_000 - i as i64,
            sigma: 8_333_333,
            group: keccak256([i as u8]),
        })
        .collect();
    let field = FieldEntry {
        week: B256::repeat_byte(0x77),
        ladder_id: ladder_id("racing", 1),
        arena: spec.arena,
        budget_version: 1,
        rating_version: 1,
        standings_version: 1,
        field_root: field_root(&leaves).unwrap(),
        pool_close: close + 3600,
        final_close: close + 7200,
        championship: true,
        rounds: 5,
    };
    let entries = vec![
        Entry::Arena {
            digest: spec.arena,
            ladder_id: ladder_id("racing", 1),
            payload_schema: 1,
        }
        .encode(),
        Entry::Rating { version: 1 }.encode(),
        session.encode(),
        Entry::Field(field.clone()).encode(),
        Entry::Standings { version: 1 }.encode(),
    ];
    let receipt = chain
        .send(
            &operator,
            chain.results,
            Results::postCall {
                entries: entries.iter().cloned().map(Bytes::from).collect(),
            }
            .abi_encode(),
        )
        .await;
    let posted = receipt
        .logs
        .iter()
        .find_map(|log| match decode(&chain.contracts(), log) {
            Some(Event::Posted(p)) => Some(p),
            _ => None,
        })
        .expect("a Posted event");
    assert_eq!(posted.root, merkle::root(&entries), "Merkle root");
    let decoded: Vec<Vec<u8>> = posted.entries.iter().map(|b| b.to_vec()).collect();
    assert_eq!(decoded, entries, "the post emits the list");
    // The field entry and its leaves decode and hash as the contracts do.
    let f = chain
        .rpc
        .call_typed(
            chain.results,
            &Results::decodeFieldCall {
                entry: Bytes::from(entries[3].clone()),
            },
            BlockTag::Latest,
        )
        .await
        .unwrap();
    assert_eq!(
        (
            f.week,
            f.fieldRoot,
            f.poolClose,
            f.finalClose,
            f.standingsVersion
        ),
        (
            field.week,
            field.field_root,
            field.pool_close,
            field.final_close,
            1
        )
    );
    let s = chain
        .rpc
        .call_typed(
            chain.results,
            &Results::decodeSessionCall {
                entry: Bytes::from(entries[2].clone()),
            },
            BlockTag::Latest,
        )
        .await
        .unwrap();
    assert_eq!((s.week, s.round), (B256::repeat_byte(0x77), 1));
    for l in &leaves {
        let on_chain = chain
            .rpc
            .call_typed(
                chain.settlement,
                &Settlement::leafHashCall {
                    leaf: Settlement::FieldLeaf {
                        digest: l.digest,
                        payout: l.payout,
                        mu: l.mu,
                        sigma: l.sigma,
                        group: l.group,
                    },
                },
                BlockTag::Latest,
            )
            .await
            .unwrap();
        assert_eq!(on_chain, keccak256(l.encode()), "leaf hash");
    }
    for (i, entry) in entries.iter().enumerate() {
        let proven = chain
            .rpc
            .call_typed(
                chain.results,
                &Results::inPostCall {
                    number: posted.post,
                    entry: Bytes::from(entry.clone()),
                    proof: merkle::proof(&entries, i),
                },
                BlockTag::Latest,
            )
            .await
            .unwrap();
        assert!(proven, "entry {i} proves");
    }
    assert_eq!(
        Entry::decode(&entries[2]).unwrap().id(),
        keccak256(&entries[2])
    );

    // A SubmitKey approved through the mock verifier, from a journal the SDK
    // encoded and the contract decoded.
    let enclave = Key::from_bytes(&keccak256("anvil-test-enclave").0).unwrap();
    chain
        .rpc
        .request(
            "anvil_setBalance",
            json!([enclave.address(), "0x56BC75E2D63100000"]),
        )
        .await
        .unwrap();
    let journal = Journal {
        image_digest: env("BOTSTADIA_LOCAL_IMAGE_DIGEST").parse().unwrap(),
        project_id: keccak256(env("BOTSTADIA_PROJECT_ID")),
        submit_key: enclave.address(),
        bundle_key: keccak256("anvil-test-bundle-key"),
        chain_id: chain.chain_id,
        results: chain.results,
        instruction: 1,
        issued_at: chain.rpc.block(BlockTag::Latest).await.unwrap().timestamp,
        root_hash: env("BOTSTADIA_LOCAL_ROOT_HASH").parse().unwrap(),
    };
    let journal_bytes = journal.encode();
    let guest: B256 = env("BOTSTADIA_LOCAL_GUEST_IMAGE_ID").parse().unwrap();
    let mock: Address = env("BOTSTADIA_MOCK_VERIFIER").parse().unwrap();
    let digest = B256::from_slice(&Sha256::digest(&journal_bytes));
    let receipt0 = chain
        .rpc
        .call_typed(
            mock,
            &mockProveCall {
                imageId: guest,
                journalDigest: digest,
            },
            BlockTag::Latest,
        )
        .await
        .unwrap();
    let verifier = chain
        .rpc
        .call_typed(
            chain.results,
            &Results::verifierIdCall {
                verifier: mock,
                guestImageId: guest,
            },
            BlockTag::Latest,
        )
        .await
        .unwrap();
    chain
        .send(
            &enclave,
            chain.results,
            Results::approveKeyCall {
                verifier,
                seal: receipt0.seal,
                journal: Bytes::from(journal_bytes),
            }
            .abi_encode(),
        )
        .await;
    let active = chain
        .rpc
        .call_typed(
            chain.results,
            &Results::keyActiveCall {
                key: enclave.address(),
            },
            BlockTag::Latest,
        )
        .await
        .unwrap();
    assert!(active, "the key is approved");

    // Anchor after close, then a signed result the contract accepts.
    chain.warp(2 * 3600 + 5).await;
    let receipt = chain
        .send(
            &enclave,
            chain.results,
            Results::anchorCall {
                items: vec![Results::AnchorItem {
                    post: posted.post,
                    entry: Bytes::from(entries[2].clone()),
                    proof: merkle::proof(&entries, 2),
                    fieldEntry: Bytes::new(),
                }],
            }
            .abi_encode(),
        )
        .await;
    let anchored = receipt
        .logs
        .iter()
        .find_map(|log| match decode(&chain.contracts(), log) {
            Some(Event::Anchored(a)) => Some(a),
            _ => None,
        })
        .expect("an Anchored event");
    assert_eq!(anchored.session, session.id());
    assert_eq!(anchored.key, enclave.address());

    chain.warp(15 * 60).await;
    let outcome = Outcome::from_groups(3, &[vec![1], vec![0, 2]]).unwrap();
    let message = ResultMessage {
        chain_id: chain.chain_id,
        results: chain.results,
        session: session.id(),
        outcome: outcome.encode(),
        anchor: anchored.anchor,
        anchor_block: anchored.blockNumber,
        seed: keccak256("seed"),
        spec_hash: spec.hash(),
        archive_hash: keccak256("archive"),
    };
    let signature = enclave.sign_message(&message.encode()).unwrap();
    let receipt = chain
        .send(
            &enclave,
            chain.results,
            Results::submitCall {
                items: vec![Results::ResultItem {
                    session: session.id(),
                    anchor: anchored.anchor,
                    anchorBlock: anchored.blockNumber,
                    specHash: spec.hash(),
                    outcome: Bytes::from(outcome.encode()),
                    seed: message.seed,
                    archiveHash: message.archive_hash,
                    signature: signature.clone(),
                }],
                ratingItems: vec![],
            }
            .abi_encode(),
        )
        .await;
    let accepted = receipt
        .logs
        .iter()
        .find_map(|log| match decode(&chain.contracts(), log) {
            Some(Event::ResultAccepted(r)) => Some(r),
            _ => None,
        })
        .expect("a ResultAccepted event");
    assert_eq!(Outcome::decode(&accepted.outcome).unwrap(), outcome);
    // Anyone can check the single result off-chain from the event alone.
    let rebuilt = ResultMessage {
        outcome: accepted.outcome.to_vec(),
        seed: accepted.seed,
        archive_hash: accepted.archiveHash,
        ..message
    };
    assert_eq!(
        recover(&rebuilt.encode(), &accepted.signature).unwrap(),
        enclave.address()
    );
    let state = chain
        .rpc
        .call_typed(
            chain.results,
            &Results::sessionStateCall {
                session: session.id(),
            },
            BlockTag::Latest,
        )
        .await
        .unwrap();
    assert!(state.resolved);
    assert_eq!(state.firstMask, U256::from(1u8 << 1));
}

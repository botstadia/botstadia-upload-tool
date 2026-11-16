//! BotStadia's chain SDK.
//!
//! One crate, shared by everything that talks to the contracts, so the api,
//! the keeper, the alert Worker, the session runner and the CLI encode and
//! check exactly what the contracts do:
//!
//! - [`abi`]: bindings generated from the contracts' ABI, committed under
//!   `abi/` and checked against `contracts/out` so they can't drift
//! - [`spec`]: the session spec and its hash (TRUST.md#what-the-enclave-signs)
//! - [`entry`]: the hourly post's entries and session ids
//! - [`merkle`]: the post's Merkle tree, domain-separated leaves
//! - [`outcome`]: a result's outcome encoding
//! - [`sign`]: SubmitKey signing (EIP-191 over opaque bytes), the result and
//!   final-rating messages, recovery
//! - [`journal`]: the zk guest's journal, as the results contract decodes it
//! - [`tx`]: signing EIP-1559 transactions for a key
//! - [`rpc`]: JSON-RPC behind one trait, over HTTP natively and over fetch
//!   in Workers, with the reads and sends the rest of the platform needs
//! - [`events`]: decoding the contracts' events for indexing
//!
//! It builds for native targets and for `wasm32-unknown-unknown` (Workers):
//! nothing here brings a runtime or a network stack of its own.

pub mod abi;
pub mod entry;
pub mod events;
pub mod journal;
pub mod merkle;
pub mod outcome;
pub mod rpc;
pub mod sign;
pub mod spec;
pub mod tx;
pub mod wallet;

pub use alloy_primitives::{Address, B256, Bytes, Signature, U256, keccak256};

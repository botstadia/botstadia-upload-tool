//! The public upload path (TRUST.md#bundle-encryption).
//!
//! Every bundle is encrypted with a fresh random data key, and the data key
//! is wrapped twice: to the BundleKey, so enclaves can open it, and to the
//! builder's author key, so its builder can rekey it. We store the
//! ciphertext and both wrapped copies and can open neither.
//!
//! - [`author`]: the author key, generated once, kept by the CLI, with its
//!   recovery phrase; its two halves (wrapping and signing)
//! - [`seal`]: encrypting a bundle and wrapping its data key; opening and
//!   rewrapping (the enclave and `botstadia rekey`)
//! - [`proof`]: checking the BundleKey's boot proof before wrapping to it
//!   (with feature `chain`)
//! - [`client`]: the account side the CLI and the standalone tool share:
//!   the config folder and author key storage, the api client, and the
//!   `login`, `key`, `upload`, `status`, `rekey`, `confirm-wallet` and `sign`
//!   commands (with feature `client`)
//!
//! With feature `tool`, it builds the standalone upload tool,
//! `botstadia-upload`, made entirely from public source.
//!
//! This crate holds only code a builder's bundle touches, so it can be
//! exported, alone, to the standalone upload tool's public repository.

pub mod author;
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "chain")]
pub mod proof;
pub mod seal;

/// `sha256-<hex>` of a bundle's plaintext ZIP: how a bot is named.
pub fn digest(zip: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256-{}", hex::encode(Sha256::digest(zip)))
}

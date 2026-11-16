//! The recovery key and what's saved with it (TRUST.md#a-way-out-without-us).
//!
//! A recovery key is a secp256k1 key made in the browser and added as an
//! owner. It's written with a checksum, so a bad copy is caught at entry,
//! and it's saved as one thing with the wallet's address and setup data:
//! all anyone needs to deploy and move the wallet without us.
//!
//! The written form is `bsrk1-` then the key's 64 hex digits in eight groups
//! of eight, then an eight-digit checksum (the first four bytes of the
//! key's keccak256), all dash-separated. Case and spacing don't matter when
//! it's typed back.

use alloy_primitives::{Address, Bytes, keccak256};
use serde::{Deserialize, Serialize};

use crate::sign::Key;

pub const PREFIX: &str = "bsrk1";

/// The key as written down.
pub fn encode(secret: &[u8; 32]) -> String {
    let hex = alloy_primitives::hex::encode(secret);
    let check = alloy_primitives::hex::encode(&keccak256(secret)[..4]);
    let mut parts = vec![PREFIX.to_string()];
    parts.extend(
        hex.as_bytes()
            .chunks(8)
            .map(|c| String::from_utf8_lossy(c).into_owned()),
    );
    parts.push(check);
    parts.join("-")
}

/// Why a typed key was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// Not a recovery key's shape at all.
    NotAKey,
    /// The right shape, but a digit is wrong: a bad copy.
    BadChecksum,
}

/// Read a typed or pasted key back, checking its checksum.
pub fn decode(text: &str) -> Result<Key, Refused> {
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_lowercase();
    let body = cleaned.strip_prefix(PREFIX).ok_or(Refused::NotAKey)?;
    if body.len() != 72 || !body.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Refused::NotAKey);
    }
    let secret: [u8; 32] = alloy_primitives::hex::decode(&body[..64])
        .map_err(|_| Refused::NotAKey)?
        .try_into()
        .map_err(|_| Refused::NotAKey)?;
    let check = alloy_primitives::hex::decode(&body[64..]).map_err(|_| Refused::NotAKey)?;
    if keccak256(secret)[..4] != check[..] {
        return Err(Refused::BadChecksum);
    }
    Key::from_bytes(&secret).map_err(|_| Refused::NotAKey)
}

/// What's saved: the key (if there is one), the wallet and its setup data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Save {
    pub recovery_key: Option<String>,
    pub wallet: Address,
    pub chain_id: u64,
    pub setup_data: Bytes,
}

impl Save {
    /// The plain text a password manager, a printout or a download holds.
    pub fn text(&self) -> String {
        let mut out = String::from("BotStadia wallet\n");
        if let Some(k) = &self.recovery_key {
            out.push_str(&format!("recovery key: {k}\n"));
        }
        out.push_str(&format!("wallet: {:#x}\n", self.wallet));
        out.push_str(&format!("chain: {}\n", self.chain_id));
        out.push_str(&format!("setup data: {}\n", self.setup_data));
        out
    }

    /// Read the saved text back (the exit page's input). Lines in any order.
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let mut key = None;
        let mut wallet = None;
        let mut chain = None;
        let mut setup = None;
        for line in text.lines() {
            let Some((k, v)) = line.split_once(':') else {
                continue;
            };
            let v = v.trim();
            match k.trim() {
                "recovery key" => key = Some(v.to_string()),
                "wallet" => wallet = Some(v.parse()?),
                "chain" => chain = Some(v.parse()?),
                "setup data" => setup = Some(v.parse()?),
                _ => {}
            }
        }
        Ok(Self {
            recovery_key: key,
            wallet: wallet.ok_or_else(|| anyhow::anyhow!("no wallet line"))?,
            chain_id: chain.ok_or_else(|| anyhow::anyhow!("no chain line"))?,
            setup_data: setup.ok_or_else(|| anyhow::anyhow!("no setup data line"))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_round_trips_and_a_bad_copy_is_caught() {
        let secret = [0x5a; 32];
        let text = encode(&secret);
        assert!(text.starts_with("bsrk1-"));
        assert_eq!(decode(&text).unwrap().secret(), secret);
        // Spacing and case don't matter.
        assert_eq!(
            decode(&text.to_uppercase().replace('-', " "))
                .unwrap()
                .secret(),
            secret
        );
        // One digit wrong.
        let mut bad = text.clone().into_bytes();
        let i = 10;
        bad[i] = if bad[i] == b'a' { b'b' } else { b'a' };
        assert_eq!(
            decode(&String::from_utf8(bad).unwrap()).unwrap_err(),
            Refused::BadChecksum
        );
        assert_eq!(decode("hello").unwrap_err(), Refused::NotAKey);
    }

    #[test]
    fn the_save_reads_back() {
        let s = Save {
            recovery_key: Some(encode(&[1; 32])),
            wallet: Address::repeat_byte(3),
            chain_id: 84532,
            setup_data: vec![1, 2, 3].into(),
        };
        assert_eq!(Save::parse(&s.text()).unwrap(), s);
    }
}

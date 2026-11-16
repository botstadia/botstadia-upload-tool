//! The author key (TRUST.md#bundle-encryption): a builder's own key, made by
//! the CLI on first use and kept in its config folder. It's never crypto the
//! builder handles or pays with.
//!
//! One 32-byte secret, shown as a 24-word recovery phrase (BIP-39), gives two
//! keys by HKDF-SHA256 under their own labels:
//! - an X25519 key that unwraps the builder's copy of each data key (rekey);
//! - a secp256k1 key that signs (ownership, retirements, `confirm-wallet`).
//!
//! The api keeps both public halves per bot; neither is shown on profiles.

use botstadia_chain::sign::Key;
use hkdf::Hkdf;
use sha2_011::Sha256;

const WRAP_LABEL: &[u8] = b"botstadia-author-x25519-v1";
const SIGN_LABEL: &[u8] = b"botstadia-author-secp256k1-v1";

#[derive(Clone)]
pub struct AuthorKey {
    secret: [u8; 32],
}

impl std::fmt::Debug for AuthorKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AuthorKey({})", self.address())
    }
}

fn derive(secret: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(None, secret)
        .expand(label, &mut out)
        .expect("32 bytes is a valid HKDF length");
    out
}

impl AuthorKey {
    /// A new key from the operating system's randomness.
    pub fn generate() -> anyhow::Result<Self> {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;
        Ok(Self { secret })
    }

    pub fn from_secret(secret: [u8; 32]) -> Self {
        Self { secret }
    }

    pub fn secret(&self) -> [u8; 32] {
        self.secret
    }

    /// The 24-word recovery phrase.
    pub fn phrase(&self) -> String {
        bip39::Mnemonic::from_entropy(&self.secret)
            .expect("32 bytes of entropy make a 24-word phrase")
            .to_string()
    }

    /// Restore from a recovery phrase; a typo fails its checksum.
    pub fn from_phrase(phrase: &str) -> anyhow::Result<Self> {
        let m = bip39::Mnemonic::parse_normalized(phrase.trim())
            .map_err(|e| anyhow::anyhow!("that recovery phrase isn't right: {e}"))?;
        let entropy = m.to_entropy();
        let secret: [u8; 32] = entropy
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("a recovery phrase is 24 words"))?;
        Ok(Self { secret })
    }

    /// The wrapping half's private key (X25519).
    pub fn x25519_secret(&self) -> [u8; 32] {
        derive(&self.secret, WRAP_LABEL)
    }

    /// The wrapping half's public key, as the api keeps it.
    pub fn x25519_public(&self) -> [u8; 32] {
        crate::seal::x25519_public(&self.x25519_secret())
    }

    /// The signing half.
    pub fn signer(&self) -> Key {
        // A derived 32 bytes is a valid secp256k1 secret but for a 2^-128
        // chance; re-derive with a counter rather than fail.
        let mut label = SIGN_LABEL.to_vec();
        loop {
            if let Ok(key) = Key::from_bytes(&derive(&self.secret, &label)) {
                return key;
            }
            label.push(0);
        }
    }

    /// The signing half's address, as the api keeps it.
    pub fn address(&self) -> String {
        format!("{:#x}", self.signer().address())
    }

    /// EIP-191 over `message`, 0x hex.
    pub fn sign(&self, message: &str) -> anyhow::Result<String> {
        Ok(self.signer().sign_message(message.as_bytes())?.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_phrase_restores_the_same_key_and_a_typo_fails() {
        let key = AuthorKey::from_secret([7; 32]);
        let phrase = key.phrase();
        assert_eq!(phrase.split_whitespace().count(), 24);
        let back = AuthorKey::from_phrase(&phrase).unwrap();
        assert_eq!(back.address(), key.address());
        assert_eq!(back.x25519_public(), key.x25519_public());
        let mut words: Vec<&str> = phrase.split_whitespace().collect();
        words.swap(0, 1);
        assert!(AuthorKey::from_phrase(&words.join(" ")).is_err() || words[0] == words[1]);
    }

    #[test]
    fn the_two_halves_are_different_keys() {
        let key = AuthorKey::generate().unwrap();
        assert_ne!(key.x25519_secret(), key.signer().secret());
        let sig = key.sign("hello").unwrap();
        let sig: botstadia_chain::Bytes = sig.parse().unwrap();
        assert_eq!(
            format!(
                "{:#x}",
                botstadia_chain::sign::recover(b"hello", &sig).unwrap()
            ),
            key.address()
        );
    }
}

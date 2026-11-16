//! Encrypting a bundle and wrapping its data key (TRUST.md#bundle-encryption).
//!
//! - The body: XChaCha20-Poly1305 under a fresh random 32-byte data key, a
//!   random 24-byte nonce in front, the bundle's digest as associated data.
//! - Each wrapped copy: HPKE (RFC 9180; DHKEM(X25519, HKDF-SHA256),
//!   HKDF-SHA256, ChaCha20-Poly1305) single-shot, base mode, to the
//!   recipient's X25519 key, with one context label per use, so a ciphertext
//!   made for one use can't be opened as another. Encoded as `enc ‖ ciphertext`.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hpke::{Deserializable, Kem as _, OpModeR, OpModeS, Serializable};

type Kem = hpke::kem::X25519HkdfSha256;
type Kdf = hpke::kdf::HkdfSha256;
type HpkeAead = hpke::aead::ChaCha20Poly1305;

/// The context label of a data key wrapped to the BundleKey.
pub const LABEL_BUNDLE_WRAP: &[u8] = b"botstadia-bundle-wrap-v1";
/// The context label of a data key wrapped to an author key.
pub const LABEL_AUTHOR_WRAP: &[u8] = b"botstadia-author-wrap-v1";
/// The context label of the BundleKey sealed to a requester at handover.
pub const LABEL_HANDOVER: &[u8] = b"botstadia-handover-v1";

const ENC_LEN: usize = 32;

/// An X25519 private key's public half.
pub fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    let private =
        <Kem as hpke::Kem>::PrivateKey::from_bytes(secret).expect("32 bytes is an X25519 key");
    let public = Kem::sk_to_pk(&private);
    public.to_bytes().into()
}

/// A new random X25519 key pair (the BundleKey, at a mint).
pub fn x25519_generate() -> anyhow::Result<([u8; 32], [u8; 32])> {
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;
    Ok((secret, x25519_public(&secret)))
}

/// HPKE-seal `plaintext` to `public` under `label`, binding `aad`.
pub fn wrap(
    public: &[u8; 32],
    label: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let public = <Kem as hpke::Kem>::PublicKey::from_bytes(public)
        .map_err(|_| anyhow::anyhow!("not an X25519 public key"))?;
    let (enc, ciphertext) = hpke::single_shot_seal::<HpkeAead, Kdf, Kem>(
        &OpModeS::Base,
        &public,
        label,
        plaintext,
        aad,
    )
    .map_err(|_| anyhow::anyhow!("sealing failed"))?;
    let mut out = enc.to_bytes().to_vec();
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open what [`wrap`] made, with the recipient's private key.
pub fn unwrap(
    secret: &[u8; 32],
    label: &[u8],
    aad: &[u8],
    wrapped: &[u8],
) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(wrapped.len() > ENC_LEN, "too short to be wrapped");
    let private = <Kem as hpke::Kem>::PrivateKey::from_bytes(secret)
        .map_err(|_| anyhow::anyhow!("not an X25519 key"))?;
    let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&wrapped[..ENC_LEN])
        .map_err(|_| anyhow::anyhow!("malformed"))?;
    hpke::single_shot_open::<HpkeAead, Kdf, Kem>(
        &OpModeR::Base,
        &private,
        &enc,
        label,
        &wrapped[ENC_LEN..],
        aad,
    )
    .map_err(|_| anyhow::anyhow!("this isn't wrapped to that key for that use"))
}

/// An encrypted bundle, ready to upload.
#[derive(Debug, Clone)]
pub struct Sealed {
    pub digest: String,
    pub ciphertext: Vec<u8>,
    pub wrapped_bundle_key: Vec<u8>,
    pub wrapped_author_key: Vec<u8>,
}

impl Sealed {
    pub fn b64(bytes: &[u8]) -> String {
        STANDARD.encode(bytes)
    }
}

pub fn from_b64(text: &str) -> anyhow::Result<Vec<u8>> {
    Ok(STANDARD.decode(text.trim())?)
}

/// Encrypt a bundle's ZIP and wrap its data key to the BundleKey and to the
/// author key.
pub fn seal_bundle(
    zip: &[u8],
    bundle_key: &[u8; 32],
    author_key: &[u8; 32],
) -> anyhow::Result<Sealed> {
    let digest = crate::digest(zip);
    let mut data_key = [0u8; 32];
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut data_key).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;
    getrandom::fill(&mut nonce).map_err(|e| anyhow::anyhow!("no randomness: {e}"))?;
    let cipher = XChaCha20Poly1305::new((&data_key).into());
    let body = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: zip,
                aad: digest.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("encryption failed"))?;
    let mut ciphertext = nonce.to_vec();
    ciphertext.extend_from_slice(&body);
    Ok(Sealed {
        wrapped_bundle_key: wrap(bundle_key, LABEL_BUNDLE_WRAP, digest.as_bytes(), &data_key)?,
        wrapped_author_key: wrap(author_key, LABEL_AUTHOR_WRAP, digest.as_bytes(), &data_key)?,
        digest,
        ciphertext,
    })
}

/// Decrypt a bundle with its data key, and check the plaintext's digest is
/// the one claimed (the enclave's check: TRUST.md#bundle-encryption).
pub fn open_bundle(ciphertext: &[u8], data_key: &[u8], digest: &str) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        ciphertext.len() > 24 && data_key.len() == 32,
        "malformed bundle"
    );
    let key: [u8; 32] = data_key.try_into()?;
    let nonce: [u8; 24] = ciphertext[..24].try_into()?;
    let cipher = XChaCha20Poly1305::new(&key.into());
    let zip = cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &ciphertext[24..],
                aad: digest.as_bytes(),
            },
        )
        .map_err(|_| anyhow::anyhow!("the bundle doesn't decrypt"))?;
    anyhow::ensure!(
        crate::digest(&zip) == digest,
        "the plaintext's digest isn't the bot's"
    );
    Ok(zip)
}

/// The enclave's side: unwrap with the BundleKey and open.
pub fn open_with_bundle_key(
    bundle_secret: &[u8; 32],
    digest: &str,
    wrapped: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let data_key = unwrap(bundle_secret, LABEL_BUNDLE_WRAP, digest.as_bytes(), wrapped)?;
    open_bundle(ciphertext, &data_key, digest)
}

/// `botstadia rekey`: unwrap the author's copy locally and rewrap the data
/// key to the new BundleKey. Nothing else is re-uploaded.
pub fn rekey(
    author_secret: &[u8; 32],
    digest: &str,
    wrapped_author: &[u8],
    new_bundle_key: &[u8; 32],
) -> anyhow::Result<Vec<u8>> {
    let data_key = unwrap(
        author_secret,
        LABEL_AUTHOR_WRAP,
        digest.as_bytes(),
        wrapped_author,
    )?;
    wrap(
        new_bundle_key,
        LABEL_BUNDLE_WRAP,
        digest.as_bytes(),
        &data_key,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::author::AuthorKey;

    #[test]
    fn an_enclave_opens_a_sealed_bundle_and_checks_its_digest() {
        let (bundle_secret, bundle_pub) = x25519_generate().unwrap();
        let author = AuthorKey::from_secret([3; 32]);
        let zip = b"PK\x03\x04 a bundle".to_vec();
        let s = seal_bundle(&zip, &bundle_pub, &author.x25519_public()).unwrap();
        assert_ne!(s.ciphertext[24..], zip[..]);
        let opened = open_with_bundle_key(
            &bundle_secret,
            &s.digest,
            &s.wrapped_bundle_key,
            &s.ciphertext,
        )
        .unwrap();
        assert_eq!(opened, zip);
        // A swapped digest, or the author's copy opened as the BundleKey's, fails.
        assert!(
            open_with_bundle_key(
                &bundle_secret,
                &crate::digest(b"other"),
                &s.wrapped_bundle_key,
                &s.ciphertext
            )
            .is_err()
        );
        assert!(
            unwrap(
                &bundle_secret,
                LABEL_BUNDLE_WRAP,
                s.digest.as_bytes(),
                &s.wrapped_author_key
            )
            .is_err()
        );
    }

    #[test]
    fn encrypting_the_same_bundle_twice_gives_different_ciphertext() {
        let (_, bundle_pub) = x25519_generate().unwrap();
        let author = AuthorKey::from_secret([3; 32]);
        let a = seal_bundle(b"same", &bundle_pub, &author.x25519_public()).unwrap();
        let b = seal_bundle(b"same", &bundle_pub, &author.x25519_public()).unwrap();
        assert_eq!(a.digest, b.digest);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    #[test]
    fn a_rekey_rewraps_to_a_new_bundle_key_from_the_author_s_copy_alone() {
        let (_, old_pub) = x25519_generate().unwrap();
        let (new_secret, new_pub) = x25519_generate().unwrap();
        let author = AuthorKey::from_secret([4; 32]);
        let zip = b"bundle".to_vec();
        let s = seal_bundle(&zip, &old_pub, &author.x25519_public()).unwrap();
        let rewrapped = rekey(
            &author.x25519_secret(),
            &s.digest,
            &s.wrapped_author_key,
            &new_pub,
        )
        .unwrap();
        assert_eq!(
            open_with_bundle_key(&new_secret, &s.digest, &rewrapped, &s.ciphertext).unwrap(),
            zip
        );
        // A wrong author key can't rekey.
        let thief = AuthorKey::from_secret([5; 32]);
        assert!(
            rekey(
                &thief.x25519_secret(),
                &s.digest,
                &s.wrapped_author_key,
                &new_pub
            )
            .is_err()
        );
    }
}

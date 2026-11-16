//! A passkey's assertion, as Safe's WebAuthn signer verifies it.
//!
//! The signer rebuilds the client data JSON from the challenge it was asked
//! about, so the page passes only what follows the challenge field
//! (`clientDataFields`), and the signer can't be shown a signature over any
//! other challenge. The signed message is
//! `sha256(authenticatorData ‖ sha256(clientDataJSON))`, verified as P-256
//! by Base's `P256VERIFY` precompile.

use alloy_primitives::{B256, Bytes, U256};
use alloy_sol_types::SolValue;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// P-256's group order, and half of it: signatures go out low-s, the form
/// every verifier accepts.
const N: U256 = U256::from_be_bytes([
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
]);

/// The challenge as WebAuthn carries it in client data: base64url, no padding.
pub fn challenge_b64(challenge: B256) -> String {
    URL_SAFE_NO_PAD.encode(challenge.as_slice())
}

/// The fields after the challenge in the client data JSON, without the
/// closing brace: what the signer appends to rebuild it. Refuses client data
/// that isn't a `webauthn.get` over exactly this challenge.
pub fn client_data_fields(client_data_json: &str, challenge: B256) -> anyhow::Result<String> {
    let prefix = format!(
        r#"{{"type":"webauthn.get","challenge":"{}","#,
        challenge_b64(challenge)
    );
    let rest = client_data_json
        .strip_prefix(&prefix)
        .ok_or_else(|| anyhow::anyhow!("client data isn't a webauthn.get over this challenge"))?;
    let fields = rest
        .strip_suffix('}')
        .ok_or_else(|| anyhow::anyhow!("client data doesn't end its object"))?;
    Ok(fields.to_string())
}

/// A DER ECDSA signature (what `navigator.credentials.get` returns) as low-s
/// `(r, s)`.
pub fn der_to_rs(der: &[u8]) -> anyhow::Result<(U256, U256)> {
    fn int(b: &[u8]) -> anyhow::Result<(U256, &[u8])> {
        anyhow::ensure!(b.len() >= 2 && b[0] == 0x02, "a DER integer");
        let len = b[1] as usize;
        anyhow::ensure!(b.len() >= 2 + len && len <= 33, "a DER integer's length");
        // A positive integer with its top bit set carries a leading zero.
        let mut v = &b[2..2 + len];
        if v.len() == 33 {
            anyhow::ensure!(v[0] == 0, "a DER integer too large for P-256");
            v = &v[1..];
        }
        Ok((U256::from_be_slice(v), &b[2 + len..]))
    }
    anyhow::ensure!(der.len() >= 2 && der[0] == 0x30, "a DER sequence");
    let body = &der[2..];
    anyhow::ensure!(body.len() == der[1] as usize, "a DER sequence's length");
    let (r, rest) = int(body)?;
    let (s, rest) = int(rest)?;
    anyhow::ensure!(rest.is_empty(), "nothing after a signature");
    Ok((r, low_s(s)))
}

pub fn low_s(s: U256) -> U256 {
    if s > N >> 1 { N - s } else { s }
}

/// The signer's signature bytes:
/// `abi.encode(bytes authenticatorData, string clientDataFields, uint256 r, uint256 s)`.
pub fn signature(authenticator_data: &[u8], client_data_fields: &str, r: U256, s: U256) -> Bytes {
    (
        Bytes::from(authenticator_data.to_vec()),
        client_data_fields.to_string(),
        r,
        low_s(s),
    )
        .abi_encode_params()
        .into()
}

/// A placeholder of a real assertion's size, for gas estimation. Its flags
/// say user present and verified, so the signer runs the whole check (an
/// unverified one is refused before the curve, and estimates low).
pub fn dummy() -> Bytes {
    let mut auth = [0u8; 37];
    auth[32] = 0x05;
    let fields =
        r#""origin":"https://botstadia-site-testnet.example.workers.dev","crossOrigin":false"#;
    signature(&auth, fields, N >> 2, N >> 2)
}

/// A passkey's public key from the SubjectPublicKeyInfo WebAuthn returns
/// (`getPublicKey()`): the uncompressed point's two coordinates.
pub fn spki_to_xy(spki: &[u8]) -> anyhow::Result<(U256, U256)> {
    // A P-256 SPKI is 91 bytes: a fixed 26-byte header, then 0x04 ‖ x ‖ y.
    const HEADER: [u8; 26] = [
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    anyhow::ensure!(
        spki.len() == 91 && spki[..26] == HEADER && spki[26] == 0x04,
        "not a P-256 public key"
    );
    Ok((
        U256::from_be_slice(&spki[27..59]),
        U256::from_be_slice(&spki[59..91]),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_follow_the_challenge() {
        let c = B256::repeat_byte(7);
        let json = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://x.test","crossOrigin":false}}"#,
            challenge_b64(c)
        );
        assert_eq!(
            client_data_fields(&json, c).unwrap(),
            r#""origin":"https://x.test","crossOrigin":false"#
        );
        assert!(client_data_fields(&json, B256::repeat_byte(8)).is_err());
    }

    #[test]
    fn der_with_leading_zeros_parses() {
        let mut der = vec![0x30, 0x44, 0x02, 0x21, 0x00];
        der.extend_from_slice(&[0xff; 32]);
        der.extend_from_slice(&[0x02, 0x1f]);
        der.extend_from_slice(&[0x01; 31]);
        let (r, s) = der_to_rs(&der).unwrap();
        assert_eq!(r, U256::from_be_slice(&[0xff; 32]));
        assert_eq!(s, U256::from_be_slice(&[0x01; 31]));
    }

    #[test]
    fn high_s_is_folded() {
        let high = N - U256::from(5);
        assert_eq!(low_s(high), U256::from(5));
        assert_eq!(low_s(U256::from(5)), U256::from(5));
    }
}

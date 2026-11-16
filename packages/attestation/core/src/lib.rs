//! What the attestation proof checks, and what it says when it passes
//! (TRUST.md#the-tee-and-the-zk-proof).
//!
//! An enclave running in Confidential Space asks Google for an attestation
//! token: a JWT, signed with RS256, whose claims describe the hardware, the
//! boot, the container image and the project it runs in, and carry a nonce
//! the enclave chose. A PKI token is signed by a short-lived key whose
//! certificate chain, up to Google's Confidential Space Root CA (the
//! GoogleRootCert), travels in its header (see [`pki`]); an OIDC token by a
//! key Google publishes in its JWKS. The zkVM guest runs [`verify`] over the
//! token and commits the [`Journal`] it returns, so the results contract can
//! believe the claims without checking an RSA signature or parsing JSON.
//!
//! BotStadia trusts PKI tokens: the results contract pins the root's hash
//! under a timelock, so Google can rotate its intermediate keys freely. An
//! OIDC token's anchor is a JWKS key hash, which no results contract
//! approves, so it can be verified (enclaves do, at handover, if given one)
//! but never approve a key.
//!
//! The same code runs natively: in the enclave, which checks a peer's token
//! itself at handover, in the CLI, which checks a boot proof's token before
//! wrapping a bundle, and in this crate's unit tests.
//!
//! # The journal
//!
//! `abi.encode(Results.Journal)`, nine words ([`Journal::LEN`] bytes), the
//! layout the results contract decodes: image digest, project id
//! (`keccak256` of the GCP project id), SubmitKey, BundleKey public half,
//! chain id, results contract, new-key instruction, issue time and trust
//! root. A proof is verified against `sha256` of these bytes.

#![forbid(unsafe_code)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::signature::Verifier;
use rsa::{BigUint, RsaPublicKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sha3::Keccak256;

/// Who issues Confidential Space attestation tokens.
pub const ISSUER: &str = "https://confidentialcomputing.googleapis.com";
/// The audience a BotStadia enclave asks for in its custom token, so a token
/// requested for any other relying party is never accepted here, and nobody
/// can run our image in their own project and pass it off.
pub const AUDIENCE: &str = "https://botstadia.com/attestation";
/// A production image: a debug image lets the host read memory, and so keys.
pub const DEBUG_DISABLED: &str = "disabled-since-boot";
/// The Confidential Space launcher, as opposed to any other software.
pub const SOFTWARE: &str = "CONFIDENTIAL_SPACE";
/// The hardware root: Intel TDX. Launch uses a single vendor.
pub const HARDWARE: &str = "GCP_INTEL_TDX";
/// Google's own mark of a Confidential Space image version that is supported
/// and receives security fixes, which a fixed minimum version would not
/// follow as versions age out.
pub const SUPPORTED: &str = "STABLE";
/// The smallest RSA key accepted, in bits.
pub const MIN_KEY_BITS: usize = 2048;
/// What a boot token's nonce commits to is hashed under this tag, so it can
/// never be mistaken for any other hash.
pub const NONCE_TAG: &[u8] = b"botstadia-attestation-nonce:v1";
/// A handover token's nonce, binding the peer's fresh challenge
/// (TRUST.md#bootstrap-and-handover), uses its own tag.
pub const HANDOVER_NONCE_TAG: &[u8] = b"botstadia-handover-nonce:v1";

/// Google's Confidential Space JWKS as published on 6 October 2026, from the
/// `jwks_uri` of the issuer's OpenID configuration
/// (`https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com`).
/// Google rotates these keys; a checker is deployed with the keys published
/// when it is.
pub const GOOGLE_JWKS_2026_10_06: &str = include_str!("../testdata/google-jwks-2026-10-06.json");

/// The Google key set pinned now, for checking OIDC tokens. Pinning a newer
/// set is a new `google-jwks-<date>.json` beside this one and this line
/// naming it.
pub const PINNED_GOOGLE_JWKS: &str = include_str!("../testdata/google-jwks-2026-10-06.json");

/// Google's Confidential Space Root CA (RSA-4096, valid from 19 January
/// 2024 to 16 January 2034), as Google publishes it at
/// `https://confidentialcomputing.googleapis.com/.well-known/confidential_space_root.crt`.
/// A PKI token's chain ends in it; the results contract approves its hash
/// ([`confidential_space_root_hash`]) as a GoogleRootCert.
pub const CONFIDENTIAL_SPACE_ROOT: &str = include_str!("../testdata/confidential-space-root.crt");

/// What the results contract approves to accept PKI tokens whose chain ends
/// in Google's Confidential Space Root CA: `sha256` of the certificate's DER
/// ([`pki::root_hash`]).
pub fn confidential_space_root_hash() -> [u8; 32] {
    pki::root_hash(
        &pki::pem_der(CONFIDENTIAL_SPACE_ROOT).expect("the pinned root is a PEM certificate"),
    )
}

/// One of Google's signing keys, as published in its JWKS.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Jwk {
    pub kid: String,
    /// The modulus, big-endian.
    pub n: Vec<u8>,
    /// The public exponent, big-endian.
    pub e: Vec<u8>,
}

impl Jwk {
    /// What the journal names the key by, and what a checker trusts:
    /// `sha256(len(n) ‖ n ‖ len(e) ‖ e)`, each length a big-endian u32 and
    /// each number without leading zeros. The `kid` is a label, not the key,
    /// so it is not part of it.
    pub fn key_hash(&self) -> [u8; 32] {
        let n = strip_zeros(&self.n);
        let e = strip_zeros(&self.e);
        let mut hasher = Sha256::new();
        hasher.update((n.len() as u32).to_be_bytes());
        hasher.update(n);
        hasher.update((e.len() as u32).to_be_bytes());
        hasher.update(e);
        hasher.finalize().into()
    }

    /// The RSA keys of a JWKS document (`{"keys": [...]}`); anything else
    /// in it is skipped.
    pub fn from_jwks(json: &str) -> Result<Vec<Jwk>, Error> {
        let doc: Value = serde_json::from_str(json).map_err(|_| Error::Malformed("jwks"))?;
        let keys = doc
            .get("keys")
            .and_then(Value::as_array)
            .ok_or(Error::Malformed("jwks"))?;
        let mut out = Vec::new();
        for key in keys {
            if key.get("kty").and_then(Value::as_str) != Some("RSA") {
                continue;
            }
            let field = |name: &'static str| -> Result<&str, Error> {
                key.get(name)
                    .and_then(Value::as_str)
                    .ok_or(Error::Malformed("jwk"))
            };
            out.push(Jwk {
                kid: field("kid")?.into(),
                n: b64(field("n")?)?,
                e: b64(field("e")?)?,
            });
        }
        Ok(out)
    }
}

fn strip_zeros(bytes: &[u8]) -> &[u8] {
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    &bytes[first..]
}

/// What an enclave binds into its token's nonce: its keys, its chain binding
/// and the new-key instruction its BundleKey belongs to. Nothing in the token
/// says these otherwise, so they are what make the token about this enclave.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Binding {
    /// The SubmitKey's address.
    pub submit_key: [u8; 20],
    /// The BundleKey's public half (X25519). Zero before the enclave holds
    /// it: a registration or handover token names no BundleKey yet.
    pub bundle_key: [u8; 32],
    /// The chain binding: the chain id and the results contract.
    pub chain_id: u64,
    pub results: [u8; 20],
    /// The new-key instruction the BundleKey belongs to; zero before it
    /// holds one.
    pub instruction: u64,
}

impl Binding {
    fn hash(&self, tag: &[u8], challenge: Option<&[u8; 32]>) -> String {
        let mut hasher = Sha256::new();
        hasher.update(tag);
        hasher.update(self.submit_key);
        hasher.update(self.bundle_key);
        hasher.update(self.chain_id.to_be_bytes());
        hasher.update(self.results);
        hasher.update(self.instruction.to_be_bytes());
        if let Some(challenge) = challenge {
            hasher.update(challenge);
        }
        hex::encode(hasher.finalize())
    }

    /// The nonce a boot token carries: the lowercase hex of
    /// `sha256(NONCE_TAG ‖ submit_key ‖ bundle_key ‖ chain_id (8, big-endian)
    /// ‖ results ‖ instruction (8, big-endian))`, 64 characters
    /// (Confidential Space takes nonces of 8 to 88 bytes).
    pub fn nonce(&self) -> String {
        self.hash(NONCE_TAG, None)
    }

    /// The nonce a handover token carries: the same binding plus the peer's
    /// fresh 32-byte challenge, under [`HANDOVER_NONCE_TAG`], so a captured
    /// token is useless to anyone without its key and outside its exchange.
    pub fn handover_nonce(&self, challenge: &[u8; 32]) -> String {
        self.hash(HANDOVER_NONCE_TAG, Some(challenge))
    }
}

/// What the guest reads.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Input {
    /// The attestation token, as the compact JWT the enclave was given.
    pub token: String,
    /// The signing keys to check an OIDC token against. A PKI token carries
    /// its own chain, and these are not used for it.
    pub keys: Vec<Jwk>,
    /// The prover's clock, in seconds. The token must be valid at it. The
    /// results contract judges freshness by the token's `iat` against its
    /// own clock.
    pub now: u64,
    pub binding: Binding,
}

/// What a token says once its signature, chain and claims have passed every
/// check but the audience, `STABLE` and the nonce, which [`verify`] adds for
/// a BotStadia boot token. An enclave checking a peer at handover reads
/// this and applies its own nonce rule.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub image_digest: [u8; 32],
    /// The GCP project id, as the token names it.
    pub project: String,
    pub issued_at: u64,
    pub audiences: Vec<String>,
    pub nonces: Vec<String>,
    /// Whether Google marks the OS image `STABLE` (supported).
    pub stable: bool,
    /// The OS image's version (`swversion`), for an image's OS minimum.
    pub swversion: Vec<String>,
    /// What the signature is trusted by: a PKI token's root certificate's
    /// [`pki::root_hash`], or an OIDC key's [`Jwk::key_hash`].
    pub root_hash: [u8; 32],
}

/// What the proof says, once the token has passed every check.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub struct Journal {
    pub image_digest: [u8; 32],
    pub project_id: [u8; 32],
    pub submit_key: [u8; 20],
    pub bundle_key: [u8; 32],
    pub chain_id: u64,
    pub results: [u8; 20],
    pub instruction: u64,
    pub issued_at: u64,
    /// The trust root the token chained to ([`Token::root_hash`]).
    pub root_hash: [u8; 32],
}

fn word_u64(value: u64) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[24..].copy_from_slice(&value.to_be_bytes());
    word
}

fn word_address(address: &[u8; 20]) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..].copy_from_slice(address);
    word
}

impl Journal {
    /// Nine 32-byte words.
    pub const LEN: usize = 288;

    /// `abi.encode(Results.Journal)`: the bytes the guest commits.
    pub fn encode(&self) -> [u8; Self::LEN] {
        let words = [
            self.image_digest,
            self.project_id,
            word_address(&self.submit_key),
            self.bundle_key,
            word_u64(self.chain_id),
            word_address(&self.results),
            word_u64(self.instruction),
            word_u64(self.issued_at),
            self.root_hash,
        ];
        let mut out = [0u8; Self::LEN];
        for (i, word) in words.iter().enumerate() {
            out[i * 32..(i + 1) * 32].copy_from_slice(word);
        }
        out
    }

    /// The journal from its encoding; `None` unless it is exactly the
    /// canonical `abi.encode` (padding zero, as `abi.decode` requires).
    pub fn decode(bytes: &[u8]) -> Option<Journal> {
        if bytes.len() != Self::LEN {
            return None;
        }
        let word = |i: usize| -> [u8; 32] { bytes[i * 32..(i + 1) * 32].try_into().unwrap() };
        let address = |i: usize| -> Option<[u8; 20]> {
            let w = word(i);
            w[..12]
                .iter()
                .all(|b| *b == 0)
                .then(|| w[12..].try_into().unwrap())
        };
        let small = |i: usize| -> Option<u64> {
            let w = word(i);
            w[..24]
                .iter()
                .all(|b| *b == 0)
                .then(|| u64::from_be_bytes(w[24..].try_into().unwrap()))
        };
        Some(Journal {
            image_digest: word(0),
            project_id: word(1),
            submit_key: address(2)?,
            bundle_key: word(3),
            chain_id: small(4)?,
            results: address(5)?,
            instruction: small(6)?,
            issued_at: small(7)?,
            root_hash: word(8),
        })
    }

    /// `sha256` of the encoding: what a RISC Zero seal is verified against.
    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }
}

/// The local target's mock root CA's hash ([`mock::root_hash`], checked by a
/// test there), so a verifier can recognise a mock token and refuse it
/// anywhere but the local target without building the mock CA.
pub const LOCAL_MOCK_ROOT_HASH: [u8; 32] = [
    0x64, 0x16, 0xeb, 0xf8, 0x5b, 0x07, 0xac, 0x14, 0x7a, 0x7a, 0xbf, 0xe7, 0xa1, 0xcf, 0xf6, 0x30,
    0x09, 0x37, 0x7c, 0x22, 0x3c, 0xfe, 0x9a, 0x70, 0x3d, 0x43, 0xbd, 0x5c, 0x10, 0x59, 0x00, 0xbb,
];

/// A GCP project id as the results contract pins it: `keccak256` of its
/// bytes.
pub fn project_id(gce_project: &str) -> [u8; 32] {
    Keccak256::digest(gce_project.as_bytes()).into()
}

/// Why a token was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Not well formed: the part named.
    Malformed(&'static str),
    /// Not signed with RS256.
    Algorithm,
    /// No key with the OIDC token's `kid` was given.
    UnknownKey,
    /// The key is too small, or not a valid RSA key.
    WeakKey,
    BadSignature,
    /// A claim that must hold doesn't: the claim named.
    Claim(&'static str),
    /// Not valid at the prover's clock.
    NotFresh,
    /// The nonce doesn't bind these keys and this chain binding.
    Nonce,
    /// A PKI token's certificate chain is refused: the reason named.
    Chain(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Malformed(part) => write!(f, "the token's {part} is malformed"),
            Error::Algorithm => write!(f, "the token is not signed with RS256"),
            Error::UnknownKey => write!(f, "no key was given for the token's kid"),
            Error::WeakKey => write!(f, "the signing key is not an RSA key of at least 2048 bits"),
            Error::BadSignature => write!(f, "the token's signature does not verify"),
            Error::Claim(claim) => write!(f, "the token's `{claim}` claim is not accepted"),
            Error::NotFresh => write!(f, "the token is not valid at the given time"),
            Error::Nonce => write!(
                f,
                "the token's nonce does not bind the given keys and chain binding"
            ),
            Error::Chain(why) => write!(f, "the token's certificate chain is refused: {why}"),
        }
    }
}

impl core::error::Error for Error {}

fn b64(text: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| Error::Malformed("base64"))
}

/// Check a BotStadia boot token as the proof does, and say what it attests
/// to: [`verify_token`], then exactly our audience, an OS image Google marks
/// `STABLE`, and a nonce binding these keys and this chain binding.
pub fn verify(input: &Input) -> Result<Journal, Error> {
    let token = verify_token(&input.token, &input.keys, input.now)?;
    if token.audiences != [AUDIENCE] {
        return Err(Error::Claim("/aud"));
    }
    if !token.stable {
        return Err(Error::Claim(
            "/submods/confidential_space/support_attributes",
        ));
    }
    let nonce = input.binding.nonce();
    if !token.nonces.contains(&nonce) {
        return Err(Error::Nonce);
    }
    let b = &input.binding;
    Ok(Journal {
        image_digest: token.image_digest,
        project_id: project_id(&token.project),
        submit_key: b.submit_key,
        bundle_key: b.bundle_key,
        chain_id: b.chain_id,
        results: b.results,
        instruction: b.instruction,
        issued_at: token.issued_at,
        root_hash: token.root_hash,
    })
}

/// Check a Confidential Space token's signature, chain and claims, whatever
/// it was requested for, and say what it says.
pub fn verify_token(token: &str, keys: &[Jwk], now: u64) -> Result<Token, Error> {
    let mut parts = token.split('.');
    let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Error::Malformed("structure"));
    };

    let header: Value =
        serde_json::from_slice(&b64(header_b64)?).map_err(|_| Error::Malformed("header"))?;
    if header.get("alg").and_then(Value::as_str) != Some("RS256") {
        return Err(Error::Algorithm);
    }
    let signed = &token[..header_b64.len() + 1 + payload_b64.len()];
    let signature = b64(signature_b64)?;

    // A PKI token carries its signing key's certificate chain, and is trusted
    // by the chain's root; any other is signed by one of the keys given.
    let (anchor, chain) = match header.get("x5c") {
        Some(x5c) => {
            let chain = pki::check_chain(&pki::decode_x5c(x5c)?)?;
            verify_rs256(&chain.leaf, signed, &signature)?;
            (chain.root, Some(chain))
        }
        None => {
            let kid = header
                .get("kid")
                .and_then(Value::as_str)
                .ok_or(Error::Malformed("header"))?;
            let key = keys
                .iter()
                .find(|key| key.kid == kid)
                .ok_or(Error::UnknownKey)?;
            let public = RsaPublicKey::new(
                BigUint::from_bytes_be(&key.n),
                BigUint::from_bytes_be(&key.e),
            )
            .map_err(|_| Error::WeakKey)?;
            if rsa::traits::PublicKeyParts::n(&public).bits() < MIN_KEY_BITS {
                return Err(Error::WeakKey);
            }
            verify_rs256(&public, signed, &signature)?;
            (key.key_hash(), None)
        }
    };

    let claims: Value =
        serde_json::from_slice(&b64(payload_b64)?).map_err(|_| Error::Malformed("claims"))?;
    // Every certificate valid when the token was issued; checked before the
    // claims (a token without an `iat` is refused by the claims' check).
    if let Some(chain) = chain
        && let Some(iat) = claims.pointer("/iat").and_then(Value::as_u64)
    {
        chain.check_time(iat)?;
    }
    let mut token = check_claims(&claims, now)?;
    token.root_hash = anchor;
    Ok(token)
}

/// An RS256 (PKCS#1 v1.5, SHA-256) signature over `signed` by `key`.
fn verify_rs256(key: &RsaPublicKey, signed: &str, signature: &[u8]) -> Result<(), Error> {
    let signature = Signature::try_from(signature).map_err(|_| Error::BadSignature)?;
    VerifyingKey::<Sha256>::new(key.clone())
        .verify(signed.as_bytes(), &signature)
        .map_err(|_| Error::BadSignature)
}

fn string<'a>(claims: &'a Value, pointer: &'static str) -> Result<&'a str, Error> {
    claims
        .pointer(pointer)
        .and_then(Value::as_str)
        .ok_or(Error::Claim(pointer))
}

fn require(claims: &Value, pointer: &'static str, value: &str) -> Result<(), Error> {
    if string(claims, pointer)? == value {
        Ok(())
    } else {
        Err(Error::Claim(pointer))
    }
}

/// Absent, null, or empty: the operator overrode nothing the image says.
fn nothing_overridden(claims: &Value, pointer: &'static str) -> Result<(), Error> {
    match claims.pointer(pointer) {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Array(items)) if items.is_empty() => Ok(()),
        Some(Value::Object(items)) if items.is_empty() => Ok(()),
        Some(_) => Err(Error::Claim(pointer)),
    }
}

/// The environment variables a launch may set, as the image's launch policy
/// allows them: the chain binding and the api's URL, all public.
pub const LAUNCH_VARS: &[&str] = &[
    "BOTSTADIA_API_URL",
    "BOTSTADIA_CHAIN_ID",
    "BOTSTADIA_RESULTS",
];

/// An environment override that sets only [`LAUNCH_VARS`], to strings.
fn only_launch_vars(claims: &Value, pointer: &'static str) -> Result<(), Error> {
    match claims.pointer(pointer) {
        None | Some(Value::Null) => Ok(()),
        Some(Value::Object(vars))
            if vars
                .iter()
                .all(|(name, value)| LAUNCH_VARS.contains(&name.as_str()) && value.is_string()) =>
        {
            Ok(())
        }
        Some(_) => Err(Error::Claim(pointer)),
    }
}

/// A claim that is a string, or an array of strings (JWT allows either for
/// `aud`, and Confidential Space uses either for `eat_nonce`).
fn strings<'a>(claims: &'a Value, pointer: &'static str) -> Result<Vec<&'a str>, Error> {
    match claims.pointer(pointer) {
        Some(Value::String(one)) => Ok(alloc::vec![one.as_str()]),
        Some(Value::Array(many)) => many
            .iter()
            .map(|item| item.as_str().ok_or(Error::Claim(pointer)))
            .collect(),
        _ => Err(Error::Claim(pointer)),
    }
}

/// Every claim check but the audience, `STABLE` and the nonce, on a token
/// whose signature has already verified. The root hash is left zero for the
/// caller to fill.
fn check_claims(claims: &Value, now: u64) -> Result<Token, Error> {
    require(claims, "/iss", ISSUER)?;
    let audiences = strings(claims, "/aud")?;

    let time = |pointer: &'static str| claims.pointer(pointer).and_then(Value::as_u64);
    let iat = time("/iat").ok_or(Error::Claim("/iat"))?;
    let exp = time("/exp").ok_or(Error::Claim("/exp"))?;
    if iat > now || now >= exp {
        return Err(Error::NotFresh);
    }
    if let Some(nbf) = claims.pointer("/nbf")
        && nbf.as_u64().is_none_or(|nbf| nbf > now)
    {
        return Err(Error::NotFresh);
    }

    require(claims, "/dbgstat", DEBUG_DISABLED)?;
    require(claims, "/swname", SOFTWARE)?;
    require(claims, "/hwmodel", HARDWARE)?;
    if claims.pointer("/secboot").and_then(Value::as_bool) != Some(true) {
        return Err(Error::Claim("/secboot"));
    }
    let stable =
        strings(claims, "/submods/confidential_space/support_attributes")?.contains(&SUPPORTED);
    let swversion = match claims.pointer("/swversion") {
        None => Vec::new(),
        Some(_) => strings(claims, "/swversion")?
            .into_iter()
            .map(String::from)
            .collect(),
    };

    // The image's own arguments and environment are part of its digest; an
    // operator's overrides are not. The launch policy allows no command
    // override, and environment overrides of the binding and api variables
    // only (TRUST.md#the-tee-and-the-zk-proof): the nonce binds the chain
    // binding anyway, and the api is a courier the enclave checks.
    nothing_overridden(claims, "/submods/container/cmd_override")?;
    only_launch_vars(claims, "/submods/container/env_override")?;
    let digest = string(claims, "/submods/container/image_digest")?;
    let image_digest: [u8; 32] = digest
        .strip_prefix("sha256:")
        .filter(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
        .and_then(|hex| hex::decode(hex).ok())
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(Error::Claim("/submods/container/image_digest"))?;

    let project = string(claims, "/submods/gce/project_id")?;
    if project.is_empty() {
        return Err(Error::Claim("/submods/gce/project_id"));
    }

    let nonces = strings(claims, "/eat_nonce")
        .map_err(|_| Error::Nonce)?
        .into_iter()
        .map(String::from)
        .collect();

    Ok(Token {
        image_digest,
        project: project.into(),
        issued_at: iat,
        audiences: audiences.into_iter().map(String::from).collect(),
        nonces,
        stable,
        swversion,
        root_hash: [0; 32],
    })
}

pub mod pki;
pub mod receipt;

#[cfg(any(test, feature = "fixture"))]
pub mod fixture;

#[cfg(any(test, feature = "mock"))]
pub mod mock;

#[cfg(test)]
mod tests;

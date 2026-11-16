//! Signed test tokens in Google's format.
//!
//! Google publishes the token's format and its signing keys, but no signed
//! sample token: a real one exists only inside a Confidential Space VM. So
//! these tokens carry the claims a real one carries, in the same shapes,
//! signed with RS256 under a 2048-bit test key that only tests trust,
//! generated from a fixed public seed. A checker deployed for real trusts
//! Google's keys, never this one.

use alloc::string::String;
use alloc::vec::Vec;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::{Value, json};
use sha2::Sha256;

use crate::{AUDIENCE, Binding, DEBUG_DISABLED, HARDWARE, ISSUER, Input, Jwk, SOFTWARE};

/// The seed the test key is generated from. Public on purpose: the key
/// signs nothing but fixtures.
pub const TEST_KEY_SEED: [u8; 32] = *b"botstadia attest fixture key 001";
/// The `kid` the test key is published under.
pub const TEST_KID: &str = "botstadia-test-signing-key";
pub use crate::GOOGLE_JWKS_2026_10_06;

/// The image digest the sample token names.
pub const IMAGE_DIGEST: &str =
    "sha256:3b9e5f2a6c1d4e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7";
/// The GCE project the sample instance runs in.
pub const PROJECT: &str = "botstadia-enclaves-1";

/// The test key, the same every time (generated once per process).
pub fn test_private_key() -> RsaPrivateKey {
    use rand_chacha::ChaCha20Rng;
    use rand_chacha::rand_core::SeedableRng;
    static KEY: std::sync::OnceLock<RsaPrivateKey> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        RsaPrivateKey::new(&mut ChaCha20Rng::from_seed(TEST_KEY_SEED), 2048)
            .expect("the test key generates")
    })
    .clone()
}

/// The test key as a JWKS entry.
pub fn test_jwk() -> Jwk {
    let public = RsaPublicKey::from(&test_private_key());
    Jwk {
        kid: TEST_KID.into(),
        n: public.n().to_bytes_be(),
        e: public.e().to_bytes_be(),
    }
}

/// The claims of a production token from a Confidential Space VM on Intel
/// TDX, issued at `iat` for an hour, its nonce binding `binding`.
pub fn claims(binding: &Binding, iat: u64) -> Value {
    json!({
        "aud": AUDIENCE,
        "iss": ISSUER,
        "sub": format!(
            "https://www.googleapis.com/compute/v1/projects/{PROJECT}/zones/us-central1-a/instances/enclave-1"
        ),
        "iat": iat,
        "nbf": iat,
        "exp": iat + 3600,
        "dbgstat": DEBUG_DISABLED,
        "eat_nonce": [binding.nonce()],
        "eat_profile": "https://cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims",
        "google_service_accounts": [format!("enclave@{PROJECT}.iam.gserviceaccount.com")],
        "hwmodel": HARDWARE,
        "oemid": 11129,
        "secboot": true,
        "swname": SOFTWARE,
        "swversion": ["25090100"],
        "submods": {
            "confidential_space": {
                "monitoring_enabled": {"memory": false},
                "support_attributes": ["LATEST", "STABLE", "USABLE"]
            },
            "container": {
                "args": ["/usr/local/bin/botstadia-enclave"],
                "env": {
                    "HOSTNAME": "enclave-1",
                    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                },
                "image_digest": IMAGE_DIGEST,
                "image_id": "sha256:0d1e2f3a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f6",
                "image_reference": "us-docker.pkg.dev/botstadia/enclave/enclave@sha256:3b9e5f2a6c1d4e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7",
                "restart_policy": "Never"
            },
            "gce": {
                "instance_id": "1234567890123456789",
                "instance_name": "enclave-1",
                "project_id": PROJECT,
                "project_number": "123456789012",
                "zone": "us-central1-a"
            }
        }
    })
}

/// The header Google's tokens carry, naming `kid`.
pub fn header(kid: &str) -> Value {
    json!({"alg": "RS256", "kid": kid, "typ": "JWT"})
}

/// A compact JWT of `header` and `claims`, signed with RS256 under `key`.
pub fn sign_with(key: &RsaPrivateKey, header: &Value, claims: &Value) -> String {
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap()),
    );
    let signature: Vec<u8> = SigningKey::<Sha256>::new(key.clone())
        .sign(signing_input.as_bytes())
        .to_vec();
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

/// `claims` signed under the test key.
pub fn sign(claims: &Value) -> String {
    sign_with(&test_private_key(), &header(TEST_KID), claims)
}

/// Foundry's default chain id.
pub const CHAIN_ID: u64 = 31_337;
/// The sample enclave's SubmitKey address.
pub const SUBMIT_KEY: [u8; 20] = [0xE7; 20];
/// The sample results contract.
pub const RESULTS: [u8; 20] = [0x0A; 20];

/// A sample binding: a SubmitKey, a BundleKey, the local chain and a results
/// contract, under genesis.
pub fn binding() -> Binding {
    Binding {
        submit_key: SUBMIT_KEY,
        bundle_key: [0x5A; 32],
        chain_id: CHAIN_ID,
        results: RESULTS,
        instruction: 1,
    }
}

/// A guest input that passes: a token issued at `iat`, checked at `now`,
/// against Google's published keys and the test key.
pub fn input(binding: &Binding, iat: u64, now: u64) -> Input {
    let mut keys = Jwk::from_jwks(GOOGLE_JWKS_2026_10_06).expect("Google's JWKS parses");
    keys.push(test_jwk());
    Input {
        token: sign(&claims(binding, iat)),
        keys,
        now,
        binding: *binding,
    }
}

/// A genuine boot token from a BotStadia testnet enclave
/// (`botstadia-enclave-testnet-aw1`, a Confidential Space VM on Intel TDX
/// running the launcher image `261001`), issued on 15 November 2026 in
/// Google's PKI format: an `x5c` chain in the header (leaf, intermediate,
/// Google's Confidential Space Root CA), signed by the leaf's key, whose
/// `kid` is among no published keys. It was requested for our own relying
/// party ([`AUDIENCE`], [`Binding::nonce`]) and published with its boot
/// proof, so it passes [`crate::verify`] whole and gives back exactly the
/// journal that was proven ([`REAL_JOURNAL`]): what the enclave and the
/// guest accept is known to include what Google really issues. It carries
/// no secret.
pub const REAL_PKI_TOKEN: &str = include_str!("../testdata/cs-token-pki-2026-11-15.jwt");
/// The real token's `iat`; it expires an hour later, at [`REAL_PKI_EXP`].
pub const REAL_PKI_IAT: u64 = 1_794_776_564;
pub const REAL_PKI_EXP: u64 = REAL_PKI_IAT + 3600;
/// `sha256` of Google's Confidential Space Root CA certificate (DER), as
/// `openssl x509 -outform der | sha256sum` gives it.
pub const CONFIDENTIAL_SPACE_ROOT_HASH: &str =
    "148b293821bb0c6a317f413c8ba475814091cb22d49b9e3c94198db8e8f86c39";
/// The real token's image digest (the testnet runner image) and project.
pub const REAL_IMAGE_DIGEST: &str =
    "sha256:83f994a31614ee0580e6e27ac31f736e5de201242436fb183b1078cd21114bd2";
pub const REAL_PROJECT: &str = "botstadia";
/// The audience the real token was requested for: ours.
pub const REAL_AUDIENCE: &str = AUDIENCE;
/// The real token's nonce: [`Binding::nonce`] of [`real_binding`].
pub const REAL_NONCE: &str = "46dbccda8a0164255d64bbc9b501d48808e5bff27b592cc765cb05c0f205c26d";
/// The binding the real token's nonce commits to, as its boot proof
/// published it: the enclave's SubmitKey address, its BundleKey's public
/// half, Base Sepolia and the testnet results contract, and the new-key
/// instruction the BundleKey belongs to.
pub const REAL_SUBMIT_KEY: &str = "42936e4ef841fc89da65ce7075c98d50483219de";
pub const REAL_BUNDLE_KEY: &str =
    "cef48ddc6c55b8210419ed38a02c7a36eacf6e7f075f61d2d3630a568d0f3e56";
pub const REAL_CHAIN_ID: u64 = 84_532;
pub const REAL_RESULTS: &str = "8673f88c1ae2a541fc316b855354ca4cfe9e9493";
pub const REAL_INSTRUCTION: u64 = 2;
/// The journal the real token's boot proof committed (`abi.encode`, nine
/// words), as the testnet api publishes it.
pub const REAL_JOURNAL: &str = concat!(
    "83f994a31614ee0580e6e27ac31f736e5de201242436fb183b1078cd21114bd2",
    "e127e3368f3778c09ac16389f9bab26a38f72604fd0e04700e829ecb3077340c",
    "00000000000000000000000042936e4ef841fc89da65ce7075c98d50483219de",
    "cef48ddc6c55b8210419ed38a02c7a36eacf6e7f075f61d2d3630a568d0f3e56",
    "0000000000000000000000000000000000000000000000000000000000014a34",
    "0000000000000000000000008673f88c1ae2a541fc316b855354ca4cfe9e9493",
    "0000000000000000000000000000000000000000000000000000000000000002",
    "000000000000000000000000000000000000000000000000000000006afa1df4",
    "148b293821bb0c6a317f413c8ba475814091cb22d49b9e3c94198db8e8f86c39",
);

/// The binding the real token's nonce commits to.
pub fn real_binding() -> Binding {
    fn bytes<const N: usize>(hex: &str) -> [u8; N] {
        hex::decode(hex).unwrap().try_into().unwrap()
    }
    Binding {
        submit_key: bytes(REAL_SUBMIT_KEY),
        bundle_key: bytes(REAL_BUNDLE_KEY),
        chain_id: REAL_CHAIN_ID,
        results: bytes(REAL_RESULTS),
        instruction: REAL_INSTRUCTION,
    }
}

/// A guest input for the real token, checked at `now`. No JWKS key is
/// given: the chain is the token's own.
pub fn real_input(now: u64) -> Input {
    Input {
        token: REAL_PKI_TOKEN.trim().into(),
        keys: Vec::new(),
        now,
        binding: real_binding(),
    }
}

/// A certificate chain of the test's own, in the shape Google's PKI tokens
/// carry (a leaf, an intermediate CA, a root CA), its keys generated from
/// fixed public seeds like the test key. A checker deployed for real pins
/// Google's root, never this one.
pub mod chain {
    use alloc::string::String;
    use alloc::vec::Vec;
    use core::str::FromStr;
    use core::time::Duration;

    use base64::Engine;
    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use rsa::pkcs1v15::SigningKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::signature::{SignatureEncoding, Signer};
    use rsa::{RsaPrivateKey, RsaPublicKey};
    use serde_json::{Value, json};
    use sha2::Sha256;
    use x509_cert::certificate::{Certificate, TbsCertificate, Version};
    use x509_cert::der::asn1::{Any, BitString, ObjectIdentifier, OctetString, UtcTime};
    use x509_cert::der::{Decode, Encode};
    use x509_cert::ext::Extension;
    use x509_cert::ext::pkix::{BasicConstraints, KeyUsage, KeyUsages};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
    use x509_cert::time::{Time, Validity};

    use crate::{Binding, Input};

    /// The seeds the chain's keys are generated from. Public on purpose:
    /// they sign nothing but fixtures.
    pub const ROOT_SEED: [u8; 32] = *b"botstadia attest test root   001";
    pub const INTERMEDIATE_SEED: [u8; 32] = *b"botstadia attest test interm 001";
    pub const LEAF_SEED: [u8; 32] = *b"botstadia attest test leaf   001";
    /// Another root, which no checker pins.
    pub const OTHER_ROOT_SEED: [u8; 32] = *b"botstadia attest other root  001";

    const SEEDS: [[u8; 32]; 4] = [ROOT_SEED, INTERMEDIATE_SEED, LEAF_SEED, OTHER_ROOT_SEED];

    /// The key generated from `seed` (one of the seeds above), the same
    /// every time and generated once per process.
    pub fn key(seed: [u8; 32]) -> RsaPrivateKey {
        use rand_chacha::ChaCha20Rng;
        use rand_chacha::rand_core::SeedableRng;
        static KEYS: [std::sync::OnceLock<RsaPrivateKey>; 4] = [
            std::sync::OnceLock::new(),
            std::sync::OnceLock::new(),
            std::sync::OnceLock::new(),
            std::sync::OnceLock::new(),
        ];
        let at = SEEDS
            .iter()
            .position(|known| *known == seed)
            .expect("one of the fixture's seeds");
        KEYS[at]
            .get_or_init(|| {
                RsaPrivateKey::new(&mut ChaCha20Rng::from_seed(seed), 2048)
                    .expect("the test key generates")
            })
            .clone()
    }

    pub const ROOT_NAME: &str = "CN=BotStadia Test Root CA,O=BotStadia Test";
    pub const INTERMEDIATE_NAME: &str = "CN=BotStadia Test Intermediate CA,O=BotStadia Test";
    pub const LEAF_NAME: &str = "CN=BotStadia Test Leaf Certificate,O=BotStadia Test";

    /// `sha256WithRSAEncryption`.
    pub const SHA256_WITH_RSA: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    /// An extension no checker knows (a private arc).
    pub const UNKNOWN_EXTENSION: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.3.6.1.4.1.99999.1");

    /// What one certificate says.
    #[derive(Clone, Debug)]
    pub struct Spec {
        pub subject: &'static str,
        pub issuer: &'static str,
        /// Valid from and until (inclusive), Unix seconds.
        pub not_before: u64,
        pub not_after: u64,
        /// Basic constraints, if present: `cA` and the path length
        /// constraint.
        pub basic: Option<(bool, Option<u8>)>,
        /// Key usage, if present.
        pub usage: Option<x509_cert::der::flagset::FlagSet<KeyUsages>>,
        /// An extension no checker knows, marked critical.
        pub unknown_critical: bool,
        /// The signature algorithm named (sha256WithRSAEncryption unless
        /// a test says otherwise).
        pub algorithm: ObjectIdentifier,
    }

    impl Spec {
        /// A root CA, valid for twenty years around `iat`.
        pub fn root(iat: u64) -> Spec {
            Spec {
                subject: ROOT_NAME,
                issuer: ROOT_NAME,
                not_before: iat - 10 * 365 * 86_400,
                not_after: iat + 10 * 365 * 86_400,
                basic: Some((true, None)),
                usage: Some(KeyUsages::KeyCertSign | KeyUsages::CRLSign),
                unknown_critical: false,
                algorithm: SHA256_WITH_RSA,
            }
        }

        /// An intermediate CA, valid for three years around `iat`.
        pub fn intermediate(iat: u64) -> Spec {
            Spec {
                subject: INTERMEDIATE_NAME,
                issuer: ROOT_NAME,
                not_before: iat - 365 * 86_400,
                not_after: iat + 2 * 365 * 86_400,
                ..Spec::root(iat)
            }
        }

        /// A leaf as Google issues them: not a CA, no key usage, valid for
        /// sixty days from a few days before `iat`.
        pub fn leaf(iat: u64) -> Spec {
            Spec {
                subject: LEAF_NAME,
                issuer: INTERMEDIATE_NAME,
                not_before: iat - 3 * 86_400,
                not_after: iat + 57 * 86_400,
                basic: Some((false, None)),
                usage: None,
                unknown_critical: false,
                algorithm: SHA256_WITH_RSA,
            }
        }
    }

    fn time(seconds: u64) -> Time {
        Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(seconds)).expect("a time"))
    }

    fn extension(oid: ObjectIdentifier, critical: bool, value: Vec<u8>) -> Extension {
        Extension {
            extn_id: oid,
            critical,
            extn_value: OctetString::new(value).expect("an extension value"),
        }
    }

    /// A certificate of `subject`'s key as `spec` says, signed by `issuer`.
    pub fn certificate(spec: &Spec, subject: &RsaPublicKey, issuer: &RsaPrivateKey) -> Vec<u8> {
        let algorithm = AlgorithmIdentifierOwned {
            oid: spec.algorithm,
            parameters: Some(Any::null()),
        };
        let mut extensions = Vec::new();
        if let Some((ca, path_len_constraint)) = spec.basic {
            let value = BasicConstraints {
                ca,
                path_len_constraint,
            };
            extensions.push(extension(
                ObjectIdentifier::new_unwrap("2.5.29.19"),
                true,
                value.to_der().unwrap(),
            ));
        }
        if let Some(usage) = spec.usage {
            extensions.push(extension(
                ObjectIdentifier::new_unwrap("2.5.29.15"),
                true,
                KeyUsage(usage).to_der().unwrap(),
            ));
        }
        if spec.unknown_critical {
            extensions.push(extension(UNKNOWN_EXTENSION, true, alloc::vec![0x05, 0x00]));
        }
        let spki = subject.to_public_key_der().expect("an RSA key encodes");
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[0x01, 0x23, 0x45]).unwrap(),
            signature: algorithm.clone(),
            issuer: Name::from_str(spec.issuer).unwrap(),
            validity: Validity {
                not_before: time(spec.not_before),
                not_after: time(spec.not_after),
            },
            subject: Name::from_str(spec.subject).unwrap(),
            subject_public_key_info: SubjectPublicKeyInfoOwned::from_der(spki.as_bytes()).unwrap(),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(extensions),
        };
        let signature: Vec<u8> = SigningKey::<Sha256>::new(issuer.clone())
            .sign(&tbs.to_der().unwrap())
            .to_vec();
        Certificate {
            tbs_certificate: tbs,
            signature_algorithm: algorithm,
            signature: BitString::from_bytes(&signature).unwrap(),
        }
        .to_der()
        .unwrap()
    }

    /// The test chain, as Google's: leaf, intermediate, root, each as its
    /// spec says, each signed by the next (the root by itself).
    pub fn chain_of(leaf: &Spec, intermediate: &Spec, root: &Spec) -> Vec<Vec<u8>> {
        let (root_key, intermediate_key, leaf_key) =
            (key(ROOT_SEED), key(INTERMEDIATE_SEED), key(LEAF_SEED));
        alloc::vec![
            certificate(leaf, &leaf_key.to_public_key(), &intermediate_key),
            certificate(intermediate, &intermediate_key.to_public_key(), &root_key),
            certificate(root, &root_key.to_public_key(), &root_key),
        ]
    }

    /// The test chain for a token issued at `iat`.
    pub fn chain(iat: u64) -> Vec<Vec<u8>> {
        chain_of(&Spec::leaf(iat), &Spec::intermediate(iat), &Spec::root(iat))
    }

    /// What a checker pins to accept tokens chained to the test root.
    pub fn root_hash(iat: u64) -> [u8; 32] {
        crate::pki::root_hash(chain(iat).last().unwrap())
    }

    /// The test root as a PEM certificate, as a prover is given a root.
    pub fn root_pem(iat: u64) -> String {
        let der = STANDARD.encode(chain(iat).pop().unwrap());
        let lines: Vec<&str> = der
            .as_bytes()
            .chunks(64)
            .map(|line| core::str::from_utf8(line).unwrap())
            .collect();
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            lines.join("\n")
        )
    }

    /// A PKI token's header carrying `chain`.
    pub fn header(chain: &[Vec<u8>]) -> Value {
        let x5c: Vec<String> = chain.iter().map(|der| STANDARD.encode(der)).collect();
        json!({"alg": "RS256", "kid": "botstadia-test-leaf", "typ": "JWT", "x5c": x5c})
    }

    /// `claims` as a PKI token carrying `chain`, signed by `signer`.
    pub fn token(chain: &[Vec<u8>], signer: &RsaPrivateKey, claims: &Value) -> String {
        super::sign_with(signer, &header(chain), claims)
    }

    /// A guest input that passes: a PKI token issued at `iat` under the test
    /// chain, checked at `now`. No JWKS key is given: the chain is the
    /// token's own.
    pub fn input(binding: &Binding, iat: u64, now: u64) -> Input {
        Input {
            token: token(&chain(iat), &key(LEAF_SEED), &super::claims(binding, iat)),
            keys: Vec::new(),
            now,
            binding: *binding,
        }
    }

    /// The header's `x5c` of a compact token, decoded.
    pub fn x5c_of(token: &str) -> Vec<Vec<u8>> {
        let header = token.split('.').next().unwrap();
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header).unwrap()).unwrap();
        header["x5c"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| STANDARD.decode(item.as_str().unwrap()).unwrap())
            .collect()
    }
}

//! Account wallets (TRUST.md#account-wallets, MONEY.md#accounts-and-wallets):
//! a Safe with Safe's ERC-4337 module on EntryPoint v0.7, its first passkey
//! through Safe's shared WebAuthn signer, gas paid in USDC through Circle's
//! Paymaster.
//!
//! Everything here is pure encoding, shared by the keeper (deploys from the
//! canonical template), the api (ERC-1271 checks), the site (building and
//! signing operations) and the exit page, so they all agree byte for byte:
//!
//! - [`safe`]: the canonical setup template, its counterfactual address, the
//!   factory call that deploys it, and owner changes
//! - [`op`]: user operations, their hash, the SafeOp a Safe's owners sign,
//!   and the signature layouts for a passkey and an address owner
//! - [`webauthn`]: a passkey's assertion as Safe's WebAuthn signer reads it
//! - [`paymaster`]: Circle's Paymaster data and USDC's permit
//! - [`calls`]: the calls an operation batches (claims, approve, the
//!   eligibility statement, bets, transfers)
//!
//! Every contract address comes from [`Contracts`], filled from `config.yml`,
//! never from the caller: a tampered template could otherwise point the
//! passkey at a verifier of someone else's (TRUST.md#you-sign-on-our-site).

pub mod bundler;
pub mod calls;
pub mod check;
pub mod flow;
pub mod op;
pub mod paymaster;
pub mod recovery;
pub mod safe;
pub mod webauthn;

use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};

/// The contracts an account wallet is set up with and talks to, one set per
/// target (`config.yml`'s `WALLET_*`). Safe's and Circle's contracts are at
/// the same addresses on Base and Base Sepolia.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Contracts {
    pub chain_id: u64,
    /// ERC-4337 EntryPoint v0.7.
    pub entry_point: Address,
    /// SafeL2 1.4.1: the singleton every account wallet's proxy points at.
    pub safe_singleton: Address,
    /// SafeProxyFactory 1.4.1.
    pub proxy_factory: Address,
    /// Safe4337Module 0.3.0: the module and the fallback handler.
    pub safe_4337_module: Address,
    /// SafeModuleSetup 0.3.0, delegatecalled in setup to enable the module.
    pub safe_module_setup: Address,
    /// MultiSend 1.4.1, delegatecalled in setup only.
    pub multi_send: Address,
    /// MultiSendCallOnly 1.4.1, which batches an operation's calls.
    pub multi_send_call_only: Address,
    /// SafeWebAuthnSharedSigner 0.2.1: the first passkey's owner address.
    pub webauthn_shared_signer: Address,
    /// SafeWebAuthnSignerFactory 0.2.1: a later passkey's signer contract.
    pub webauthn_signer_factory: Address,
    /// P-256 verifiers, packed as Safe's signer reads them: the
    /// `P256VERIFY` precompile's address in the top 16 bits, a fallback
    /// verifier contract below. Ours is the precompile alone (TRUST.md#what-a-wallet-is):
    /// Safe withdrew its FCL fallback for known bugs.
    pub p256_verifiers: U256,
    /// Native USDC.
    pub usdc: Address,
    /// USDC's EIP-712 domain name, which its permit signs over: `USDC` on
    /// Base Sepolia (check `name()` on each chain; mainnet's may differ).
    #[serde(default = "default_usdc_name")]
    pub usdc_name: String,
    /// Circle's Paymaster for EntryPoint v0.7.
    pub paymaster: Address,
    /// The fallback when Circle's fails: Pimlico's ERC-20 paymaster
    /// (MONEY.md#currency). None leaves Circle's alone.
    #[serde(default)]
    pub fallback_paymaster: Option<Address>,
    /// Our settlement contract.
    pub settlement: Address,
}

fn default_usdc_name() -> String {
    "USDC".into()
}

impl Contracts {
    /// Pack `P256VERIFY`'s address and a fallback verifier the way
    /// `P256.Verifiers` does (a `uint176`).
    pub fn pack_verifiers(precompile: u16, fallback: Address) -> U256 {
        (U256::from(precompile) << 160) | U256::from_be_slice(fallback.as_slice())
    }

    /// Safe's and Circle's contracts as deployed on Base and Base Sepolia,
    /// with this target's chain, USDC and settlement contract.
    pub fn base(chain_id: u64, usdc: Address, settlement: Address) -> Self {
        use alloy_primitives::address;
        Self {
            chain_id,
            entry_point: address!("0x0000000071727De22E5E9d8BAf0edAc6f37da032"),
            safe_singleton: address!("0x29fcB43b46531BcA003ddC8FCB67FFE91900C762"),
            proxy_factory: address!("0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67"),
            safe_4337_module: address!("0x75cf11467937ce3F2f357CE24ffc3DBF8fD5c226"),
            safe_module_setup: address!("0x2dd68b007B46fBe91B9A7c3EDa5A7a1063cB5b47"),
            multi_send: address!("0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526"),
            multi_send_call_only: address!("0x9641d764fc13c8B624c04430C7356C1C7C8102e2"),
            webauthn_shared_signer: address!("0x94a4F6affBd8975951142c3999aEAB7ecee555c2"),
            webauthn_signer_factory: address!("0x1d31F259eE307358a26dFb23EB365939E8641195"),
            p256_verifiers: Self::pack_verifiers(0x100, Address::ZERO),
            usdc,
            usdc_name: default_usdc_name(),
            paymaster: address!("0x31BE08D380A21fc740883c0BC434FcFc88740b58"),
            fallback_paymaster: Some(address!("0x777777777777AeC03fd955926DbF81597e66834C")),
            settlement,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `config.yml`'s testnet wallet contracts are Safe's and Circle's as
    /// deployed, the precompile alone for P-256, and our testnet USDC and
    /// settlement: what the api, the keeper, the site and the exit page read.
    #[test]
    fn the_configured_contracts_are_the_deployed_ones() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../config.yml");
        let config = std::fs::read_to_string(root).unwrap();
        let value = |key: &str| {
            let line = config
                .lines()
                .find(|l| l.trim_start().starts_with(&format!("{key}:")))
                .unwrap_or_else(|| panic!("{key} in config.yml"));
            line.split_once(':')
                .unwrap()
                .1
                .trim()
                .trim_matches('"')
                .to_string()
        };
        let start = config.find("WALLET_CONTRACTS_TESTNET: >-").unwrap();
        let block: String = config[start..]
            .lines()
            .skip(1)
            .take_while(|l| l.starts_with("    "))
            .collect::<Vec<_>>()
            .join(" ")
            .replace("{{.CHAIN_TOKEN_TESTNET}}", &value("CHAIN_TOKEN_TESTNET"))
            .replace(
                "{{.CHAIN_TESTNET_SETTLEMENT}}",
                &value("CHAIN_TESTNET_SETTLEMENT"),
            )
            .replace(
                "{{.WALLET_FALLBACK_PAYMASTER}}",
                &value("WALLET_FALLBACK_PAYMASTER"),
            );
        let parsed: Contracts = serde_json::from_str(&block).unwrap();
        let expected = Contracts::base(
            84532,
            value("CHAIN_TOKEN_TESTNET").parse().unwrap(),
            value("CHAIN_TESTNET_SETTLEMENT").parse().unwrap(),
        );
        assert_eq!(parsed, expected);
    }
}

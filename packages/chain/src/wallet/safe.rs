//! The canonical setup template (TRUST.md#deploying-a-wallet): what the
//! keeper deploys, what the recovery save carries, and the address both
//! commit to.
//!
//! In the template the owners and the first passkey's public key are free;
//! everything else is fixed: a threshold of one, Safe's 4337 module enabled
//! and set as the fallback handler, every contract from [`Contracts`], no
//! other delegatecall, no payment, and a salt nonce of zero. So a wallet's
//! address follows from its first owners alone, and the keeper can check
//! any setup data by rebuilding it from them.

use alloy_primitives::{Address, B256, Bytes, U256, keccak256};
use alloy_sol_types::{SolCall, SolValue, sol};
use serde::{Deserialize, Serialize};

use super::Contracts;

sol! {
    #[allow(missing_docs)]
    function setup(
        address[] owners,
        uint256 threshold,
        address to,
        bytes data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address paymentReceiver
    );

    #[allow(missing_docs)]
    function createProxyWithNonce(address singleton, bytes initializer, uint256 saltNonce)
        returns (address proxy);

    #[allow(missing_docs)]
    function enableModules(address[] modules);

    #[allow(missing_docs)]
    struct SignerConfig {
        uint256 x;
        uint256 y;
        uint176 verifiers;
    }

    #[allow(missing_docs)]
    function configure(SignerConfig signer);

    #[allow(missing_docs)]
    function multiSend(bytes transactions);

    #[allow(missing_docs)]
    function addOwnerWithThreshold(address owner, uint256 threshold);

    #[allow(missing_docs)]
    function removeOwner(address prevOwner, address owner, uint256 threshold);

    #[allow(missing_docs)]
    function getOwners() returns (address[] owners);

    #[allow(missing_docs)]
    function createSigner(uint256 x, uint256 y, uint176 verifiers) returns (address signer);

    #[allow(missing_docs)]
    function getSigner(uint256 x, uint256 y, uint176 verifiers) returns (address signer);

    #[allow(missing_docs)]
    function getConfiguration(address account) returns (SignerConfig signer);
}

/// Safe's linked-list sentinel for owners and modules.
pub const SENTINEL: Address =
    Address::new([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

/// The salt nonce of every account wallet.
pub const SALT_NONCE: U256 = U256::ZERO;

/// SafeProxyFactory 1.4.1's `proxyCreationCode()`, as on Base.
const PROXY_CREATION_CODE: &str = include_str!("safe_proxy_creation_code.hex");

/// A passkey's public key, the two P-256 coordinates.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Passkey {
    pub x: U256,
    pub y: U256,
}

/// A wallet's first owners, the free part of the template.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirstOwners {
    /// The first passkey, set up through the shared signer.
    pub passkey: Option<Passkey>,
    /// Address owners: a recovery key, a wallet of the user's own.
    pub addresses: Vec<Address>,
}

impl FirstOwners {
    /// Every first owner needs one that works without botstadia.com
    /// (TRUST.md#a-way-out-without-us): an address owner.
    pub fn check(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.addresses.is_empty(),
            "a wallet's first owners include a recovery key or a wallet of the user's own"
        );
        let mut seen = self.addresses.clone();
        seen.sort();
        seen.dedup();
        anyhow::ensure!(
            seen.len() == self.addresses.len(),
            "an owner is listed twice"
        );
        anyhow::ensure!(
            !self.addresses.contains(&Address::ZERO) && !self.addresses.contains(&SENTINEL),
            "an owner can't be the zero or sentinel address"
        );
        Ok(())
    }

    /// The Safe's owner list: the shared signer first when there's a passkey,
    /// then the address owners in the order given.
    pub fn owners(&self, c: &Contracts) -> Vec<Address> {
        let mut out = Vec::with_capacity(self.addresses.len() + 1);
        if self.passkey.is_some() {
            out.push(c.webauthn_shared_signer);
        }
        out.extend(self.addresses.iter().copied());
        out
    }
}

/// One MultiSend transaction: `operation ‖ to ‖ value ‖ len ‖ data`.
pub fn multi_send_tx(out: &mut Vec<u8>, delegate: bool, to: Address, value: U256, data: &[u8]) {
    out.push(u8::from(delegate));
    out.extend_from_slice(to.as_slice());
    out.extend_from_slice(&value.to_be_bytes::<32>());
    out.extend_from_slice(&U256::from(data.len()).to_be_bytes::<32>());
    out.extend_from_slice(data);
}

/// The Safe's `setup` initializer for these first owners: the setup data
/// the recovery save carries.
pub fn initializer(c: &Contracts, first: &FirstOwners) -> anyhow::Result<Bytes> {
    first.check()?;
    let enable = enableModulesCall {
        modules: vec![c.safe_4337_module],
    }
    .abi_encode();
    let (to, data) = match first.passkey {
        None => (c.safe_module_setup, enable),
        Some(key) => {
            let mut txs = Vec::new();
            multi_send_tx(&mut txs, true, c.safe_module_setup, U256::ZERO, &enable);
            let configure = configureCall {
                signer: SignerConfig {
                    x: key.x,
                    y: key.y,
                    verifiers: verifiers_u176(c.p256_verifiers)?,
                },
            }
            .abi_encode();
            multi_send_tx(
                &mut txs,
                true,
                c.webauthn_shared_signer,
                U256::ZERO,
                &configure,
            );
            (
                c.multi_send,
                multiSendCall {
                    transactions: txs.into(),
                }
                .abi_encode(),
            )
        }
    };
    Ok(setupCall {
        owners: first.owners(c),
        threshold: U256::from(1),
        to,
        data: data.into(),
        fallbackHandler: c.safe_4337_module,
        paymentToken: Address::ZERO,
        payment: U256::ZERO,
        paymentReceiver: Address::ZERO,
    }
    .abi_encode()
    .into())
}

/// The packed verifiers as `configure` and the signer factory take them.
pub fn verifiers_u176(v: U256) -> anyhow::Result<alloy_primitives::aliases::U176> {
    anyhow::ensure!(v.bit_len() <= 176, "verifiers don't fit a uint176");
    Ok(alloy_primitives::aliases::U176::from_be_slice(
        &v.to_be_bytes::<32>()[32 - 22..],
    ))
}

/// The factory call that deploys the wallet: anyone may send it.
pub fn deploy_call(c: &Contracts, initializer: &[u8]) -> Vec<u8> {
    createProxyWithNonceCall {
        singleton: c.safe_singleton,
        initializer: initializer.to_vec().into(),
        saltNonce: SALT_NONCE,
    }
    .abi_encode()
}

/// The counterfactual address the factory deploys `initializer` to.
pub fn address(c: &Contracts, initializer: &[u8]) -> Address {
    let salt = keccak256((keccak256(initializer), SALT_NONCE).abi_encode_packed());
    let mut code = alloy_primitives::hex::decode(PROXY_CREATION_CODE.trim())
        .expect("the proxy creation code is hex");
    code.extend_from_slice(&U256::from_be_slice(c.safe_singleton.as_slice()).to_be_bytes::<32>());
    c.proxy_factory.create2(salt, keccak256(&code))
}

/// A wallet as the recovery save and the keeper know it: its address and
/// the exact setup data it deploys with.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Setup {
    pub address: Address,
    pub owners: FirstOwners,
    pub initializer: Bytes,
}

impl Setup {
    pub fn new(c: &Contracts, owners: FirstOwners) -> anyhow::Result<Self> {
        let initializer = initializer(c, &owners)?;
        Ok(Self {
            address: address(c, &initializer),
            owners,
            initializer,
        })
    }

    /// Rebuild from the first owners and check that `initializer` is the
    /// canonical template's, at `address`. The keeper deploys nothing else,
    /// since Safe's setup can delegatecall anywhere.
    pub fn check_canonical(
        c: &Contracts,
        address: Address,
        initializer: &[u8],
    ) -> anyhow::Result<Self> {
        let owners = parse_owners(c, initializer)?;
        let setup = Self::new(c, owners)?;
        anyhow::ensure!(
            setup.initializer.as_ref() == initializer,
            "setup data isn't the canonical template"
        );
        anyhow::ensure!(
            setup.address == address,
            "setup data doesn't deploy to that address"
        );
        Ok(setup)
    }

    pub fn salt_hash(&self) -> B256 {
        keccak256(&self.initializer)
    }
}

/// Read the free part (owners, passkey key) back out of setup data, so it
/// can be rebuilt and compared byte for byte.
pub fn parse_owners(c: &Contracts, initializer: &[u8]) -> anyhow::Result<FirstOwners> {
    let call = setupCall::abi_decode(initializer)?;
    let mut owners = call.owners;
    let passkey = if owners.first() == Some(&c.webauthn_shared_signer) {
        owners.remove(0);
        // multiSend(delegatecall enableModules, delegatecall configure)
        let txs = multiSendCall::abi_decode(&call.data)?.transactions;
        let configure = last_tx_data(&txs)?;
        let cfg = configureCall::abi_decode(configure)?.signer;
        Some(Passkey { x: cfg.x, y: cfg.y })
    } else {
        None
    };
    Ok(FirstOwners {
        passkey,
        addresses: owners,
    })
}

fn last_tx_data(txs: &[u8]) -> anyhow::Result<&[u8]> {
    let mut i = 0;
    let mut last = None;
    while i < txs.len() {
        anyhow::ensure!(txs.len() >= i + 85, "a truncated MultiSend transaction");
        // Any setup data may arrive here, so no length is trusted to fit.
        let len: usize = U256::from_be_slice(&txs[i + 53..i + 85])
            .try_into()
            .map_err(|_| anyhow::anyhow!("a MultiSend length that doesn't fit"))?;
        let end = (i + 85)
            .checked_add(len)
            .filter(|end| *end <= txs.len())
            .ok_or_else(|| anyhow::anyhow!("a truncated MultiSend transaction"))?;
        last = Some(&txs[i + 85..end]);
        i = end;
    }
    last.ok_or_else(|| anyhow::anyhow!("an empty MultiSend"))
}

/// `removeOwner`'s `prevOwner`: the owner before `owner` in Safe's linked
/// list, which `getOwners` returns in order.
pub fn prev_owner(owners: &[Address], owner: Address) -> anyhow::Result<Address> {
    let i = owners
        .iter()
        .position(|o| *o == owner)
        .ok_or_else(|| anyhow::anyhow!("{owner:#x} isn't an owner"))?;
    Ok(if i == 0 { SENTINEL } else { owners[i - 1] })
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    fn contracts() -> Contracts {
        Contracts::base(
            84532,
            address!("0x036CbD53842c5426634e7929541eC2318f3dCF7e"),
            address!("0x3eeB6D36DE9CBF82feeF09F50C4A49707eB0Ff2A"),
        )
    }

    #[test]
    fn the_template_round_trips_and_refuses_anything_else() {
        let c = contracts();
        let first = FirstOwners {
            passkey: Some(Passkey {
                x: U256::from(7),
                y: U256::from(9),
            }),
            addresses: vec![address!("0x00000000000000000000000000000000000000aa")],
        };
        let s = Setup::new(&c, first.clone()).unwrap();
        assert_eq!(parse_owners(&c, &s.initializer).unwrap(), first);
        assert_eq!(
            Setup::check_canonical(&c, s.address, &s.initializer).unwrap(),
            s
        );

        // Another delegatecall target, same owners: refused.
        let mut other = c.clone();
        other.multi_send = address!("0x00000000000000000000000000000000000000bb");
        let tampered = initializer(&other, &first).unwrap();
        assert!(Setup::check_canonical(&c, address(&c, &tampered), &tampered).is_err());

        // Another verifier for the passkey: refused.
        let mut other = c.clone();
        other.p256_verifiers = Contracts::pack_verifiers(0x100, Address::repeat_byte(0xcc));
        let tampered = initializer(&other, &first).unwrap();
        assert!(Setup::check_canonical(&c, address(&c, &tampered), &tampered).is_err());
    }

    #[test]
    fn every_wallet_has_an_owner_that_works_without_the_domain() {
        let first = FirstOwners {
            passkey: Some(Passkey {
                x: U256::from(1),
                y: U256::from(2),
            }),
            addresses: vec![],
        };
        assert!(initializer(&contracts(), &first).is_err());
    }

    #[test]
    fn hostile_setup_data_is_refused_not_a_panic() {
        let c = contracts();
        let mut txs = vec![0u8; 85];
        txs[53..85].copy_from_slice(&[0xff; 32]);
        let call = setupCall {
            owners: vec![c.webauthn_shared_signer, Address::repeat_byte(1)],
            threshold: U256::from(1),
            to: c.multi_send,
            data: multiSendCall {
                transactions: txs.into(),
            }
            .abi_encode()
            .into(),
            fallbackHandler: c.safe_4337_module,
            paymentToken: Address::ZERO,
            payment: U256::ZERO,
            paymentReceiver: Address::ZERO,
        }
        .abi_encode();
        assert!(parse_owners(&c, &call).is_err());
    }

    #[test]
    fn prev_owner_walks_the_list() {
        let a = address!("0x00000000000000000000000000000000000000aa");
        let b = address!("0x00000000000000000000000000000000000000bb");
        assert_eq!(prev_owner(&[a, b], a).unwrap(), SENTINEL);
        assert_eq!(prev_owner(&[a, b], b).unwrap(), a);
        assert!(prev_owner(&[a], b).is_err());
    }
}

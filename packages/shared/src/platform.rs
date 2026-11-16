//! The platform's endpoints beyond accounts: api keys, bots and bundles, the
//! builder's status, the fleet, jobs, posts, ratings, binds, statements,
//! retirements, knobs, admin actions and public reads.

use serde::{Deserialize, Serialize};

use crate::api::{Access, Empty, Endpoint, Method};

macro_rules! endpoint {
    ($(#[$doc:meta])* $name:ident, $method:ident, $path:literal, $access:ident, $req:ty => $res:ty) => {
        $(#[$doc])*
        pub struct $name;
        impl Endpoint for $name {
            const METHOD: Method = Method::$method;
            const PATH: &'static str = $path;
            const ACCESS: Access = Access::$access;
            type Req = $req;
            type Res = $res;
        }
    };
    ($(#[$doc:meta])* key $name:ident, $method:ident, $path:literal, $access:ident, $req:ty => $res:ty) => {
        $(#[$doc])*
        pub struct $name;
        impl Endpoint for $name {
            const METHOD: Method = Method::$method;
            const PATH: &'static str = $path;
            const ACCESS: Access = Access::$access;
            const API_KEY: bool = true;
            type Req = $req;
            type Res = $res;
        }
    };
}

/// The prefix every api key starts with, so a key is never mistaken for a
/// session token.
pub const API_KEY_PREFIX: &str = "bsk_";

// --- api keys -----------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKeyName {
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKeyCreated {
    pub id: String,
    /// The key itself, shown once and never stored.
    pub key: String,
    pub prefix: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub created_at: u64,
    pub last_used_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdOnly {
    pub id: String,
}

endpoint!(
    /// Make an api key for the CLI. Never by an api key.
    ApiKeysCreate, Post, "/api-keys/create", Verified, ApiKeyName => ApiKeyCreated
);
endpoint!(ApiKeysList, Get, "/api-keys", Verified, Empty => Vec<ApiKeyInfo>);
endpoint!(ApiKeysRevoke, Post, "/api-keys/revoke", Verified, IdOnly => Empty);

// --- bots and bundles -----------------------------------------------------------

/// The zero address: a bot with no payout statement pays its builder point
/// to the treasury (MONEY.md#how-a-builder-earns).
pub const ZERO_ADDRESS: &str = "0x0000000000000000000000000000000000000000";

/// What `botstadia upload` sends: the encrypted bundle, both wrapped data
/// keys, and the author key's public halves (TRUST.md#bundle-encryption).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleUpload {
    pub name: String,
    pub arena_id: String,
    pub payload_schema: u32,
    /// policy | rust | c
    pub kind: String,
    /// The plaintext ZIP's digest, `sha256-<hex>`; verification confirms it.
    pub digest: String,
    pub author_address: String,
    pub author_x25519: String,
    /// The BundleKey wrapped to, and its new-key instruction.
    pub bundle_key_pub: String,
    pub instruction: u64,
    /// Base64.
    pub wrapped_bundle_key: String,
    pub wrapped_author_key: String,
    pub ciphertext: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadReceipt {
    pub bot_id: String,
    /// Printed on every upload (BOTS.md#builder-tooling).
    pub payout_address: String,
    /// False with the zero address: wins pay the builder nothing.
    pub earning: bool,
    /// First verifications ahead of this one.
    pub queue_ahead: u64,
    /// Pending binds, rebinds and email changes on the account.
    pub notices: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BotStatus {
    pub id: String,
    pub name: String,
    pub arena_id: String,
    pub digest: String,
    /// verifying | active | failed | retired
    pub state: String,
    /// The warm-up status a builder sees (COMPETITION.md#warm-up):
    /// queued | running | finished | waiting on BotStadia; `None` before
    /// verification passes.
    pub warmup: Option<String>,
    pub queue_ahead: Option<u64>,
    pub awaiting_rekey: bool,
    pub retiring_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BuilderStatus {
    /// The account's id: what `confirm-wallet` signs for.
    pub account: String,
    pub bots: Vec<BotStatus>,
    pub payout_address: String,
    pub earning: bool,
    pub notices: Vec<String>,
}

endpoint!(
    /// Upload a bundle, which becomes a bot once it passes verification.
    key BundlesUpload, Post, "/bundles/upload", Verified, BundleUpload => UploadReceipt
);
endpoint!(
    /// The builder's own bots and account notices.
    key BuilderStatusGet, Get, "/builder/status", Verified, Empty => BuilderStatus
);

/// A bot awaiting a rekey, with the author's wrapped copy to rewrap
/// (TRUST.md#make-losing-it-cheap).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RekeyNeeded {
    pub bot_id: String,
    pub name: String,
    pub digest: String,
    pub wrapped_author_key: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RekeySubmit {
    pub bot_id: String,
    pub wrapped_bundle_key: String,
    pub bundle_key_pub: String,
    pub instruction: u64,
}

endpoint!(
    /// Bots awaiting a rekey, with what `botstadia rekey` needs.
    key RekeyList, Get, "/bundles/rekey", Verified, Empty => Vec<RekeyNeeded>
);
endpoint!(
    /// A rewrapped data key, held until an enclave holding the new key has
    /// opened the bundle and checked its digest.
    key RekeySubmitPost, Post, "/bundles/rekey/submit", Verified, RekeySubmit => Empty
);

// --- the fleet -------------------------------------------------------------------

/// Every machine request after registration: a body, signed with the node's
/// SubmitKey over the path, the node's current api nonce and the body's
/// hash ([`machine_message`]). Each nonce is good once; the response names
/// the next.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed<T> {
    pub address: String,
    pub nonce: String,
    /// EIP-191, 0x hex.
    pub signature: String,
    pub body: T,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Answer<T> {
    pub next_nonce: String,
    pub body: T,
}

/// What a machine signs: `botstadia-machine-v1 ‖ \n ‖ path ‖ \n ‖ nonce ‖ \n
/// ‖ sha256(body JSON) hex`.
pub fn machine_message(path: &str, nonce: &str, body_sha256_hex: &str) -> String {
    format!("botstadia-machine-v1\n{path}\n{nonce}\n{body_sha256_hex}")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    pub address: String,
    /// The attestation token (mock on the local target), its nonce binding
    /// this address and binding with no BundleKey yet.
    pub token: String,
    pub chain_id: u64,
    pub results: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Holder {
    pub address: String,
    pub bundle_key_pub: String,
    pub instruction: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registered {
    pub nonce: String,
    /// Where to ask for the BundleKey: a hint, never a credential.
    pub holders: Vec<Holder>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayMessage {
    pub id: String,
    pub from: String,
    pub to: String,
    /// challenge | request | reply | refusal
    pub kind: String,
    pub body: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelaySend {
    pub to: String,
    pub kind: String,
    pub body: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldingKey {
    pub bundle_key_pub: String,
    pub instruction: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintAsk {
    pub instruction: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintAnswer {
    /// Mint (`true`), or fetch from a holder: another is minting or holds it.
    pub mint: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootToken {
    /// The fresh token the boot proof is made from, its nonce binding the
    /// SubmitKey, the BundleKey, the binding and the instruction.
    pub token: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootProof {
    pub address: String,
    pub token: String,
    /// 0x hex, once the prover has made it.
    pub journal: Option<String>,
    pub seal: Option<String>,
}

/// The keys for the image's allowlisted RPC providers, `name=key` pairs
/// separated by commas: the api supplies keys, never URLs, since the image
/// pins the hosts (TRUST.md#how-the-enclave-talks-to-the-chain).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcKeys {
    pub keys: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimAsk {
    pub kinds: Vec<String>,
    /// The jobs the machine holds: a job claimed for it that isn't here lost
    /// its answer, and is offered again.
    #[serde(default)]
    pub held: Vec<String>,
}

/// The reason a runner reports for a job whose thread panicked: a host bug,
/// alerted as `job_panicked` (never a verdict on the bot).
pub const JOB_PANICKED: &str = "the job panicked";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobOffer {
    pub id: String,
    pub kind: String,
    pub bot_id: Option<String>,
    pub session_id: Option<String>,
    /// Everything the job needs that the api couriers: a session's spec,
    /// entry, post and proof; a warm-up's opponent list; a bundle's
    /// metadata. JSON.
    pub payload: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleAsk {
    pub bot_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleFetched {
    pub bot_id: String,
    pub digest: String,
    pub ciphertext: String,
    pub wrapped_bundle_key: String,
    pub bundle_key_pub: String,
    pub instruction: u64,
    /// A rekey waiting for its check, if any.
    pub pending_wrapped_key: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveUpload {
    pub session_id: String,
    /// Base64: the replay archive and the metrics file.
    pub archive: String,
    pub metrics: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobDone {
    pub id: String,
    /// done | failed | fault | release
    pub outcome: String,
    /// JSON: an upload report, a rekey check's verdict, why it failed.
    pub result: String,
}

endpoint!(
    /// Register a boot, on its attestation token alone.
    FleetRegister, Post, "/fleet/register", Public, Registration => Registered
);
endpoint!(FleetHeartbeat, Post, "/fleet/heartbeat", Machine, Signed<serde_json::Value> => Answer<Empty>);
endpoint!(FleetHolders, Post, "/fleet/holders", Machine, Signed<Empty> => Answer<Vec<Holder>>);
endpoint!(FleetRelaySend, Post, "/fleet/relay/send", Machine, Signed<RelaySend> => Answer<Empty>);
endpoint!(FleetRelayInbox, Post, "/fleet/relay/inbox", Machine, Signed<Empty> => Answer<Vec<RelayMessage>>);
endpoint!(FleetMint, Post, "/fleet/mint", Machine, Signed<MintAsk> => Answer<MintAnswer>);
endpoint!(FleetHolding, Post, "/fleet/holding", Machine, Signed<HoldingKey> => Answer<Empty>);
endpoint!(FleetBootToken, Post, "/fleet/boot-token", Machine, Signed<BootToken> => Answer<Empty>);
endpoint!(FleetBootProof, Post, "/fleet/boot-proof", Machine, Signed<Empty> => Answer<BootProof>);
endpoint!(
    /// The RPC providers' keys, for a registered machine: never in its launch
    /// environment, which its public attestation token states.
    FleetRpcKeys, Post, "/fleet/rpc-keys", Machine, Signed<Empty> => Answer<RpcKeys>
);
endpoint!(FleetClaim, Post, "/fleet/claim", Machine, Signed<ClaimAsk> => Answer<Option<JobOffer>>);
endpoint!(FleetBundle, Post, "/fleet/bundle", Machine, Signed<BundleAsk> => Answer<BundleFetched>);
endpoint!(FleetFinish, Post, "/fleet/finish", Machine, Signed<JobDone> => Answer<Empty>);
endpoint!(FleetDeregister, Post, "/fleet/deregister", Machine, Signed<Empty> => Answer<Empty>);
endpoint!(
    /// A session's replay archive and metrics, uploaded only once the batch
    /// carrying its result is included (TRUST.md#submitting-results).
    FleetArchive, Post, "/fleet/archive", Machine, Signed<ArchiveUpload> => Answer<Empty>
);

// --- wallets, statements and retirements ------------------------------------------

/// What `botstadia confirm-wallet` signs with the key of the account's
/// oldest bot (EIP-191), so a first wallet binds at once
/// (MONEY.md#stolen-sign-ins).
pub fn confirm_wallet_message(account: &str, wallet: &str) -> String {
    format!(
        "BotStadia: bind this wallet to my account at once.\naccount: {account}\nwallet: {}",
        wallet.to_lowercase()
    )
}

/// What an author-key signature starting or stopping a retirement names:
/// the bot and a fresh request id, so it can't be replayed.
pub fn retirement_message(action: &str, bot_id: &str, request: &str) -> String {
    format!("BotStadia: {action} the retirement of a bot.\nbot: {bot_id}\nrequest: {request}")
}

/// What a payout statement says (MONEY.md#how-a-builder-earns). One naming
/// an address carries the eligibility attestation; one naming zero doesn't.
pub fn statement_message(account: &str, number: u64, address: &str) -> String {
    let address = address.to_lowercase();
    if address == ZERO_ADDRESS {
        format!(
            "BotStadia payout statement {number}\naccount: {account}\naddress: {address}\nPay my bots' builder share to the treasury: I'm not earning."
        )
    } else {
        format!(
            "BotStadia payout statement {number}\naccount: {account}\naddress: {address}\nPay my bots' builder share to this address. I am 18 or older, I am not an excluded person, such as a US person or a sanctioned person, and I am not acting for one."
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletBind {
    pub address: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindState {
    pub id: String,
    pub address: String,
    /// first | rebind
    pub kind: String,
    /// waiting | bound
    pub state: String,
    pub effective_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletConfirm {
    pub account: String,
    pub wallet: String,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatementSubmit {
    pub number: u64,
    pub address: String,
    pub signer: String,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatementState {
    pub number: u64,
    pub address: String,
    /// held | in_force
    pub state: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetireBot {
    pub bot_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetireSigned {
    pub bot_id: String,
    pub request: String,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetirementState {
    pub id: String,
    pub bot_id: String,
    /// waiting | done | stopped | refused
    pub state: String,
    pub effective_at: u64,
}

endpoint!(WalletBindStart, Post, "/wallet/bind", Verified, WalletBind => BindState);
endpoint!(
    /// `botstadia confirm-wallet` posts its signature here: it names the
    /// account and wallet itself, so no sign-in is needed.
    WalletConfirmPost, Post, "/wallet/confirm", Public, WalletConfirm => Empty
);
endpoint!(WalletBindCancel, Post, "/wallet/bind/cancel", Verified, IdOnly => Empty);
endpoint!(StatementsSubmit, Post, "/statements/submit", Verified, StatementSubmit => StatementState);
endpoint!(RetireBySignin, Post, "/bots/retire", Verified, RetireBot => RetirementState);
endpoint!(RetireStopBySignin, Post, "/bots/retire/stop", Verified, RetireBot => RetirementState);
endpoint!(
    /// An author-key retirement, with or without the account.
    RetireByAuthor, Post, "/bots/retire/author", Public, RetireSigned => RetirementState
);
endpoint!(RetireStopByAuthor, Post, "/bots/retire/author/stop", Public, RetireSigned => RetirementState);
endpoint!(
    /// Anyone signed in may ask, with no proof; a person judges it.
    RetireRequest, Post, "/bots/retire/request", Verified, RetireBot => RetirementState
);

endpoint!(
    /// A retirement started by the account's wallet: its signature alone
    /// names the account, so no sign-in is needed.
    RetireByWallet, Post, "/bots/retire/wallet", Public, RetireSigned => RetirementState
);

// --- account wallets (TRUST.md#account-wallets) ----------------------------------------

/// What a wallet signs when the site sets it up and binds it: the account
/// and the wallet, so the bind is the wallet's own.
pub fn wallet_setup_message(account: &str, wallet: &str) -> String {
    format!(
        "BotStadia: this is my account's wallet.\naccount: {account}\nwallet: {}",
        wallet.to_lowercase()
    )
}

/// What a device signs before it's first shown a deposit address after a
/// bind (MONEY.md#funding-and-withdrawal): free, and moves nothing.
pub fn deposit_check_message(account: &str, wallet: &str, nonce: &str) -> String {
    format!(
        "BotStadia: show this device my deposit address.\naccount: {account}\nwallet: {}\nnonce: {nonce}",
        wallet.to_lowercase()
    )
}

/// A passkey's public key and WebAuthn credential, as registered with a
/// wallet. `owner` is the Safe owner it signs through.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyReg {
    pub credential_id: String,
    pub x: String,
    pub y: String,
    pub owner: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletSetup {
    pub address: String,
    /// The Safe's setup data (the canonical template), 0x hex.
    pub initializer: String,
    /// The first passkey, if the wallet has one.
    pub passkey: Option<PasskeyReg>,
    /// What each first address owner is: `recovery` or `own_wallet`.
    #[serde(default)]
    pub labels: std::collections::BTreeMap<String, String>,
    /// The wallet's ERC-1271 signature over [`wallet_setup_message`].
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletInfo {
    pub address: String,
    pub initializer: String,
    pub created_at: u64,
    pub deploy_requested_at: Option<u64>,
    pub deployed_at: Option<u64>,
    /// What each address owner is: `recovery` or `own_wallet`.
    #[serde(default)]
    pub labels: std::collections::BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletsMine {
    pub wallets: Vec<WalletInfo>,
    pub passkeys: Vec<serde_json::Value>,
    /// The account's bound wallet, if any.
    pub bound: Option<String>,
    /// A wallet whose bind is waiting (a first bind's or a rebind's wait).
    #[serde(default)]
    pub waiting: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalletAddress {
    pub address: String,
}

/// A JSON-RPC call relayed through the api, which holds the providers' keys.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayCall {
    pub method: String,
    pub params: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyAdd {
    pub wallet: String,
    pub passkey: PasskeyReg,
}

/// Name an address owner added later (`recovery` or `own_wallet`), or
/// forget one removed (`kind` empty).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerLabel {
    pub wallet: String,
    pub owner: String,
    pub kind: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DepositCheck {
    pub wallet: String,
    pub nonce: String,
    pub signature: String,
}

endpoint!(
    /// Record a wallet the site set up, checked against the canonical
    /// template, and bind it.
    WalletSetupPost, Post, "/wallet/setup", Verified, WalletSetup => BindState
);
endpoint!(WalletsMineGet, Get, "/wallet/mine", Verified, Empty => WalletsMine);
endpoint!(
    /// The user is acting: the keeper deploys the wallet at once.
    WalletDeployPost, Post, "/wallet/deploy", Verified, WalletAddress => Empty
);
endpoint!(
    /// A chain read, through the api's RPC: reads only.
    WalletRpcPost, Post, "/wallet/rpc", Verified, RelayCall => serde_json::Value
);
endpoint!(
    /// A bundler call, one bundler at a time with failover.
    WalletBundlerPost, Post, "/wallet/bundler", Verified, RelayCall => serde_json::Value
);
endpoint!(
    /// A later passkey, once it's an owner on the chain: it can sign in.
    WalletPasskeyAdd, Post, "/wallet/passkey", Verified, PasskeyAdd => Empty
);
endpoint!(
    /// The account wallet's bets and claims as indexed (sessions and weeks).
    WalletBetsGet, Get, "/wallet/bets", Verified, WalletAddress => Vec<serde_json::Value>
);
endpoint!(WalletOwnerLabelPost, Post, "/wallet/owner-label", Verified, OwnerLabel => Empty);
endpoint!(
    /// The check before a device's first deposit address after a bind: the
    /// bound wallet's signature over a nonce the device made. The device
    /// keeps the result; a device that can't sign is never shown an address.
    WalletDepositCheck, Post, "/wallet/deposit-check", Verified, DepositCheck => Empty
);

// --- admin ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KnobValue {
    pub key: String,
    pub value: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArenaPublishReq {
    pub digest: String,
    pub arena_id: String,
    pub version: String,
    pub payload_schema: u32,
    pub declaration_json: String,
    pub project_json: Option<String>,
    /// The admin key's EIP-191 signature over [`arena_publish_message`].
    pub signature: String,
}

/// One of our own bots, registered by digest ahead of its file going public
/// on the CDN (TRUST.md#seed-bots).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HouseBotReq {
    pub arena_id: String,
    pub payload_schema: u32,
    pub kind: String,
    pub digest: String,
    pub name: String,
    pub bundle_url: String,
}

/// What the admin key signs to publish an arena version.
pub fn arena_publish_message(digest: &str) -> String {
    format!("BotStadia: publish arena engine {digest}")
}

/// A proof of one waiting boot token, hex-encoded.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofSubmit {
    pub address: String,
    pub journal: String,
    pub seal: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestOnly {
    pub digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BotHold {
    pub bot_id: String,
    pub held: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BotRename {
    pub bot_id: String,
    pub name: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingOnly {
    pub binding: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Judgement {
    pub id: String,
    pub grant: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Held {
    /// The bot's sessions not yet anchored, for the admin to cancel on-chain.
    pub unanchored_sessions: Vec<String>,
}

endpoint!(AdminKnobs, Get, "/admin/knobs", Admin, Empty => Vec<KnobValue>);
endpoint!(AdminKnobSet, Post, "/admin/knobs/set", Admin, KnobValue => Empty);
endpoint!(AdminArenaPublish, Post, "/admin/arenas/publish", Admin, ArenaPublishReq => Empty);
endpoint!(AdminArenaWithdraw, Post, "/admin/arenas/withdraw", Admin, DigestOnly => Empty);
endpoint!(AdminBotHold, Post, "/admin/bots/hold", Admin, BotHold => Held);
endpoint!(AdminBotRegister, Post, "/admin/bots/register", Admin, HouseBotReq => Empty);
endpoint!(AdminBotRename, Post, "/admin/bots/rename", Admin, BotRename => Empty);
endpoint!(AdminBotRetire, Post, "/admin/bots/retire", Admin, RetireBot => Empty);
endpoint!(AdminJobRequeue, Post, "/admin/jobs/requeue", Admin, IdOnly => Empty);
endpoint!(AdminRetirementJudge, Post, "/admin/retirements/judge", Admin, Judgement => Empty);
endpoint!(AdminBindingRetiring, Post, "/admin/bindings/retiring", Admin, BindingOnly => Empty);
endpoint!(AdminImageMark, Post, "/admin/images/mark", Admin, DigestOnly => Empty);
endpoint!(AdminImageClear, Post, "/admin/images/clear", Admin, DigestOnly => Empty);
endpoint!(AdminFleet, Get, "/admin/fleet", Admin, Empty => Vec<serde_json::Value>);
endpoint!(
    /// Running and recent weeks, with what the cold key signs to call one off
    /// (TRUST.md#admin-powers).
    AdminWeeks, Get, "/admin/weeks", Admin, Empty => Vec<serde_json::Value>
);

/// A session's replay file, as its enclave uploaded it: raw bytes, not JSON,
/// with `?id=<session id>`. Served only once the api has checked the archive
/// against the hash its result signed, so it never changes: cacheable for
/// good, and readable from any origin (the player's frame is on the CDN's).
pub const PATH_PUBLIC_REPLAY: &str = "/public/replay";
/// A session's metrics file, the other half of its archive, the same way.
pub const PATH_PUBLIC_METRICS: &str = "/public/metrics";

/// The open an admin gave the devnet's compressed week, and the one after.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeekOpened {
    /// Unix seconds.
    pub open: u64,
    pub next_open: u64,
}
endpoint!(
    /// Open a week at once, on a target whose week is compressed (the
    /// devnet): every arena's week opens on the keeper's next pass, and
    /// later weeks follow from it. Refused where weeks run on the calendar
    /// (the testnet and prod), and while a week is still running
    /// (OPERATIONS.md#the-devnet).
    AdminWeekOpen, Post, "/admin/weeks/open", Admin, Empty => WeekOpened
);

// --- public reads --------------------------------------------------------------------
//
// Loose JSON for now: the site integration plan gives them typed shapes as
// it wires each page (HANDOFF/SITE-INTEGRATION.md).

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionsQuery {
    /// open | ended
    pub which: String,
    pub limit: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdQuery {
    pub id: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LadderQuery {
    pub arena_id: String,
    pub payload_schema: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NumberQuery {
    pub number: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WeeksQuery {
    pub arena_id: String,
    pub payload_schema: String,
    pub limit: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RangeQuery {
    pub from: String,
    pub to: String,
}

type Json = serde_json::Value;

endpoint!(PublicSessions, Get, "/public/sessions", Public, SessionsQuery => Vec<Json>);
endpoint!(PublicSession, Get, "/public/session", Public, IdQuery => Json);
endpoint!(PublicBot, Get, "/public/bot", Public, IdQuery => Json);
endpoint!(PublicBuilder, Get, "/public/builder", Public, IdQuery => Json);
endpoint!(PublicLadder, Get, "/public/ladder", Public, LadderQuery => Json);
endpoint!(PublicBootProofs, Get, "/public/boot-proofs", Public, Empty => Vec<Json>);
endpoint!(
    /// Boot tokens waiting for the prover, each with the binding its proof
    /// must carry (TRUST.md#the-keeper-and-the-prover).
    PublicProofRequests, Get, "/public/proof-requests", Public, Empty => Vec<Json>
);
endpoint!(
    /// A prover's proof of a waiting token: recorded only if its journal
    /// binds that request and the verifier contract accepts its seal.
    ProverProof, Post, "/prover/proof", Public, ProofSubmit => crate::api::Empty
);
endpoint!(PublicOpponentList, Get, "/public/opponent-list", Public, IdQuery => Json);
endpoint!(PublicArenas, Get, "/public/arenas", Public, Empty => Vec<Json>);
endpoint!(PublicPost, Get, "/public/post", Public, NumberQuery => Json);
endpoint!(
    /// An arena's weeks, newest first (COMPETITION.md#the-week).
    PublicWeeks, Get, "/public/weeks", Public, WeeksQuery => Vec<Json>
);
endpoint!(
    /// One week: its field, rounds, standings, final, champion and
    /// week-winner pool.
    PublicWeek, Get, "/public/week", Public, IdQuery => Json
);
endpoint!(
    /// An arena's current standings, each bot with its titles.
    PublicStandings, Get, "/public/standings", Public, LadderQuery => Json
);
endpoint!(
    /// Post lists, for recomputing a week's rounds.
    PublicPostLists, Get, "/public/post-lists", Public, RangeQuery => Vec<Json>
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::*;

    fn takes_key<E: Endpoint>() -> bool {
        E::API_KEY
    }

    /// An api key can upload, rekey and read its builder's own status, and
    /// nothing else (MONEY.md#accounts-and-wallets): never bind a wallet,
    /// change sign-in or email, retire a bot, start a timeout or make
    /// another key. Every endpoint is listed here with what it allows.
    #[test]
    fn only_upload_rekey_and_status_take_an_api_key() {
        assert!(takes_key::<BundlesUpload>());
        assert!(takes_key::<BuilderStatusGet>());
        assert!(takes_key::<RekeyList>());
        assert!(takes_key::<RekeySubmitPost>());
        let refused = [
            takes_key::<ApiKeysCreate>(),
            takes_key::<ApiKeysList>(),
            takes_key::<ApiKeysRevoke>(),
            takes_key::<AuthSignoutEverywhere>(),
            takes_key::<AuthConfirmReset>(),
            takes_key::<AuthSendVerification>(),
            takes_key::<AccountFinishRegistration>(),
            takes_key::<WalletBindStart>(),
            takes_key::<WalletBindCancel>(),
            takes_key::<StatementsSubmit>(),
            takes_key::<RetireBySignin>(),
            takes_key::<RetireStopBySignin>(),
            takes_key::<RetireRequest>(),
        ];
        assert!(refused.iter().all(|taken| !taken));
    }
}

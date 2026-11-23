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
/// `account` is the account's statement reference
/// (`botstadia_chain::wallet::statement_ref`), published with it, never its id.
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

/// A request with no proof, with the asking device's own random id (kept in
/// its storage, never a cookie), which its daily limit counts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetireAsk {
    pub bot_id: String,
    pub device: String,
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
    RetireRequest, Post, "/bots/retire/request", Verified, RetireAsk => RetirementState
);

endpoint!(
    /// A retirement started by the account's wallet: its signature alone
    /// names the account, so no sign-in is needed.
    RetireByWallet, Post, "/bots/retire/wallet", Public, RetireSigned => RetirementState
);
endpoint!(
    /// The wallet stops a sign-in's retirement or its own, by signature alone.
    RetireStopByWallet, Post, "/bots/retire/wallet/stop", Public, RetireSigned => RetirementState
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
    /// It's meant as the account's first wallet: refused if there's one, so
    /// a page that didn't know can't start a rebind.
    #[serde(default)]
    pub first: bool,
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

/// Where one of a builder's bots stands (COMPETITION.md#warm-up,
/// BOTS.md#bundles). A warm-up shows its status and nothing more.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BotStage {
    VerifyQueued,
    #[default]
    Verifying,
    /// Never passed its first verification, so it isn't a bot.
    Failed,
    WarmUpQueued,
    WarmUpRunning,
    /// Waiting on BotStadia: nothing for the builder to do.
    Waiting,
    Rated,
    Retired,
}

/// One bot's requests with no proof, as the person judging them reads them
/// (MONEY.md#retiring-a-bot): one entry a bot.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetirementQueued {
    /// The newest request listed: judging it covers the bot's up to it.
    pub id: String,
    pub bot_id: String,
    pub bot_name: String,
    pub arena_id: String,
    pub builder: Option<String>,
    pub builder_email: String,
    /// When the bot's first request's wait ends: no grant before it.
    pub judge_from: u64,
    /// The newest first.
    pub requests: Vec<RetirementRequested>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetirementRequested {
    pub requester: Option<String>,
    pub requester_email: String,
    /// When the asking account was made.
    pub requester_since: String,
    pub started_at: u64,
}

/// Who started a retirement, which decides who may stop it
/// (MONEY.md#retiring-a-bot).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetiredBy {
    Signin,
    Wallet,
    Author,
    Request,
}

impl RetiredBy {
    /// Whether a sign-in or the account's wallet may stop it.
    pub fn account_may_stop(self) -> bool {
        matches!(self, Self::Signin | Self::Wallet)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Retirement {
    pub by: RetiredBy,
    /// Unix ms. A bot in a running week's field also plays out that week.
    pub effective_at: u64,
    /// A request with no proof, once a person granted it.
    pub granted: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountBot {
    pub id: String,
    pub name: String,
    pub arena_id: String,
    pub stage: BotStage,
    /// Of a queued verification or warm-up.
    pub queue_ahead: Option<u64>,
    /// Why it failed verification: told to its builder only.
    pub failure: Option<String>,
    /// The rating's mean and uncertainty, in millionths.
    pub mu: Option<i64>,
    pub sigma: Option<i64>,
    /// One that never has retires at once on sign-in.
    pub played_bettable: bool,
    pub awaiting_rekey: bool,
    pub code_exposed: bool,
    /// In a running week's field until its final's close (unix seconds).
    pub in_week_until: Option<u64>,
    pub retirements: Vec<Retirement>,
    /// The field a statement signed now reaches it at (unix seconds): this
    /// week's while that isn't set yet, else the next.
    pub starts_at: Option<u64>,
    /// It still pays a wallet the account's statement can't re-point
    /// (MONEY.md#stolen-sign-ins, "What a rebind covers").
    pub pays_earlier: Option<String>,
}

/// A statement waiting on its wallet's bind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeldStatement {
    pub number: u64,
    pub address: String,
    /// When the wait ends, unix ms.
    pub effective_at: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountBots {
    pub bots: Vec<AccountBot>,
    pub bot_cap: u64,
    /// The wait before a retirement or a bind takes effect, in seconds.
    pub waiting_period_s: u64,
    /// The address in force; zero isn't earning.
    pub payout_address: String,
    pub held: Option<HeldStatement>,
    /// What reached an address the account signed for, in USDC's millionths,
    /// as indexed.
    pub paid_total: u64,
    /// Shares whose transfer failed, as indexed. Claiming one emits nothing,
    /// so what's still owed is the chain's `builderOwed`.
    pub failed_total: u64,
    pub next_statement: u64,
    /// The earliest field a statement signed now would start from (unix
    /// seconds), where the week's times are set. Each bot has its own.
    pub starts_at: Option<u64>,
    /// The same for one signed by a wallet whose bind is waiting, or held.
    pub starts_after_wait: Option<u64>,
}

/// An account's bets across all its wallets, as indexed. What a claim signs
/// for still reads the chain.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountBets {
    pub pools: Vec<BetPool>,
    /// The newest first.
    pub activity: Vec<BetActivity>,
}

/// One wallet's whole position in one pool.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BetPool {
    /// The session's id, or the week's.
    pub id: String,
    pub week: bool,
    pub wallet: String,
    pub arena_id: Option<String>,
    pub close: u64,
    /// In the week now running, or the last to have run: what "this week's
    /// net" counts.
    pub this_week: bool,
    /// Only one bot is backed: as it stands, every stake comes back.
    pub one_sided: bool,
    pub total: u64,
    pub stakes: Vec<BetStake>,
    pub state: BetState,
    /// What it pays by the contract's rules, claimed or not.
    pub owed: u64,
    pub claimed: Option<u64>,
    /// What a week's claim passes: its bound final's entry, or the scheduled
    /// final's until the binding is indexed (the contract checks its hash).
    pub final_entry: Option<String>,
    /// A session's round (0: the final) and who's in it, for its title.
    pub round: Option<u64>,
    pub against: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BetStake {
    /// The bot's digest, `0x` hex, as the pool has it.
    pub digest: String,
    pub bot_id: Option<String>,
    pub name: Option<String>,
    pub amount: u64,
    /// What the whole position returns if this bot alone finishes first and
    /// betting closed now.
    pub pays_if_first: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BetState {
    Pending,
    Won,
    /// Backed one of several that shared first: the winners split the pool.
    Tied,
    Lost,
    /// Only one bot was backed: refunded in full.
    OneSided,
    /// Nobody backed the winner: refunded less the fee.
    NoWinningBacker,
    Voided,
    Cancelled,
    KeyRevoked,
    PastDeadline,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BetActivity {
    pub kind: String,
    pub wallet: String,
    /// The session or week, for a bet or a claim.
    pub id: Option<String>,
    pub amount: u64,
    pub block: u64,
    pub tx_hash: String,
    /// A bet someone else's money made: an auto-back fill from the deposit,
    /// or a bet made for this wallet. It didn't leave the wallet.
    pub paid_elsewhere: bool,
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
    /// One wallet's raw bet events. For a site built before `/account/bets`:
    /// delete once that one has been live a release.
    WalletBetsGet, Get, "/wallet/bets", Verified, WalletAddress => Vec<serde_json::Value>
);
/// One auto-back of the account's (MONEY.md#standing-orders), as indexed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountOrder {
    /// The wallet it belongs to.
    pub owner: String,
    /// The bot's bundle digest, `sha256-…`, which an order names.
    pub digest: String,
    pub bot_id: Option<String>,
    pub name: Option<String>,
    pub arena_id: Option<String>,
    /// verifying | active | retired, or none for a digest we don't know.
    pub bot_state: Option<String>,
    pub held: bool,
    pub code_exposed: bool,
    /// USDC millionths a session.
    pub amount: u64,
    pub daily_cap: u64,
    /// Sessions it filled today (UTC), as the contract counts.
    pub filled_today: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountOrders {
    pub orders: Vec<AccountOrder>,
    /// What each wallet has set aside, as indexed; the chain is the truth.
    pub balances: Vec<(String, u64)>,
}

endpoint!(
    /// The account's auto-backs across its wallets.
    AccountOrdersGet, Get, "/account/orders", Verified, Empty => AccountOrders
);
endpoint!(
    /// Every notice choice, as the person has it (OPERATIONS.md#notifications).
    NoticeChoicesGet, Get, "/account/notices", Verified, Empty => crate::notices::NoticeChoices
);
endpoint!(
    /// Set one notice choice, answering all of them.
    NoticeChoiceSet, Post, "/account/notices", Verified, crate::notices::NoticeChoice => crate::notices::NoticeChoices
);
endpoint!(
    /// The account's recent notices, as the site lists them.
    NoticesRecentGet, Get, "/account/notices/recent", Verified, Empty => Vec<crate::notices::RecentNotice>
);
endpoint!(
    /// The bots the account follows.
    FollowsGet, Get, "/account/follows", Verified, Empty => Vec<crate::notices::FollowedBot>
);
endpoint!(
    /// Follow or unfollow a bot, answering the list.
    FollowSet, Post, "/follows", Verified, crate::notices::Follow => Vec<crate::notices::FollowedBot>
);
endpoint!(
    /// An emailed notice's opt-out link, confirmed on the page by a press:
    /// its token turns that one choice off and nothing else.
    NoticeOptOutPost, Post, "/notices/opt-out", Public, crate::notices::NoticeOptOut => Empty
);
endpoint!(
    /// The signed-in builder's bots and earning, as the site shows them. An
    /// api key reads `BuilderStatusGet` instead.
    AccountBotsGet, Get, "/account/bots", Verified, Empty => AccountBots
);
endpoint!(
    /// The account's bets across all its wallets, and their activity.
    AccountBetsGet, Get, "/account/bets", Verified, Empty => AccountBets
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
endpoint!(
    /// Retirement requests with no proof, one entry a bot.
    AdminRetirements, Get, "/admin/retirements", Admin, Empty => Vec<RetirementQueued>
);
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
            takes_key::<WalletSetupPost>(),
            takes_key::<WalletBindCancel>(),
            takes_key::<StatementsSubmit>(),
            takes_key::<RetireBySignin>(),
            takes_key::<RetireStopBySignin>(),
            takes_key::<RetireRequest>(),
            takes_key::<AccountBetsGet>(),
            takes_key::<AccountBotsGet>(),
            takes_key::<NoticeChoicesGet>(),
            takes_key::<AccountOrdersGet>(),
            takes_key::<SaferGet>(),
            takes_key::<SaferLimitPost>(),
            takes_key::<SaferBlockPost>(),
            takes_key::<SaferBlockSignPost>(),
            takes_key::<NoticesRecentGet>(),
            takes_key::<NoticeChoiceSet>(),
            takes_key::<FollowsGet>(),
            takes_key::<FollowSet>(),
            takes_key::<NoticeOptOutPost>(),
            takes_key::<GeoGet>(),
            takes_key::<BotCodeExposed>(),
            takes_key::<WalletRebindCancelSigned>(),
            takes_key::<TakeBackNonceGet>(),
            takes_key::<TakeBackPost>(),
            takes_key::<crate::auth::AccountEmailChange>(),
            takes_key::<crate::auth::AccountEmailConfirm>(),
            takes_key::<crate::auth::LinkPeek>(),
            takes_key::<crate::auth::LinkUse>(),
            takes_key::<crate::auth::AuthSendSigninLink>(),
            takes_key::<crate::auth::AuthSigninLink>(),
            takes_key::<RetireStopByWallet>(),
            takes_key::<AdminRetirements>(),
            takes_key::<WalletBetsGet>(),
        ];
        assert!(refused.iter().all(|taken| !taken));
    }
}

// --- safer play (MONEY.md#safer-play) ----------------------------------------

/// One period's limit, in USDC millionths, with any raise waiting.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaferLimit {
    /// day | week | month: rolling 24 hours, 7 days, 31 days.
    pub period: String,
    /// In force now; none is no limit.
    pub amount: Option<u64>,
    /// A raise waiting its cooling-off: what it becomes (none for no limit)
    /// and when, unix ms.
    pub raise: Option<(Option<u64>, u64)>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaferBlock {
    pub id: String,
    /// timeout | exclusion
    pub kind: String,
    pub started_at: u64,
    /// As asked; none for good.
    pub asked_end: Option<u64>,
    /// When it really ends: as asked once the wallet signs, else no later
    /// than the unsigned most. None for good.
    pub ends_at: Option<u64>,
    pub signed: bool,
    /// What the wallet signs to let it run as asked, when that's longer.
    pub to_sign: Option<String>,
}

/// An account's safer play, with what it has spent and its orders' burn in
/// each period, in USDC millionths.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaferPlay {
    pub limits: Vec<SaferLimit>,
    pub block: Option<SaferBlock>,
    /// Bet in each rolling period, as indexed: (day, week, month).
    pub spent: (u64, u64, u64),
    /// Its standing orders' burn for each period: (day, week, month).
    pub burn: (u64, u64, u64),
    /// What a bet or a new order may add in each period now.
    pub room: (Option<u64>, Option<u64>, Option<u64>),
    /// The chain is indexed to this block: a bet the site placed in a later
    /// block isn't counted yet, and the site counts it itself.
    #[serde(default)]
    pub indexed_to: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaferLimitSet {
    pub period: String,
    pub amount: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaferBlockStart {
    /// timeout | exclusion
    pub kind: String,
    /// Its length; none for good (an exclusion only).
    pub days: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaferBlockSign {
    pub id: String,
    pub signer: String,
    pub signature: String,
}

/// What the account's wallet signs to let a block run past the unsigned most:
/// the page composes it itself, so the server never chooses what's signed.
/// `account` is the statement reference.
pub fn block_message(account: &str, id: &str, kind: &str, until_ms: Option<u64>) -> String {
    let until = until_ms.map_or("for good".to_string(), |at| {
        format!("until {}", utc_minute(at))
    });
    format!(
        "BotStadia: no betting for me, {until} ({kind}). It can't be ended early.\naccount: {account}\nblock: {id}"
    )
}

/// A moment as `2026-11-23 01:59 UTC`, the same on every side.
pub fn utc_minute(ms: u64) -> String {
    let (days, rest) = ((ms / 86_400_000) as i64, ms % 86_400_000);
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        rest / 3_600_000,
        rest % 3_600_000 / 60_000
    )
}

#[cfg(test)]
mod block_message_tests {
    use super::*;

    #[test]
    fn moments_word_the_same_everywhere() {
        assert_eq!(utc_minute(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc_minute(1_795_553_918_000), "2026-11-24 20:58 UTC");
        assert_eq!(utc_minute(951_782_400_000), "2000-02-29 00:00 UTC");
        assert!(block_message("0xab", "b1", "exclusion", None).contains("for good (exclusion)"));
    }
}

endpoint!(
    /// The account's limits, any timeout or exclusion, and what it has spent.
    SaferGet, Get, "/account/safer", Verified, Empty => SaferPlay
);
endpoint!(
    /// Set a limit: lower at once, a raise after the cooling-off.
    SaferLimitPost, Post, "/account/safer/limit", Verified, SaferLimitSet => SaferPlay
);
endpoint!(
    /// Start a timeout or an exclusion, at once and for good.
    SaferBlockPost, Post, "/account/safer/block", Verified, SaferBlockStart => SaferPlay
);
endpoint!(
    /// The wallet's signature, letting a block run past the unsigned most.
    SaferBlockSignPost, Post, "/account/safer/block/sign", Verified, SaferBlockSign => SaferPlay
);

// --- eligibility by place (MONEY.md#eligibility) ------------------------------

/// What the request's place allows. A VPN defeats it; it keeps the site from
/// serving places the statement excludes. Never a claim or a withdrawal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Geo {
    /// Adding funds, betting and a non-zero payout statement.
    pub betting: bool,
    pub sign_up: bool,
}

/// Whether a place is on a list of `CC` and `CC-RR` entries.
fn listed(list: &str, country: &str, region: Option<&str>) -> bool {
    list.split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .any(|e| match e.split_once('-') {
            Some((c, r)) => {
                c.eq_ignore_ascii_case(country) && region.is_some_and(|x| x.eq_ignore_ascii_case(r))
            }
            None => e.eq_ignore_ascii_case(country),
        })
}

/// The place's eligibility under the target's lists. Empty lists block
/// nowhere; an unknown country blocks nothing.
pub fn geo(excluded: &str, sanctioned: &str, country: Option<&str>, region: Option<&str>) -> Geo {
    let Some(country) = country.filter(|c| !c.is_empty()) else {
        return Geo {
            betting: true,
            sign_up: true,
        };
    };
    let sanctioned = listed(sanctioned, country, region);
    Geo {
        betting: !sanctioned && !listed(excluded, country, region),
        sign_up: !sanctioned,
    }
}

endpoint!(
    /// What the caller's place allows, for the site's refusals.
    GeoGet, Get, "/geo", Public, Empty => Geo
);

#[cfg(test)]
mod geo_tests {
    use super::*;

    #[test]
    fn places_are_matched_by_country_or_region() {
        let (ex, sa) = ("US,PR", "CU,UA-43,UA-09");
        assert_eq!(
            geo(ex, sa, Some("US"), Some("CA")),
            Geo {
                betting: false,
                sign_up: true
            }
        );
        assert_eq!(
            geo(ex, sa, Some("cu"), None),
            Geo {
                betting: false,
                sign_up: false
            }
        );
        assert_eq!(
            geo(ex, sa, Some("UA"), Some("43")),
            Geo {
                betting: false,
                sign_up: false
            }
        );
        assert_eq!(
            geo(ex, sa, Some("UA"), Some("30")),
            Geo {
                betting: true,
                sign_up: true
            }
        );
        assert_eq!(
            geo(ex, sa, Some("IL"), None),
            Geo {
                betting: true,
                sign_up: true
            }
        );
        assert_eq!(
            geo("", "", Some("US"), None),
            Geo {
                betting: true,
                sign_up: true
            },
            "testnet"
        );
        assert!(geo(ex, sa, None, None).betting);
    }
}

// --- the wallet over a stolen sign-in (MONEY.md#stolen-sign-ins) --------------

/// What the account's current wallet signs to cancel a rebind's wait: it
/// names the account (its statement reference) and the waiting wallet.
pub fn rebind_cancel_message(account: &str, waiting: &str) -> String {
    format!(
        "BotStadia: cancel the wallet waiting to replace this account's wallet.\naccount: {account}\nwaiting: {}",
        waiting.to_lowercase()
    )
}

/// What the account's current wallet signs to take the account back: every
/// sign-in and api key ends, and its email becomes `email`.
pub fn take_back_message(account: &str, nonce: &str, email: &str) -> String {
    format!(
        "BotStadia: take this account back. Every sign-in and api key ends, and its email becomes {}.\naccount: {account}\nnonce: {nonce}",
        email.trim().to_lowercase()
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RebindCancelSigned {
    /// The account's current wallet, which signs.
    pub wallet: String,
    /// The wallet waiting to replace it.
    pub waiting: String,
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TakeBackNonce {
    pub nonce: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TakeBack {
    /// The account's current wallet, which signs.
    pub wallet: String,
    pub nonce: String,
    pub email: String,
    pub password: String,
    pub signature: String,
}

endpoint!(
    /// The current wallet's signature cancels a rebind's wait, with no
    /// sign-in: the signature alone names the account.
    WalletRebindCancelSigned, Post, "/wallet/rebind/cancel-signed", Public, RebindCancelSigned => Empty
);
endpoint!(
    /// A fresh nonce for a take-back's signature.
    TakeBackNonceGet, Post, "/account/take-back/nonce", Public, Empty => TakeBackNonce
);
endpoint!(
    /// The current wallet takes the account back, with no sign-in.
    TakeBackPost, Post, "/account/take-back", Public, TakeBack => Empty
);

// --- a builder marks their own bot code-exposed (TRUST.md#a-leaked-bundlekey-cant-be-taken-back)

/// What the bot's author key or the account's wallet signs to mark it
/// code-exposed: a label only, which can't be undone.
pub fn code_exposed_message(bot_id: &str) -> String {
    format!(
        "BotStadia: mark this bot code-exposed. Its code may have leaked, and this can't be undone.\nbot: {bot_id}"
    )
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeExposedSigned {
    pub bot_id: String,
    /// author | wallet
    pub by: String,
    pub signature: String,
}

endpoint!(
    /// The bot's author key or the account's wallet marks it code-exposed,
    /// with no sign-in.
    BotCodeExposed, Post, "/bots/code-exposed", Public, CodeExposedSigned => Empty
);

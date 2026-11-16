//! Talking to BotStadia: `login`, `key`, `upload`, `status`, `rekey`,
//! `confirm-wallet` and `sign` (BOTS.md#builder-tooling), with their
//! arguments, shared by the CLI and the standalone tool.

use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use botstadia_chain::rpc::{Client, Http};
use botstadia_shared::api::Empty;
use botstadia_shared::platform::*;

use super::{Settings, api, config, program};
use crate::author::AuthorKey;
use crate::proof::{self, Expect};
use crate::seal::{self, Sealed};

#[derive(Debug, clap::Args)]
pub struct LoginArgs {
    /// An api key from the site's API keys page.
    #[arg(long)]
    pub key: String,
    /// The api to talk to (default: botstadia.com's).
    #[arg(long)]
    pub api: Option<String>,
}

pub fn login(args: LoginArgs) -> Result<()> {
    let mut s = Settings::load()?;
    s.api_key = Some(args.key);
    if args.api.is_some() {
        s.api_url = args.api;
    }
    s.save()?;
    let status: BuilderStatus = api::call::<BuilderStatusGet>(&s, &Empty {})?;
    println!("Signed in: {} bot(s) on this account.", status.bots.len());
    Ok(())
}

#[derive(Debug, clap::Subcommand)]
pub enum KeyCommand {
    /// Show the author key's recovery phrase, to write down.
    Phrase,
    /// Restore the author key from its recovery phrase on this machine.
    Restore {
        /// The 24 words (asked for if left out).
        #[arg(long)]
        phrase: Option<String>,
    },
    /// The author key's public address.
    Show,
}

pub fn key(command: KeyCommand) -> Result<()> {
    match command {
        KeyCommand::Phrase => {
            let key = config::author_key()?;
            println!("{}", key.phrase());
            let mut s = Settings::load()?;
            s.phrase_shown = Some(true);
            s.save()
        }
        KeyCommand::Restore { phrase } => {
            let phrase = match phrase {
                Some(p) => p,
                None => config::ask("Recovery phrase: ")?,
            };
            let key = AuthorKey::from_phrase(&phrase)?;
            if let Some(existing) = config::stored_key()?
                && existing.address() != key.address()
            {
                bail!(
                    "this machine already has a different author key ({}); move it aside first",
                    existing.address()
                );
            }
            config::save_key(&key)?;
            println!("Restored author key {}", key.address());
            Ok(())
        }
        KeyCommand::Show => {
            let key = config::stored_key()?
                .ok_or_else(|| anyhow!("no author key on this machine yet"))?;
            println!("{}", key.address());
            Ok(())
        }
    }
}

fn rpc_pair(s: &Settings) -> Result<(Client<Http>, Client<Http>)> {
    let urls = s
        .rpc_urls
        .clone()
        .ok_or_else(|| anyhow!("no RPC providers configured (BOTSTADIA_RPC_URLS)"))?;
    let a = urls
        .first()
        .ok_or_else(|| anyhow!("no RPC providers configured"))?
        .clone();
    let b = urls.get(1).cloned().unwrap_or_else(|| a.clone());
    if urls.len() < 2 && s.target.as_deref() != Some("local") {
        bail!("the BundleKey check needs two RPC providers that agree");
    }
    Ok((Client::new(Http::new(a)), Client::new(Http::new(b))))
}

fn expect(s: &Settings) -> Result<Expect> {
    Ok(Expect {
        chain_id: s
            .chain_id
            .ok_or_else(|| anyhow!("no chain id configured"))?,
        results: s
            .results
            .as_deref()
            .ok_or_else(|| anyhow!("no results contract configured"))?
            .parse()?,
        project: s
            .project
            .clone()
            .ok_or_else(|| anyhow!("no project configured"))?,
    })
}

/// The BundleKey in force, checked against the chain ourselves.
fn bundle_key(s: &Settings) -> Result<proof::Checked> {
    let proofs: Vec<serde_json::Value> = api::call_public::<PublicBootProofs>(s, &Empty {})?;
    let pairs: Vec<(String, String)> = proofs
        .iter()
        .filter_map(|p| {
            Some((
                p["token"].as_str()?.to_string(),
                p["journal"].as_str()?.to_string(),
            ))
        })
        .collect();
    let (a, b) = rpc_pair(s)?;
    let expect = expect(s)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(proof::check_any((&a, &b), &expect, &pairs))
}

fn print_notices(notices: &[String]) {
    for n in notices {
        println!("! {n}");
    }
}

#[derive(Debug, clap::Args)]
pub struct UploadArgs {
    /// The bundle ZIP (`botstadia build` or `botstadia bundle` makes it).
    pub bundle: PathBuf,
    /// The bot's name on BotStadia.
    #[arg(long)]
    pub name: String,
}

pub fn upload(args: UploadArgs) -> Result<()> {
    let mut s = Settings::load()?;
    let zip = std::fs::read(&args.bundle)
        .with_context(|| format!("reading {}", args.bundle.display()))?;
    let manifest = super::bundle::read_manifest(&zip)?;
    let key = config::author_key()?;
    config::offer_phrase(&mut s, &key)?;
    let checked = bundle_key(&s)?;
    let sealed: Sealed = seal::seal_bundle(&zip, &checked.bundle_key, &key.x25519_public())?;
    let receipt: UploadReceipt = api::call::<BundlesUpload>(
        &s,
        &BundleUpload {
            name: args.name,
            arena_id: manifest.arena.clone(),
            payload_schema: manifest.payload_schema_version,
            kind: format!("{:?}", manifest.kind).to_lowercase(),
            digest: sealed.digest.clone(),
            author_address: key.address(),
            author_x25519: format!("0x{}", hex::encode(key.x25519_public())),
            bundle_key_pub: format!("0x{}", hex::encode(checked.bundle_key)),
            instruction: checked.instruction,
            wrapped_bundle_key: Sealed::b64(&sealed.wrapped_bundle_key),
            wrapped_author_key: Sealed::b64(&sealed.wrapped_author_key),
            ciphertext: Sealed::b64(&sealed.ciphertext),
        },
    )?;
    println!(
        "Uploaded {} as bot {}. Verification is queued ({} ahead).",
        sealed.digest, receipt.bot_id, receipt.queue_ahead
    );
    println!("Payout address: {}", receipt.payout_address);
    if !receipt.earning {
        println!(
            "This bot isn't earning: its wins pay you nothing until you opt in on the site (Start earning). \
             Builders in places where betting is barred can't earn the share."
        );
    }
    print_notices(&receipt.notices);
    Ok(())
}

pub fn status() -> Result<()> {
    let s = Settings::load()?;
    let st: BuilderStatus = api::call::<BuilderStatusGet>(&s, &Empty {})?;
    println!(
        "Payout address: {} ({})",
        st.payout_address,
        if st.earning { "earning" } else { "not earning" }
    );
    for b in &st.bots {
        let mut line = format!("{}  {}  {}  {}", b.name, b.arena_id, b.state, b.digest);
        if let Some(w) = &b.warmup {
            line.push_str(&format!("  warm-up: {w}"));
        }
        if let Some(n) = b.queue_ahead {
            line.push_str(&format!("  ({n} ahead)"));
        }
        if b.awaiting_rekey {
            line.push_str(&format!("  awaiting a rekey: run `{} rekey`", program()));
        }
        if let Some(at) = b.retiring_at {
            line.push_str(&format!("  retiring at {at}"));
        }
        println!("{line}");
    }
    print_notices(&st.notices);
    Ok(())
}

/// The author key already on this machine, never a new one: signing and
/// rekeying with a fresh key would prove nothing.
fn existing_key() -> Result<AuthorKey> {
    config::stored_key()?.ok_or_else(|| {
        anyhow!(
            "no author key on this machine: `{} key restore` it from your recovery phrase",
            program()
        )
    })
}

pub fn rekey() -> Result<()> {
    let s = Settings::load()?;
    let key = existing_key()?;
    let needed: Vec<RekeyNeeded> = api::call::<RekeyList>(&s, &Empty {})?;
    if needed.is_empty() {
        println!("Nothing awaits a rekey.");
        return Ok(());
    }
    let checked = bundle_key(&s)?;
    for n in needed {
        let wrapped = seal::from_b64(&n.wrapped_author_key)?;
        let rewrapped = seal::rekey(
            &key.x25519_secret(),
            &n.digest,
            &wrapped,
            &checked.bundle_key,
        )
        .with_context(|| {
            format!(
                "{}: this author key can't open its copy (is it the key you uploaded with?)",
                n.name
            )
        })?;
        api::call::<RekeySubmitPost>(
            &s,
            &RekeySubmit {
                bot_id: n.bot_id.clone(),
                wrapped_bundle_key: Sealed::b64(&rewrapped),
                bundle_key_pub: format!("0x{}", hex::encode(checked.bundle_key)),
                instruction: checked.instruction,
            },
        )?;
        println!(
            "Rekeyed {}: it plays again once an enclave has checked it.",
            n.name
        );
    }
    Ok(())
}

#[derive(Debug, clap::Args)]
pub struct ConfirmWalletArgs {
    /// The wallet address the site is binding.
    pub address: String,
    /// Don't ask before signing (for scripts that already showed the address).
    #[arg(long)]
    pub yes: bool,
}

pub fn confirm_wallet(args: ConfirmWalletArgs) -> Result<()> {
    let s = Settings::load()?;
    let address = args.address.to_lowercase();
    anyhow::ensure!(
        address.len() == 42 && address.starts_with("0x"),
        "a wallet address is 0x and 40 hex digits"
    );
    let st: BuilderStatus = api::call::<BuilderStatusGet>(&s, &Empty {})?;
    let key = existing_key()?;
    println!("Bind wallet {address} to your account at once.");
    println!("Don't go on if you didn't start this on the site yourself.");
    if !args.yes {
        if !config::interactive() {
            bail!("run it interactively, or pass --yes once you've checked the address");
        }
        if !config::ask("Sign? [y/N] ")?.eq_ignore_ascii_case("y") {
            bail!("not signed");
        }
    }
    let signature = key.sign(&confirm_wallet_message(&st.account, &address))?;
    match api::call_public::<WalletConfirmPost>(
        &s,
        &WalletConfirm {
            account: st.account,
            wallet: address,
            signature,
        },
    ) {
        Ok(_) => {
            println!("Done: the wallet binds now.");
            Ok(())
        }
        Err(e) if e.to_string().contains("oldest bot") => bail!(
            "{e}. This machine's author key isn't the one your oldest bot was uploaded with: \
             restore that one with `{} key restore` and try again",
            program()
        ),
        Err(e) => Err(e),
    }
}

#[derive(Debug, clap::Args)]
pub struct SignArgs {
    /// `start` or `stop` the bot's retirement.
    pub action: String,
    /// The bot's id, as the site shows it.
    #[arg(long)]
    pub bot: String,
    /// The request id the site gave for this retirement.
    #[arg(long)]
    pub request: String,
    /// Don't ask before signing (for scripts that already showed the text).
    #[arg(long)]
    pub yes: bool,
}

/// The author key's signature (EIP-191, 0x hex), on stdout, over a request
/// to start or stop a bot's retirement: the signing command
/// (TRUST.md#bundle-encryption). It signs only that message, which names the
/// bot and the request, so its signature can't be replayed or stand for
/// anything else; it never signs text it's handed, which a phisher could
/// word as something else (a wallet bind, say).
pub fn sign(args: SignArgs) -> Result<()> {
    let action = match args.action.as_str() {
        "start" | "stop" => args.action.as_str(),
        other => bail!("`{other}` isn't an action: start or stop"),
    };
    let message = botstadia_shared::platform::retirement_message(action, &args.bot, &args.request);
    let key = existing_key()?;
    // The prompt on stderr: stdout carries only the signature.
    eprintln!("Sign with author key {}:\n\n{message}\n", key.address());
    eprintln!("Don't go on if you didn't start this on the site yourself.");
    if !args.yes {
        if !config::interactive() {
            bail!("run it interactively, or pass --yes once you've checked the text");
        }
        if !config::ask("Sign? [y/N] ")?.eq_ignore_ascii_case("y") {
            bail!("not signed");
        }
    }
    println!("{}", key.sign(&message)?);
    Ok(())
}

#[derive(Debug, clap::Args)]
pub struct BundleArgs {
    /// The bot's program: a component for the `agent` world.
    #[arg(long)]
    pub component: PathBuf,
    #[arg(long)]
    pub arena: String,
    /// The arena's payload schema version.
    #[arg(long)]
    pub schema: u32,
    /// `policy`, `rust` or `c`.
    #[arg(long)]
    pub kind: String,
    /// A model, as `name=path.onnx`, in order; repeat for more.
    #[arg(long = "model", value_name = "NAME=PATH")]
    pub models: Vec<String>,
    /// Makes the same files a new bot (BOTS.md#bundles).
    #[arg(long)]
    pub nonce: Option<String>,
    /// Where to write the ZIP.
    #[arg(long)]
    pub out: PathBuf,
}

/// The deterministic bundle ZIP from a component and any models, as
/// `botstadia bundle` makes it, but with no session host: models aren't
/// preflighted here (an enclave's verification does that on upload).
pub fn bundle(args: BundleArgs) -> Result<()> {
    use botstadia_interface::bundle::{BotKind, Manifest, ModelEntry};
    let kind = match args.kind.as_str() {
        "policy" => BotKind::Policy,
        "rust" => BotKind::Rust,
        "c" => BotKind::C,
        other => bail!("`{other}` isn't a kind: policy, rust or c"),
    };
    let mut manifest = Manifest::new(&args.arena, args.schema, kind);
    manifest.nonce = args.nonce;
    let mut models = Vec::new();
    for spec in &args.models {
        let (name, path) = spec.split_once('=').context("a model is NAME=PATH")?;
        manifest.models.push(ModelEntry {
            name: name.into(),
            path: format!("artifacts/{name}.onnx"),
        });
        models.push(std::fs::read(path).with_context(|| format!("reading {path}"))?);
    }
    let component = std::fs::read(&args.component)
        .with_context(|| format!("reading {}", args.component.display()))?;
    let zip = super::bundle::write(&manifest, &component, &models)?;
    if let Some(parent) = args.out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&args.out, &zip).with_context(|| format!("writing {}", args.out.display()))?;
    println!("{} · {}", args.out.display(), crate::digest(&zip));
    Ok(())
}

//! `botstadia-upload`: BotStadia's standalone upload tool, built entirely
//! from public source (TRUST.md#bundle-encryption). It uploads, rekeys and
//! signs exactly as the CLI does, sharing its config folder, so a builder who
//! would rather check than trust can use it in the CLI's place.

use botstadia_upload::client::{self, commands};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "botstadia-upload",
    version,
    about = "BotStadia's standalone upload tool, built entirely from public source",
    long_about = "BotStadia's standalone upload tool, built entirely from public source.\n\n\
                  It builds bundle ZIPs, encrypts and uploads them, rekeys them and signs with your author key \
                  exactly as the `botstadia` CLI does, checking BotStadia's key against the chain \
                  itself. It shares the CLI's config folder (BOTSTADIA_CONFIG_DIR, else the OS \
                  config folder's `botstadia`), so the same api key and author key work with both."
)]
struct Tool {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Save an api key from the site, for upload, status and rekey.
    Login(commands::LoginArgs),
    /// Wrap a component (and any models) in a deterministic bundle ZIP.
    Bundle(commands::BundleArgs),
    /// Your author key: its recovery phrase, restoring it, its address.
    #[command(subcommand)]
    Key(commands::KeyCommand),
    /// Encrypt and upload a bundle; it becomes a bot once verified.
    Upload(commands::UploadArgs),
    /// Your bots, their verification and warm-up, and account notices.
    Status,
    /// Re-wrap your bundles for a new BotStadia key, if it was ever lost.
    Rekey,
    /// Sign with your oldest bot's key, so a first wallet binds at once.
    ConfirmWallet(commands::ConfirmWalletArgs),
    /// Sign a message with your author key, to prove you own your bots.
    Sign(commands::SignArgs),
}

fn main() {
    client::set_program("botstadia-upload");
    let tool = Tool::parse();
    let result = match tool.command {
        Command::Login(args) => commands::login(args),
        Command::Bundle(args) => commands::bundle(args),
        Command::Key(command) => commands::key(command),
        Command::Upload(args) => commands::upload(args),
        Command::Status => commands::status(),
        Command::Rekey => commands::rekey(),
        Command::ConfirmWallet(args) => commands::confirm_wallet(args),
        Command::Sign(args) => commands::sign(args),
    };
    if let Err(error) = result {
        eprintln!("✗ {error:#}");
        std::process::exit(1);
    }
}

//! The account side (with feature `client`): what the CLI and the standalone
//! upload tool both run to talk to BotStadia (BOTS.md#builder-tooling).
//!
//! - [`config`]: the config folder, [`Settings`], and keeping the author key
//!   there, owner-only, with its skippable recovery phrase
//! - [`api`]: the api client
//! - [`bundle`]: a bundle ZIP's manifest, read without a session host
//! - [`commands`]: `login`, `key`, `upload`, `status`, `rekey`,
//!   `confirm-wallet` and `sign`, with their arguments
//!
//! Both programs keep everything in one config folder in one format, so a
//! builder can switch between them with the same api key and author key.

pub mod api;
pub mod bundle;
pub mod commands;
pub mod config;

use std::sync::OnceLock;

pub use config::Settings;

static PROGRAM: OnceLock<&'static str> = OnceLock::new();

/// Name the running program, for the commands messages tell the builder to
/// run. Set once at startup; the default is `botstadia`, the CLI.
pub fn set_program(name: &'static str) {
    let _ = PROGRAM.set(name);
}

/// The running program's name, as messages show it.
pub fn program() -> &'static str {
    PROGRAM.get().copied().unwrap_or("botstadia")
}

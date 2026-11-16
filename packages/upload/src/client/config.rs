//! Where the account side keeps the author key and the api key, and which
//! target it talks to. The CLI and the standalone tool share one config
//! folder and one file format, so either reads what the other wrote.
//!
//! - The author key is generated on first use and kept in the config folder,
//!   never derived from sign-in (TRUST.md#bundle-encryption). Its recovery
//!   phrase is shown before the first upload, skippably, with a reminder later.
//! - On a machine with no key it offers to restore from the phrase first; a
//!   non-interactive run fails with a message rather than make a key.

use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde::{Deserialize, Serialize};

use super::program;
use crate::author::AuthorKey;

/// Where everything lives: `BOTSTADIA_CONFIG_DIR`, else the OS config folder.
pub fn config_dir() -> Result<PathBuf> {
    if let Ok(dir) = std::env::var("BOTSTADIA_CONFIG_DIR") {
        return Ok(PathBuf::from(dir));
    }
    Ok(dirs::config_dir()
        .ok_or_else(|| anyhow!("no config folder on this machine"))?
        .join("botstadia"))
}

/// What the CLI is pointed at. The default is prod; local work sets
/// `BOTSTADIA_TARGET=local` or `botstadia login --target local`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Settings {
    pub target: Option<String>,
    pub api_url: Option<String>,
    pub api_key: Option<String>,
    /// Two public RPC providers the boot-proof check reads the chain through.
    pub rpc_urls: Option<Vec<String>>,
    pub chain_id: Option<u64>,
    pub results: Option<String>,
    pub project: Option<String>,
    /// Whether the recovery phrase has been shown (or knowingly skipped).
    pub phrase_shown: Option<bool>,
}

impl Settings {
    pub fn load() -> Result<Self> {
        let path = config_dir()?.join("settings.json");
        let mut s: Settings = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("reading {}", path.display()))?,
            Err(_) => Settings::default(),
        };
        // The environment wins, for CI and tests.
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        if let Some(v) = env("BOTSTADIA_TARGET") {
            s.target = Some(v);
        }
        if let Some(v) = env("BOTSTADIA_API_URL") {
            s.api_url = Some(v);
        }
        if let Some(v) = env("BOTSTADIA_API_KEY") {
            s.api_key = Some(v);
        }
        if let Some(v) = env("BOTSTADIA_RPC_URLS") {
            s.rpc_urls = Some(v.split(',').map(str::to_string).collect());
        }
        if let Some(v) = env("BOTSTADIA_CHAIN_ID") {
            s.chain_id = v.parse().ok();
        }
        if let Some(v) = env("BOTSTADIA_RESULTS") {
            s.results = Some(v);
        }
        if let Some(v) = env("BOTSTADIA_PROJECT") {
            s.project = Some(v);
        }
        Ok(s)
    }

    pub fn save(&self) -> Result<()> {
        let dir = config_dir()?;
        std::fs::create_dir_all(&dir)?;
        write_private(
            &dir.join("settings.json"),
            &serde_json::to_vec_pretty(self)?,
        )
    }

    pub fn api_url(&self) -> String {
        self.api_url
            .clone()
            .unwrap_or_else(|| "https://api.botstadia.com".into())
    }

    pub fn api_key(&self) -> Result<String> {
        self.api_key.clone().ok_or_else(|| {
            anyhow!(
                "no api key: make one on the site (API keys) and run `{} login --key <key>`",
                program()
            )
        })
    }
}

/// Write a file only its owner can read, from its first byte: a fresh 0600
/// file beside it, written whole, then renamed over the old one. It never
/// exists with the default mode, even for a moment, and a failure leaves the
/// old file as it was.
#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow!("no file name in {}", path.display()))?;
    // One fixed name, so a crash's leftover is cleared by the next write.
    let temp = path.with_file_name(format!(".{name}.tmp"));
    match std::fs::remove_file(&temp) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).context(format!("clearing {}", temp.display())),
    }
    let written = (|| -> std::io::Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        std::fs::rename(&temp, path)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    written.with_context(|| format!("writing {}", path.display()))
}

/// Windows keeps a user's config folder theirs already.
#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path.display()))
}

fn save_key_in(dir: &Path, key: &AuthorKey) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    write_private(
        &dir.join("author.key"),
        hex::encode(key.secret()).as_bytes(),
    )
}

fn stored_key_in(dir: &Path) -> Result<Option<AuthorKey>> {
    match std::fs::read_to_string(dir.join("author.key")) {
        Ok(text) => {
            let bytes = hex::decode(text.trim()).context("the author key file is damaged")?;
            let secret: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow!("the author key file is damaged"))?;
            Ok(Some(AuthorKey::from_secret(secret)))
        }
        Err(_) => Ok(None),
    }
}

fn author_key_in(dir: &Path, interactive: bool) -> Result<AuthorKey> {
    if let Some(key) = stored_key_in(dir)? {
        return Ok(key);
    }
    if !interactive {
        bail!(
            "this machine has no author key. Run `{} key restore` with your recovery phrase \
             (or interactively, to make a new key) before uploading from a non-interactive run",
            program()
        );
    }
    let answer = ask(
        "No author key on this machine. Do you have a recovery phrase from another machine? [y/N] ",
    )?;
    let key = if answer.eq_ignore_ascii_case("y") {
        AuthorKey::from_phrase(&ask("Recovery phrase: ")?)?
    } else {
        AuthorKey::generate()?
    };
    save_key_in(dir, &key)?;
    Ok(key)
}

pub fn interactive() -> bool {
    std::io::stdin().is_terminal() && std::env::var("BOTSTADIA_NONINTERACTIVE").is_err()
}

pub fn ask(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

pub fn save_key(key: &AuthorKey) -> Result<()> {
    save_key_in(&config_dir()?, key)
}

/// The author key on this machine, if there is one.
pub fn stored_key() -> Result<Option<AuthorKey>> {
    stored_key_in(&config_dir()?)
}

/// The author key, made or restored on first use. On a machine with no key
/// it asks whether to restore first, so one key keeps covering all a
/// builder's bots; a non-interactive run fails rather than make one.
pub fn author_key() -> Result<AuthorKey> {
    author_key_in(&config_dir()?, interactive())
}

/// Before the first upload: show the recovery phrase, skippably, and say what
/// skipping risks. Reminds on later uploads while it's been skipped.
pub fn offer_phrase(settings: &mut Settings, key: &AuthorKey) -> Result<()> {
    if settings.phrase_shown == Some(true) {
        return Ok(());
    }
    eprintln!(
        "Your author key proves you own your bots, and lets you rekey them if BotStadia ever loses its key."
    );
    if !interactive() {
        eprintln!(
            "Reminder: you haven't saved your recovery phrase. Run `{} key phrase` and keep it somewhere safe.",
            program()
        );
        return Ok(());
    }
    let answer = ask("Show its recovery phrase now to write down? [Y/n] ")?;
    if answer.eq_ignore_ascii_case("n") {
        eprintln!(
            "Skipped. Without the phrase, if this machine's key and BotStadia's key were both lost, your bots couldn't be rekeyed; \
             and a thief with this laptop would keep your bots for good. Run `{} key phrase` any time.",
            program()
        );
        return Ok(());
    }
    eprintln!("\n  {}\n", key.phrase());
    settings.phrase_shown = Some(true);
    settings.save()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_config(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "botstadia-upload-test-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[cfg(unix)]
    #[test]
    fn secrets_are_owner_only_from_the_start_even_over_a_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_config("private");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("author.key");
        // An old file anyone could read is replaced, not reused.
        std::fs::write(&path, "old").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        write_private(&path, b"new").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        // Nothing left beside it.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// One test, since the config folder comes from the environment.
    #[test]
    fn a_non_interactive_run_with_no_key_fails_and_a_restored_key_is_kept() {
        let dir = temp_config("key");
        let err = author_key_in(&dir, false).unwrap_err().to_string();
        assert!(err.contains("no author key"), "{err}");
        assert!(stored_key_in(&dir).unwrap().is_none(), "no key was made");
        let key = AuthorKey::from_secret([8; 32]);
        save_key_in(&dir, &key).unwrap();
        assert_eq!(author_key_in(&dir, false).unwrap().address(), key.address());
        let restored = AuthorKey::from_phrase(&key.phrase()).unwrap();
        assert_eq!(restored.address(), key.address());
        // The file format both programs share: the secret, as hex.
        assert_eq!(
            std::fs::read_to_string(dir.join("author.key")).unwrap(),
            hex::encode([8; 32])
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

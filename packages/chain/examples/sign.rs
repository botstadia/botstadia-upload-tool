//! Signs a message as Ethereum's `personal_sign` does (EIP-191) and prints
//! the signature: `sign <message>`. The key (`SEND_KEY`) comes from the
//! environment, never the command line. The testnet's arena publishing
//! signs each digest with its hot admin key this way
//! (`task api:publish-arena-testnet`).

use anyhow::{Context, bail};
use botstadia_chain::sign::Key;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [message] = args.as_slice() else {
        bail!("usage: sign <message>");
    };
    let key = Key::from_hex(&std::env::var("SEND_KEY").context("SEND_KEY")?)?;
    println!("{}", key.sign_message(message.as_bytes())?);
    Ok(())
}

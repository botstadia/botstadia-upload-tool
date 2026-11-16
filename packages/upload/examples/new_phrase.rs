//! A fresh author key's recovery phrase, appended to a file as
//! `<NAME>=<phrase>` and never printed: for a builder account run
//! non-interactively, such as the testnet's house builder.
//! `cargo run -p botstadia-upload --example new_phrase -- <file> <NAME>`

use std::io::Write;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [file, name] = args.as_slice() else {
        anyhow::bail!("usage: new_phrase <file> <NAME>");
    };
    let key = botstadia_upload::author::AuthorKey::generate()?;
    let mut f = std::fs::OpenOptions::new().append(true).open(file)?;
    writeln!(f, "{name}={}", key.phrase())?;
    println!("{name} written to {file}");
    Ok(())
}

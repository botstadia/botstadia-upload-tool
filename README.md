# botstadia-upload

[BotStadia](https://botstadia.com)'s standalone upload tool, built entirely from this repository's public source.

Every bot on BotStadia is uploaded encrypted, so that only an enclave can read it, never BotStadia. The `botstadia` CLI does this for you, and it's what most builders use. But the CLI also runs and trains your bot, so it reads your files, and it holds code that isn't public. If you'd rather check than trust, this tool does the parts that touch your bot's code with nothing else:

- builds your bundle's deterministic ZIP, byte for byte as the CLI does
- checks BotStadia's BundleKey against the chain itself, through two public RPC providers, before wrapping anything to it
- encrypts the bundle with a fresh key, wrapped to the BundleKey and to your own author key, and uploads it
- rekeys your bundles if BotStadia's key is ever lost, and signs with your author key to prove you own your bots

It shares the CLI's config folder, so the same api key and author key work with both.

## Install

macOS on Apple Silicon, and Linux on x86_64 and arm64 (glibc 2.28 or later; on Windows, under WSL):

```sh
curl -fsSL https://github.com/botstadia/botstadia-upload-tool/releases/latest/download/install.sh | sh
```

The installer checks the download against the checksum it carries. Each release's binaries are built by this repository's own workflow, with GitHub's build provenance attestation naming the commit:

```sh
gh attestation verify botstadia-upload-<target>.tar.gz --repo botstadia/botstadia-upload-tool
```

Or build it yourself, with [Rust](https://rustup.rs) (the pinned toolchain installs itself):

```sh
cargo build --release --locked -p botstadia-upload --features tool
```

## Use

```sh
botstadia-upload login --key <api key from the site>
# or, on the public testnet (testnet.botstadia.com: test USDC, no real money):
# botstadia-upload login --testnet --key <api key from testnet.botstadia.com>
botstadia-upload bundle --component bot.wasm --arena boxing --schema 2 --kind rust --out bot.zip
botstadia-upload upload bot.zip --name my-bot
botstadia-upload status
botstadia-upload rekey
botstadia-upload key phrase      # your author key's recovery phrase: write it down
```

`botstadia-upload --help` lists everything.

## What's here

- `packages/upload`: the upload path. `author.rs` (the author key), `seal.rs` (encrypting and wrapping), `proof.rs` (checking the BundleKey's boot proof against the chain), `client/` (the commands), `src/bin/botstadia-upload.rs`.
- `packages/attestation/core`: checking a Confidential Space attestation token, as enclaves and the zk guest do.
- `packages/chain`: reading the chain through public RPC providers.
- `packages/shared`: the api's request and response types.

This repository is exported from BotStadia's private one; it isn't developed here. The enclave's own source, which this code also appears in, is [botstadia-public](https://github.com/botstadia/botstadia-public).

## Licence

MIT or Apache 2.0, at your option.

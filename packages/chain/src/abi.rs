//! Bindings for the contracts, from their ABI as Foundry builds it.
//!
//! `abi/*.json` is copied from `contracts/out` by `task chain:abi`; the
//! `abi_matches_the_contracts` test fails whenever the two differ, and
//! `task test` builds the contracts before cargo runs, so a contract change
//! without its bindings fails the suite.

alloy_sol_types::sol!(
    #[allow(missing_docs, clippy::too_many_arguments)]
    #[sol(all_derives)]
    Results,
    "abi/Results.json"
);

alloy_sol_types::sol!(
    #[allow(missing_docs, clippy::too_many_arguments)]
    #[sol(all_derives)]
    Settlement,
    "abi/Settlement.json"
);

alloy_sol_types::sol!(
    #[allow(missing_docs, clippy::too_many_arguments)]
    #[sol(all_derives)]
    StandingOrders,
    "abi/StandingOrders.json"
);

alloy_sol_types::sol!(
    #[allow(missing_docs, clippy::too_many_arguments)]
    #[sol(all_derives)]
    MockUSDC,
    "abi/MockUSDC.json"
);

#[cfg(test)]
mod tests {
    use std::path::Path;

    /// The committed ABI is the contracts' ABI, whenever `contracts/out`
    /// exists (it does under `task test`, which runs forge first).
    #[test]
    fn abi_matches_the_contracts() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let out = root.join("../../contracts/out");
        if !out.exists() {
            eprintln!("contracts/out isn't built: skipping the drift check");
            return;
        }
        for name in ["Results", "Settlement", "StandingOrders", "MockUSDC"] {
            let artifact: serde_json::Value = serde_json::from_slice(
                &std::fs::read(out.join(format!("{name}.sol/{name}.json"))).unwrap(),
            )
            .unwrap();
            let committed: serde_json::Value = serde_json::from_slice(
                &std::fs::read(root.join(format!("abi/{name}.json"))).unwrap(),
            )
            .unwrap();
            assert_eq!(
                artifact["abi"], committed,
                "abi/{name}.json is stale: run `task chain:abi`"
            );
        }
        let artifact: serde_json::Value = serde_json::from_slice(
            &std::fs::read(out.join("WalletSignatureCheck.sol/WalletSignatureCheck.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            artifact["bytecode"]["object"].as_str().unwrap(),
            crate::wallet::check::BYTECODE.trim(),
            "abi/WalletSignatureCheck.bytecode is stale: run `task chain:abi`"
        );
    }
}

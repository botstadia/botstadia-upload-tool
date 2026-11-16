//! The hourly post's Merkle tree, exactly as `contracts/src/Merkle.sol`
//! builds it: domain-separated leaves, sorted pairs, an odd node moving up
//! unchanged.
//!
//! - leaf  = keccak256(0x00 ‖ keccak256(entry))
//! - inner = keccak256(0x01 ‖ min(a, b) ‖ max(a, b))

use alloy_primitives::{B256, keccak256};

pub fn leaf(entry_hash: B256) -> B256 {
    let mut bytes = [0u8; 33];
    bytes[1..].copy_from_slice(entry_hash.as_slice());
    keccak256(bytes)
}

pub fn node(a: B256, b: B256) -> B256 {
    let (lo, hi) = if a < b { (a, b) } else { (b, a) };
    let mut bytes = [0u8; 65];
    bytes[0] = 1;
    bytes[1..33].copy_from_slice(lo.as_slice());
    bytes[33..].copy_from_slice(hi.as_slice());
    keccak256(bytes)
}

fn up(level: &[B256]) -> Vec<B256> {
    level
        .chunks(2)
        .map(|pair| match pair {
            [a, b] => node(*a, *b),
            [a] => *a,
            _ => unreachable!(),
        })
        .collect()
}

/// The root over these entries, in list order.
pub fn root(entries: &[Vec<u8>]) -> B256 {
    if entries.is_empty() {
        return B256::ZERO;
    }
    let mut level: Vec<B256> = entries.iter().map(|e| leaf(keccak256(e))).collect();
    while level.len() > 1 {
        level = up(&level);
    }
    level[0]
}

/// The proof for entry `index`: its siblings, bottom up, skipping levels
/// where it had none.
pub fn proof(entries: &[Vec<u8>], index: usize) -> Vec<B256> {
    let mut level: Vec<B256> = entries.iter().map(|e| leaf(keccak256(e))).collect();
    let mut at = index;
    let mut out = Vec::new();
    while level.len() > 1 {
        if let Some(sibling) = level.get(at ^ 1) {
            out.push(*sibling);
        }
        level = up(&level);
        at /= 2;
    }
    out
}

pub fn verify(proof: &[B256], root: B256, entry: &[u8]) -> bool {
    let mut h = leaf(keccak256(entry));
    for sibling in proof {
        h = node(h, *sibling);
    }
    h == root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_entry_proves_and_nothing_else_does() {
        for n in 1..12 {
            let entries: Vec<Vec<u8>> = (0..n).map(|i| vec![i as u8; 40]).collect();
            let r = root(&entries);
            for i in 0..n {
                assert!(verify(&proof(&entries, i), r, &entries[i]), "n={n} i={i}");
                assert!(!verify(&proof(&entries, i), r, b"not listed"));
            }
        }
    }

    #[test]
    fn an_inner_node_is_not_an_entry() {
        let entries: Vec<Vec<u8>> = (0..4).map(|i| vec![i as u8]).collect();
        let r = root(&entries);
        assert!(!verify(&[], r, r.as_slice()));
    }
}

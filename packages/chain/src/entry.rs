//! The hourly post's entries (TRUST.md#the-hourly-post).
//!
//! Each is ABI-encoded with a leading kind, exactly as the results contract
//! decodes it. A session's id is the hash of its entry.

use alloy_primitives::{Address, B256, keccak256};
use alloy_sol_types::SolType;
use alloy_sol_types::sol_data::{self, Array, FixedBytes, Int, Uint};

type ArenaEntry = (Uint<8>, FixedBytes<32>, FixedBytes<32>, Uint<32>);
type RatingEntry = (Uint<8>, Uint<32>);
type SessionEntry = (
    Uint<8>,
    FixedBytes<32>,
    Array<FixedBytes<32>>,
    Uint<64>,
    FixedBytes<32>,
    Uint<32>,
);
type FieldTuple = (
    Uint<8>,
    FixedBytes<32>,
    FixedBytes<32>,
    FixedBytes<32>,
    Uint<32>,
    Uint<32>,
    Uint<32>,
    FixedBytes<32>,
    Uint<64>,
    Uint<64>,
    sol_data::Bool,
    Uint<32>,
);
type StandingsEntry = (Uint<8>, Uint<32>);
type Leaf = (
    FixedBytes<32>,
    sol_data::Address,
    Int<64>,
    Int<64>,
    FixedBytes<32>,
);

pub const KIND_ARENA: u8 = 1;
pub const KIND_RATING: u8 = 2;
pub const KIND_SESSION: u8 = 3;
pub const KIND_FIELD: u8 = 4;
pub const KIND_STANDINGS: u8 = 5;

/// A session entry's round for a week's final; league rounds count from 1.
pub const ROUND_FINAL: u32 = 0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// A new arena version's digest with its ladder (arena id and payload
    /// schema version).
    Arena {
        digest: B256,
        ladder_id: B256,
        payload_schema: u32,
    },
    /// A new rating version, from this post.
    Rating { version: u32 },
    /// One session of a week: a league round (from 1) or its final (0).
    Session {
        spec_hash: B256,
        digests: Vec<B256>,
        close: u64,
        week: B256,
        round: u32,
    },
    /// A week's field entry, at its Sunday freeze (COMPETITION.md#the-field).
    Field(FieldEntry),
    /// A new standings version, from this post.
    Standings { version: u32 },
}

/// Everything a week depends on, committed at its freeze.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldEntry {
    pub week: B256,
    pub ladder_id: B256,
    pub arena: B256,
    pub budget_version: u32,
    pub rating_version: u32,
    pub standings_version: u32,
    /// The Merkle root over the field's leaves, in strictly ascending digest
    /// order ([`field_root`]).
    pub field_root: B256,
    /// The week-winner pool's close: the last league round's close.
    pub pool_close: u64,
    /// The final's close.
    pub final_close: u64,
    /// Whether the week has a championship: a final and a week-winner pool
    /// (a field of at least twice the arena's minimum, and any raise).
    pub championship: bool,
    /// How many league rounds the week plays: its league slots, at the rounds
    /// per day in force at the freeze. The final runs only after exactly that
    /// many, or after a round that could hold no session ended the league.
    pub rounds: u32,
}

impl Entry {
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Arena {
                digest,
                ladder_id,
                payload_schema,
            } => ArenaEntry::abi_encode_params(&(KIND_ARENA, *digest, *ladder_id, *payload_schema)),
            Self::Rating { version } => RatingEntry::abi_encode_params(&(KIND_RATING, *version)),
            Self::Session {
                spec_hash,
                digests,
                close,
                week,
                round,
            } => SessionEntry::abi_encode_params(&(
                KIND_SESSION,
                *spec_hash,
                digests.clone(),
                *close,
                *week,
                *round,
            )),
            Self::Field(f) => FieldTuple::abi_encode_params(&(
                KIND_FIELD,
                f.week,
                f.ladder_id,
                f.arena,
                f.budget_version,
                f.rating_version,
                f.standings_version,
                f.field_root,
                f.pool_close,
                f.final_close,
                f.championship,
                f.rounds,
            )),
            Self::Standings { version } => {
                StandingsEntry::abi_encode_params(&(KIND_STANDINGS, *version))
            }
        }
    }

    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(bytes.len() >= 32, "an entry is at least one word");
        anyhow::ensure!(
            bytes[..31].iter().all(|b| *b == 0),
            "an entry's kind is one byte"
        );
        let kind = bytes[31];
        Ok(match kind {
            KIND_ARENA => {
                let (_, digest, ladder_id, payload_schema) = ArenaEntry::abi_decode_params(bytes)?;
                Self::Arena {
                    digest,
                    ladder_id,
                    payload_schema,
                }
            }
            KIND_RATING => {
                let (_, version) = RatingEntry::abi_decode_params(bytes)?;
                Self::Rating { version }
            }
            KIND_SESSION => {
                let (_, spec_hash, digests, close, week, round) =
                    SessionEntry::abi_decode_params(bytes)?;
                Self::Session {
                    spec_hash,
                    digests,
                    close,
                    week,
                    round,
                }
            }
            KIND_FIELD => {
                let (
                    _,
                    week,
                    ladder_id,
                    arena,
                    budget_version,
                    rating_version,
                    standings_version,
                    field_root,
                    pool_close,
                    final_close,
                    championship,
                    rounds,
                ) = FieldTuple::abi_decode_params(bytes)?;
                Self::Field(FieldEntry {
                    week,
                    ladder_id,
                    arena,
                    budget_version,
                    rating_version,
                    standings_version,
                    field_root,
                    pool_close,
                    final_close,
                    championship,
                    rounds,
                })
            }
            KIND_STANDINGS => {
                let (_, version) = StandingsEntry::abi_decode_params(bytes)?;
                Self::Standings { version }
            }
            other => anyhow::bail!("unknown entry kind {other}"),
        })
    }

    /// `keccak256(entry)`: a session's id.
    pub fn id(&self) -> B256 {
        keccak256(self.encode())
    }
}

/// A ladder's id: an arena and its payload schema version
/// (COMPETITION.md#ratings).
pub fn ladder_id(arena_id: &str, payload_schema: u32) -> B256 {
    keccak256(format!("{arena_id}/{payload_schema}"))
}

/// A week's id: its ladder and its open (the Sunday freeze), in unix seconds.
pub fn week_id(ladder_id: B256, open: u64) -> B256 {
    keccak256(<(FixedBytes<32>, Uint<64>)>::abi_encode_params(&(
        ladder_id, open,
    )))
}

/// A pseudonymous account group for one week: unlinkable across weeks, and
/// never naming the account. Each of our own bots is a group of its own, by
/// passing its digest as `member`.
pub fn group_id(week: B256, member: &str) -> B256 {
    let mut bytes = b"botstadia-group".to_vec();
    bytes.extend_from_slice(week.as_slice());
    bytes.extend_from_slice(member.as_bytes());
    keccak256(bytes)
}

/// One bot's leaf in a week's field: its digest, payout address, rating at
/// the freeze (× 1e6) and account group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldLeaf {
    pub digest: B256,
    pub payout: Address,
    pub mu: i64,
    pub sigma: i64,
    pub group: B256,
}

impl FieldLeaf {
    /// `abi.encode(digest, payout, mu, sigma, group)`, as the settlement
    /// contract hashes it.
    pub fn encode(&self) -> Vec<u8> {
        Leaf::abi_encode_params(&(self.digest, self.payout, self.mu, self.sigma, self.group))
    }

    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let (digest, payout, mu, sigma, group) = Leaf::abi_decode_params(bytes)?;
        Ok(Self {
            digest,
            payout,
            mu,
            sigma,
            group,
        })
    }
}

/// The field's root over its leaves (which must be in strictly ascending
/// digest order), with the posts' own Merkle tree.
pub fn field_root(leaves: &[FieldLeaf]) -> anyhow::Result<B256> {
    anyhow::ensure!(!leaves.is_empty(), "an empty field has no entry");
    anyhow::ensure!(
        leaves.windows(2).all(|w| w[0].digest < w[1].digest),
        "a field's leaves are in strictly ascending digest order"
    );
    let encoded: Vec<Vec<u8>> = leaves.iter().map(FieldLeaf::encode).collect();
    Ok(crate::merkle::root(&encoded))
}

/// Leaf `index`'s proof against [`field_root`].
pub fn field_proof(leaves: &[FieldLeaf], index: usize) -> Vec<B256> {
    let encoded: Vec<Vec<u8>> = leaves.iter().map(FieldLeaf::encode).collect();
    crate::merkle::proof(&encoded, index)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(n: u8) -> FieldLeaf {
        FieldLeaf {
            digest: B256::repeat_byte(n),
            payout: Address::repeat_byte(n),
            mu: 25_000_000,
            sigma: -1,
            group: B256::repeat_byte(100 + n),
        }
    }

    #[test]
    fn entries_round_trip() {
        for entry in [
            Entry::Arena {
                digest: B256::repeat_byte(7),
                ladder_id: ladder_id("racing", 1),
                payload_schema: 1,
            },
            Entry::Rating { version: 2 },
            Entry::Session {
                spec_hash: B256::repeat_byte(9),
                digests: vec![B256::repeat_byte(1), B256::repeat_byte(2)],
                close: 1_800_000_000,
                week: B256::repeat_byte(3),
                round: ROUND_FINAL,
            },
            Entry::Field(FieldEntry {
                week: week_id(ladder_id("racing", 1), 1_800_000_000),
                ladder_id: ladder_id("racing", 1),
                arena: B256::repeat_byte(7),
                budget_version: 1,
                rating_version: 1,
                standings_version: 1,
                field_root: B256::repeat_byte(4),
                pool_close: 1_800_400_000,
                final_close: 1_800_450_000,
                championship: true,
                rounds: 5,
            }),
            Entry::Standings { version: 1 },
        ] {
            assert_eq!(Entry::decode(&entry.encode()).unwrap(), entry);
        }
    }

    #[test]
    fn every_leaf_proves_against_the_field_root() {
        let leaves: Vec<FieldLeaf> = (1..=7).map(leaf).collect();
        let root = field_root(&leaves).unwrap();
        for (i, l) in leaves.iter().enumerate() {
            assert!(crate::merkle::verify(
                &field_proof(&leaves, i),
                root,
                &l.encode()
            ));
            assert_eq!(FieldLeaf::decode(&l.encode()).unwrap(), *l);
        }
        let mut backwards = leaves.clone();
        backwards.reverse();
        assert!(field_root(&backwards).is_err());
    }

    #[test]
    fn groups_differ_by_week_and_member() {
        let (a, b) = (B256::repeat_byte(1), B256::repeat_byte(2));
        assert_ne!(group_id(a, "user-1"), group_id(b, "user-1"));
        assert_ne!(group_id(a, "user-1"), group_id(a, "user-2"));
    }
}

//! A result's outcome (TRUST.md#what-the-enclave-signs): a finishing order
//! with ties over the spec's entrants, or a void with a reason code.
//!
//! Encoded as `abi.encode(uint8 kind, uint16 voidReason, uint8[] places)`,
//! where `places[i]` is the spec's entrant i's place (0 is first, ties share
//! a place).

use alloy_sol_types::SolType;
use alloy_sol_types::sol_data::{Array, Uint};

type Encoded = (Uint<8>, Uint<16>, Array<Uint<8>>);
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Order { places: Vec<u8> },
    Void { reason: VoidReason },
}

/// Why a session voided: our system failed, not a bot
/// (MONEY.md#settlement, COMPETITION.md#rules-for-failures).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u16)]
pub enum VoidReason {
    /// The run failed inside the enclave, outside any seat.
    EnclaveFailure = 1,
    /// The arena trapped or errored.
    ArenaTrap = 2,
    /// The session reached the safety limit.
    SafetyLimit = 3,
    /// An entrant couldn't be compiled or instantiated after the anchor.
    EntrantUnavailable = 4,
}

impl VoidReason {
    pub fn code(self) -> u16 {
        self as u16
    }

    pub fn from_code(code: u16) -> Option<Self> {
        Some(match code {
            1 => Self::EnclaveFailure,
            2 => Self::ArenaTrap,
            3 => Self::SafetyLimit,
            4 => Self::EntrantUnavailable,
            _ => return None,
        })
    }
}

impl Outcome {
    /// From the host's finishing order: groups of spec positions, first
    /// place first, ties in one group.
    pub fn from_groups(entrants: usize, groups: &[Vec<usize>]) -> anyhow::Result<Self> {
        let mut places = vec![u8::MAX; entrants];
        let mut place = 0usize;
        for group in groups {
            for &i in group {
                anyhow::ensure!(i < entrants, "entrant {i} out of range");
                places[i] = u8::try_from(place)?;
            }
            place += group.len();
        }
        anyhow::ensure!(
            places.iter().all(|p| *p != u8::MAX),
            "every entrant needs a place"
        );
        Ok(Self::Order { places })
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Order { places } => Encoded::abi_encode_params(&(0u8, 0u16, places.clone())),
            Self::Void { reason } => {
                Encoded::abi_encode_params(&(1u8, reason.code(), Vec::<u8>::new()))
            }
        }
    }

    pub fn decode(bytes: &[u8]) -> anyhow::Result<Self> {
        let (kind, reason, places) = Encoded::abi_decode_params(bytes)?;
        Ok(match kind {
            0 => Self::Order { places },
            1 => Self::Void {
                reason: VoidReason::from_code(reason)
                    .ok_or_else(|| anyhow::anyhow!("unknown void reason {reason}"))?,
            },
            other => anyhow::bail!("unknown outcome kind {other}"),
        })
    }

    /// The entrants who finished first, by spec position.
    pub fn first(&self) -> Vec<usize> {
        match self {
            Self::Order { places } => places
                .iter()
                .enumerate()
                .filter(|(_, p)| **p == 0)
                .map(|(i, _)| i)
                .collect(),
            Self::Void { .. } => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups_become_places_with_ties_sharing() {
        let o = Outcome::from_groups(4, &[vec![2, 0], vec![3], vec![1]]).unwrap();
        assert_eq!(
            o,
            Outcome::Order {
                places: vec![0, 3, 0, 2]
            }
        );
        assert_eq!(o.first(), vec![0, 2]);
        assert_eq!(Outcome::decode(&o.encode()).unwrap(), o);
        let v = Outcome::Void {
            reason: VoidReason::EntrantUnavailable,
        };
        assert_eq!(Outcome::decode(&v.encode()).unwrap(), v);
    }
}

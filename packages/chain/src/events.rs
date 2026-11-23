//! Decoding the contracts' events, for the keeper's index and anyone else's
//! (MONEY.md#chain-and-tooling).

use alloy_primitives::{Address, B256, Log as PrimitiveLog, LogData};
use alloy_sol_types::SolEvent;

use crate::abi::{Results, Settlement, StandingOrders};
use crate::rpc::Log;

/// One decoded event from one of our contracts.
#[derive(Debug, Clone)]
pub enum Event {
    Posted(Results::Posted),
    Cancelled(Results::Cancelled),
    WeekCancelled(Results::WeekCancelled),
    WeekBound(Results::WeekBound),
    Anchored(Results::Anchored),
    ResultAccepted(Results::ResultAccepted),
    RatingAccepted(Results::RatingAccepted),
    SeedBotNamed(Results::SeedBotNamed),
    KeyApproved(Results::KeyApproved),
    KeyRevoked(Results::KeyRevoked),
    ResultsRejected(Results::Rejected),
    Proposed(Results::Proposed),
    Revoked(Results::Revoked),
    Retired(Results::Retired),
    /// A pending timelocked action withdrawn.
    ResultsWithdrawn(Results::Withdrawn),
    OperatorChanged(Results::OperatorChanged),
    PostsClosed(Results::PostsClosed),
    PoolOpened(Settlement::PoolOpened),
    WeekPoolOpened(Settlement::WeekPoolOpened),
    WeekBet(Settlement::WeekBet),
    WeekClaimed(Settlement::WeekClaimed),
    WeekFeeClaimed(Settlement::WeekFeeClaimed),
    Bet(Settlement::Bet),
    Claimed(Settlement::Claimed),
    FeeClaimed(Settlement::FeeClaimed),
    BuilderPaid(Settlement::BuilderPaid),
    StatementRecorded(Settlement::StatementRecorded),
    BettingSwitched(Settlement::BettingSwitched),
    OrderSet(StandingOrders::OrderSet),
    Filled(StandingOrders::Filled),
    Deposited(StandingOrders::Deposited),
    Withdrawn(StandingOrders::Withdrawn),
    /// One of ours, but not an event the index needs.
    Other {
        address: Address,
        topic: B256,
    },
}

/// Where each contract lives, to tell their events apart.
#[derive(Debug, Clone, Copy)]
pub struct Contracts {
    pub results: Address,
    pub settlement: Address,
    pub standing_orders: Address,
}

fn primitive(log: &Log) -> PrimitiveLog {
    PrimitiveLog {
        address: log.address,
        data: LogData::new_unchecked(log.topics.clone(), log.data.clone()),
    }
}

fn try_decode<E: SolEvent>(log: &PrimitiveLog) -> Option<E> {
    E::decode_log(log).ok().map(|decoded| decoded.data)
}

/// The events we decode, per contract: one table, so what's asked of a node
/// ([`topics`]) and what's decoded ([`decode`]) can never differ.
macro_rules! decoded {
    ($($contract:ident { $($ty:ty => $variant:ident),* $(,)? })*) => {
        /// Every topic [`decode`] knows. A log read filtered by these leaves
        /// out what our contracts emit that we never use, which anyone can
        /// make them emit for gas alone (`Skipped`).
        pub fn topics() -> Vec<B256> {
            vec![$($(<$ty>::SIGNATURE_HASH,)*)*]
        }

        /// Decode a log from one of our contracts. `None` for anyone else's.
        pub fn decode(contracts: &Contracts, log: &Log) -> Option<Event> {
            let topic = *log.topics.first()?;
            let p = primitive(log);
            $(if log.address == contracts.$contract {
                $(if topic == <$ty>::SIGNATURE_HASH {
                    return try_decode::<$ty>(&p).map(Event::$variant);
                })*
                return Some(Event::Other {
                    address: log.address,
                    topic,
                });
            })*
            None
        }
    };
}

decoded! {
    results {
        Results::Posted => Posted,
        Results::Cancelled => Cancelled,
        Results::WeekCancelled => WeekCancelled,
        Results::WeekBound => WeekBound,
        Results::Anchored => Anchored,
        Results::ResultAccepted => ResultAccepted,
        Results::RatingAccepted => RatingAccepted,
        Results::SeedBotNamed => SeedBotNamed,
        Results::KeyApproved => KeyApproved,
        Results::KeyRevoked => KeyRevoked,
        Results::Rejected => ResultsRejected,
        Results::Proposed => Proposed,
        Results::Revoked => Revoked,
        Results::Retired => Retired,
        Results::Withdrawn => ResultsWithdrawn,
        Results::OperatorChanged => OperatorChanged,
        Results::PostsClosed => PostsClosed,
    }
    settlement {
        Settlement::PoolOpened => PoolOpened,
        Settlement::WeekPoolOpened => WeekPoolOpened,
        Settlement::WeekBet => WeekBet,
        Settlement::WeekClaimed => WeekClaimed,
        Settlement::WeekFeeClaimed => WeekFeeClaimed,
        Settlement::Bet => Bet,
        Settlement::Claimed => Claimed,
        Settlement::FeeClaimed => FeeClaimed,
        Settlement::BuilderPaid => BuilderPaid,
        Settlement::StatementRecorded => StatementRecorded,
        Settlement::BettingSwitched => BettingSwitched,
    }
    standing_orders {
        StandingOrders::OrderSet => OrderSet,
        StandingOrders::Filled => Filled,
        StandingOrders::Deposited => Deposited,
        StandingOrders::Withdrawn => Withdrawn,
    }
}

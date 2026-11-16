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

/// Decode a log from one of our contracts. `None` for anyone else's.
pub fn decode(contracts: &Contracts, log: &Log) -> Option<Event> {
    let topic = *log.topics.first()?;
    let p = primitive(log);
    macro_rules! pick {
        ($($ty:ty => $variant:ident),* $(,)?) => {
            $(if topic == <$ty>::SIGNATURE_HASH {
                return try_decode::<$ty>(&p).map(Event::$variant);
            })*
        };
    }
    if log.address == contracts.results {
        pick!(
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
            Results::OperatorChanged => OperatorChanged,
            Results::PostsClosed => PostsClosed,
        );
    } else if log.address == contracts.settlement {
        pick!(
            Settlement::PoolOpened => PoolOpened,
            Settlement::WeekPoolOpened => WeekPoolOpened,
            Settlement::WeekBet => WeekBet,
            Settlement::WeekClaimed => WeekClaimed,
            Settlement::WeekFeeClaimed => WeekFeeClaimed,
            Settlement::Bet => Bet,
            Settlement::Claimed => Claimed,
            Settlement::FeeClaimed => FeeClaimed,
            Settlement::StatementRecorded => StatementRecorded,
            Settlement::BettingSwitched => BettingSwitched,
        );
    } else if log.address == contracts.standing_orders {
        pick!(
            StandingOrders::OrderSet => OrderSet,
            StandingOrders::Filled => Filled,
            StandingOrders::Deposited => Deposited,
            StandingOrders::Withdrawn => Withdrawn,
        );
    } else {
        return None;
    }
    Some(Event::Other {
        address: log.address,
        topic,
    })
}

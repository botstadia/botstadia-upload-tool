//! Which notices are opt-in, and how (OPERATIONS.md#notifications): each
//! kind a notification record can carry belongs to one choice a person turns
//! on or off, or to none, which means it's never optional.

use serde::{Deserialize, Serialize};

/// One thing a person can opt in to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Choice {
    pub key: &'static str,
    /// Its kinds: every record kind it turns on or off.
    pub kinds: &'static [&'static str],
    /// On until turned off. Only "refund available", which says nothing of
    /// who won.
    pub default_on: bool,
}

pub const CHOICES: &[Choice] = &[
    Choice {
        key: "replay",
        kinds: &["replay_ready", "replay_lost"],
        default_on: false,
    },
    Choice {
        key: "refund",
        kinds: &["refund_available"],
        default_on: true,
    },
    Choice {
        key: "low",
        kinds: &["order_running_low"],
        default_on: false,
    },
    Choice {
        key: "followed",
        kinds: &["followed_upcoming"],
        default_on: false,
    },
    Choice {
        key: "weeks",
        kinds: &["week_finalists", "week_champion", "week_no_champion"],
        default_on: false,
    },
    Choice {
        key: "verified",
        kinds: &["bot_verified", "bot_failed_verification"],
        default_on: false,
    },
    Choice {
        key: "warmup",
        kinds: &["warmup_finished"],
        default_on: false,
    },
    Choice {
        key: "waiting",
        kinds: &["waiting_on_us"],
        default_on: false,
    },
    Choice {
        key: "first",
        kinds: &["first_week", "first_session_scheduled"],
        default_on: false,
    },
    Choice {
        key: "final",
        kinds: &["bot_in_final"],
        default_on: false,
    },
    Choice {
        key: "payout",
        kinds: &["payout_received"],
        default_on: false,
    },
];

/// The choice a kind belongs to; none means it always goes, whatever anyone
/// chose (account security and notices that ask someone to act).
pub fn choice_of(kind: &str) -> Option<&'static Choice> {
    CHOICES.iter().find(|c| c.kinds.contains(&kind))
}

pub fn choice(key: &str) -> Option<&'static Choice> {
    CHOICES.iter().find(|c| c.key == key)
}

/// Whether a record of `kind` goes, given the choices a person has set.
pub fn goes(kind: &str, set: impl Fn(&str) -> Option<bool>) -> bool {
    match choice_of(kind) {
        None => true,
        Some(c) => set(c.key).unwrap_or(c.default_on),
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoticeChoice {
    pub key: String,
    pub on: bool,
}

/// Every choice, as the person has it now.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoticeChoices {
    pub choices: Vec<NoticeChoice>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Follow {
    pub bot_id: String,
    pub follow: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FollowedBot {
    pub bot_id: String,
    pub name: String,
    pub arena_id: String,
    /// Retired bots stay followed, so they stay listed.
    pub retired: bool,
}

/// A notice as the site lists it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentNotice {
    pub subject: String,
    pub text: String,
    /// A path on the site.
    pub path: String,
    /// Unix ms.
    pub at: u64,
}

/// An emailed notice's way out of its choice, with no sign-in: what it
/// names is all it can turn off.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoticeOptOut {
    pub token: String,
    pub choice: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kind_has_one_choice_and_only_refunds_go_unasked() {
        let mut seen = std::collections::HashSet::new();
        for c in CHOICES {
            for k in c.kinds {
                assert!(seen.insert(*k), "{k} in two choices");
            }
        }
        assert!(goes("refund_available", |_| None));
        assert!(!goes("replay_ready", |_| None));
        assert!(goes("replay_ready", |k| (k == "replay").then_some(true)));
        assert!(!goes("refund_available", |k| (k == "refund").then_some(false)));
    }

    #[test]
    fn security_and_action_notices_are_never_optional() {
        for kind in [
            "first_bind_started",
            "rebind_started",
            "retirement_started",
            "retirement_granted",
            "unproven_retirement_request",
            "rekey_failed",
        ] {
            assert!(goes(kind, |_| Some(false)), "{kind}");
        }
    }
}

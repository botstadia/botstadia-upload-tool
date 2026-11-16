//! The one error type every api response can carry, and every client call
//! can return.

use serde::{Deserialize, Serialize};

/// Sent as the JSON body of every non-2xx response. `Display` is the
/// user-facing text, so a page can show an error as it is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum ApiError {
    /// 401: no credential, or one that no longer verifies.
    Unauthorized,
    /// 403: not allowed. Also a mutating request whose `Origin` is missing
    /// or not on the api's allow list.
    Forbidden,
    /// 403: signed in, but the handle and the terms are still to come
    /// (`/finish-registration`).
    RegistrationRequired,
    /// 403: signed in, but this needs a confirmed email address.
    VerificationRequired,
    /// 404: no such route, or no such record.
    NotFound,
    /// 422: `message` is for the person and says what to do about it.
    Validation { field: String, message: String },
    /// 429: too many attempts. Try again after `retry_after_secs`.
    TooManyRequests { retry_after_secs: u32 },
    /// 409: the request conflicts with what's there (a duplicate bundle, a
    /// retirement already waiting). `message` says what.
    Conflict { message: String },
    /// 503: this target isn't set up for it yet: the chain, fleet and job
    /// routes on a target whose contracts aren't deployed.
    NotConfigured,
    /// 500: anything unexpected. The details go to the worker log, never to
    /// the client.
    Internal,
    /// Client side only: the request never completed.
    Request { message: String },
    /// Client side only: a non-2xx response that was not a typed error (a
    /// proxy's error page, say).
    HttpStatus { status: u16, body: String },
}

impl ApiError {
    pub fn status_code(&self) -> u16 {
        match self {
            Self::Unauthorized => 401,
            Self::Forbidden | Self::RegistrationRequired | Self::VerificationRequired => 403,
            Self::NotFound => 404,
            Self::Validation { .. } => 422,
            Self::Conflict { .. } => 409,
            Self::NotConfigured => 503,
            Self::TooManyRequests { .. } => 429,
            Self::Internal | Self::Request { .. } => 500,
            Self::HttpStatus { status, .. } => *status,
        }
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::Conflict {
            message: message.into(),
        }
    }

    pub fn validation(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Validation {
            field: field.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthorized => write!(f, "You're signed out. Sign in and try again."),
            Self::Forbidden => write!(f, "That isn't allowed."),
            Self::RegistrationRequired => {
                write!(f, "Pick your handle and accept the terms first.")
            }
            Self::VerificationRequired => write!(f, "Confirm your email address first."),
            Self::NotFound => write!(f, "Not found."),
            Self::Validation { message, .. } => write!(f, "{message}"),
            Self::Conflict { message } => write!(f, "{message}"),
            Self::NotConfigured => write!(f, "That isn't available yet."),
            Self::TooManyRequests { retry_after_secs } => {
                let minutes = retry_after_secs.div_ceil(60);
                if minutes <= 1 {
                    write!(f, "Too many attempts. Try again in a minute.")
                } else {
                    write!(f, "Too many attempts. Try again in {minutes} minutes.")
                }
            }
            Self::Internal => write!(f, "Something went wrong on our side. Try again."),
            Self::Request { .. } => write!(f, "Couldn't reach Botstadia. Check your connection."),
            Self::HttpStatus { status, .. } => {
                write!(f, "Something went wrong (status {status}). Try again.")
            }
        }
    }
}

impl std::error::Error for ApiError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_round_trip_with_a_tag() {
        let err = ApiError::validation("email", "That email address isn't complete.");
        let json = serde_json::to_string(&err).unwrap();
        assert_eq!(
            json,
            r#"{"error":"validation","field":"email","message":"That email address isn't complete."}"#
        );
        assert_eq!(serde_json::from_str::<ApiError>(&json).unwrap(), err);
        let json = serde_json::to_string(&ApiError::Unauthorized).unwrap();
        assert_eq!(json, r#"{"error":"unauthorized"}"#);
    }

    #[test]
    fn statuses() {
        assert_eq!(ApiError::Unauthorized.status_code(), 401);
        assert_eq!(ApiError::RegistrationRequired.status_code(), 403);
        assert_eq!(
            ApiError::TooManyRequests {
                retry_after_secs: 5
            }
            .status_code(),
            429
        );
    }
}

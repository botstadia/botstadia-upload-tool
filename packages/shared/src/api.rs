//! The api's endpoints as types: each is a method, a path, who may call it,
//! and its request and response. The worker routes on these and the site's
//! client calls through them, so the two cannot disagree about any of it.

use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// The header a response carries a fresh session token in. The site keeps it
/// in memory and sends it back as `Authorization: Bearer …`.
pub const HEADER_SESSION_TOKEN_UPDATE: &str = "X-Botstadia-Session-Token";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
        }
    }
}

/// Who may call an endpoint. Ordered: each level includes the ones before.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Access {
    /// Anyone. No credential is even looked at.
    Public,
    /// Signed in, whatever state the account is in: enough to read it and to
    /// finish registering.
    Account,
    /// Signed in with a handle and the current terms accepted.
    Member,
    /// A member whose email address is confirmed.
    Verified,
    /// A verified member with [`crate::auth::Role::Admin`].
    Admin,
    /// An enclave, by a request signed with its SubmitKey over a fresh api
    /// nonce (NOTES: the api design). No account is involved; it is checked
    /// apart from the levels above.
    Machine,
}

/// One endpoint.
pub trait Endpoint {
    const METHOD: Method;
    const PATH: &'static str;
    const ACCESS: Access;
    /// Whether a CLI api key may call it instead of a session. Only upload,
    /// rekey and the builder's own status (MONEY.md#accounts-and-wallets).
    const API_KEY: bool = false;
    /// A GET's request comes from its query string, every field a string.
    type Req: Serialize + DeserializeOwned;
    type Res: Serialize + DeserializeOwned;
}

/// The body of a request or response that carries nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Empty {}

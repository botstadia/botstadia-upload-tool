//! Accounts: who someone is, and every endpoint that signs them in, out and
//! up. Two ways in: an email address with a password, or Google.
//!
//! A new account is "partly registered" until it has a handle and has
//! accepted the terms (the site's `/finish-registration`, the same page
//! whichever way in was used). Its email address is confirmed by a link we
//! send, or by Google vouching for it.

use serde::{Deserialize, Serialize};

use crate::api::{Access, Empty, Endpoint, Method};

/// The version of the terms of use and privacy policy. Raise it when they
/// change, and everyone accepts the new text before they carry on.
pub const TERMS_VERSION: u32 = 1;

pub const MIN_PASSWORD_LENGTH: usize = 8;
pub const USERNAME_MIN_LENGTH: usize = 3;
pub const USERNAME_MAX_LENGTH: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Admin,
}

impl Role {
    pub const ALL: [Role; 1] = [Self::Admin];

    /// As stored in `user_roles.role`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admin => "admin",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|role| role.as_str() == value)
    }
}

/// The signed-in person, as the api tells it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Me {
    pub id: String,
    pub email: String,
    /// The public handle. `None` until registration is finished.
    pub username: Option<String>,
    /// A link we emailed was opened, or Google vouched for the address.
    pub email_verified: bool,
    /// The terms version accepted, if any.
    pub terms_version: Option<u32>,
    /// False for an account made with Google that never set a password.
    pub has_password: bool,
    pub has_google: bool,
    pub roles: Vec<Role>,
}

impl Me {
    /// Has a handle and has accepted the current terms.
    pub fn is_registered(&self) -> bool {
        self.username.is_some() && self.terms_version.is_some_and(|v| v >= TERMS_VERSION)
    }

    pub fn is_admin(&self) -> bool {
        self.roles.contains(&Role::Admin)
    }
}

// ── Requests and responses ──────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailPassword {
    pub email: String,
    pub password: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailOnly {
    pub email: String,
}

/// The one-time token from an emailed link or the Google round trip.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenOnly {
    pub token: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResetPassword {
    pub token: String,
    pub new_password: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GoogleStarted {
    /// Google's consent page, to send the browser to.
    pub url: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthOptions {
    /// "Continue with Google" is set up.
    pub google: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsernameOnly {
    pub username: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsernameCheck {
    /// The rule it breaks, if it breaks one.
    pub problem: Option<String>,
    pub available: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinishRegistration {
    pub username: String,
    /// Must be [`TERMS_VERSION`]: the version the page showed.
    pub accept_terms_version: u32,
    pub opt_in_updates: bool,
}

/// Debug builds only: the last link the api would have emailed. Locally
/// there is no mailbox.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevAuthLink {
    pub to: String,
    pub url: String,
}

// ── Endpoints ───────────────────────────────────────────────────────────

macro_rules! endpoint {
    ($(#[$doc:meta])* $name:ident, $method:ident, $path:literal, $access:ident, $req:ty => $res:ty) => {
        $(#[$doc])*
        pub struct $name;

        impl Endpoint for $name {
            const METHOD: Method = Method::$method;
            const PATH: &'static str = $path;
            const ACCESS: Access = Access::$access;
            type Req = $req;
            type Res = $res;
        }
    };
}

endpoint!(
    /// Who is signed in.
    MeGet, Get, "/me", Account, Empty => Me
);
endpoint!(
    /// Which ways in are switched on.
    AuthOptionsGet, Get, "/auth/options", Public, Empty => AuthOptions
);
endpoint!(
    /// Make an account with an email address and a password, sign in, and
    /// email a confirmation link.
    AuthRegister, Post, "/auth/register", Public, EmailPassword => Me
);
endpoint!(AuthSignin, Post, "/auth/signin", Public, EmailPassword => Me);
endpoint!(
    /// Always answers 200, signed in or not.
    AuthSignout, Post, "/auth/signout", Public, Empty => Empty
);
endpoint!(
    /// Sign out every browser this account is signed in on.
    AuthSignoutEverywhere, Post, "/auth/signout-everywhere", Account, Empty => Empty
);
endpoint!(
    /// Spend the refresh cookie for a fresh session.
    AuthRefresh, Post, "/auth/refresh", Public, Empty => Me
);
endpoint!(
    AuthSendVerification, Post, "/auth/email/send-verification", Account, Empty => Empty
);
endpoint!(
    /// Confirm the address from the emailed link. Signs in too, so a link
    /// opened on another device lands on a usable account.
    AuthConfirmVerification, Post, "/auth/email/verify", Public, TokenOnly => Me
);
endpoint!(
    /// Always answers 200, so it cannot tell anyone which addresses have
    /// accounts.
    AuthSendReset, Post, "/auth/password/send-reset", Public, EmailOnly => Empty
);
endpoint!(
    /// Set a new password from the emailed link. Signs every other browser
    /// out, and this one in.
    AuthConfirmReset, Post, "/auth/password/reset", Public, ResetPassword => Me
);
endpoint!(AuthGoogleStart, Post, "/auth/google/start", Public, Empty => GoogleStarted);
endpoint!(
    /// Trade the token Google's round trip ended with for a session.
    AuthGoogleFinish, Post, "/auth/google/finish", Public, TokenOnly => Me
);

/// A passkey sign-in's nonce. The page signs the hash of a fixed tag and it
/// (`keccak256("BotStadia sign-in\n" ‖ nonce)`), never a challenge we choose.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyNonce {
    pub nonce: String,
}

/// A WebAuthn assertion, base64url fields as the browser returns them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeySignin {
    pub nonce: String,
    pub credential_id: String,
    pub authenticator_data: String,
    pub client_data_json: String,
    pub signature: String,
}

endpoint!(AuthPasskeyNonce, Post, "/auth/passkey/nonce", Public, Empty => PasskeyNonce);
endpoint!(
    /// Sign in with a passkey registered with the account's wallet.
    AuthPasskeySignin, Post, "/auth/passkey/signin", Public, PasskeySignin => Me
);
endpoint!(
    AccountUsernameCheck, Post, "/account/username-check", Account, UsernameOnly => UsernameCheck
);
endpoint!(
    /// Choose the handle and accept the terms.
    AccountFinishRegistration, Post, "/account/finish-registration", Account, FinishRegistration => Me
);
endpoint!(
    /// Debug builds only.
    DevLastAuthLink, Get, "/dev/last-auth-link", Public, Empty => DevAuthLink
);

// --- account security (MONEY.md#stolen-sign-ins) ------------------------------

endpoint!(
    /// Email a sign-in link to the account's verified address. Always
    /// answers 200, so it cannot tell anyone which addresses have accounts.
    AuthSendSigninLink, Post, "/auth/signin-link", Public, EmailOnly => Empty
);
endpoint!(
    /// The emailed link, once and briefly: it signs this browser in.
    AuthSigninLink, Post, "/auth/signin-link/confirm", Public, TokenOnly => Me
);

endpoint!(
    /// Ask to move the account's email: a link goes to the new address, and
    /// nothing changes until it's opened.
    AccountEmailChange, Post, "/account/email", Verified, EmailOnly => Empty
);
endpoint!(
    /// The new address's link: the change happens, and the old address is
    /// told, with a link that undoes it for one waiting period.
    AccountEmailConfirm, Post, "/account/email/confirm", Public, TokenOnly => Empty
);

/// What a notice's one-time link does, before it's used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkInfo {
    /// cancel_bind | stop_retirement | undo_email
    pub action: String,
    pub expires_at: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkDone {
    /// What it did, in plain words.
    pub said: String,
}

endpoint!(
    /// What a link would do. Nothing changes: mail scanners open links.
    LinkPeek, Post, "/links/peek", Public, TokenOnly => LinkInfo
);
endpoint!(
    /// Use a link, once, with no sign-in.
    LinkUse, Post, "/links/use", Public, TokenOnly => LinkDone
);

/// Where Google sends the browser back to. A browser navigation, not a call:
/// the api answers it with a redirect to the site.
pub const PATH_GOOGLE_CALLBACK: &str = "/auth/google/callback";

// ── Rules ───────────────────────────────────────────────────────────────

/// The address, trimmed and lower-cased, or what is wrong with it.
pub fn normalize_email(email: &str) -> Result<String, String> {
    let email = email.trim().to_ascii_lowercase();
    let valid = email.len() <= 254
        && !email.contains(char::is_whitespace)
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && !domain.contains('@')
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
        });
    if valid {
        Ok(email)
    } else {
        Err("That email address doesn't look complete.".to_string())
    }
}

pub fn check_password(password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_LENGTH {
        return Err(format!("Use at least {MIN_PASSWORD_LENGTH} characters."));
    }
    if password.len() > 1024 {
        return Err("That password is too long.".to_string());
    }
    Ok(())
}

/// The handle, trimmed, or what is wrong with it. Case is kept as typed;
/// uniqueness ignores it.
pub fn normalize_username(username: &str) -> Result<String, String> {
    let username = username.trim();
    let length = username.chars().count();
    if !(USERNAME_MIN_LENGTH..=USERNAME_MAX_LENGTH).contains(&length) {
        return Err(format!(
            "Use {USERNAME_MIN_LENGTH} to {USERNAME_MAX_LENGTH} characters."
        ));
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err("Use only letters, numbers, hyphens and underscores.".to_string());
    }
    Ok(username.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me() -> Me {
        Me {
            id: "u".into(),
            email: "a@example.com".into(),
            username: Some("ada".into()),
            email_verified: true,
            terms_version: Some(TERMS_VERSION),
            has_password: true,
            has_google: false,
            roles: vec![],
        }
    }

    #[test]
    fn registration_needs_a_handle_and_the_current_terms() {
        assert!(me().is_registered());
        let mut partial = me();
        partial.username = None;
        assert!(!partial.is_registered());
        let mut old_terms = me();
        old_terms.terms_version = Some(TERMS_VERSION - 1);
        assert!(!old_terms.is_registered());
        let mut none = me();
        none.terms_version = None;
        assert!(!none.is_registered());
    }

    #[test]
    fn emails_are_normalized_or_refused() {
        assert_eq!(
            normalize_email("  Ada@Example.COM ").unwrap(),
            "ada@example.com"
        );
        for bad in [
            "",
            "ada",
            "ada@",
            "@example.com",
            "ada@example",
            "a b@c.d",
            "a@.com",
            "a@b.com.",
        ] {
            assert!(normalize_email(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn handles() {
        assert_eq!(normalize_username(" Robo_Ada-1 ").unwrap(), "Robo_Ada-1");
        assert!(normalize_username("ab").is_err());
        assert!(normalize_username(&"a".repeat(33)).is_err());
        assert!(normalize_username("no spaces").is_err());
        assert!(normalize_username("dots.no").is_err());
    }

    #[test]
    fn passwords() {
        assert!(check_password("1234567").is_err());
        assert!(check_password("12345678").is_ok());
        assert!(check_password(&"x".repeat(2000)).is_err());
    }

    #[test]
    fn roles_round_trip() {
        for role in Role::ALL {
            assert_eq!(Role::parse(role.as_str()), Some(role));
        }
        assert_eq!(Role::parse("nope"), None);
    }
}

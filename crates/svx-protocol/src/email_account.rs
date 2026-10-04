//! Email + password accounts: the service is its own sign-in provider
//! ([`EMAIL_ISSUER`]) for people who don't use Google.
//!
//! Proving the email address is what matters (the directory sends files
//! to whoever owns `bob@…`), so every step that binds keys to an account
//! needs a fresh six-digit code sent to that address, plus the password
//! for an existing account. After sign-up, requests are signed with the
//! device key exactly as for Google accounts.

use serde::{Deserialize, Serialize};

use crate::encoding::{hex_array, hex_vec};

/// The `issuer` of email accounts in account records and configs.
pub const EMAIL_ISSUER: &str = "svx:email";
/// What the app shows for the provider.
pub const EMAIL_PROVIDER_NAME: &str = "Email";

pub const MIN_PASSWORD_LEN: usize = 12;
pub const MAX_PASSWORD_LEN: usize = 128;
/// The lowest acceptable zxcvbn score (0–4): "safely unguessable".
pub const MIN_PASSWORD_SCORE: u8 = 3;
pub const MAX_NAME_LEN: usize = 64;
/// Digits in an emailed code.
pub const CODE_LEN: usize = 6;

/// What an emailed code is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodePurpose {
    /// Create a new account.
    SignUp,
    /// Register this device's keys (new computer, or a key reset).
    SignIn,
    /// Choose a new password.
    ResetPassword,
}

impl CodePurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            CodePurpose::SignUp => "sign_up",
            CodePurpose::SignIn => "sign_in",
            CodePurpose::ResetPassword => "reset_password",
        }
    }
}

/// `POST /v1/auth/email/code`. The answer is the same whether or not an
/// account exists, so it can't be used to find out who has one.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailCodeRequest {
    pub email: String,
    pub purpose: CodePurpose,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailCodeResponse {
    /// Names this code in the next request.
    #[serde(with = "hex_array")]
    pub challenge: [u8; 16],
    pub expires_at: i64,
}

/// What to do with this device's keys.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyMode {
    /// Keys made on this device or restored from the backup.
    #[default]
    Keep,
    /// Replace the account's keys (lost device without a backup).
    Reset,
}

/// `POST /v1/accounts/email`: create an account (code purpose `sign_up`),
/// or register this device's keys for one (`sign_in`, needs the password).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmailAccountRequest {
    #[serde(with = "hex_array")]
    pub challenge: [u8; 16],
    pub code: String,
    pub email: String,
    pub password: String,
    /// Only for a new account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    /// Max (Ed25519 + ML-DSA-87 + SLH-DSA) signing key.
    #[serde(with = "hex_vec")]
    pub signing_public: Vec<u8>,
    /// MLKEM1024-P384 encryption key.
    #[serde(with = "hex_vec")]
    pub kem_public: Vec<u8>,
    #[serde(default)]
    pub keys: KeyMode,
}

/// `POST /v1/auth/email/reset`: forgot password. The device keys are not
/// touched; a new computer still needs the backup (or a key reset).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordResetRequest {
    #[serde(with = "hex_array")]
    pub challenge: [u8; 16],
    pub code: String,
    pub email: String,
    pub new_password: String,
}

/// `POST /v1/me/password`, signed with the device key.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
}

/// The result of [`password_strength`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordStrength {
    /// zxcvbn's score, 0 (very guessable) to 4.
    pub score: u8,
    /// Whether the service will accept it.
    pub ok: bool,
    /// Why not, or how to make it stronger (may be empty).
    pub feedback: Vec<String>,
}

/// Check a new password: [`MIN_PASSWORD_LEN`]–[`MAX_PASSWORD_LEN`]
/// characters and a zxcvbn score of at least [`MIN_PASSWORD_SCORE`],
/// counting the person's email and names as guessable. The app (for the
/// live meter) and the service (which enforces it) use this same check.
pub fn password_strength(password: &str, user_inputs: &[&str]) -> PasswordStrength {
    let len = password.chars().count();
    let mut feedback = Vec::new();
    if len > MAX_PASSWORD_LEN {
        return PasswordStrength {
            score: 0,
            ok: false,
            feedback: vec![format!("Use at most {MAX_PASSWORD_LEN} characters.")],
        };
    }
    // Email parts count as guessable too ("alice", "example").
    let mut owned: Vec<String> = Vec::new();
    for i in user_inputs {
        let i = i.trim().to_lowercase();
        if i.is_empty() {
            continue;
        }
        owned.extend(
            i.split(['@', '.', '-', '_', '+', ' '])
                .filter(|p| p.chars().count() >= 3)
                .map(str::to_owned),
        );
        owned.push(i);
    }
    let inputs: Vec<&str> = owned.iter().map(String::as_str).collect();
    let score = if password.is_empty() {
        0
    } else {
        let e = zxcvbn::zxcvbn(password, &inputs);
        if let Some(f) = e.feedback() {
            if let Some(w) = f.warning() {
                feedback.push(w.to_string());
            }
            feedback.extend(f.suggestions().iter().map(|s| s.to_string()));
        }
        u8::from(e.score())
    };
    // zxcvbn scores "AliceExample2024" well; what's left after taking out
    // the person's own names must still be long enough on its own.
    let mut rest = password.to_lowercase();
    for i in &inputs {
        rest = rest.replace(i, "");
    }
    let personal = rest.chars().filter(|c| c.is_alphanumeric()).count() < MIN_PASSWORD_LEN / 2;
    let score = if personal {
        score.min(MIN_PASSWORD_SCORE - 1)
    } else {
        score
    };
    if len < MIN_PASSWORD_LEN {
        feedback.insert(0, format!("Use at least {MIN_PASSWORD_LEN} characters."));
    } else if personal {
        feedback.insert(0, "Don't build it from your name or email address.".into());
    } else if score < MIN_PASSWORD_SCORE && feedback.is_empty() {
        feedback.push("Add another word or two; uncommon words are best.".into());
    }
    PasswordStrength {
        score,
        ok: len >= MIN_PASSWORD_LEN && score >= MIN_PASSWORD_SCORE,
        feedback,
    }
}

/// A first or last name: 1–64 characters, no control characters and
/// nothing that could pass for an address (`@`, `<`, `>`), so a name can't
/// impersonate someone's email where it is shown next to it.
pub fn valid_name(name: &str) -> bool {
    let n = name.trim();
    !n.is_empty()
        && n.chars().count() <= MAX_NAME_LEN
        && !n
            .chars()
            .any(|c| c.is_control() || matches!(c, '@' | '<' | '>' | '"' | '\\'))
}

/// An emailed code: exactly [`CODE_LEN`] ASCII digits.
pub fn valid_code(code: &str) -> bool {
    code.len() == CODE_LEN && code.bytes().all(|b| b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_passwords_are_refused() {
        for (pw, why) in [
            ("", "empty"),
            ("short1!", "too short"),
            ("Password123!", "common pattern"),
            ("aaaaaaaaaaaaaaaa", "repeats"),
            ("qwertyuiop1234", "keyboard walk"),
            ("alice@example.test", "the email"),
            ("AliceExample2024", "names and a year"),
        ] {
            let s = password_strength(pw, &["alice@example.test", "Alice", "Example"]);
            assert!(!s.ok, "{why}: {pw} scored {}", s.score);
            assert!(!s.feedback.is_empty(), "{why}: no feedback");
        }
        let long = "x".repeat(MAX_PASSWORD_LEN + 1);
        assert!(!password_strength(&long, &[]).ok);
    }

    #[test]
    fn strong_passwords_pass() {
        for pw in [
            "correct horse battery staple",
            "Tangerine-Ocelot-Fjord-42",
            "wq8#Lm2!vZr9@pTx",
        ] {
            let s = password_strength(pw, &["alice@example.test", "Alice", "Example"]);
            assert!(s.ok, "{pw} scored {}: {:?}", s.score, s.feedback);
        }
    }

    #[test]
    fn names_and_codes() {
        assert!(valid_name("Alice"));
        assert!(valid_name("Anne-Marie O'Neil"));
        assert!(valid_name("Zoë"));
        for bad in ["", "   ", "bob@bank.test", "<Bob>", "a\nb", &"x".repeat(65)] {
            assert!(!valid_name(bad), "{bad:?}");
        }
        assert!(valid_code("012345"));
        for bad in ["12345", "1234567", "12a456", "１２３４５６", " 12345"] {
            assert!(!valid_code(bad), "{bad:?}");
        }
    }
}

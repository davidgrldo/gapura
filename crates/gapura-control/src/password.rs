//! Store-mode passwords: how they are kept, and which usernames and passwords are accepted.
//!
//! argon2id with the crate's default parameters (19 MiB of memory, two passes, one lane), the
//! setting OWASP recommends. The stored value is a PHC string, so its parameters travel with it
//! and a later change of defaults still verifies every hash already written.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use std::sync::LazyLock;

/// The PHC string for `password`, with a fresh salt.
pub fn hash(password: &str) -> anyhow::Result<String> {
    // The salt comes from `rand`, which this crate already uses for every other secret it
    // makes, rather than from a second generator argon2 would bring in for this one call.
    let salt = SaltString::encode_b64(&rand::random::<[u8; 16]>())
        .map_err(|e| anyhow::anyhow!("encoding a password salt: {e}"))?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("hashing a password: {e}"))
}

/// Whether `password` is the one `stored` was made from. A stored value that is not a PHC
/// string matches nothing, rather than failing the sign-in some other, more telling way.
pub fn verify(password: &str, stored: &str) -> bool {
    PasswordHash::new(stored).is_ok_and(|parsed| {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
}

/// What an unknown username is verified against, so it costs what a real account costs and
/// timing cannot tell the two apart. Made once, from a password nobody was ever told.
pub static DUMMY: LazyLock<String> = LazyLock::new(|| {
    hash(&format!("{:032x}", rand::random::<u128>())).expect("hashing a 32-character string")
});

/// Letters, digits and `.` `_` `~` `-`: the characters a URL path segment carries unescaped,
/// so a username can sit in a link or a log line exactly as it was typed.
pub fn check_username(username: &str) -> Result<(), String> {
    if username.is_empty() {
        return Err("a username cannot be empty".to_string());
    }
    match username
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '~' | '-')))
    {
        Some(c) => Err(format!(
            "a username may use letters, digits and . _ ~ -, not {c:?}"
        )),
        None => Ok(()),
    }
}

pub const MIN_PASSWORD_CHARS: usize = 12;

/// Long enough, and not the username with something added: the first guess anyone makes.
pub fn check_password(username: &str, password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(format!(
            "a password needs at least {MIN_PASSWORD_CHARS} characters"
        ));
    }
    if !username.is_empty() && password.to_lowercase().contains(&username.to_lowercase()) {
        return Err("a password must not contain the username".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_password_verifies_against_its_own_hash_and_nothing_else() {
        let stored = hash("correct horse battery").unwrap();
        assert!(stored.starts_with("$argon2id$"), "got {stored}");
        assert!(verify("correct horse battery", &stored));
        assert!(!verify("correct horse batterY", &stored));
        assert!(!verify("correct horse battery", "not a hash at all"));
    }

    #[test]
    fn the_same_password_hashes_differently_each_time() {
        assert_ne!(
            hash("correct horse battery").unwrap(),
            hash("correct horse battery").unwrap()
        );
    }

    #[test]
    fn the_dummy_is_a_real_hash_nobody_can_match() {
        assert!(DUMMY.starts_with("$argon2id$"));
        assert!(!verify("", &DUMMY));
    }

    #[test]
    fn usernames_use_letters_digits_and_four_marks() {
        for good in ["maya", "maya.lestari", "ops-breakglass", "a_b~c", "R2D2"] {
            assert_eq!(check_username(good), Ok(()), "{good}");
        }
        for bad in [
            "",
            "maya lestari",
            "maya@example.test",
            "maya/lestari",
            "mäya",
        ] {
            assert!(check_username(bad).is_err(), "{bad:?} was accepted");
        }
    }

    #[test]
    fn passwords_are_twelve_characters_and_do_not_contain_the_username() {
        assert!(check_password("maya", "elevenchars").is_err());
        assert_eq!(check_password("maya", "twelve chars"), Ok(()));
        let error = check_password("maya", "hello-MAYA-2026").unwrap_err();
        assert!(error.contains("username"), "got {error}");
    }
}

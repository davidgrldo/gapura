//! Store-mode passwords: how they are kept, and which usernames and passwords are accepted.
//!
//! argon2id with the crate's default parameters (19 MiB of memory, two passes, one lane), which
//! is OWASP's minimum recommended setting. The stored value is a PHC string, so its parameters
//! travel with it and a later change of defaults still verifies every hash already written.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use std::sync::LazyLock;

/// The PHC string for `password`, with a fresh salt.
pub fn hash(password: &str) -> anyhow::Result<String> {
    // The salt comes from `rand`, which this crate already uses for every other secret it
    // makes. `SaltString::generate` would want a `rand_core` 0.6 generator, which rand 0.9's
    // thread-local one is not, so the bytes are drawn here and only encoded by argon2.
    let salt = SaltString::encode_b64(&rand::random::<[u8; 16]>())
        .map_err(|e| anyhow::anyhow!("encoding a password salt: {e}"))?;
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("hashing a password: {e}"))
}

/// Whether `password` is the one `stored` was made from, using the parameters `stored` carries.
/// A stored value that is not a PHC string matches nothing.
pub fn verify(password: &str, stored: &str) -> bool {
    PasswordHash::new(stored).is_ok_and(|parsed| {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    })
}

/// What an unknown username is verified against, so it costs what a real account costs and
/// timing cannot tell the two apart. Made once, from a password nobody was ever told, and made
/// by `hash` so its cost is exactly what this build writes. Store mode forces it at start-up, so
/// the first unknown name after a restart does not also pay for making it.
pub static DUMMY: LazyLock<String> = LazyLock::new(|| {
    hash(&format!("{:032x}", rand::random::<u128>())).expect("hashing a 32-character string")
});

/// How many password checks may run at once. Each holds 19 MiB for about 20 ms, and the sign-in
/// form answers anyone, so without a bound a burst of attempts would run as many of them as the
/// blocking pool has threads -- 512 by default, gigabytes of memory from an unauthenticated form.
static CHECKING: LazyLock<tokio::sync::Semaphore> = LazyLock::new(|| {
    tokio::sync::Semaphore::new(std::thread::available_parallelism().map_or(2, |n| n.get()))
});

/// Verifies `password` against `stored`, or against `DUMMY` when there is no account, off the
/// async workers and a bounded number at a time.
///
/// Every sign-in goes through here and pays for one verification whether or not the account
/// exists, which is what makes an unknown name and a wrong password cost alike; choosing the
/// dummy inside the blocking task keeps even its first use off the async workers.
pub async fn verify_or_dummy(password: String, stored: Option<String>) -> bool {
    if password.len() > MAX_PASSWORD_BYTES {
        return false;
    }
    let Ok(_permit) = CHECKING.acquire().await else {
        return false;
    };
    tokio::task::spawn_blocking(move || {
        verify(&password, stored.as_deref().unwrap_or(DUMMY.as_str()))
    })
    .await
    .unwrap_or(false)
}

pub const MAX_USERNAME_CHARS: usize = 64;

/// A letter or digit first, then letters, digits and `.` `_` `~` `-`, at most
/// `MAX_USERNAME_CHARS`: the characters a URL path segment carries unescaped, so a username can
/// sit in a link or a log line exactly as it was typed. Starting with a letter or digit rules out
/// `.` and `..`, which a URL resolves away, and names that read as command-line flags.
pub fn check_username(username: &str) -> Result<(), String> {
    let Some(first) = username.chars().next() else {
        return Err("a username cannot be empty".to_string());
    };
    if !first.is_ascii_alphanumeric() {
        return Err("a username must start with a letter or a digit".to_string());
    }
    if username.chars().count() > MAX_USERNAME_CHARS {
        return Err(format!(
            "a username has at most {MAX_USERNAME_CHARS} characters"
        ));
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

/// Twelve characters, the floor this console was given. It is counted in characters, not bytes,
/// so a password in another script is held to the same length as one in ASCII. Passwords are
/// compared exactly as typed, without Unicode normalisation: adding it later would stop every
/// stored non-ASCII password from verifying, so it is a choice to make before accounts exist.
pub const MIN_PASSWORD_CHARS: usize = 12;

/// Far above any password a person types, and low enough that the hashing the sign-in form
/// does for anyone stays bounded by the memory-hard part rather than by reading the input.
pub const MAX_PASSWORD_BYTES: usize = 1024;

/// Long enough, short enough, and not the username with something added: the first guess
/// anyone makes. The containment check skips usernames under three characters, which would
/// otherwise refuse every password sharing a letter with them.
pub fn check_password(username: &str, password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(format!(
            "a password needs at least {MIN_PASSWORD_CHARS} characters"
        ));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(format!("a password has at most {MAX_PASSWORD_BYTES} bytes"));
    }
    if username.chars().count() >= 3 && password.to_lowercase().contains(&username.to_lowercase()) {
        return Err("a password must not contain the username".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parameters every hash this build writes carries. Pinned, so lowering them -- to make
    /// tests faster, or by a crate upgrade changing its defaults -- fails here instead of
    /// quietly weakening new hashes and making the dummy cost less than real ones.
    const PARAMS: &str = "$argon2id$v=19$m=19456,t=2,p=1$";

    #[test]
    fn a_password_verifies_against_its_own_hash_and_nothing_else() {
        let stored = hash("correct horse battery").unwrap();
        assert!(stored.starts_with(PARAMS), "got {stored}");
        assert!(verify("correct horse battery", &stored));
        assert!(!verify("correct horse batterY", &stored));
        assert!(!verify("correct horse battery", "not a hash at all"));
    }

    #[test]
    fn a_hash_made_with_other_parameters_still_verifies() {
        use argon2::{Algorithm, Params, Version};
        let cheap = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(8, 1, 1, None).unwrap(),
        );
        let salt = SaltString::encode_b64(&[7u8; 16]).unwrap();
        let stored = cheap
            .hash_password(b"correct horse battery", &salt)
            .unwrap()
            .to_string();
        assert!(verify("correct horse battery", &stored));
        assert!(!verify("correct horse batterY", &stored));
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
        assert!(DUMMY.starts_with(PARAMS));
        assert!(!verify("", &DUMMY));
    }

    #[tokio::test]
    async fn verify_or_dummy_checks_an_account_and_refuses_without_one() {
        let stored = hash("correct horse battery").unwrap();
        assert!(verify_or_dummy("correct horse battery".into(), Some(stored.clone())).await);
        assert!(!verify_or_dummy("wrong horse battery".into(), Some(stored)).await);
        assert!(!verify_or_dummy("correct horse battery".into(), None).await);
        assert!(!verify_or_dummy("x".repeat(MAX_PASSWORD_BYTES + 1), None).await);
    }

    #[test]
    fn usernames_start_with_a_letter_or_digit_and_use_four_marks() {
        for good in [
            "maya",
            "maya.lestari",
            "ops-breakglass",
            "a_b~c",
            "R2D2",
            "7eleven",
        ] {
            assert_eq!(check_username(good), Ok(()), "{good}");
        }
        let longest = "a".repeat(MAX_USERNAME_CHARS);
        assert_eq!(check_username(&longest), Ok(()));
        for bad in [
            "",
            ".",
            "..",
            "-x",
            "~maya",
            "maya lestari",
            "maya@example.test",
            "maya/lestari",
            "mäya",
        ] {
            assert!(check_username(bad).is_err(), "{bad:?} was accepted");
        }
        assert!(check_username(&format!("{longest}a")).is_err());
    }

    #[test]
    fn passwords_are_twelve_characters_to_a_kilobyte_and_do_not_contain_the_username() {
        assert!(check_password("maya", "elevenchars").is_err());
        assert_eq!(check_password("maya", "twelve chars"), Ok(()));
        // Characters, not bytes: eleven é are 22 bytes and still too short.
        assert!(check_password("maya", &"é".repeat(11)).is_err());
        assert_eq!(check_password("maya", &"é".repeat(12)), Ok(()));
        assert!(check_password("maya", &"x".repeat(MAX_PASSWORD_BYTES + 1)).is_err());
        let error = check_password("maya", "hello-MAYA-2026").unwrap_err();
        assert!(error.contains("username"), "got {error}");
        // A two-letter username is not checked for, or "ab" would refuse half of all passwords.
        assert_eq!(check_password("ab", "absolutely fine pass"), Ok(()));
    }
}

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

/// How many password checks, and hashes, may run at once. Each holds 19 MiB for about 20 ms, and the sign-in
/// form answers anyone, so without a bound a burst of attempts would run as many of them as the
/// blocking pool has threads -- 512 by default, gigabytes of memory from an unauthenticated form.
///
/// A fixed number, not the core count. In a pod with a memory limit and no CPU limit -- the chart's
/// default, 128Mi -- `available_parallelism` is the node's core count, so on a node with seven or
/// more cores seven anonymous sign-ins at once exceed the limit and the pod is OOM-killed, over and
/// over. Two checks at a time is 38 MiB, and still two sign-ins every 20 ms, far more than people
/// signing in ever need; an attacker gets a queue instead of a restart.
const MAX_CONCURRENT_CHECKS: usize = 2;

// 19 MiB per check (m=19456 KiB); the chart limits the console to 128 MiB, which also has to hold
// the process itself, so concurrent checks get at most half. Raising the cap past that, or the
// memory cost per check, fails the build here rather than OOM-killing a pod in production.
const _: () = assert!(MAX_CONCURRENT_CHECKS * 19 <= 128 / 2);

/// How many password checks may wait for one of the `MAX_CONCURRENT_CHECKS` places. Past it, a
/// check is refused at once with `Busy` instead of joining the queue.
///
/// The sign-in throttle holds any one address to ten attempts in flight, but many addresses
/// together could still queue thousands, and a FIFO queue that long puts every real sign-in,
/// the break-glass superuser's included, minutes behind them (#157). Sixteen is eight rounds of
/// two checks, a fraction of a second of waiting; beyond that the honest answer is "busy, try
/// again", which a person can act on and a queue of minutes is not.
const MAX_WAITING_CHECKS: usize = 16;

/// Every password check, and every hash, goes through these.
static CHECKING: LazyLock<Checks> =
    LazyLock::new(|| Checks::new(MAX_CONCURRENT_CHECKS, MAX_WAITING_CHECKS));

/// A check refused because `MAX_WAITING_CHECKS` were already waiting. It says nothing about the
/// password, and is decided before any account's hash is looked at, so it reads the same for a
/// name that has an account and one that does not.
#[derive(Debug, PartialEq, Eq)]
pub struct Busy;

/// The places to run a check in, and a bound on how many may wait for one.
struct Checks {
    permits: tokio::sync::Semaphore,
    waiting: std::sync::atomic::AtomicUsize,
    max_waiting: usize,
}

impl Checks {
    fn new(concurrent: usize, max_waiting: usize) -> Self {
        Self {
            permits: tokio::sync::Semaphore::new(concurrent),
            waiting: std::sync::atomic::AtomicUsize::new(0),
            max_waiting,
        }
    }

    /// A place to run one check in: now, after a short wait, or `Busy` when the queue is full.
    async fn enter(&self) -> Result<tokio::sync::SemaphorePermit<'_>, Busy> {
        use std::sync::atomic::Ordering;
        if let Ok(permit) = self.permits.try_acquire() {
            return Ok(permit);
        }
        if self.waiting.fetch_add(1, Ordering::SeqCst) >= self.max_waiting {
            self.waiting.fetch_sub(1, Ordering::SeqCst);
            return Err(Busy);
        }
        // Uncounted however the wait ends, a request whose client hung up included.
        struct Waiting<'a>(&'a std::sync::atomic::AtomicUsize);
        impl Drop for Waiting<'_> {
            fn drop(&mut self) {
                self.0.fetch_sub(1, Ordering::SeqCst);
            }
        }
        let _waiting = Waiting(&self.waiting);
        self.permits.acquire().await.map_err(|_| Busy)
    }
}

/// Verifies `password` against `stored`, or against `DUMMY` when there is no account, off the
/// async workers and a bounded number at a time; `Busy` when too many are already waiting.
///
/// Every sign-in goes through here and pays for one verification whether or not the account
/// exists, which is what makes an unknown name and a wrong password cost alike; choosing the
/// dummy inside the blocking task keeps even its first use off the async workers.
pub async fn verify_or_dummy(password: String, stored: Option<String>) -> Result<bool, Busy> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Ok(false);
    }
    let permit = CHECKING.enter().await?;
    Ok(tokio::task::spawn_blocking(move || {
        // The permit travels with the work. Held by the request instead, it would be returned
        // the moment a client hung up mid-check, while the hashing it was counting carried on.
        let _permit = permit;
        verify(&password, stored.as_deref().unwrap_or(DUMMY.as_str()))
    })
    .await
    .unwrap_or(false))
}

/// The PHC string for `password`, made as `verify_or_dummy` checks one: off the async workers,
/// under the same bound, and queued the same way, so `Busy` at once when too many are already
/// waiting. A hash costs what a check costs, and every hash this console makes goes through here:
/// a sign-up, which anyone can reach, and an account's own password change and a superuser's
/// create and reset. Waiting for a place however long the queue was let a flood of those add to
/// the memory the bound was set for and put real sign-ins behind it.
pub async fn hash_or_busy(password: String) -> Result<anyhow::Result<String>, Busy> {
    hash_in(&CHECKING, password).await
}

async fn hash_in(
    checks: &'static Checks,
    password: String,
) -> Result<anyhow::Result<String>, Busy> {
    let permit = checks.enter().await?;
    Ok(tokio::task::spawn_blocking(move || {
        // Held by the work, as in `verify_or_dummy`.
        let _permit = permit;
        hash(&password)
    })
    .await
    .map_err(anyhow::Error::from)
    .and_then(|hashed| hashed))
}

/// Long enough for any name a person or a team uses, and well inside what a unique index on
/// the column can hold.
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

/// Long enough, short enough, typeable, and not the username with something added: the first
/// guess anyone makes. The containment check skips usernames under three characters, which
/// would otherwise refuse every password sharing a letter with them.
pub fn check_password(username: &str, password: &str) -> Result<(), String> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(format!(
            "a password needs at least {MIN_PASSWORD_CHARS} characters"
        ));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(format!("a password has at most {MAX_PASSWORD_BYTES} bytes"));
    }
    // A sign-in form's password field cannot hold a line break, so a password with one could
    // never be typed back. The usual way to get one is a Secret made with `echo`, which adds a
    // newline the operator never sees.
    if password.chars().any(char::is_control) {
        return Err(
            "a password must not contain a line break or other control character; a value \
             written with `echo` ends in one"
                .to_string(),
        );
    }
    if username.chars().count() >= 3 && password.to_lowercase().contains(&username.to_lowercase()) {
        return Err("a password must not contain the username".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn a_hash_behind_a_full_queue_is_busy_rather_than_waiting() {
        let checks: &'static Checks = Box::leak(Box::new(Checks::new(1, 0)));
        let running = checks.enter().await.unwrap();
        assert_eq!(
            hash_in(checks, "correct horse battery".into()).await.err(),
            Some(Busy),
            "no place and no room to wait: refused at once"
        );
        drop(running);
        let stored = hash_in(checks, "correct horse battery".into())
            .await
            .expect("a place")
            .unwrap();
        assert!(verify("correct horse battery", &stored));
    }

    #[test]
    fn the_check_semaphore_has_the_fixed_size() {
        assert_eq!(CHECKING.permits.available_permits(), MAX_CONCURRENT_CHECKS);
    }

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
        assert_eq!(
            verify_or_dummy("correct horse battery".into(), Some(stored.clone())).await,
            Ok(true)
        );
        assert_eq!(
            verify_or_dummy("wrong horse battery".into(), Some(stored)).await,
            Ok(false)
        );
        assert_eq!(
            verify_or_dummy("correct horse battery".into(), None).await,
            Ok(false)
        );
        // Refused for its length alone: the hash below would match it without the cap.
        let long = "x".repeat(MAX_PASSWORD_BYTES + 1);
        let long_hash = hash(&long).unwrap();
        assert_eq!(verify_or_dummy(long, Some(long_hash)).await, Ok(false));
    }

    #[tokio::test]
    async fn a_full_queue_answers_busy_at_once_instead_of_queueing() {
        // #157: the queue in front of the checks used to be unbounded and first come, first
        // served, so a burst put every real sign-in behind it. Its own instance, so the shared
        // one the other tests use is never held here.
        let checks = Checks::new(1, 2);
        let running = checks.enter().await.unwrap();
        let waiters = [checks.enter(), checks.enter()];
        let mut waiters = waiters.map(Box::pin);
        // Polled once each, so both are counted as waiting.
        for waiter in &mut waiters {
            assert!(futures_poll_once(waiter.as_mut()).await.is_none());
        }
        assert_eq!(checks.enter().await.err(), Some(Busy));
        // A waiter that gives up frees its place in the queue.
        let [one, two] = waiters;
        drop(one);
        let mut third = Box::pin(checks.enter());
        assert!(futures_poll_once(third.as_mut()).await.is_none());
        // And the queue moves when a check ends.
        drop(running);
        assert!(two.await.is_ok());
    }

    /// Polls `future` once, answering what it was ready with, if anything.
    async fn futures_poll_once<F: std::future::Future + Unpin>(future: F) -> Option<F::Output> {
        let mut future = future;
        std::future::poll_fn(|cx| {
            std::task::Poll::Ready(match std::pin::Pin::new(&mut future).poll(cx) {
                std::task::Poll::Ready(v) => Some(v),
                std::task::Poll::Pending => None,
            })
        })
        .await
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
        assert!(check_password("maya", "correct horse battery\n").is_err());
        assert!(check_password("maya", "correct\thorse battery").is_err());
        let error = check_password("maya", "hello-MAYA-2026").unwrap_err();
        assert!(error.contains("username"), "got {error}");
        // A two-letter username is not checked for, or "ab" would refuse half of all passwords.
        assert_eq!(check_password("ab", "absolutely fine pass"), Ok(()));
    }
}

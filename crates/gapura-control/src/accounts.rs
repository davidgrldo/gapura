//! Accounts: who may change them, the rules a change must keep, and the temporary passwords a
//! superuser hands out. Pure; the store applies these over rows it has locked.

use crate::access::{Method, User};
use crate::configuration::FieldError;
use crate::grants::Refusal;
use serde::Deserialize;

/// Twenty characters from an alphabet with no look-alikes (`0 O 1 l I`): about 116 bits, typed
/// once from a message and then replaced.
pub const TEMPORARY_ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
pub const TEMPORARY_LEN: usize = 20;

/// A temporary password for `username` that meets `password::check_password`, as every password
/// must (drawn again in the rare case it contains the username).
pub fn temporary_password(username: &str) -> String {
    loop {
        let candidate: String = (0..TEMPORARY_LEN)
            .map(|_| TEMPORARY_ALPHABET[rand::random_range(0..TEMPORARY_ALPHABET.len())] as char)
            .collect();
        if crate::password::check_password(username, &candidate).is_ok() {
            return candidate;
        }
    }
}

/// What a superuser sends to create an account.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewAccount {
    pub username: String,
    #[serde(default)]
    pub superuser: bool,
}

/// What someone sends to change their own password.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordChange {
    pub current: String,
    pub new: String,
}

/// By hand, so a `{:?}` in a log line or a panic never prints either password.
impl std::fmt::Debug for PasswordChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasswordChange")
            .field("current", &"[redacted]")
            .field("new", &"[redacted]")
            .finish()
    }
}

/// The field a wrong current password is refused on. The handler counts a refusal on it as a
/// failed sign-in, which no other refusal of a password change is.
pub const CURRENT: &str = "current";

/// The refusal of a current password that is not the account's.
pub fn wrong_current() -> FieldError {
    FieldError {
        field: CURRENT.into(),
        sentence: "That is not your current password.".into(),
    }
}

/// `password.rs` words its refusals as fragments ("a username cannot be empty"); the API answers
/// in sentences.
pub(crate) fn sentence(fragment: String) -> String {
    let mut s = fragment;
    if let Some(first) = s.get(..1) {
        let upper = first.to_uppercase();
        s.replace_range(..1, &upper);
    }
    s.push('.');
    s
}

/// The username a new account is created with, or why it cannot be.
pub fn username(input: &NewAccount) -> Result<String, FieldError> {
    crate::password::check_username(&input.username)
        .map(|()| input.username.clone())
        .map_err(|f| FieldError {
            field: "username".into(),
            sentence: sentence(f),
        })
}

/// Whether `change.new` may replace the current password of `username`: a password like any
/// other, and not the one it replaces.
pub fn new_password(username: &str, change: &PasswordChange) -> Result<(), FieldError> {
    if change.new == change.current {
        return Err(FieldError {
            field: "new".into(),
            sentence: "Choose a password different from the current one.".into(),
        });
    }
    crate::password::check_password(username, &change.new).map_err(|f| FieldError {
        field: "new".into(),
        sentence: sentence(f),
    })
}

/// Account actions are a superuser's (ADR 5 rule 2).
pub fn may_administer(caller: &User) -> Result<(), Refusal> {
    if caller.superuser && !caller.disabled {
        return Ok(());
    }
    Err(Refusal::Forbidden(
        "Accounts are a superuser's to change.".into(),
    ))
}

/// Whether sign-up is open is a superuser's to change, like the accounts it lets in.
pub fn may_change_settings(caller: &User) -> Result<(), Refusal> {
    if caller.superuser && !caller.disabled {
        return Ok(());
    }
    Err(Refusal::Forbidden(
        "Settings are a superuser's to change.".into(),
    ))
}

/// A change a superuser makes to an account that already exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    Reset,
    Disable,
    Enable,
    Superuser(bool),
    Delete,
}

/// Whether `caller` may make `change` to `target`, given how many enabled superusers there are
/// (counted over rows the store has locked). Refusals are `Conflict` (409), with the reason.
pub fn guard(
    caller: &User,
    target: &User,
    change: &Change,
    enabled_superusers: usize,
) -> Result<(), Refusal> {
    let oidc = target.method != Method::Local;
    match change {
        Change::Reset if oidc => {
            return Err(Refusal::Conflict(format!(
                "{} signs in through the identity provider, so there is no password here to \
                 reset.",
                target.name
            )))
        }
        Change::Delete if oidc => {
            return Err(Refusal::Conflict(format!(
                "{} signs in through the identity provider and would be back at their next \
                 sign-in. Disable the account instead.",
                target.name
            )))
        }
        _ => {}
    }
    let locks_out = matches!(
        change,
        Change::Disable | Change::Delete | Change::Superuser(false)
    );
    if locks_out && caller.id == target.id {
        return Err(Refusal::Conflict(
            "You cannot disable, delete or demote yourself; another superuser can.".into(),
        ));
    }
    if locks_out && target.superuser && !target.disabled && enabled_superusers <= 1 {
        return Err(Refusal::Conflict(format!(
            "{} is the last enabled superuser. Make someone else a superuser first.",
            target.name
        )));
    }
    Ok(())
}

/// Whether a session issued at `issued_at` (Unix milliseconds) still stands for an account whose
/// sessions were cut off at `valid_after`.
pub fn session_current(issued_at: u64, valid_after: Option<i64>) -> bool {
    valid_after.is_none_or(|cut| i128::from(issued_at) >= i128::from(cut))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn user(name: &str, method: Method, superuser: bool) -> User {
        User {
            id: Uuid::new_v4(),
            name: name.into(),
            method,
            superuser,
            disabled: false,
            groups: Vec::new(),
            last_sign_in: None,
            must_change_password: false,
            sessions_valid_after: None,
        }
    }

    fn conflict(result: Result<(), Refusal>) -> String {
        match result {
            Err(Refusal::Conflict(sentence)) => sentence,
            other => panic!("expected a conflict, got {other:?}"),
        }
    }

    #[test]
    fn a_temporary_password_is_twenty_unambiguous_characters_and_a_valid_password() {
        for _ in 0..200 {
            let p = temporary_password("abcdefghij");
            assert_eq!(p.chars().count(), TEMPORARY_LEN);
            assert!(
                p.bytes().all(|b| TEMPORARY_ALPHABET.contains(&b)),
                "{p} has a character outside the alphabet"
            );
            assert!(crate::password::check_password("abcdefghij", &p).is_ok());
        }
        for look_alike in b"0O1lI" {
            assert!(!TEMPORARY_ALPHABET.contains(look_alike));
        }
    }

    #[test]
    fn temporary_passwords_differ() {
        assert_ne!(temporary_password("maya"), temporary_password("maya"));
    }

    #[test]
    fn a_username_is_refused_in_a_sentence_on_its_field() {
        let refused = username(&NewAccount {
            username: "-maya".into(),
            superuser: false,
        })
        .unwrap_err();
        assert_eq!(refused.field, "username");
        assert_eq!(
            refused.sentence,
            "A username must start with a letter or a digit."
        );
        let empty = username(&NewAccount {
            username: String::new(),
            superuser: false,
        })
        .unwrap_err();
        assert_eq!(empty.sentence, "A username cannot be empty.");
    }

    #[test]
    fn a_good_username_is_kept_as_typed() {
        let name = username(&NewAccount {
            username: "Maya.K".into(),
            superuser: true,
        })
        .unwrap();
        assert_eq!(name, "Maya.K");
    }

    #[test]
    fn a_new_password_must_differ_from_the_current_one() {
        let refused = new_password(
            "maya",
            &PasswordChange {
                current: "correct horse battery".into(),
                new: "correct horse battery".into(),
            },
        )
        .unwrap_err();
        assert_eq!(refused.field, "new");
        assert_eq!(
            refused.sentence,
            "Choose a password different from the current one."
        );
    }

    #[test]
    fn a_new_password_is_held_to_the_rules_on_its_field() {
        let short = new_password(
            "maya",
            &PasswordChange {
                current: "correct horse battery".into(),
                new: "short".into(),
            },
        )
        .unwrap_err();
        assert_eq!(short.field, "new");
        assert_eq!(short.sentence, "A password needs at least 12 characters.");
        let named = new_password(
            "maya",
            &PasswordChange {
                current: "correct horse battery".into(),
                new: "MAYA-and-something".into(),
            },
        )
        .unwrap_err();
        assert_eq!(named.field, "new");
        assert!(new_password(
            "maya",
            &PasswordChange {
                current: "correct horse battery".into(),
                new: "staple battery horse".into(),
            },
        )
        .is_ok());
    }

    #[test]
    fn a_password_change_never_shows_its_passwords() {
        let change = PasswordChange {
            current: "correct horse battery".into(),
            new: "staple battery horse".into(),
        };
        for shown in [format!("{change:?}"), format!("{change:#?}")] {
            assert!(!shown.contains("horse"), "{shown}");
            assert!(shown.contains("[redacted]"), "{shown}");
        }
    }

    #[test]
    fn a_wrong_current_password_is_refused_on_its_field() {
        assert_eq!(wrong_current().field, CURRENT);
    }

    #[test]
    fn only_an_enabled_superuser_administers_accounts() {
        let mut caller = user("root", Method::Local, true);
        assert!(may_administer(&caller).is_ok());
        caller.disabled = true;
        assert!(matches!(
            may_administer(&caller),
            Err(Refusal::Forbidden(_))
        ));
        let plain = user("maya", Method::Local, false);
        assert!(matches!(may_administer(&plain), Err(Refusal::Forbidden(_))));
        let oidc = user("Maya", Method::Oidc, true);
        assert!(may_administer(&oidc).is_ok());
    }

    #[test]
    fn nobody_disables_deletes_or_demotes_themselves() {
        let me = user("root", Method::Local, true);
        for change in [Change::Disable, Change::Delete, Change::Superuser(false)] {
            let sentence = conflict(guard(&me, &me, &change, 5));
            assert!(sentence.contains("yourself"), "{change:?}: {sentence}");
        }
        // What does not lock anyone out is theirs to do to themselves.
        for change in [Change::Reset, Change::Enable, Change::Superuser(true)] {
            assert!(guard(&me, &me, &change, 1).is_ok(), "{change:?}");
        }
    }

    #[test]
    fn the_last_enabled_superuser_stays_one() {
        let caller = user("root", Method::Local, true);
        let last = user("maya", Method::Local, true);
        for change in [Change::Disable, Change::Delete, Change::Superuser(false)] {
            let sentence = conflict(guard(&caller, &last, &change, 1));
            assert!(sentence.starts_with("maya is the last enabled superuser"));
        }
        // Changes that keep them a superuser are allowed.
        for change in [Change::Reset, Change::Enable, Change::Superuser(true)] {
            assert!(guard(&caller, &last, &change, 1).is_ok(), "{change:?}");
        }
    }

    #[test]
    fn a_second_superuser_allows_demoting_the_first() {
        let caller = user("root", Method::Local, true);
        let other = user("maya", Method::Local, true);
        for change in [Change::Disable, Change::Delete, Change::Superuser(false)] {
            assert!(guard(&caller, &other, &change, 2).is_ok(), "{change:?}");
        }
    }

    #[test]
    fn a_disabled_superuser_is_not_the_last_one() {
        let caller = user("root", Method::Local, true);
        let mut other = user("maya", Method::Local, true);
        other.disabled = true;
        assert!(guard(&caller, &other, &Change::Delete, 1).is_ok());
        assert!(guard(&caller, &other, &Change::Superuser(false), 1).is_ok());
    }

    #[test]
    fn locking_out_someone_who_is_not_a_superuser_needs_no_count() {
        let caller = user("root", Method::Local, true);
        let plain = user("maya", Method::Local, false);
        for change in [Change::Disable, Change::Delete, Change::Superuser(false)] {
            assert!(guard(&caller, &plain, &change, 1).is_ok(), "{change:?}");
        }
    }

    #[test]
    fn an_oidc_account_has_no_password_to_reset_and_is_not_deleted() {
        let caller = user("root", Method::Local, true);
        let oidc = user("Maya Kusuma", Method::Oidc, false);
        let reset = conflict(guard(&caller, &oidc, &Change::Reset, 2));
        assert!(reset.starts_with("Maya Kusuma signs in through the identity provider"));
        let delete = conflict(guard(&caller, &oidc, &Change::Delete, 2));
        assert!(delete.ends_with("Disable the account instead."));
        for change in [
            Change::Disable,
            Change::Enable,
            Change::Superuser(true),
            Change::Superuser(false),
        ] {
            assert!(guard(&caller, &oidc, &change, 2).is_ok(), "{change:?}");
        }
    }

    #[test]
    fn with_no_cut_off_every_session_is_current() {
        assert!(session_current(0, None));
        assert!(session_current(1_700_000_000_000, None));
    }

    #[test]
    fn a_session_issued_before_the_cut_off_is_not_current() {
        assert!(!session_current(1_699_999_999_999, Some(1_700_000_000_000)));
    }

    #[test]
    fn a_session_issued_at_or_after_the_cut_off_is_current() {
        assert!(session_current(1_700_000_000_000, Some(1_700_000_000_000)));
        assert!(session_current(1_700_000_000_001, Some(1_700_000_000_000)));
    }

    #[test]
    fn a_session_from_before_issue_times_is_cut_off_by_any_cut_off() {
        assert!(!session_current(0, Some(1)));
        // A cut-off before the epoch is still one a 0 meets.
        assert!(session_current(0, Some(-5)));
    }
}

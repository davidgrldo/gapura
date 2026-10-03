//! The first superuser, for a store that has no accounts yet.
//!
//! A console nobody can sign in to cannot grant anyone a role, so the first account cannot be
//! created through it. Two variables, fed from a Secret, create it at start-up instead, and
//! only into an empty table. Once anyone exists they are ignored -- not applied and not even
//! checked -- so rotating the Secret never quietly changes a password, and a Secret still mounted
//! long after, or a rule tightened by an upgrade, never stops a console that no longer needs it.

use crate::store::Store;

pub const USERNAME_VAR: &str = "GAPURA_BOOTSTRAP_USERNAME";
pub const PASSWORD_VAR: &str = "GAPURA_BOOTSTRAP_PASSWORD";

/// What the two variables ask for, or why they cannot be used. Kept apart from `run` so the
/// rules are tested without a store or a process environment.
pub fn requested(
    username: Option<String>,
    password: Option<String>,
) -> anyhow::Result<Option<(String, String)>> {
    match (username, password) {
        (None, None) => Ok(None),
        (Some(username), Some(password)) => {
            crate::password::check_username(&username)
                .map_err(|e| anyhow::anyhow!("{USERNAME_VAR}: {e}"))?;
            crate::password::check_password(&username, &password)
                .map_err(|e| anyhow::anyhow!("{PASSWORD_VAR}: {e}"))?;
            Ok(Some((username, password)))
        }
        _ => anyhow::bail!("{USERNAME_VAR} and {PASSWORD_VAR} must be set together"),
    }
}

/// One variable: `None` when unset, an error when set to something that is not UTF-8, rather
/// than mistaking that for unset.
fn variable(name: &str) -> anyhow::Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            anyhow::bail!("{name} is set, but not to valid UTF-8")
        }
    }
}

/// Reads the two variables and applies them to `store`.
pub async fn run(store: &Store) -> anyhow::Result<()> {
    apply(store, variable(USERNAME_VAR)?, variable(PASSWORD_VAR)?).await
}

/// Applies a requested pair to `store`, taking the values as arguments so it is tested without
/// touching the process environment.
///
/// Once any account exists the pair is ignored without being checked. Into an empty table an
/// invalid pair stops the process instead: a console that started anyway would be one where
/// nobody can be granted anything, with nothing on the screen saying why.
pub async fn apply(
    store: &Store,
    username: Option<String>,
    password: Option<String>,
) -> anyhow::Result<()> {
    let asked = username.is_some() || password.is_some();
    if store.user_count().await? > 0 {
        if asked {
            tracing::info!(
                "accounts already exist, so {USERNAME_VAR} and {PASSWORD_VAR} are ignored"
            );
        }
        return Ok(());
    }
    match requested(username, password)? {
        Some((username, password)) => {
            let hash = crate::password::hash(&password)?;
            if store.bootstrap_superuser(&username, &hash).await? {
                tracing::info!(%username, "created the bootstrap superuser");
            } else {
                // Another replica created the first account between the count and the lock.
                tracing::info!(
                    "accounts already exist, so {USERNAME_VAR} and {PASSWORD_VAR} are ignored"
                );
            }
        }
        None => tracing::warn!(
            "the store holds no accounts and {USERNAME_VAR} is not set, so nobody can grant \
             access in the console; set it before anyone signs in, because the first account of \
             any kind, an OIDC sign-in included, makes it too late"
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> Option<String> {
        Some(v.to_string())
    }

    #[test]
    fn neither_variable_asks_for_nothing() {
        assert!(requested(None, None).unwrap().is_none());
    }

    #[test]
    fn both_variables_valid_ask_for_that_account() {
        assert_eq!(
            requested(s("root"), s("correct horse battery")).unwrap(),
            Some(("root".to_string(), "correct horse battery".to_string()))
        );
    }

    #[test]
    fn one_without_the_other_is_refused_naming_both() {
        for (u, p) in [(s("root"), None), (None, s("correct horse battery"))] {
            let error = requested(u, p).unwrap_err().to_string();
            assert!(
                error.contains(USERNAME_VAR) && error.contains(PASSWORD_VAR),
                "got {error}"
            );
        }
    }

    #[test]
    fn the_account_rules_apply_and_an_unresolved_secret_is_refused() {
        assert!(requested(s("ro ot"), s("correct horse battery")).is_err());
        assert!(requested(s("root"), s("too short")).is_err());
        assert!(requested(s("root"), s("my-root-password")).is_err());
        // What a Secret that never resolved looks like: both set, to nothing.
        assert!(requested(s(""), s("")).is_err());
    }
}

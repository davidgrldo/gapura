//! Accounts: who may change them, the rules a change must keep, and the temporary passwords a
//! superuser hands out. Pure; the store applies these over rows it has locked.

/// Whether a session issued at `issued_at` (Unix milliseconds) still stands for an account whose
/// sessions were cut off at `valid_after`.
pub fn session_current(issued_at: u64, valid_after: Option<i64>) -> bool {
    valid_after.is_none_or(|cut| i128::from(issued_at) >= i128::from(cut))
}

#[cfg(test)]
mod tests {
    use super::*;

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

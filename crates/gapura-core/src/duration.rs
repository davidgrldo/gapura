//! Parser for the Gateway API Duration format (GEP-2257): `^([0-9]{1,5}(h|m|s|ms)){1,4}$`.
//!
//! Input is case-sensitive and whitespace-intolerant, exactly like the regex. The *digit count*
//! is bounded, not the value: `000001s` is rejected even though it denotes 1 s. Repeated and
//! out-of-order units are accepted and summed (`1h1h` = 2 h, `1s1h` = 1 h 1 s), because GEP-2257
//! defers to Go's `time.ParseDuration` and only recommends descending, non-repeating units for
//! authors. Formatting durations back out (not done here) must use descending units and `0s`.

/// Parse a Gateway API duration into milliseconds. Returns `None` when the format is invalid.
///
/// `Some(0)` is a valid result (`"0s"`, `"0h"`, ...). Per the Gateway API `HTTPRouteTimeouts`
/// contract a zero duration means the timeout is *disabled*, not "expire immediately": callers
/// must never pass it through as a zero deadline.
///
/// # Examples
///
/// ```
/// use gapura_core::duration::parse_millis;
/// assert_eq!(parse_millis("1h30m"), Some(5_400_000));
/// assert_eq!(parse_millis("0s"), Some(0));
/// assert_eq!(parse_millis("1.5s"), None);
/// ```
pub fn parse_millis(s: &str) -> Option<u64> {
    if s.is_empty() {
        return None;
    }
    let mut rest = s;
    let mut total: u64 = 0;
    let mut parts = 0;
    while !rest.is_empty() {
        let digits_end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        if digits_end == 0 || digits_end > 5 {
            return None;
        }
        let n: u64 = rest[..digits_end].parse().ok()?;
        rest = &rest[digits_end..];
        let (multiplier, unit_len) = if rest.starts_with("ms") {
            (1, 2)
        } else if rest.starts_with('h') {
            (3_600_000, 1)
        } else if rest.starts_with('m') {
            (60_000, 1)
        } else if rest.starts_with('s') {
            (1_000, 1)
        } else {
            return None;
        };
        total = total.checked_add(n.checked_mul(multiplier)?)?;
        rest = &rest[unit_len..];
        parts += 1;
        if parts > 4 {
            return None;
        }
    }
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_durations_to_millis() {
        assert_eq!(parse_millis("10s"), Some(10_000));
        assert_eq!(parse_millis("500ms"), Some(500));
        assert_eq!(parse_millis("1h30m"), Some(5_400_000));
        assert_eq!(parse_millis("1h30m10s500ms"), Some(5_410_500));
        assert_eq!(parse_millis("0s"), Some(0));
        assert_eq!(parse_millis("1ms"), Some(1));
        assert_eq!(parse_millis("1m"), Some(60_000));
    }

    #[test]
    fn five_digits_and_four_components_are_the_upper_bounds() {
        assert_eq!(parse_millis("99999s"), Some(99_999_000));
        assert_eq!(
            parse_millis("99999h99999h99999h99999h"),
            Some(1_439_985_600_000)
        );
        assert_eq!(parse_millis("123456s"), None);
        assert_eq!(parse_millis("1s1s1s1s1s"), None);
    }

    #[test]
    fn repeated_and_out_of_order_units_sum_like_go() {
        // GEP-2257: repeated/out-of-order units are legal and sum, per Go time.ParseDuration.
        assert_eq!(parse_millis("1h1h"), Some(7_200_000));
        assert_eq!(parse_millis("1s1h"), Some(3_601_000));
    }

    #[test]
    fn rejects_invalid_durations() {
        assert_eq!(parse_millis(""), None);
        assert_eq!(parse_millis("10"), None);
        assert_eq!(parse_millis("s"), None);
        assert_eq!(parse_millis("abc"), None);
        assert_eq!(parse_millis("1d"), None);
        assert_eq!(parse_millis("-5s"), None);
        assert_eq!(parse_millis("+5s"), None);
        assert_eq!(parse_millis("1.5s"), None);
        assert_eq!(parse_millis("10S"), None);
        assert_eq!(parse_millis("1H30M"), None);
        assert_eq!(parse_millis(" 10s"), None);
        assert_eq!(parse_millis("10s "), None);
        assert_eq!(parse_millis("1h 30m"), None);
        assert_eq!(parse_millis("1٣s"), None);
    }

    proptest::proptest! {
        #[test]
        fn every_string_matching_the_spec_regex_parses(s in "([0-9]{1,5}(h|m|s|ms)){1,4}") {
            proptest::prop_assert!(parse_millis(&s).is_some(), "spec-conforming input rejected: {s:?}");
        }

        #[test]
        fn never_panics_on_arbitrary_input(s in "[0-9a-zA-Z .:+-]{0,24}") {
            let _ = parse_millis(&s);
        }
    }
}

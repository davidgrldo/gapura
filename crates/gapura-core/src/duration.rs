//! Parser for the Gateway API Duration format: `^([0-9]{1,5}(h|m|s|ms)){1,4}$`.

/// Parse a Gateway API duration into milliseconds. Returns `None` when the format is invalid.
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
    }

    #[test]
    fn rejects_invalid_durations() {
        assert_eq!(parse_millis(""), None);
        assert_eq!(parse_millis("10"), None);
        assert_eq!(parse_millis("abc"), None);
        assert_eq!(parse_millis("1d"), None);
        assert_eq!(parse_millis("123456s"), None);
        assert_eq!(parse_millis("1s1s1s1s1s"), None);
        assert_eq!(parse_millis("-5s"), None);
    }
}

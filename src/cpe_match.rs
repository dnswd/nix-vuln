#![deny(clippy::all, clippy::pedantic)]

fn category(c: char) -> u8 {
    if c == '.' || c == '-' {
        0
    } else if c.is_ascii_digit() {
        1
    } else {
        2
    }
}

fn split_components(v: &str) -> Vec<&str> {
    let mut components = Vec::new();
    let mut start = 0;
    
    let bytes = v.as_bytes();
    let stop = bytes.len();

    while start < stop {
        let cat0 = category(bytes[start] as char);
        let mut i = start + 1;
        while i < stop && category(bytes[i] as char) == cat0 {
            i += 1;
        }
        if cat0 != 0 {
            components.push(&v[start..i]);
        }
        start = i;
    }
    components
}

fn components_lt(left: &str, right: &str) -> bool {
    let lnum: Option<i64> = left.parse().ok();
    let rnum: Option<i64> = right.parse().ok();

    if let (Some(l), Some(r)) = (lnum, rnum) {
        return l < r;
    }
    if left.is_empty() && rnum.is_some() {
        return true;
    }
    if left == "pre" && right != "pre" {
        return true;
    }
    if right == "pre" {
        return false;
    }
    if rnum.is_some() {
        return true;
    }
    if lnum.is_some() {
        return false;
    }

    left < right
}

fn compare_versions(left: &str, right: &str) -> i8 {
    if left == right {
        return 0;
    }
    let lcomps = split_components(left);
    let rcomps = split_components(right);

    let max_len = std::cmp::max(lcomps.len(), rcomps.len());
    for i in 0..max_len {
        let lc = if i < lcomps.len() { lcomps[i] } else { "" };
        let rc = if i < rcomps.len() { rcomps[i] } else { "" };

        if lc == rc {
            continue;
        }
        if components_lt(lc, rc) {
            return -1;
        }
        if components_lt(rc, lc) {
            return 1;
        }
    }
    0
}

fn is_dotted_numeric(v: &str) -> bool {
    if v.is_empty() { return false; }
    let mut expect_digit = true;
    for c in v.chars() {
        if expect_digit {
            if !c.is_ascii_digit() {
                return false;
            }
            expect_digit = false;
        } else if c == '.' {
            expect_digit = true;
        } else if !c.is_ascii_digit() {
            return false;
        }
    }
    !expect_digit
}

fn dotted_numeric_version(v: &str) -> Option<Vec<i64>> {
    if !is_dotted_numeric(v) {
        return None;
    }
    let mut parts: Vec<i64> = v.split('.').filter_map(|s| s.parse().ok()).collect();
    while parts.len() > 1 && *parts.last().unwrap() == 0 {
        parts.pop();
    }
    Some(parts)
}

#[must_use]
pub fn compare_cpe_versions(left: &str, right: &str) -> i8 {
    let left_numeric = dotted_numeric_version(left);
    let right_numeric = dotted_numeric_version(right);

    if let (Some(ln), Some(rn)) = (left_numeric, right_numeric) {
        if ln < rn {
            return -1;
        }
        if ln > rn {
            return 1;
        }
        return 0;
    }
    compare_versions(left, right)
}

#[must_use]
pub fn cpe_versions_equal(left: &str, right: &str) -> bool {
    if left == right {
        return true;
    }
    let left_numeric = dotted_numeric_version(left);
    if left_numeric.is_none() {
        return false;
    }
    let right_numeric = dotted_numeric_version(right);
    right_numeric.is_some() && left_numeric == right_numeric
}

/// Returns `Ok(true)` if package version `pvers` complies with `spec`.
/// `spec` is typically something like ">=153.0.0" or "<=2.0".
/// Returns `Err` if the `spec` is invalid.
///
/// # Errors
/// Returns `Err` if the version specification starts with an unknown operator.
pub fn in_range(pvers: &str, spec: &str) -> Result<bool, &'static str> {
    let (op, version) = if let Some(stripped) = spec.strip_prefix(">=") {
        (">=", stripped)
    } else if let Some(stripped) = spec.strip_prefix("<=") {
        ("<=", stripped)
    } else if let Some(stripped) = spec.strip_prefix('>') {
        (">", stripped)
    } else if let Some(stripped) = spec.strip_prefix('<') {
        ("<", stripped)
    } else {
        return Err("Invalid version spec");
    };

    let version_cmp = compare_cpe_versions(pvers, version);
    match op {
        ">=" => Ok(version_cmp >= 0),
        ">" => Ok(version_cmp == 1),
        "<=" => Ok(version_cmp <= 0),
        "<" => Ok(version_cmp == -1),
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpe_versions_equal_ignores_numeric_trailing_zero_components() {
        assert!(cpe_versions_equal("153.0", "153.0.0"));
        assert!(cpe_versions_equal("153", "153.0.0"));
        assert!(cpe_versions_equal("0", "0.0"));
        assert!(!cpe_versions_equal("153.0.1", "153.0.0"));
        assert!(!cpe_versions_equal("152.0.6", "153.0.0"));
        assert!(!cpe_versions_equal("2.0-1", "2.0.1"));
    }

    #[test]
    fn test_compare_cpe_versions_ignores_numeric_trailing_zero_components() {
        assert_eq!(compare_cpe_versions("153.0", "153.0.0"), 0);
        assert_eq!(compare_cpe_versions("153", "153.0.0"), 0);
        assert_eq!(compare_cpe_versions("153.0.1", "153.0.0"), 1);
        assert_eq!(compare_cpe_versions("152.0.6", "153.0.0"), -1);
    }

    #[test]
    fn test_compare_cpe_versions_falls_back_for_mixed_versions() {
        assert_eq!(compare_cpe_versions("153.0esr", "153.0.0"), -1);
    }

    #[test]
    fn test_match_numeric_range_ignores_trailing_zero_components() {
        assert_eq!(in_range("152.0.6", "<153.0.0").unwrap(), true);
        assert_eq!(in_range("153", "<153.0.0").unwrap(), false);
        assert_eq!(in_range("153.0", "<153.0.0").unwrap(), false);
        assert_eq!(in_range("153.0.0", "<153.0.0").unwrap(), false);
        assert_eq!(in_range("153.0.1", "<153.0.0").unwrap(), false);
    }

    #[test]
    fn test_match_inclusive_numeric_range_accepts_trailing_zero_equivalence() {
        assert_eq!(in_range("153", "<=153.0.0").unwrap(), true);
        assert_eq!(in_range("153.0", "<=153.0.0").unwrap(), true);
        assert_eq!(in_range("153.0.0", "<=153.0.0").unwrap(), true);
    }

    #[test]
    fn test_match_exact_numeric_version_ignores_trailing_zero_components() {
        assert!(cpe_versions_equal("153", "153.0.0"));
        assert!(cpe_versions_equal("153.0", "153.0.0"));
        assert!(cpe_versions_equal("153.0.0", "153.0.0"));
        assert!(!cpe_versions_equal("152.0.6", "153.0.0"));
        assert!(!cpe_versions_equal("153.0.1", "153.0.0"));
    }

    #[test]
    fn test_match_exact_non_numeric_version_stays_strict() {
        assert!(cpe_versions_equal("2.0-1", "2.0-1"));
        assert!(!cpe_versions_equal("2.0.1", "2.0-1"));
    }
}

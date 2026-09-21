use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionComparator {
    Exact,
    GreaterEqual,
    Greater,
    LessEqual,
    Less,
    Compatible,
}

impl fmt::Display for VersionComparator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact => write!(f, "=="),
            Self::GreaterEqual => write!(f, ">="),
            Self::Greater => write!(f, ">"),
            Self::LessEqual => write!(f, "<="),
            Self::Less => write!(f, "<"),
            Self::Compatible => write!(f, "^"),
        }
    }
}

/// A structured version constraint preserving exact mathematical semantics.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "op", content = "version", rename_all = "snake_case")]
pub enum VersionConstraint {
    Exact(String),
    GreaterEqual(String),
    Greater(String),
    LessEqual(String),
    Less(String),
    Compatible(String),
    Range {
        lower: (VersionComparator, String),
        upper: (VersionComparator, String),
    },
    Any,
}

impl fmt::Display for VersionConstraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(v) => write!(f, "=={}", v),
            Self::GreaterEqual(v) => write!(f, ">={}", v),
            Self::Greater(v) => write!(f, ">{}", v),
            Self::LessEqual(v) => write!(f, "<={}", v),
            Self::Less(v) => write!(f, "<{}", v),
            Self::Compatible(v) => write!(f, "^{}", v),
            Self::Range { lower, upper } => {
                write!(f, "{}{}, {}{}", lower.0, lower.1, upper.0, upper.1)
            }
            Self::Any => write!(f, "*"),
        }
    }
}

/// Extract numeric dot/dash-separated version components from any string (e.g. "26.0.2.1", "v1.2.3").
pub fn parse_version_components(ver_str: &str) -> Vec<u64> {
    let clean = ver_str
        .trim()
        .trim_start_matches(|c: char| !c.is_ascii_digit());

    let mut components = Vec::new();
    for part in clean.split(['.', '-', '_', '+']) {
        let num_part: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(num) = num_part.parse::<u64>() {
            components.push(num);
        } else {
            break;
        }
    }
    components
}

/// Compares two numeric version component vectors, treating omitted trailing zeros as equivalent.
pub fn compare_version_components(a: &[u64], b: &[u64]) -> Ordering {
    let max_len = a.len().max(b.len());
    for i in 0..max_len {
        let val_a = a.get(i).copied().unwrap_or(0);
        let val_b = b.get(i).copied().unwrap_or(0);
        match val_a.cmp(&val_b) {
            Ordering::Equal => continue,
            non_eq => return non_eq,
        }
    }
    Ordering::Equal
}

impl VersionConstraint {
    /// Parse a raw constraint string into a structured `VersionConstraint`.
    /// When a version has no operator prefix (e.g. "21.0.2" or "11.24.0"), it is treated as an exact pin `==`.
    pub fn parse(s: &str) -> Self {
        let trimmed = s.trim();
        if trimmed.is_empty() || trimmed == "*" {
            return Self::Any;
        }

        // Check for range like ">=21.0.2, <27" or ">=3.10 <3.13"
        if trimmed.contains(',')
            || (trimmed.contains(' ') && (trimmed.contains('<') || trimmed.contains('>')))
        {
            let parts: Vec<&str> = trimmed
                .split([',', ' '])
                .map(|p| p.trim())
                .filter(|p| !p.is_empty())
                .collect();

            if parts.len() == 2 {
                let parse_op_ver = |p: &str| -> Option<(VersionComparator, String)> {
                    if let Some(rest) = p.strip_prefix(">=") {
                        Some((VersionComparator::GreaterEqual, rest.trim().to_string()))
                    } else if let Some(rest) = p.strip_prefix('>') {
                        Some((VersionComparator::Greater, rest.trim().to_string()))
                    } else if let Some(rest) = p.strip_prefix("<=") {
                        Some((VersionComparator::LessEqual, rest.trim().to_string()))
                    } else if let Some(rest) = p.strip_prefix('<') {
                        Some((VersionComparator::Less, rest.trim().to_string()))
                    } else {
                        p.strip_prefix("==")
                            .map(|rest| (VersionComparator::Exact, rest.trim().to_string()))
                    }
                };

                if let (Some(lower), Some(upper)) = (parse_op_ver(parts[0]), parse_op_ver(parts[1]))
                {
                    return Self::Range { lower, upper };
                }
            }
        }

        if let Some(rest) = trimmed.strip_prefix(">=") {
            Self::GreaterEqual(rest.trim().to_string())
        } else if let Some(rest) = trimmed.strip_prefix('>') {
            Self::Greater(rest.trim().to_string())
        } else if let Some(rest) = trimmed.strip_prefix("<=") {
            Self::LessEqual(rest.trim().to_string())
        } else if let Some(rest) = trimmed.strip_prefix('<') {
            Self::Less(rest.trim().to_string())
        } else if let Some(rest) = trimmed.strip_prefix("==") {
            Self::Exact(rest.trim().to_string())
        } else if let Some(rest) = trimmed.strip_prefix('=') {
            Self::Exact(rest.trim().to_string())
        } else if let Some(rest) = trimmed.strip_prefix('^') {
            Self::Compatible(rest.trim().to_string())
        } else if let Some(rest) = trimmed.strip_prefix('~') {
            Self::Compatible(rest.trim().to_string())
        } else {
            // Default with no operator is exact pin
            let clean_exact = if let Some(rest) = trimmed.strip_prefix("version_") {
                rest
            } else if let Some(rest) = trimmed.strip_prefix("version-") {
                rest
            } else if let Some(rest) = trimmed.strip_prefix('v') {
                if rest.starts_with(|c: char| c.is_ascii_digit()) {
                    rest
                } else {
                    trimmed
                }
            } else {
                trimmed
            };
            Self::Exact(clean_exact.to_string())
        }
    }

    /// Check if actual version satisfies this constraint.
    pub fn matches(&self, actual_str: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(expected) => {
                let actual_comp = parse_version_components(actual_str);
                let expected_comp = parse_version_components(expected);
                if !actual_comp.is_empty() && !expected_comp.is_empty() {
                    compare_version_components(&actual_comp, &expected_comp) == Ordering::Equal
                } else {
                    actual_str.trim().eq_ignore_ascii_case(expected.trim())
                }
            }
            Self::GreaterEqual(expected) => {
                let actual_comp = parse_version_components(actual_str);
                let expected_comp = parse_version_components(expected);
                if !actual_comp.is_empty() && !expected_comp.is_empty() {
                    compare_version_components(&actual_comp, &expected_comp) != Ordering::Less
                } else {
                    actual_str.trim() >= expected.trim()
                }
            }
            Self::Greater(expected) => {
                let actual_comp = parse_version_components(actual_str);
                let expected_comp = parse_version_components(expected);
                if !actual_comp.is_empty() && !expected_comp.is_empty() {
                    compare_version_components(&actual_comp, &expected_comp) == Ordering::Greater
                } else {
                    actual_str.trim() > expected.trim()
                }
            }
            Self::LessEqual(expected) => {
                let actual_comp = parse_version_components(actual_str);
                let expected_comp = parse_version_components(expected);
                if !actual_comp.is_empty() && !expected_comp.is_empty() {
                    compare_version_components(&actual_comp, &expected_comp) != Ordering::Greater
                } else {
                    actual_str.trim() <= expected.trim()
                }
            }
            Self::Less(expected) => {
                let actual_comp = parse_version_components(actual_str);
                let expected_comp = parse_version_components(expected);
                if !actual_comp.is_empty() && !expected_comp.is_empty() {
                    compare_version_components(&actual_comp, &expected_comp) == Ordering::Less
                } else {
                    actual_str.trim() < expected.trim()
                }
            }
            Self::Compatible(expected) => {
                let actual_comp = parse_version_components(actual_str);
                let expected_comp = parse_version_components(expected);
                if !actual_comp.is_empty() && !expected_comp.is_empty() {
                    // Caret: major versions must match, and actual >= expected
                    actual_comp[0] == expected_comp[0]
                        && compare_version_components(&actual_comp, &expected_comp)
                            != Ordering::Less
                } else {
                    actual_str.trim() == expected.trim()
                }
            }
            Self::Range { lower, upper } => {
                let lower_matches = match lower.0 {
                    VersionComparator::GreaterEqual => {
                        let actual_comp = parse_version_components(actual_str);
                        let expected_comp = parse_version_components(&lower.1);
                        compare_version_components(&actual_comp, &expected_comp) != Ordering::Less
                    }
                    VersionComparator::Greater => {
                        let actual_comp = parse_version_components(actual_str);
                        let expected_comp = parse_version_components(&lower.1);
                        compare_version_components(&actual_comp, &expected_comp)
                            == Ordering::Greater
                    }
                    _ => true,
                };
                let upper_matches = match upper.0 {
                    VersionComparator::LessEqual => {
                        let actual_comp = parse_version_components(actual_str);
                        let expected_comp = parse_version_components(&upper.1);
                        compare_version_components(&actual_comp, &expected_comp)
                            != Ordering::Greater
                    }
                    VersionComparator::Less => {
                        let actual_comp = parse_version_components(actual_str);
                        let expected_comp = parse_version_components(&upper.1);
                        compare_version_components(&actual_comp, &expected_comp) == Ordering::Less
                    }
                    _ => true,
                };
                lower_matches && upper_matches
            }
        }
    }

    /// Calculate the mathematical intersection of two constraints.
    pub fn intersect(&self, other: &Self) -> Result<Self, String> {
        match (self, other) {
            (Self::Any, o) | (o, Self::Any) => Ok(o.clone()),
            (Self::Exact(v1), Self::Exact(v2)) => {
                let c1 = parse_version_components(v1);
                let c2 = parse_version_components(v2);
                if compare_version_components(&c1, &c2) == Ordering::Equal {
                    Ok(Self::Exact(v1.clone()))
                } else {
                    Err(format!("Conflicting exact versions: =={} vs =={}", v1, v2))
                }
            }
            (Self::Exact(exact_v), Self::GreaterEqual(ge_v))
            | (Self::GreaterEqual(ge_v), Self::Exact(exact_v)) => {
                let c_exact = parse_version_components(exact_v);
                let c_ge = parse_version_components(ge_v);
                if compare_version_components(&c_exact, &c_ge) != Ordering::Less {
                    Ok(Self::Exact(exact_v.clone()))
                } else {
                    Err(format!(
                        "Exact version =={} does not satisfy minimum requirement >={}",
                        exact_v, ge_v
                    ))
                }
            }
            (Self::Compatible(compat_v), Self::Exact(exact_v))
            | (Self::Exact(exact_v), Self::Compatible(compat_v)) => {
                let c_compat = parse_version_components(compat_v);
                let c_exact = parse_version_components(exact_v);
                if !c_compat.is_empty()
                    && !c_exact.is_empty()
                    && c_compat[0] == c_exact[0]
                    && compare_version_components(&c_exact, &c_compat) != Ordering::Less
                {
                    Ok(Self::Exact(exact_v.clone()))
                } else {
                    Err(format!(
                        "Exact version =={} is incompatible with ^{}",
                        exact_v, compat_v
                    ))
                }
            }
            (Self::GreaterEqual(v1), Self::GreaterEqual(v2)) => {
                let c1 = parse_version_components(v1);
                let c2 = parse_version_components(v2);
                if compare_version_components(&c1, &c2) == Ordering::Less {
                    Ok(Self::GreaterEqual(v2.clone()))
                } else {
                    Ok(Self::GreaterEqual(v1.clone()))
                }
            }
            (Self::GreaterEqual(lower_v), Self::Less(upper_v)) => {
                let c_low = parse_version_components(lower_v);
                let c_up = parse_version_components(upper_v);
                if compare_version_components(&c_low, &c_up) == Ordering::Less {
                    Ok(Self::Range {
                        lower: (VersionComparator::GreaterEqual, lower_v.clone()),
                        upper: (VersionComparator::Less, upper_v.clone()),
                    })
                } else {
                    Err(format!(
                        "Unsatisfiable range: >={} but <{}",
                        lower_v, upper_v
                    ))
                }
            }
            _ => Ok(self.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_pin_semantics() {
        let req = VersionConstraint::parse("21.0.2");
        assert_eq!(req, VersionConstraint::Exact("21.0.2".to_string()));

        // Exactly 21.0.2 matches 21.0.2
        assert!(req.matches("21.0.2"));
        // 21.0.3 must fail
        assert!(!req.matches("21.0.3"));
        // 26.0.2.1 must fail
        assert!(!req.matches("26.0.2.1"));
    }

    #[test]
    fn test_greater_equal_semantics() {
        let req = VersionConstraint::parse(">=21.0.2");
        assert!(req.matches("21.0.2"));
        assert!(req.matches("21.0.3"));
        assert!(req.matches("26.0.2.1"));
        assert!(!req.matches("20.0.0"));
    }

    #[test]
    fn test_range_semantics() {
        let req = VersionConstraint::parse(">=21.0.2, <27");
        assert!(req.matches("26.0.2.1"));
        assert!(req.matches("21.0.2"));
        assert!(!req.matches("27.0.0"));
        assert!(!req.matches("20.9.0"));
    }

    #[test]
    fn test_intersection_semantics() {
        let c1 = VersionConstraint::parse(">=10.0.0");
        let c2 = VersionConstraint::parse("11.24.0");
        let merged = c1.intersect(&c2).expect("intersection succeeds");
        assert_eq!(merged, VersionConstraint::Exact("11.24.0".to_string()));

        let conflict1 = VersionConstraint::parse(">=22.0.0");
        let conflict2 = VersionConstraint::parse("20.0.0");
        assert!(conflict1.intersect(&conflict2).is_err());
    }
}

use serde::{Deserialize, Serialize};
use std::fmt;

/// Confidence level for evidence, claims, and predictions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Confidence {
    /// Insufficient evidence or unverified assumption.
    Unknown = 0,
    /// Weak heuristic or indirect clue.
    Low = 1,
    /// Multiple indirect signals or standard conventions.
    Medium = 2,
    /// Strong deterministic constraint or verified observation.
    High = 3,
    /// Directly observed and proven fact (e.g., active execution error or socket bind failure).
    Confirmed = 4,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown => write!(f, "UNKNOWN"),
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
            Self::Confirmed => write!(f, "CONFIRMED"),
        }
    }
}

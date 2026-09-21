use crate::confidence::Confidence;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Origin and provenance of an observation or fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EvidenceSource {
    /// Extracted from a file in the project repository.
    RepositoryFile {
        path: PathBuf,
        line: Option<usize>,
        detail: Option<String>,
    },
    /// Discovered by running or inspecting an executable on the machine.
    ExecutableInspection {
        path: PathBuf,
        version_string: String,
        exit_code: i32,
    },
    /// Derived from operating system metadata (e.g. /etc/os-release, uname).
    OsMetadata {
        key: String,
        value: String,
    },
    /// Probed network state (e.g. port scan, socket check).
    NetworkProbe {
        target: String,
        outcome: String,
    },
    /// Probed process table (/proc or sysinfo).
    ProcessInspection {
        pid: u32,
        name: String,
        cmdline: Option<String>,
    },
    /// Environment variable from machine or shell.
    EnvironmentVariable {
        key: String,
        value: Option<String>,
    },
    /// Direct runtime or filesystem observation.
    DirectObservation {
        detail: String,
    },
}

/// Traceable evidence supporting an observation, constraint, or diagnosis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Evidence {
    /// Provenance of the evidence.
    pub source: EvidenceSource,
    /// Confidence level in this evidence.
    pub confidence: Confidence,
    /// Human-readable explanation of what this evidence proves.
    pub description: String,
}

impl Evidence {
    pub fn new(source: EvidenceSource, confidence: Confidence, description: impl Into<String>) -> Self {
        Self {
            source,
            confidence,
            description: description.into(),
        }
    }

    pub fn from_repo_file(path: PathBuf, line: Option<usize>, description: impl Into<String>) -> Self {
        Self {
            source: EvidenceSource::RepositoryFile {
                path,
                line,
                detail: None,
            },
            confidence: Confidence::High,
            description: description.into(),
        }
    }

    pub fn from_executable(path: PathBuf, version_string: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            source: EvidenceSource::ExecutableInspection {
                path,
                version_string: version_string.into(),
                exit_code: 0,
            },
            confidence: Confidence::High,
            description: description.into(),
        }
    }
}

use serde::{Deserialize, Serialize};
use std::fmt;
use unfuck_core::evidence::Evidence;
use unfuck_core::ir::{ToolKind, ToolScope};
use unfuck_core::version::VersionConstraint;

/// Declarative environment constraint.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Constraint {
    /// Target runtime must satisfy a version constraint expression.
    RuntimeVersion {
        runtime: String,
        constraint: VersionConstraint,
    },
    /// A package manager must be available and satisfy an optional version constraint.
    PackageManagerVersion {
        name: String,
        constraint: Option<VersionConstraint>,
    },
    /// A developer, build, or codegen tool must be available.
    ToolAvailable {
        name: String,
        kind: ToolKind,
        constraint: Option<VersionConstraint>,
        scope: ToolScope,
    },
    /// A required TCP port must not be occupied by another process.
    PortAvailable { port: u16 },
    /// A required system service or daemon must be running.
    ServiceRunning {
        service: String,
        min_version: Option<String>,
    },
    /// The host operating system must match the requirement.
    OsMatch { expected_os: String },
    /// The CPU architecture must match the requirement.
    ArchMatch { expected_arch: String },
    /// Host machine must provide at least the specified memory in bytes.
    MemoryMin { min_bytes: u64 },
    /// An environment variable must be set in the environment.
    EnvVarSet { key: String, required: bool },
    /// Contradictory configuration detected across project specification files.
    ConflictDetected { target: String, details: String },
}

impl fmt::Display for Constraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuntimeVersion {
                runtime,
                constraint,
            } => {
                write!(f, "Runtime '{}' must satisfy {}", runtime, constraint)
            }
            Self::PackageManagerVersion { name, constraint } => {
                if let Some(ref c) = constraint {
                    write!(f, "Package manager '{}' must satisfy {}", name, c)
                } else {
                    write!(f, "Package manager '{}' must be installed", name)
                }
            }
            Self::ToolAvailable {
                name,
                kind,
                constraint,
                scope,
            } => {
                let ver_str = constraint
                    .as_ref()
                    .map(|c| format!(" ({})", c))
                    .unwrap_or_default();
                write!(
                    f,
                    "{} '{}'{} must be available (scope: {:?})",
                    kind, name, ver_str, scope
                )
            }
            Self::PortAvailable { port } => write!(f, "Port {} must be available", port),
            Self::ServiceRunning {
                service,
                min_version,
            } => {
                if let Some(ref ver) = min_version {
                    write!(f, "Service '{}' must be running (>= {})", service, ver)
                } else {
                    write!(f, "Service '{}' must be running", service)
                }
            }
            Self::OsMatch { expected_os } => write!(f, "OS must match '{}'", expected_os),
            Self::ArchMatch { expected_arch } => {
                write!(f, "Architecture must match '{}'", expected_arch)
            }
            Self::MemoryMin { min_bytes } => {
                write!(
                    f,
                    "Available memory must be >= {:.1} GB",
                    *min_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
                )
            }
            Self::EnvVarSet { key, required } => {
                if *required {
                    write!(f, "Environment variable '{}' must be set", key)
                } else {
                    write!(f, "Environment variable '{}' is optional but declared", key)
                }
            }
            Self::ConflictDetected { target, details } => {
                write!(f, "Configuration conflict for '{}': {}", target, details)
            }
        }
    }
}

/// The evaluation outcome of a single constraint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ConstraintStatus {
    Satisfied,
    Violated {
        reason: String,
        root_cause_hint: String,
    },
    Unknown {
        reason: String,
    },
}

/// Evaluated constraint accompanied by full provenance from both sides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvaluatedConstraint {
    pub constraint: Constraint,
    pub status: ConstraintStatus,
    pub project_evidence: Option<Evidence>,
    pub machine_evidence: Option<Evidence>,
}

impl EvaluatedConstraint {
    pub fn is_violated(&self) -> bool {
        matches!(self.status, ConstraintStatus::Violated { .. })
    }

    pub fn is_satisfied(&self) -> bool {
        matches!(self.status, ConstraintStatus::Satisfied)
    }
}

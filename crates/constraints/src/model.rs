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
    /// Docker Compose configuration cannot be instantiated due to missing env files or unresolved variables.
    ComposeConfigUnresolved {
        compose_file: std::path::PathBuf,
        project_name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        service_name: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        directly_affected_services: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        transitively_blocked_services: Vec<String>,
        missing_env_files: Vec<std::path::PathBuf>,
        unresolved_vars: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        env_templates: Vec<unfuck_core::ir::EnvFileTemplate>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        bootstrap_suggestions: Vec<String>,
    },
    /// A Docker Compose service has container state issues or has not been created.
    ComposeServiceState {
        compose_file: std::path::PathBuf,
        service_name: String,
        container_name: Option<String>,
        expected_state: String,
        actual_state: String,
    },
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
            Self::ComposeConfigUnresolved {
                compose_file,
                service_name,
                missing_env_files,
                unresolved_vars,
                ..
            } => {
                let mut issues = Vec::new();
                if !missing_env_files.is_empty() {
                    issues.push(format!(
                        "missing env file(s): {}",
                        missing_env_files
                            .iter()
                            .map(|p| p.display().to_string())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
                if !unresolved_vars.is_empty() {
                    issues.push(format!(
                        "unresolved variable(s): {}",
                        unresolved_vars.join(", ")
                    ));
                }
                let svc_str = service_name
                    .as_deref()
                    .map(|s| format!(" for service '{}'", s))
                    .unwrap_or_default();
                write!(
                    f,
                    "Docker Compose configuration at '{}'{} must be resolvable ({})",
                    compose_file.display(),
                    svc_str,
                    issues.join("; ")
                )
            }
            Self::ComposeServiceState {
                compose_file,
                service_name,
                container_name,
                expected_state,
                actual_state,
            } => {
                let c_str = container_name
                    .as_deref()
                    .map(|c| format!(" (container '{}')", c))
                    .unwrap_or_default();
                write!(
                    f,
                    "Compose service '{}'{} in '{}' state must be '{}', found '{}'",
                    service_name,
                    c_str,
                    compose_file.display(),
                    expected_state,
                    actual_state
                )
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

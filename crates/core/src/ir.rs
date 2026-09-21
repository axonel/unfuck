use crate::evidence::Evidence;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Requirement kind declared by or inferred from a project.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RequirementKind {
    /// Language or runtime requirement (e.g. Python >= 3.11, Node >= 20.0.0).
    Runtime {
        name: String,
        constraint: String,
    },
    /// Package manager requirement (e.g. bun >= 1.0, uv, pnpm).
    PackageManager {
        name: String,
        constraint: Option<String>,
    },
    /// TCP or UDP port expected by the project (e.g. 3000, 5432, 8080).
    Port {
        port: u16,
        service_hint: Option<String>,
    },
    /// External service or database (e.g. PostgreSQL, Docker, Redis).
    Service {
        name: String,
        min_version: Option<String>,
    },
    /// Environment variable expected by the application.
    EnvVar {
        name: String,
        default_value: Option<String>,
        required: bool,
    },
    /// Operating system requirement.
    Os {
        name: String,
    },
    /// CPU architecture requirement.
    Arch {
        name: String,
    },
    /// Minimum physical or available memory.
    Memory {
        min_bytes: u64,
    },
}

/// A specific requirement declared by a project, with evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectRequirement {
    pub name: String,
    pub kind: RequirementKind,
    pub evidence: Evidence,
}

/// An installed runtime on the machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Runtime {
    pub name: String,
    pub version: String,
    pub executable_path: PathBuf,
    pub evidence: Evidence,
}

/// Status of a local service or daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceStatus {
    Running,
    Stopped,
    NotInstalled,
    Unknown,
}

/// A service detected or probed on the machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    pub version: Option<String>,
    pub status: ServiceStatus,
    pub port: Option<u16>,
    pub socket_path: Option<PathBuf>,
    pub evidence: Evidence,
}

/// State of a network port.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PortState {
    Free,
    Occupied {
        pid: Option<u32>,
        process_name: Option<String>,
    },
}

/// Information about a network port on the machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub state: PortState,
    pub evidence: Evidence,
}

/// Complete machine capability discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineCapability {
    pub os: String,
    pub os_family: String,
    pub arch: String,
    pub cpu_count: usize,
    pub total_memory_bytes: u64,
    pub available_memory_bytes: u64,
    pub runtimes: Vec<Runtime>,
    pub services: Vec<Service>,
    pub listening_ports: Vec<PortInfo>,
    pub env_vars: HashMap<String, String>,
    pub path_entries: Vec<PathBuf>,
    pub evidence: Vec<Evidence>,
}

impl MachineCapability {
    pub fn find_runtime(&self, name: &str) -> Option<&Runtime> {
        self.runtimes.iter().find(|r| r.name.eq_ignore_ascii_case(name))
    }

    pub fn find_service(&self, name: &str) -> Option<&Service> {
        self.services.iter().find(|s| s.name.eq_ignore_ascii_case(name))
    }

    pub fn is_port_occupied(&self, port: u16) -> Option<&PortInfo> {
        self.listening_ports.iter().find(|p| p.port == port && matches!(p.state, PortState::Occupied { .. }))
    }
}

/// Structured manifest of project requirements extracted by the project analyzer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectManifest {
    pub name: String,
    pub root_path: PathBuf,
    pub languages: Vec<String>,
    pub package_managers: Vec<String>,
    pub requirements: Vec<ProjectRequirement>,
    pub declared_ports: Vec<u16>,
    pub env_vars: Vec<String>,
    pub docker_used: bool,
    pub evidence: Vec<Evidence>,
}

/// Canonical intermediate representation combining project and machine intelligence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentModel {
    pub project: ProjectManifest,
    pub machine: MachineCapability,
}

impl EnvironmentModel {
    pub fn new(project: ProjectManifest, machine: MachineCapability) -> Self {
        Self { project, machine }
    }
}

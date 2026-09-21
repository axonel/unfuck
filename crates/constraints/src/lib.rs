pub mod evaluator;
pub mod model;
pub mod version;

pub use evaluator::{evaluate_all, evaluate_constraint, requirement_to_constraint};
pub use model::{Constraint, ConstraintStatus, EvaluatedConstraint};
pub use version::{
    matches_version_constraint, normalize_semver, parse_version_req, VersionComparator,
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use unfuck_core::evidence::{Evidence, EvidenceSource};
    use unfuck_core::ir::{
        MachineCapability, PortInfo, PortState, ProjectRequirement, RequirementKind, Runtime,
        Service, ServiceStatus,
    };
    use unfuck_core::Confidence;

    fn mock_machine() -> MachineCapability {
        MachineCapability {
            os: "Ubuntu 24.04 LTS".to_string(),
            os_family: "linux".to_string(),
            arch: "x86_64".to_string(),
            cpu_count: 8,
            total_memory_bytes: 16 * 1024 * 1024 * 1024,
            available_memory_bytes: 8 * 1024 * 1024 * 1024,
            runtimes: vec![
                Runtime {
                    name: "python".to_string(),
                    version: "3.10.12".to_string(),
                    executable_path: PathBuf::from("/usr/bin/python3"),
                    evidence: Evidence::from_executable(
                        PathBuf::from("/usr/bin/python3"),
                        "Python 3.10.12",
                        "python3 --version",
                    ),
                },
                Runtime {
                    name: "node".to_string(),
                    version: "20.11.0".to_string(),
                    executable_path: PathBuf::from("/usr/bin/node"),
                    evidence: Evidence::from_executable(
                        PathBuf::from("/usr/bin/node"),
                        "v20.11.0",
                        "node --version",
                    ),
                },
            ],
            services: vec![Service {
                name: "docker".to_string(),
                version: None,
                status: ServiceStatus::Running,
                port: None,
                socket_path: Some(PathBuf::from("/var/run/docker.sock")),
                evidence: Evidence::new(
                    EvidenceSource::DirectObservation {
                        detail: "docker socket".to_string(),
                    },
                    Confidence::Confirmed,
                    "Docker active",
                ),
            }],
            listening_ports: vec![PortInfo {
                port: 3000,
                state: PortState::Occupied {
                    pid: Some(9999),
                    process_name: Some("node".to_string()),
                },
                evidence: Evidence::new(
                    EvidenceSource::ProcessInspection {
                        pid: 9999,
                        name: "node".to_string(),
                        cmdline: None,
                    },
                    Confidence::Confirmed,
                    "Port 3000 in use",
                ),
            }],
            env_vars: HashMap::new(),
            path_entries: vec![PathBuf::from("/usr/bin")],
            evidence: vec![],
        }
    }

    #[test]
    fn test_python_version_violated() {
        let machine = mock_machine();
        let constraint = Constraint::RuntimeVersion {
            runtime: "python".to_string(),
            constraint_str: ">= 3.11".to_string(),
        };
        let eval = evaluate_constraint(&constraint, &machine, None);
        assert!(eval.is_violated());
        if let ConstraintStatus::Violated {
            reason,
            root_cause_hint,
        } = eval.status
        {
            assert!(reason.contains("3.10.12"));
            assert_eq!(root_cause_hint, "python.version_mismatch");
        } else {
            panic!("Expected violation");
        }
    }

    #[test]
    fn test_node_version_satisfied() {
        let machine = mock_machine();
        let constraint = Constraint::RuntimeVersion {
            runtime: "node".to_string(),
            constraint_str: ">= 20.0.0".to_string(),
        };
        let eval = evaluate_constraint(&constraint, &machine, None);
        assert!(eval.is_satisfied());
    }

    #[test]
    fn test_port_collision_detected() {
        let machine = mock_machine();
        let constraint = Constraint::PortAvailable { port: 3000 };
        let eval = evaluate_constraint(&constraint, &machine, None);
        assert!(eval.is_violated());
        assert!(eval.machine_evidence.is_some());
    }

    #[test]
    fn test_free_port_satisfied() {
        let machine = mock_machine();
        let constraint = Constraint::PortAvailable { port: 8080 };
        let eval = evaluate_constraint(&constraint, &machine, None);
        assert!(eval.is_satisfied());
    }

    #[test]
    fn test_missing_service_violated() {
        let machine = mock_machine();
        let constraint = Constraint::ServiceRunning {
            service: "postgresql".to_string(),
            min_version: None,
        };
        let eval = evaluate_constraint(&constraint, &machine, None);
        assert!(eval.is_violated());
    }

    #[test]
    fn test_evaluate_all_from_requirements() {
        let machine = mock_machine();
        let requirements = vec![
            ProjectRequirement {
                name: "python".to_string(),
                kind: RequirementKind::Runtime {
                    name: "python".to_string(),
                    constraint: ">= 3.11".to_string(),
                },
                evidence: Evidence::from_repo_file(
                    PathBuf::from("pyproject.toml"),
                    None,
                    "py >= 3.11",
                ),
            },
            ProjectRequirement {
                name: "port:3000".to_string(),
                kind: RequirementKind::Port {
                    port: 3000,
                    service_hint: None,
                },
                evidence: Evidence::from_repo_file(
                    PathBuf::from("package.json"),
                    None,
                    "port 3000",
                ),
            },
        ];

        let results = evaluate_all(&requirements, &machine);
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.is_violated()));
    }
}

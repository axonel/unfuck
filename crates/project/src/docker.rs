use std::fs;
use std::path::{Path, PathBuf};
use unfuck_core::evidence::Evidence;
use unfuck_core::ir::{ProjectRequirement, RequirementKind};

pub struct DockerDiscovery {
    pub docker_used: bool,
    pub requirements: Vec<ProjectRequirement>,
    pub ports: Vec<u16>,
    pub evidence: Vec<Evidence>,
}

pub fn analyze_docker(root: &Path) -> DockerDiscovery {
    let mut docker_used = false;
    let mut requirements = Vec::new();
    let mut ports = Vec::new();
    let mut evidence = Vec::new();

    // 1. Inspect Dockerfile
    let dockerfile_path = root.join("Dockerfile");
    if dockerfile_path.exists() {
        docker_used = true;
        let ev = Evidence::from_repo_file(PathBuf::from("Dockerfile"), None, "Dockerfile detected");
        evidence.push(ev);

        if let Ok(content) = fs::read_to_string(&dockerfile_path) {
            for (idx, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                // Check EXPOSE
                if let Some(rest) = trimmed.strip_prefix("EXPOSE ") {
                    for part in rest.split_whitespace() {
                        let clean = part.split('/').next().unwrap_or(part);
                        if let Ok(port) = clean.parse::<u16>() {
                            if !ports.contains(&port) {
                                ports.push(port);
                                let ev = Evidence::from_repo_file(
                                    PathBuf::from("Dockerfile"),
                                    Some(idx + 1),
                                    format!("Port {} exposed in Dockerfile", port),
                                );
                                requirements.push(ProjectRequirement {
                                    name: format!("port:{}", port),
                                    kind: RequirementKind::Port {
                                        port,
                                        service_hint: Some("container".to_string()),
                                    },
                                    evidence: ev.clone(),
                                });
                                evidence.push(ev);
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Inspect docker-compose.yml / compose.yaml
    let compose_files = ["docker-compose.yml", "compose.yaml", "docker-compose.yaml"];
    for compose_name in compose_files {
        let compose_path = root.join(compose_name);
        if compose_path.exists() {
            docker_used = true;
            let ev = Evidence::from_repo_file(
                PathBuf::from(compose_name),
                None,
                format!("Docker compose configuration detected ({})", compose_name),
            );
            evidence.push(ev);

            if let Ok(content) = fs::read_to_string(&compose_path) {
                let mut in_ports = false;
                for (idx, line) in content.lines().enumerate() {
                    let trimmed = line.trim();

                    // Check for postgres service image
                    if trimmed.starts_with("image:") && trimmed.contains("postgres") {
                        let ev = Evidence::from_repo_file(
                            PathBuf::from(compose_name),
                            Some(idx + 1),
                            format!("PostgreSQL container image declared: {}", trimmed),
                        );
                        requirements.push(ProjectRequirement {
                            name: "postgresql".to_string(),
                            kind: RequirementKind::Service {
                                name: "postgresql".to_string(),
                                min_version: None,
                            },
                            evidence: ev.clone(),
                        });
                        evidence.push(ev);
                    }

                    // Check ports:
                    if trimmed == "ports:" {
                        in_ports = true;
                        continue;
                    }

                    if in_ports {
                        if trimmed.starts_with("- ") {
                            let port_entry = trimmed
                                .trim_start_matches("- ")
                                .trim_matches('"')
                                .trim_matches('\'');
                            // Format: "HOST:CONTAINER" e.g. "3000:3000" or "127.0.0.1:5432:5432"
                            let parts: Vec<&str> = port_entry.split(':').collect();
                            let host_port_str = if parts.len() >= 2 {
                                parts[parts.len() - 2]
                            } else {
                                parts[0]
                            };

                            if let Ok(port) = host_port_str.parse::<u16>() {
                                if !ports.contains(&port) {
                                    ports.push(port);
                                    let ev = Evidence::from_repo_file(
                                        PathBuf::from(compose_name),
                                        Some(idx + 1),
                                        format!("Port {} mapped in {}", port, compose_name),
                                    );
                                    requirements.push(ProjectRequirement {
                                        name: format!("port:{}", port),
                                        kind: RequirementKind::Port {
                                            port,
                                            service_hint: Some("docker-compose".to_string()),
                                        },
                                        evidence: ev.clone(),
                                    });
                                    evidence.push(ev);
                                }
                            }
                        } else if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            in_ports = false;
                        }
                    }
                }
            }
        }
    }

    if docker_used {
        // Project requires Docker service
        let ev = Evidence::from_repo_file(
            PathBuf::from("Dockerfile/compose"),
            None,
            "Docker service required by project containers",
        );
        requirements.push(ProjectRequirement {
            name: "docker".to_string(),
            kind: RequirementKind::Service {
                name: "docker".to_string(),
                min_version: None,
            },
            evidence: ev.clone(),
        });
        evidence.push(ev);
    }

    DockerDiscovery {
        docker_used,
        requirements,
        ports,
        evidence,
    }
}

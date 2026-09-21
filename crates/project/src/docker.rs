use std::fs;
use std::path::{Path, PathBuf};
use unfuck_core::evidence::Evidence;
use unfuck_core::ir::{ProjectRequirement, RequirementKind};
use unfuck_core::VersionConstraint;

pub struct DockerDiscovery {
    pub docker_used: bool,
    pub requirements: Vec<ProjectRequirement>,
    pub ports: Vec<u16>,
    pub env_vars: Vec<String>,
    pub evidence: Vec<Evidence>,
}

fn parse_base_image(image: &str) -> Option<(&str, Option<&str>)> {
    let base = image.split_whitespace().next()?.split('@').next()?;
    if let Some((name, tag)) = base.split_once(':') {
        Some((name, Some(tag)))
    } else {
        Some((base, None))
    }
}

pub fn analyze_docker(root: &Path) -> DockerDiscovery {
    let mut docker_used = false;
    let mut requirements = Vec::new();
    let mut ports = Vec::new();
    let mut env_vars = Vec::new();
    let mut evidence = Vec::new();

    // 1. Find all Dockerfiles (Dockerfile, Dockerfile.*, Containerfile)
    let mut dockerfiles = Vec::new();
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let fname = entry.file_name();
            let name_str = fname.to_string_lossy();
            if name_str == "Dockerfile"
                || name_str.starts_with("Dockerfile.")
                || name_str == "Containerfile"
            {
                dockerfiles.push(entry.path());
            }
        }
    }

    for df_path in dockerfiles {
        docker_used = true;
        let fname = df_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let ev = Evidence::from_repo_file(
            PathBuf::from(&fname),
            None,
            format!("Dockerfile detected ({})", fname),
        );
        evidence.push(ev);

        if let Ok(content) = fs::read_to_string(&df_path) {
            for (idx, line) in content.lines().enumerate() {
                let trimmed = line.trim();

                // Check FROM base image
                if let Some(rest) = trimmed.strip_prefix("FROM ") {
                    let image_str = rest.split_whitespace().next().unwrap_or("");
                    if let Some((name, tag)) = parse_base_image(image_str) {
                        let clean_name = name.split('/').next_back().unwrap_or(name);
                        match clean_name {
                            "node" | "bun" | "python" | "rust" | "golang" => {
                                let (rt_name, ver_constraint) = match clean_name {
                                    "golang" => {
                                        ("go", tag.map(|t| t.split('-').next().unwrap_or(t)))
                                    }
                                    other => (other, tag.map(|t| t.split('-').next().unwrap_or(t))),
                                };

                                let constraint = ver_constraint
                                    .map(|v| VersionConstraint::GreaterEqual(v.to_string()))
                                    .unwrap_or(VersionConstraint::Any);

                                let ev = Evidence::from_repo_file(
                                    PathBuf::from(&fname),
                                    Some(idx + 1),
                                    format!(
                                        "Runtime '{}' declared in Dockerfile FROM {}",
                                        rt_name, image_str
                                    ),
                                );
                                requirements.push(ProjectRequirement::new(
                                    rt_name,
                                    RequirementKind::Runtime {
                                        name: rt_name.to_string(),
                                        constraint,
                                    },
                                    ev.clone(),
                                ));
                                evidence.push(ev);
                            }
                            "postgres" | "postgresql" => {
                                let ev = Evidence::from_repo_file(
                                    PathBuf::from(&fname),
                                    Some(idx + 1),
                                    format!("PostgreSQL container image declared in {}", fname),
                                );
                                requirements.push(ProjectRequirement::new(
                                    "postgresql",
                                    RequirementKind::Service {
                                        name: "postgresql".to_string(),
                                        min_version: tag.map(|t| t.to_string()),
                                    },
                                    ev.clone(),
                                ));
                                evidence.push(ev);
                                if !ports.contains(&5432) {
                                    ports.push(5432);
                                }
                            }
                            _ => {}
                        }
                    }
                }

                // Check EXPOSE
                if let Some(rest) = trimmed.strip_prefix("EXPOSE ") {
                    for part in rest.split_whitespace() {
                        let clean = part.split('/').next().unwrap_or(part);
                        if let Ok(port) = clean.parse::<u16>() {
                            if !ports.contains(&port) {
                                ports.push(port);
                                let ev = Evidence::from_repo_file(
                                    PathBuf::from(&fname),
                                    Some(idx + 1),
                                    format!("Port {} exposed in {}", port, fname),
                                );
                                requirements.push(ProjectRequirement::new(
                                    format!("port:{}", port),
                                    RequirementKind::Port {
                                        port,
                                        service_hint: Some("docker".to_string()),
                                    },
                                    ev.clone(),
                                ));
                                evidence.push(ev);
                            }
                        }
                    }
                }

                // Check ENV
                if let Some(rest) = trimmed.strip_prefix("ENV ") {
                    let key = rest.split(['=', ' ']).next().unwrap_or("").trim();
                    if !key.is_empty() && !env_vars.contains(&key.to_string()) {
                        env_vars.push(key.to_string());
                    }
                }
            }
        }
    }

    // 2. Inspect docker-compose.yml / compose.yaml / compose.yml
    let compose_files = [
        "docker-compose.yml",
        "docker-compose.yaml",
        "compose.yaml",
        "compose.yml",
    ];

    for compose_name in compose_files {
        let compose_path = root.join(compose_name);
        if compose_path.exists() {
            docker_used = true;
            let ev = Evidence::from_repo_file(
                PathBuf::from(compose_name),
                None,
                format!("Docker Compose configuration detected ({})", compose_name),
            );
            evidence.push(ev);

            if let Ok(content) = fs::read_to_string(&compose_path) {
                let mut in_ports = false;
                let mut in_env = false;

                for (idx, line) in content.lines().enumerate() {
                    let trimmed = line.trim();

                    // Check for postgres service image
                    if (trimmed.starts_with("image:") && trimmed.contains("postgres"))
                        || (trimmed.starts_with("postgres:") || trimmed.starts_with("db:"))
                    {
                        let ev = Evidence::from_repo_file(
                            PathBuf::from(compose_name),
                            Some(idx + 1),
                            format!("PostgreSQL container service declared in {}", compose_name),
                        );
                        requirements.push(ProjectRequirement::new(
                            "postgresql",
                            RequirementKind::Service {
                                name: "postgresql".to_string(),
                                min_version: None,
                            },
                            ev.clone(),
                        ));
                        evidence.push(ev);
                    }

                    if trimmed == "ports:" {
                        in_ports = true;
                        in_env = false;
                        continue;
                    }

                    if trimmed == "environment:" {
                        in_env = true;
                        in_ports = false;
                        continue;
                    }

                    if in_ports {
                        if trimmed.starts_with("- ") {
                            let port_entry = trimmed
                                .trim_start_matches("- ")
                                .trim_matches('"')
                                .trim_matches('\'');
                            // Format: "HOST:CONTAINER" or "127.0.0.1:HOST:CONTAINER"
                            let parts: Vec<&str> = port_entry.split(':').collect();
                            let host_port_str = if parts.len() >= 2 {
                                parts[parts.len() - 2]
                            } else {
                                parts[0]
                            };

                            if let Ok(port) = host_port_str.parse::<u16>() {
                                if !ports.contains(&port) && port > 0 {
                                    ports.push(port);
                                    let ev = Evidence::from_repo_file(
                                        PathBuf::from(compose_name),
                                        Some(idx + 1),
                                        format!("Port {} mapped in {}", port, compose_name),
                                    );
                                    requirements.push(ProjectRequirement::new(
                                        format!("port:{}", port),
                                        RequirementKind::Port {
                                            port,
                                            service_hint: Some("docker-compose".to_string()),
                                        },
                                        ev.clone(),
                                    ));
                                    evidence.push(ev);
                                }
                            }
                        } else if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            in_ports = false;
                        }
                    }

                    if in_env {
                        if trimmed.starts_with("- ") {
                            let item = trimmed.trim_start_matches("- ").trim();
                            let key = item.split('=').next().unwrap_or(item).trim();
                            if !key.is_empty() && !env_vars.contains(&key.to_string()) {
                                env_vars.push(key.to_string());
                            }
                        } else if trimmed.contains(':') && !trimmed.starts_with('#') {
                            let key = trimmed.split(':').next().unwrap_or("").trim();
                            if !key.is_empty() && !env_vars.contains(&key.to_string()) {
                                env_vars.push(key.to_string());
                            }
                        } else if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            in_env = false;
                        }
                    }
                }
            }
        }
    }

    if docker_used {
        let ev = Evidence::from_repo_file(
            PathBuf::from("Dockerfile/compose"),
            None,
            "Docker service required by project containers",
        );
        requirements.push(ProjectRequirement::new(
            "docker",
            RequirementKind::Service {
                name: "docker".to_string(),
                min_version: None,
            },
            ev.clone(),
        ));
        evidence.push(ev);
    }

    DockerDiscovery {
        docker_used,
        requirements,
        ports,
        env_vars,
        evidence,
    }
}

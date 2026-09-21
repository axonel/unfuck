use std::fs;
use std::path::{Path, PathBuf};
use unfuck_core::evidence::Evidence;
use unfuck_core::ir::{ProjectRequirement, RequirementKind};

pub struct EnvDiscovery {
    pub env_vars: Vec<String>,
    pub ports: Vec<u16>,
    pub requirements: Vec<ProjectRequirement>,
    pub evidence: Vec<Evidence>,
}

pub fn analyze_env(root: &Path) -> EnvDiscovery {
    let mut env_vars = Vec::new();
    let mut ports = Vec::new();
    let mut requirements = Vec::new();
    let mut evidence = Vec::new();

    let candidate_files = [".env.example", ".env.sample", ".env.template"];

    for filename in candidate_files {
        let path = root.join(filename);
        if path.exists() {
            let ev = Evidence::from_repo_file(
                PathBuf::from(filename),
                None,
                format!("Environment template file detected ({})", filename),
            );
            evidence.push(ev);

            if let Ok(content) = fs::read_to_string(&path) {
                for (idx, line) in content.lines().enumerate() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() || trimmed.starts_with('#') {
                        continue;
                    }

                    if let Some((key, val)) = trimmed.split_once('=') {
                        let key = key.trim().to_string();
                        let val = val.trim().trim_matches('"').trim_matches('\'').to_string();

                        if !env_vars.contains(&key) {
                            env_vars.push(key.clone());
                        }

                        // Check if key is PORT
                        if key.eq_ignore_ascii_case("PORT") {
                            if let Ok(p) = val.parse::<u16>() {
                                if !ports.contains(&p) && p > 0 {
                                    ports.push(p);
                                    let ev = Evidence::from_repo_file(
                                        PathBuf::from(filename),
                                        Some(idx + 1),
                                        format!("Port {} declared via {}={}", p, key, val),
                                    );
                                    requirements.push(ProjectRequirement {
                                        name: format!("port:{}", p),
                                        kind: RequirementKind::Port {
                                            port: p,
                                            service_hint: Some("environment".to_string()),
                                        },
                                        evidence: ev.clone(),
                                    });
                                    evidence.push(ev);
                                }
                            }
                        }

                        // Check if key is DATABASE_URL and contains postgres
                        if key.contains("DATABASE") && val.contains("postgres") {
                            let ev = Evidence::from_repo_file(
                                PathBuf::from(filename),
                                Some(idx + 1),
                                format!("PostgreSQL database requirement inferred from {}", key),
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

                        let ev = Evidence::from_repo_file(
                            PathBuf::from(filename),
                            Some(idx + 1),
                            format!("Environment variable required: {}", key),
                        );
                        requirements.push(ProjectRequirement {
                            name: key.clone(),
                            kind: RequirementKind::EnvVar {
                                name: key,
                                default_value: if val.is_empty() { None } else { Some(val) },
                                required: true,
                            },
                            evidence: ev.clone(),
                        });
                    }
                }
            }
        }
    }

    EnvDiscovery {
        env_vars,
        ports,
        requirements,
        evidence,
    }
}

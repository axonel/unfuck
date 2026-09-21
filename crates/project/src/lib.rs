pub mod docker;
pub mod env;
pub mod go;
pub mod node;
pub mod python;
pub mod rust;
pub mod tool_versions;

use std::fs;
use std::path::{Path, PathBuf};
use unfuck_core::error::Result;
use unfuck_core::evidence::Evidence;
use unfuck_core::ir::{ProjectComponent, ProjectManifest, ProjectRequirement, RequirementKind};
use unfuck_core::Confidence;

/// Check if two version constraints conflict (e.g. ">=20" / "20" vs ">=22" or "<20" vs ">=20").
fn are_constraints_conflicting(c1: &str, c2: &str) -> bool {
    // Basic normalization
    let norm = |s: &str| -> String {
        s.trim()
            .trim_start_matches('v')
            .trim_start_matches('=')
            .to_string()
    };

    let s1 = norm(c1);
    let s2 = norm(c2);

    // If exact versions and not equal, conflict
    if let (Ok(v1), Ok(v2)) = (semver::Version::parse(&s1), semver::Version::parse(&s2)) {
        return v1 != v2;
    }

    // Check if one is exact number (e.g. "20" or "20.0.0") and other is ">=22"
    let extract_major = |s: &str| -> Option<u32> {
        let clean = s.trim_start_matches(['>', '=', '<', '^', '~', ' ']);
        clean.split(['.', '-']).next()?.parse::<u32>().ok()
    };

    let m1 = extract_major(&s1);
    let m2 = extract_major(&s2);

    if let (Some(major1), Some(major2)) = (m1, m2) {
        // e.g. .nvmrc has "20", package.json has ">=22"
        if !s1.contains('>') && s2.starts_with(">=") && major1 < major2 {
            return true;
        }
        if !s2.contains('>') && s1.starts_with(">=") && major2 < major1 {
            return true;
        }
        // e.g. "<20" vs ">=20"
        if s1.starts_with('<') && s2.starts_with('>') && major1 <= major2 {
            return true;
        }
        if s2.starts_with('<') && s1.starts_with('>') && major2 <= major1 {
            return true;
        }
    }

    false
}

/// Detect conflicts across multiple configuration sources within requirements.
fn detect_runtime_conflicts(requirements: &[ProjectRequirement]) -> Vec<ProjectRequirement> {
    let mut conflicts = Vec::new();
    let runtimes = ["node", "python", "rust", "go"];

    for rt in runtimes {
        let rt_reqs: Vec<&ProjectRequirement> = requirements
            .iter()
            .filter(|r| r.name == rt && matches!(r.kind, RequirementKind::Runtime { .. }))
            .collect();

        if rt_reqs.len() > 1 {
            for i in 0..rt_reqs.len() {
                for j in (i + 1)..rt_reqs.len() {
                    let r1 = rt_reqs[i];
                    let r2 = rt_reqs[j];
                    if let (
                        RequirementKind::Runtime { constraint: c1, .. },
                        RequirementKind::Runtime { constraint: c2, .. },
                    ) = (&r1.kind, &r2.kind)
                    {
                        if are_constraints_conflicting(c1, c2) {
                            let p1 = match &r1.evidence.source {
                                unfuck_core::evidence::EvidenceSource::RepositoryFile {
                                    path,
                                    ..
                                } => path.clone(),
                                _ => PathBuf::from("config1"),
                            };
                            let p2 = match &r2.evidence.source {
                                unfuck_core::evidence::EvidenceSource::RepositoryFile {
                                    path,
                                    ..
                                } => path.clone(),
                                _ => PathBuf::from("config2"),
                            };

                            let ev = Evidence::new(
                                unfuck_core::evidence::EvidenceSource::MultiSourceConflict {
                                    summary: format!(
                                        "Contradictory {} version requirements: '{}' vs '{}'",
                                        rt, c1, c2
                                    ),
                                    files: vec![p1.clone(), p2.clone()],
                                },
                                Confidence::Confirmed,
                                format!(
                                    "Configuration conflict: {} ({}) conflicts with {} ({})",
                                    r1.evidence.description,
                                    p1.display(),
                                    r2.evidence.description,
                                    p2.display()
                                ),
                            );

                            conflicts.push(ProjectRequirement {
                                name: format!("conflict:{}", rt),
                                kind: RequirementKind::Conflict {
                                    target: rt.to_string(),
                                    details: format!(
                                        "Contradictory {} version requirements: {} vs {}",
                                        rt, c1, c2
                                    ),
                                    competing_sources: vec![
                                        r1.evidence.description.clone(),
                                        r2.evidence.description.clone(),
                                    ],
                                },
                                evidence: ev,
                            });
                        }
                    }
                }
            }
        }
    }

    conflicts
}

struct DirAnalysis {
    languages: Vec<String>,
    package_managers: Vec<String>,
    requirements: Vec<ProjectRequirement>,
    declared_ports: Vec<u16>,
    env_vars: Vec<String>,
    env_var_specs: Vec<unfuck_core::ir::EnvVarSpec>,
    docker_used: bool,
    evidence: Vec<Evidence>,
}

/// Helper to analyze a specific directory for languages, requirements, and ports.
fn analyze_dir(dir: &Path) -> DirAnalysis {
    let node_disc = node::analyze_node(dir);
    let py_disc = python::analyze_python(dir);
    let rust_disc = rust::analyze_rust(dir);
    let go_disc = go::analyze_go(dir);
    let docker_disc = docker::analyze_docker(dir);
    let env_disc = env::analyze_env(dir);
    let tool_disc = tool_versions::analyze_tool_versions(dir);

    let mut languages = Vec::new();
    if node_disc.is_node {
        languages.push("javascript/typescript".to_string());
    }
    if node_disc.is_bun {
        languages.push("bun".to_string());
    }
    if py_disc.is_python {
        languages.push("python".to_string());
    }
    if rust_disc.is_rust {
        languages.push("rust".to_string());
    }
    if go_disc.is_go {
        languages.push("go".to_string());
    }

    let mut package_managers = node_disc.package_managers;
    package_managers.extend(py_disc.package_managers);
    package_managers.extend(rust_disc.package_managers);
    package_managers.extend(go_disc.package_managers);
    package_managers.sort();
    package_managers.dedup();

    let mut requirements = node_disc.requirements;
    requirements.extend(py_disc.requirements);
    requirements.extend(rust_disc.requirements);
    requirements.extend(go_disc.requirements);
    requirements.extend(docker_disc.requirements);
    requirements.extend(env_disc.requirements);
    requirements.extend(tool_disc.requirements);

    let mut declared_ports = node_disc.ports;
    declared_ports.extend(py_disc.ports);
    declared_ports.extend(docker_disc.ports);
    declared_ports.extend(env_disc.ports);
    declared_ports.sort();
    declared_ports.dedup();

    let mut env_vars = docker_disc.env_vars;
    env_vars.extend(env_disc.env_vars);
    env_vars.sort();
    env_vars.dedup();

    let mut evidence = node_disc.evidence;
    evidence.extend(py_disc.evidence);
    evidence.extend(rust_disc.evidence);
    evidence.extend(go_disc.evidence);
    evidence.extend(docker_disc.evidence);
    evidence.extend(env_disc.evidence);
    evidence.extend(tool_disc.evidence);

    let docker_used = docker_disc.docker_used;
    let env_var_specs = env_disc.env_var_specs;

    DirAnalysis {
        languages,
        package_managers,
        requirements,
        declared_ports,
        env_vars,
        env_var_specs,
        docker_used,
        evidence,
    }
}

/// Analyze a project repository deterministically and produce a structured manifest.
pub fn analyze_project(root: &Path) -> Result<ProjectManifest> {
    if !root.exists() {
        return Err(unfuck_core::UnfuckError::ProjectAnalysis(format!(
            "Target path '{}' does not exist",
            root.display()
        )));
    }
    if !root.is_dir() {
        return Err(unfuck_core::UnfuckError::ProjectAnalysis(format!(
            "Target path '{}' is not a directory",
            root.display()
        )));
    }

    let root_buf = root.canonicalize().map_err(unfuck_core::UnfuckError::Io)?;

    // 1. Analyze root directory
    let root_analysis = analyze_dir(&root_buf);
    let mut languages = root_analysis.languages;
    let mut package_managers = root_analysis.package_managers;
    let mut requirements = root_analysis.requirements;
    let mut declared_ports = root_analysis.declared_ports;
    let mut env_vars = root_analysis.env_vars;
    let mut env_var_specs = root_analysis.env_var_specs;
    let mut docker_used = root_analysis.docker_used;
    let mut evidence = root_analysis.evidence;

    // 2. Discover subcomponents (monorepo packages, frontend/backend directories, crates)
    let mut components = Vec::new();
    let candidate_subdirs = [
        "web", "frontend", "client", "ui", "backend", "server", "api", "services", "desktop",
        "mobile", "site",
    ];

    let mut candidate_paths = Vec::new();
    for sub in candidate_subdirs {
        let p = root_buf.join(sub);
        if p.is_dir() {
            candidate_paths.push((sub.to_string(), p));
        }
    }

    // Also inspect crates/* and packages/* and apps/*
    for group in ["crates", "packages", "apps"] {
        let group_dir = root_buf.join(group);
        if group_dir.is_dir() {
            if let Ok(entries) = fs::read_dir(&group_dir) {
                for entry in entries.flatten() {
                    if entry.path().is_dir() {
                        let name = format!("{}/{}", group, entry.file_name().to_string_lossy());
                        candidate_paths.push((name, entry.path()));
                    }
                }
            }
        }
    }

    for (comp_name, comp_path) in candidate_paths {
        let c_analysis = analyze_dir(&comp_path);
        if !c_analysis.languages.is_empty()
            || !c_analysis.requirements.is_empty()
            || !c_analysis.declared_ports.is_empty()
            || !c_analysis.env_vars.is_empty()
        {
            // Register component
            components.push(ProjectComponent {
                name: comp_name,
                path: comp_path,
                languages: c_analysis.languages.clone(),
                package_managers: c_analysis.package_managers.clone(),
                requirements: c_analysis.requirements.clone(),
                declared_ports: c_analysis.declared_ports.clone(),
                env_vars: c_analysis.env_vars.clone(),
            });

            // Merge up to root manifest
            languages.extend(c_analysis.languages);
            package_managers.extend(c_analysis.package_managers);
            requirements.extend(c_analysis.requirements);
            declared_ports.extend(c_analysis.declared_ports);
            env_vars.extend(c_analysis.env_vars);
            env_var_specs.extend(c_analysis.env_var_specs);
            docker_used |= c_analysis.docker_used;
            evidence.extend(c_analysis.evidence);
        }
    }

    languages.sort();
    languages.dedup();
    package_managers.sort();
    package_managers.dedup();
    declared_ports.sort();
    declared_ports.dedup();
    env_vars.sort();
    env_vars.dedup();

    // 3. Detect any conflicting requirements across sources
    let conflicts = detect_runtime_conflicts(&requirements);
    requirements.extend(conflicts);

    let name = root_buf
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "project".to_string());

    Ok(ProjectManifest {
        name,
        root_path: root_buf,
        languages,
        package_managers,
        requirements,
        declared_ports,
        env_vars,
        env_var_specs,
        components,
        docker_used,
        evidence,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_analyze_empty_directory() {
        let dir = tempdir().unwrap();
        let manifest = analyze_project(dir.path()).unwrap();
        assert!(manifest.languages.is_empty());
        assert!(manifest.package_managers.is_empty());
        assert!(manifest.requirements.is_empty());
        assert!(manifest.declared_ports.is_empty());
    }

    #[test]
    fn test_analyze_node_project() {
        let dir = tempdir().unwrap();
        let pkg_json = r#"{
            "name": "my-node-app",
            "engines": {
                "node": ">=20.0.0"
            },
            "scripts": {
                "dev": "vite --port 3000"
            }
        }"#;
        fs::write(dir.path().join("package.json"), pkg_json).unwrap();
        fs::write(dir.path().join("bun.lock"), "").unwrap();

        let manifest = analyze_project(dir.path()).unwrap();
        assert!(manifest
            .languages
            .contains(&"javascript/typescript".to_string()));
        assert!(manifest.languages.contains(&"bun".to_string()));
        assert!(manifest.package_managers.contains(&"bun".to_string()));
        assert!(manifest.declared_ports.contains(&3000));

        let node_req = manifest.requirements.iter().find(|r| r.name == "node");
        assert!(node_req.is_some());
    }

    #[test]
    fn test_analyze_rust_project() {
        let dir = tempdir().unwrap();
        let cargo_toml = r#"[package]
name = "my-rust-app"
version = "0.1.0"
edition = "2021"
rust-version = "1.85"

[dependencies]
sqlx = { version = "0.8", features = ["postgres"] }
"#;
        fs::write(dir.path().join("Cargo.toml"), cargo_toml).unwrap();

        let manifest = analyze_project(dir.path()).unwrap();
        assert!(manifest.languages.contains(&"rust".to_string()));
        assert!(manifest.package_managers.contains(&"cargo".to_string()));

        let rust_req = manifest.requirements.iter().find(|r| r.name == "rust");
        assert!(rust_req.is_some());
        if let Some(r) = rust_req {
            if let RequirementKind::Runtime { constraint, .. } = &r.kind {
                assert_eq!(constraint, ">=1.85");
            } else {
                panic!("Expected Runtime requirement");
            }
        }

        let pg_req = manifest
            .requirements
            .iter()
            .find(|r| r.name == "postgresql");
        assert!(pg_req.is_some());
    }

    #[test]
    fn test_analyze_multi_component_project() {
        let dir = tempdir().unwrap();
        let web_dir = dir.path().join("web");
        fs::create_dir_all(&web_dir).unwrap();
        let pkg_json = r#"{
            "name": "web-frontend",
            "dependencies": { "vite": "^5.0.0" },
            "scripts": { "dev": "vite" }
        }"#;
        fs::write(web_dir.join("package.json"), pkg_json).unwrap();

        let backend_dir = dir.path().join("backend");
        fs::create_dir_all(&backend_dir).unwrap();
        let pyproject = r#"[project]
name = "backend-api"
requires-python = ">=3.11"
dependencies = ["fastapi>=0.110.0"]
"#;
        fs::write(backend_dir.join("pyproject.toml"), pyproject).unwrap();

        let manifest = analyze_project(dir.path()).unwrap();
        assert!(manifest
            .languages
            .contains(&"javascript/typescript".to_string()));
        assert!(manifest.languages.contains(&"python".to_string()));
        assert_eq!(manifest.components.len(), 2);
        assert!(manifest.declared_ports.contains(&5173)); // Vite default
        assert!(manifest.declared_ports.contains(&8000)); // FastAPI default
    }

    #[test]
    fn test_analyze_runtime_conflict() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join(".nvmrc"), "20\n").unwrap();
        let pkg_json = r#"{
            "name": "conflicted-app",
            "engines": {
                "node": ">=22.0.0"
            }
        }"#;
        fs::write(dir.path().join("package.json"), pkg_json).unwrap();

        let manifest = analyze_project(dir.path()).unwrap();
        let conflict = manifest
            .requirements
            .iter()
            .find(|r| r.name == "conflict:node");
        assert!(conflict.is_some(), "Expected conflict:node to be detected");
    }

    #[test]
    fn test_analyze_nonexistent_path() {
        let path = Path::new("/path/that/definitely/does/not/exist/9999");
        let result = analyze_project(path);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("does not exist"));
    }

    #[test]
    fn test_analyze_file_not_dir() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("some_file.txt");
        fs::write(&file_path, "hello").unwrap();
        let result = analyze_project(&file_path);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("is not a directory"));
    }
}

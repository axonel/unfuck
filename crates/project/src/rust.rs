use std::fs;
use std::path::{Path, PathBuf};
use toml::Value;
use unfuck_core::evidence::Evidence;
use unfuck_core::ir::{ProjectRequirement, RequirementKind};
use unfuck_core::Confidence;
use unfuck_core::VersionConstraint;

pub struct RustDiscovery {
    pub is_rust: bool,
    pub requirements: Vec<ProjectRequirement>,
    pub package_managers: Vec<String>,
    pub evidence: Vec<Evidence>,
}

/// Analyze Rust projects (Cargo.toml, rust-toolchain.toml, rust-toolchain).
pub fn analyze_rust(root: &Path) -> RustDiscovery {
    let mut is_rust = false;
    let mut requirements = Vec::new();
    let mut package_managers = Vec::new();
    let mut evidence = Vec::new();

    let cargo_toml_path = root.join("Cargo.toml");
    if cargo_toml_path.exists() {
        is_rust = true;
        package_managers.push("cargo".to_string());

        let ev = Evidence::from_repo_file(
            PathBuf::from("Cargo.toml"),
            None,
            "Rust project detected via Cargo.toml",
        );
        evidence.push(ev);

        match fs::read_to_string(&cargo_toml_path) {
            Ok(content) => match content.parse::<Value>() {
                Ok(toml) => {
                    // 1. Check rust-version in [package]
                    let pkg_rust_ver = toml
                        .get("package")
                        .and_then(|p| p.get("rust-version"))
                        .and_then(|v| v.as_str());

                    // Check rust-version in [workspace.package]
                    let ws_rust_ver = toml
                        .get("workspace")
                        .and_then(|w| w.get("package"))
                        .and_then(|p| p.get("rust-version"))
                        .and_then(|v| v.as_str());

                    let rust_ver = pkg_rust_ver.or(ws_rust_ver);

                    if let Some(ver) = rust_ver {
                        let ev = Evidence::from_repo_file(
                            PathBuf::from("Cargo.toml"),
                            None,
                            format!("Rust MSRV declared in rust-version: {}", ver),
                        );
                        requirements.push(ProjectRequirement::new(
                            "rust",
                            RequirementKind::Runtime {
                                name: "rust".to_string(),
                                constraint: VersionConstraint::GreaterEqual(ver.to_string()),
                            },
                            ev.clone(),
                        ));
                        evidence.push(ev);
                    } else {
                        // General Rust runtime requirement
                        let ev = Evidence::new(
                            unfuck_core::evidence::EvidenceSource::RepositoryFile {
                                path: PathBuf::from("Cargo.toml"),
                                line: None,
                                detail: Some("Cargo project configuration present".to_string()),
                            },
                            Confidence::High,
                            "Rust toolchain required by Cargo project",
                        );
                        requirements.push(ProjectRequirement::new(
                            "rust",
                            RequirementKind::Runtime {
                                name: "rust".to_string(),
                                constraint: VersionConstraint::Any,
                            },
                            ev.clone(),
                        ));
                        evidence.push(ev);
                    }

                    // 2. Check for database client dependencies (sqlx, diesel, tokio-postgres, postgres)
                    let check_db = |name: &str| -> bool {
                        let in_deps = toml.get("dependencies").and_then(|d| d.get(name)).is_some();
                        let in_ws_deps = toml
                            .get("workspace")
                            .and_then(|w| w.get("dependencies"))
                            .and_then(|d| d.get(name))
                            .is_some();
                        in_deps || in_ws_deps
                    };

                    if check_db("sqlx")
                        || check_db("diesel")
                        || check_db("postgres")
                        || check_db("tokio-postgres")
                    {
                        let ev = Evidence::from_repo_file(
                            PathBuf::from("Cargo.toml"),
                            None,
                            "PostgreSQL client crate detected in Cargo dependencies",
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
                }
                Err(e) => {
                    evidence.push(Evidence::new(
                        unfuck_core::evidence::EvidenceSource::RepositoryFile {
                            path: PathBuf::from("Cargo.toml"),
                            line: None,
                            detail: Some(e.to_string()),
                        },
                        Confidence::Confirmed,
                        format!("Syntax error in Cargo.toml: {}", e),
                    ));
                }
            },
            Err(e) => {
                evidence.push(Evidence::new(
                    unfuck_core::evidence::EvidenceSource::RepositoryFile {
                        path: PathBuf::from("Cargo.toml"),
                        line: None,
                        detail: Some(e.to_string()),
                    },
                    Confidence::Confirmed,
                    format!("Failed to read Cargo.toml: {}", e),
                ));
            }
        }
    }

    // 2. Check rust-toolchain.toml or rust-toolchain
    let toolchain_toml = root.join("rust-toolchain.toml");
    let toolchain_plain = root.join("rust-toolchain");

    if toolchain_toml.exists() {
        is_rust = true;
        if let Ok(content) = fs::read_to_string(&toolchain_toml) {
            if let Ok(toml) = content.parse::<Value>() {
                if let Some(channel) = toml
                    .get("toolchain")
                    .and_then(|t| t.get("channel"))
                    .and_then(|c| c.as_str())
                {
                    let ev = Evidence::from_repo_file(
                        PathBuf::from("rust-toolchain.toml"),
                        None,
                        format!("Rust toolchain channel specified: {}", channel),
                    );
                    requirements.push(ProjectRequirement::new(
                        "rust",
                        RequirementKind::Runtime {
                            name: "rust".to_string(),
                            constraint: VersionConstraint::parse(channel),
                        },
                        ev.clone(),
                    ));
                    evidence.push(ev);
                }
            }
        }
    } else if toolchain_plain.exists() {
        is_rust = true;
        if let Ok(content) = fs::read_to_string(&toolchain_plain) {
            let channel = content.trim();
            if !channel.is_empty() {
                let ev = Evidence::from_repo_file(
                    PathBuf::from("rust-toolchain"),
                    None,
                    format!("Rust toolchain channel specified: {}", channel),
                );
                requirements.push(ProjectRequirement::new(
                    "rust",
                    RequirementKind::Runtime {
                        name: "rust".to_string(),
                        constraint: VersionConstraint::parse(channel),
                    },
                    ev.clone(),
                ));
                evidence.push(ev);
            }
        }
    }

    RustDiscovery {
        is_rust,
        requirements,
        package_managers,
        evidence,
    }
}

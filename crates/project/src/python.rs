use std::fs;
use std::path::{Path, PathBuf};
use toml::Value;
use unfuck_core::evidence::Evidence;
use unfuck_core::ir::{ProjectRequirement, RequirementKind};

pub struct PythonDiscovery {
    pub is_python: bool,
    pub package_managers: Vec<String>,
    pub requirements: Vec<ProjectRequirement>,
    pub evidence: Vec<Evidence>,
}

pub fn analyze_python(root: &Path) -> PythonDiscovery {
    let mut is_python = false;
    let mut package_managers = Vec::new();
    let mut requirements = Vec::new();
    let mut evidence = Vec::new();

    // 1. Lockfiles
    if root.join("uv.lock").exists() {
        is_python = true;
        package_managers.push("uv".to_string());
        evidence.push(Evidence::from_repo_file(
            PathBuf::from("uv.lock"),
            None,
            "uv lockfile detected",
        ));
    }
    if root.join("poetry.lock").exists() {
        is_python = true;
        package_managers.push("poetry".to_string());
        evidence.push(Evidence::from_repo_file(
            PathBuf::from("poetry.lock"),
            None,
            "Poetry lockfile detected",
        ));
    }
    if root.join("Pipfile").exists() || root.join("Pipfile.lock").exists() {
        is_python = true;
        package_managers.push("pipenv".to_string());
        evidence.push(Evidence::from_repo_file(
            PathBuf::from("Pipfile"),
            None,
            "Pipfile detected",
        ));
    }

    // 2. .python-version
    let py_ver_path = root.join(".python-version");
    if py_ver_path.exists() {
        if let Ok(content) = fs::read_to_string(&py_ver_path) {
            let ver = content.trim().to_string();
            if !ver.is_empty() {
                is_python = true;
                let ev = Evidence::from_repo_file(
                    PathBuf::from(".python-version"),
                    Some(1),
                    format!("Python version specified in .python-version: {}", ver),
                );
                requirements.push(ProjectRequirement {
                    name: "python".to_string(),
                    kind: RequirementKind::Runtime {
                        name: "python".to_string(),
                        constraint: format!(">={}", ver),
                    },
                    evidence: ev.clone(),
                });
                evidence.push(ev);
            }
        }
    }

    // 3. pyproject.toml
    let pyproject_path = root.join("pyproject.toml");
    if pyproject_path.exists() {
        is_python = true;
        if let Ok(content) = fs::read_to_string(&pyproject_path) {
            if let Ok(toml) = content.parse::<Value>() {
                // Check [project] requires-python
                if let Some(req_py) = toml
                    .get("project")
                    .and_then(|p| p.get("requires-python"))
                    .and_then(|v| v.as_str())
                {
                    let ev = Evidence::from_repo_file(
                        PathBuf::from("pyproject.toml"),
                        None,
                        format!(
                            "Python requirement declared in [project].requires-python: {}",
                            req_py
                        ),
                    );
                    requirements.push(ProjectRequirement {
                        name: "python".to_string(),
                        kind: RequirementKind::Runtime {
                            name: "python".to_string(),
                            constraint: req_py.to_string(),
                        },
                        evidence: ev.clone(),
                    });
                    evidence.push(ev);
                }

                // Check [tool.poetry.dependencies.python]
                if let Some(poetry_py) = toml
                    .get("tool")
                    .and_then(|t| t.get("poetry"))
                    .and_then(|p| p.get("dependencies"))
                    .and_then(|d| d.get("python"))
                    .and_then(|v| v.as_str())
                {
                    let ev = Evidence::from_repo_file(
                        PathBuf::from("pyproject.toml"),
                        None,
                        format!(
                            "Python requirement declared in Poetry dependencies: {}",
                            poetry_py
                        ),
                    );
                    requirements.push(ProjectRequirement {
                        name: "python".to_string(),
                        kind: RequirementKind::Runtime {
                            name: "python".to_string(),
                            constraint: poetry_py.to_string(),
                        },
                        evidence: ev.clone(),
                    });
                    evidence.push(ev);
                }

                // Check dependencies for PostgreSQL drivers (psycopg, psycopg2, asyncpg)
                let check_dep = |name: &str| -> bool {
                    let in_project = toml
                        .get("project")
                        .and_then(|p| p.get("dependencies"))
                        .and_then(|d| d.as_array())
                        .map(|arr| {
                            arr.iter()
                                .any(|v| v.as_str().map(|s| s.starts_with(name)).unwrap_or(false))
                        })
                        .unwrap_or(false);

                    let in_poetry = toml
                        .get("tool")
                        .and_then(|t| t.get("poetry"))
                        .and_then(|p| p.get("dependencies"))
                        .and_then(|d| d.get(name))
                        .is_some();

                    in_project || in_poetry
                };

                if check_dep("psycopg") || check_dep("psycopg2") || check_dep("asyncpg") {
                    let ev = Evidence::from_repo_file(
                        PathBuf::from("pyproject.toml"),
                        None,
                        "PostgreSQL driver detected in Python dependencies",
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
            }
        }
    }

    // 4. requirements.txt
    let req_txt_path = root.join("requirements.txt");
    if req_txt_path.exists() {
        is_python = true;
        if let Ok(content) = fs::read_to_string(&req_txt_path) {
            let mut found_pg = false;
            for (idx, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.starts_with("psycopg") || trimmed.starts_with("asyncpg") {
                    found_pg = true;
                    let ev = Evidence::from_repo_file(
                        PathBuf::from("requirements.txt"),
                        Some(idx + 1),
                        format!("PostgreSQL library detected: {}", trimmed),
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
                    break;
                }
            }
            if !found_pg {
                evidence.push(Evidence::from_repo_file(
                    PathBuf::from("requirements.txt"),
                    None,
                    "Python requirements.txt file detected",
                ));
            }
        }
    }

    PythonDiscovery {
        is_python,
        package_managers,
        requirements,
        evidence,
    }
}

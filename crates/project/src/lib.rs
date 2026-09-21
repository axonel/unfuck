pub mod docker;
pub mod env;
pub mod node;
pub mod python;
pub mod tool_versions;

use std::path::Path;
use unfuck_core::error::Result;
use unfuck_core::ir::ProjectManifest;

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

    let node_disc = node::analyze_node(&root_buf);
    let py_disc = python::analyze_python(&root_buf);
    let docker_disc = docker::analyze_docker(&root_buf);
    let env_disc = env::analyze_env(&root_buf);
    let tool_disc = tool_versions::analyze_tool_versions(&root_buf);

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

    let mut package_managers = node_disc.package_managers;
    package_managers.extend(py_disc.package_managers);
    package_managers.sort();
    package_managers.dedup();

    let mut requirements = node_disc.requirements;
    requirements.extend(py_disc.requirements);
    requirements.extend(docker_disc.requirements);
    requirements.extend(env_disc.requirements);
    requirements.extend(tool_disc.requirements);

    let mut declared_ports = node_disc.ports;
    declared_ports.extend(docker_disc.ports);
    declared_ports.extend(env_disc.ports);
    declared_ports.sort();
    declared_ports.dedup();

    let mut env_vars = env_disc.env_vars;
    env_vars.sort();
    env_vars.dedup();

    let mut evidence = node_disc.evidence;
    evidence.extend(py_disc.evidence);
    evidence.extend(docker_disc.evidence);
    evidence.extend(env_disc.evidence);
    evidence.extend(tool_disc.evidence);

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
        docker_used: docker_disc.docker_used,
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
    fn test_analyze_python_project() {
        let dir = tempdir().unwrap();
        let pyproject = r#"[project]
name = "my-py-app"
requires-python = ">=3.11"
dependencies = [
    "fastapi>=0.110.0",
    "psycopg2-binary>=2.9.9",
]
"#;
        fs::write(dir.path().join("pyproject.toml"), pyproject).unwrap();
        fs::write(dir.path().join("uv.lock"), "").unwrap();

        let manifest = analyze_project(dir.path()).unwrap();
        assert!(manifest.languages.contains(&"python".to_string()));
        assert!(manifest.package_managers.contains(&"uv".to_string()));

        let py_req = manifest.requirements.iter().find(|r| r.name == "python");
        assert!(py_req.is_some());

        let pg_req = manifest
            .requirements
            .iter()
            .find(|r| r.name == "postgresql");
        assert!(pg_req.is_some());
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

    #[test]
    fn test_analyze_malformed_package_json() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("package.json"), "{ invalid json").unwrap();
        let manifest = analyze_project(dir.path()).unwrap();
        let syntax_evidence = manifest
            .evidence
            .iter()
            .find(|e| e.description.contains("Syntax error in package.json"));
        assert!(syntax_evidence.is_some());
    }

    #[test]
    fn test_analyze_malformed_pyproject_toml() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("pyproject.toml"), "[invalid toml").unwrap();
        let manifest = analyze_project(dir.path()).unwrap();
        let syntax_evidence = manifest
            .evidence
            .iter()
            .find(|e| e.description.contains("Syntax error in pyproject.toml"));
        assert!(syntax_evidence.is_some());
    }
}

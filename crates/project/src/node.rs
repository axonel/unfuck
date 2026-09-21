use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use unfuck_core::evidence::Evidence;
use unfuck_core::ir::{ProjectRequirement, RequirementKind};

pub struct NodeDiscovery {
    pub is_node: bool,
    pub is_bun: bool,
    pub package_managers: Vec<String>,
    pub requirements: Vec<ProjectRequirement>,
    pub ports: Vec<u16>,
    pub scripts: Vec<String>,
    pub evidence: Vec<Evidence>,
}

pub fn analyze_node(root: &Path) -> NodeDiscovery {
    let mut is_node = false;
    let mut is_bun = false;
    let mut package_managers = Vec::new();
    let mut requirements = Vec::new();
    let mut ports = Vec::new();
    let mut scripts = Vec::new();
    let mut evidence = Vec::new();

    // 1. Check lockfiles
    if root.join("bun.lock").exists() || root.join("bun.lockb").exists() {
        is_bun = true;
        is_node = true;
        package_managers.push("bun".to_string());
        evidence.push(Evidence::from_repo_file(
            PathBuf::from("bun.lock"),
            None,
            "Bun lockfile detected",
        ));
    }
    if root.join("pnpm-lock.yaml").exists() {
        is_node = true;
        package_managers.push("pnpm".to_string());
        evidence.push(Evidence::from_repo_file(
            PathBuf::from("pnpm-lock.yaml"),
            None,
            "pnpm lockfile detected",
        ));
    }
    if root.join("yarn.lock").exists() {
        is_node = true;
        package_managers.push("yarn".to_string());
        evidence.push(Evidence::from_repo_file(
            PathBuf::from("yarn.lock"),
            None,
            "yarn lockfile detected",
        ));
    }
    if root.join("package-lock.json").exists() {
        is_node = true;
        package_managers.push("npm".to_string());
        evidence.push(Evidence::from_repo_file(
            PathBuf::from("package-lock.json"),
            None,
            "npm lockfile detected",
        ));
    }

    // 2. Check .nvmrc
    let nvmrc_path = root.join(".nvmrc");
    if nvmrc_path.exists() {
        if let Ok(content) = fs::read_to_string(&nvmrc_path) {
            let ver = content.trim().trim_start_matches('v').to_string();
            if !ver.is_empty() {
                is_node = true;
                let ev = Evidence::from_repo_file(
                    PathBuf::from(".nvmrc"),
                    Some(1),
                    format!("Node version specified in .nvmrc: {}", ver),
                );
                requirements.push(ProjectRequirement {
                    name: "node".to_string(),
                    kind: RequirementKind::Runtime {
                        name: "node".to_string(),
                        constraint: format!(">={}", ver),
                    },
                    evidence: ev.clone(),
                });
                evidence.push(ev);
            }
        }
    }

    // 3. Check package.json
    let pkg_path = root.join("package.json");
    if pkg_path.exists() {
        is_node = true;
        if let Ok(content) = fs::read_to_string(&pkg_path) {
            if let Ok(json) = serde_json::from_str::<Value>(&content) {
                // engines.node
                if let Some(engines) = json.get("engines") {
                    if let Some(node_engine) = engines.get("node").and_then(|v| v.as_str()) {
                        let ev = Evidence::from_repo_file(
                            PathBuf::from("package.json"),
                            None,
                            format!("Node version declared in engines.node: {}", node_engine),
                        );
                        requirements.push(ProjectRequirement {
                            name: "node".to_string(),
                            kind: RequirementKind::Runtime {
                                name: "node".to_string(),
                                constraint: node_engine.to_string(),
                            },
                            evidence: ev.clone(),
                        });
                        evidence.push(ev);
                    }
                    if let Some(npm_engine) = engines.get("npm").and_then(|v| v.as_str()) {
                        let ev = Evidence::from_repo_file(
                            PathBuf::from("package.json"),
                            None,
                            format!("npm version declared in engines.npm: {}", npm_engine),
                        );
                        requirements.push(ProjectRequirement {
                            name: "npm".to_string(),
                            kind: RequirementKind::PackageManager {
                                name: "npm".to_string(),
                                constraint: Some(npm_engine.to_string()),
                            },
                            evidence: ev.clone(),
                        });
                        evidence.push(ev);
                    }
                }

                // packageManager field (e.g. "pnpm@9.0.0")
                if let Some(pm) = json.get("packageManager").and_then(|v| v.as_str()) {
                    let parts: Vec<&str> = pm.split('@').collect();
                    let pm_name = parts[0].to_string();
                    let pm_ver = parts.get(1).map(|s| s.to_string());
                    if !package_managers.contains(&pm_name) {
                        package_managers.push(pm_name.clone());
                    }
                    let ev = Evidence::from_repo_file(
                        PathBuf::from("package.json"),
                        None,
                        format!("Package manager specified: {}", pm),
                    );
                    requirements.push(ProjectRequirement {
                        name: pm_name.clone(),
                        kind: RequirementKind::PackageManager {
                            name: pm_name,
                            constraint: pm_ver,
                        },
                        evidence: ev.clone(),
                    });
                    evidence.push(ev);
                }

                // Scripts
                if let Some(scripts_obj) = json.get("scripts").and_then(|v| v.as_object()) {
                    for (name, script_val) in scripts_obj {
                        scripts.push(name.clone());
                        if let Some(script_str) = script_val.as_str() {
                            // Detect port flags e.g. --port 3000 or -p 4017 or PORT=3000
                            scan_text_for_ports(script_str, &mut ports);
                        }
                    }
                }

                // Dependencies: check if pg or postgres or prisma is used
                let check_db_dep = |dep_name: &str| -> bool {
                    let in_deps = json.get("dependencies").and_then(|d| d.get(dep_name)).is_some();
                    let in_dev = json.get("devDependencies").and_then(|d| d.get(dep_name)).is_some();
                    in_deps || in_dev
                };

                if check_db_dep("pg") || check_db_dep("postgres") || check_db_dep("@prisma/client") {
                    let ev = Evidence::from_repo_file(
                        PathBuf::from("package.json"),
                        None,
                        "PostgreSQL client dependency detected in dependencies",
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

    NodeDiscovery {
        is_node,
        is_bun,
        package_managers,
        requirements,
        ports,
        scripts,
        evidence,
    }
}

pub fn scan_text_for_ports(text: &str, ports: &mut Vec<u16>) {
    // Check for PORT=1234 or --port 1234 or -p 1234
    for word in text.split_whitespace() {
        if let Some(val) = word.strip_prefix("PORT=").or_else(|| word.strip_prefix("--port=")).or_else(|| word.strip_prefix("-p=")) {
            if let Ok(p) = val.parse::<u16>() {
                if !ports.contains(&p) && p > 0 {
                    ports.push(p);
                }
            }
        }
    }
    // Also check for "--port 3000" sequence
    let words: Vec<&str> = text.split_whitespace().collect();
    for i in 0..words.len() {
        if (words[i] == "--port" || words[i] == "-p") && i + 1 < words.len() {
            if let Ok(p) = words[i + 1].parse::<u16>() {
                if !ports.contains(&p) && p > 0 {
                    ports.push(p);
                }
            }
        }
    }
}

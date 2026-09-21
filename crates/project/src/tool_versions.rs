use std::fs;
use std::path::{Path, PathBuf};
use toml::Value;
use unfuck_core::evidence::Evidence;
use unfuck_core::ir::{ProjectRequirement, RequirementKind};

pub struct ToolVersionsDiscovery {
    pub requirements: Vec<ProjectRequirement>,
    pub evidence: Vec<Evidence>,
}

pub fn analyze_tool_versions(root: &Path) -> ToolVersionsDiscovery {
    let mut requirements = Vec::new();
    let mut evidence = Vec::new();

    // 1. .tool-versions
    let tool_versions_path = root.join(".tool-versions");
    if tool_versions_path.exists() {
        if let Ok(content) = fs::read_to_string(&tool_versions_path) {
            for (idx, line) in content.lines().enumerate() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    let tool = parts[0].to_lowercase();
                    let ver = parts[1];

                    let normalized_tool = match tool.as_str() {
                        "nodejs" | "node" => "node",
                        "python" => "python",
                        "bun" => "bun",
                        "rust" => "rust",
                        "golang" | "go" => "go",
                        "java" => "java",
                        "postgres" | "postgresql" => "postgresql",
                        _ => &tool,
                    };

                    let ev = Evidence::from_repo_file(
                        PathBuf::from(".tool-versions"),
                        Some(idx + 1),
                        format!(
                            "Tool '{}' version {} declared in .tool-versions",
                            normalized_tool, ver
                        ),
                    );

                    let kind = match normalized_tool {
                        "postgresql" => RequirementKind::Service {
                            name: "postgresql".to_string(),
                            min_version: Some(ver.to_string()),
                        },
                        _ => RequirementKind::Runtime {
                            name: normalized_tool.to_string(),
                            constraint: format!(">={}", ver),
                        },
                    };

                    requirements.push(ProjectRequirement {
                        name: normalized_tool.to_string(),
                        kind,
                        evidence: ev.clone(),
                    });
                    evidence.push(ev);
                }
            }
        }
    }

    // 2. mise.toml
    let mise_path = root.join("mise.toml");
    if mise_path.exists() {
        if let Ok(content) = fs::read_to_string(&mise_path) {
            if let Ok(toml) = content.parse::<Value>() {
                if let Some(tools_table) = toml.get("tools").and_then(|t| t.as_table()) {
                    for (tool, val) in tools_table {
                        let ver_str = match val {
                            Value::String(s) => Some(s.clone()),
                            Value::Integer(i) => Some(i.to_string()),
                            Value::Float(f) => Some(f.to_string()),
                            _ => None,
                        };

                        if let Some(ver) = ver_str {
                            let normalized_tool = match tool.as_str() {
                                "nodejs" | "node" => "node",
                                "python" => "python",
                                "bun" => "bun",
                                "rust" => "rust",
                                "golang" | "go" => "go",
                                "java" => "java",
                                "postgres" | "postgresql" => "postgresql",
                                _ => tool.as_str(),
                            };

                            let ev = Evidence::from_repo_file(
                                PathBuf::from("mise.toml"),
                                None,
                                format!(
                                    "Tool '{}' version {} declared in mise.toml",
                                    normalized_tool, ver
                                ),
                            );

                            let kind = match normalized_tool {
                                "postgresql" => RequirementKind::Service {
                                    name: "postgresql".to_string(),
                                    min_version: Some(ver.clone()),
                                },
                                _ => RequirementKind::Runtime {
                                    name: normalized_tool.to_string(),
                                    constraint: format!(">={}", ver),
                                },
                            };

                            requirements.push(ProjectRequirement {
                                name: normalized_tool.to_string(),
                                kind,
                                evidence: ev.clone(),
                            });
                            evidence.push(ev);
                        }
                    }
                }
            }
        }
    }

    ToolVersionsDiscovery {
        requirements,
        evidence,
    }
}

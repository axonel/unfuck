use std::path::{Path, PathBuf};
use std::process::Command;
use unfuck_core::evidence::{Evidence, EvidenceSource};
use unfuck_core::ir::{ToolKind, ToolObservation};
use unfuck_core::Confidence;

fn resolve_in_path(binary: &str, path_entries: &[PathBuf]) -> Option<PathBuf> {
    for dir in path_entries {
        let candidate = dir.join(binary);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn parse_first_semantic_version(output: &str) -> Option<String> {
    for word in output.split_whitespace() {
        let clean = word.trim_matches(|c: char| !c.is_ascii_digit() && c != '.');
        let parts: Vec<&str> = clean.split('.').collect();
        if parts.len() >= 2
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        {
            return Some(clean.to_string());
        }
    }
    None
}

/// Classify known tool binary names into their appropriate ToolKind.
pub fn classify_tool_kind(name: &str) -> ToolKind {
    let lower = name.to_lowercase();
    if lower.contains("oazapfts")
        || lower.contains("openapi-generator")
        || lower.contains("protoc")
        || lower.contains("sqlc")
    {
        ToolKind::CodeGenerator
    } else if lower.contains("binaryen")
        || lower.contains("wasm-opt")
        || lower == "make"
        || lower == "cmake"
        || lower == "ninja"
        || lower == "gcc"
        || lower == "clang"
    {
        ToolKind::BuildTool
    } else if lower.contains("tofu")
        || lower.contains("terraform")
        || lower.contains("terragrunt")
        || lower.contains("extism")
        || lower.contains("docker-compose")
    {
        ToolKind::DeveloperTool
    } else {
        ToolKind::DeveloperTool
    }
}

/// Scan developer and build tools on the host system.
pub fn scan_tools(
    path_entries: &[PathBuf],
    project_context: Option<&Path>,
) -> Vec<ToolObservation> {
    let mut observations = Vec::new();

    // 1. Direct mise inspection if available
    if let Some(proj_dir) = project_context {
        if let Ok(output) = Command::new("mise")
            .args(["ls", "--json"])
            .current_dir(proj_dir)
            .output()
        {
            if output.status.success() {
                if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&output.stdout) {
                    if let Some(map) = json.as_object() {
                        for (tool_name, entries) in map {
                            // Skip runtimes and package managers handled elsewhere
                            if matches!(tool_name.as_str(), "node" | "python" | "java" | "rust" | "go" | "bun" | "pnpm" | "npm" | "yarn" | "cargo" | "uv" | "poetry") {
                                continue;
                            }

                            if let Some(arr) = entries.as_array() {
                                for entry in arr {
                                    let installed = entry.get("installed").and_then(|v| v.as_bool()).unwrap_or(false);
                                    if installed {
                                        let ver = entry.get("version").and_then(|v| v.as_str()).map(|s| s.to_string());
                                        let install_path = entry.get("install_path").and_then(|v| v.as_str()).unwrap_or("");
                                        let exe_path = if install_path.is_empty() {
                                            resolve_in_path(tool_name, path_entries).unwrap_or_else(|| PathBuf::from(tool_name))
                                        } else {
                                            let p1 = PathBuf::from(install_path).join(tool_name);
                                            let p2 = PathBuf::from(install_path).join("bin").join(tool_name);
                                            if p1.is_file() {
                                                p1
                                            } else if p2.is_file() {
                                                p2
                                            } else {
                                                resolve_in_path(tool_name, path_entries).unwrap_or(p1)
                                            }
                                        };

                                        let kind = classify_tool_kind(tool_name);
                                        let evidence = Evidence::new(
                                            EvidenceSource::ExecutableInspection {
                                                path: exe_path.clone(),
                                                version_string: ver.clone().unwrap_or_default(),
                                                exit_code: 0,
                                            },
                                            Confidence::Confirmed,
                                            format!(
                                                "Tool '{}' ({}) discovered via mise with version {}",
                                                tool_name,
                                                kind,
                                                ver.as_deref().unwrap_or("unknown")
                                            ),
                                        );

                                        observations.push(ToolObservation {
                                            name: tool_name.clone(),
                                            kind,
                                            version: ver,
                                            executable_path: exe_path,
                                            evidence,
                                        });
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. PATH resolution for common developer/build tools
    let common_tools = &[
        "make",
        "cmake",
        "ninja",
        "opentofu",
        "terraform",
        "terragrunt",
        "wasm-opt",
        "extism",
    ];

    for tool_name in common_tools {
        if observations.iter().any(|o| o.name == *tool_name) {
            continue;
        }

        if let Some(executable_path) = resolve_in_path(tool_name, path_entries) {
            let mut cmd = Command::new(&executable_path);
            cmd.arg("--version");
            if let Some(dir) = project_context {
                cmd.current_dir(dir);
            }

            if let Ok(out) = cmd.output() {
                if out.status.success() {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    let combined = if stdout.trim().is_empty() {
                        stderr.to_string()
                    } else {
                        stdout.to_string()
                    };

                    let ver = parse_first_semantic_version(&combined);
                    let kind = classify_tool_kind(tool_name);

                    let evidence = Evidence::new(
                        EvidenceSource::ExecutableInspection {
                            path: executable_path.clone(),
                            version_string: combined.trim().to_string(),
                            exit_code: 0,
                        },
                        Confidence::Confirmed,
                        format!(
                            "Tool '{}' ({}) discovered at {}",
                            tool_name,
                            kind,
                            executable_path.display()
                        ),
                    );

                    observations.push(ToolObservation {
                        name: tool_name.to_string(),
                        kind,
                        version: ver,
                        executable_path,
                        evidence,
                    });
                }
            }
        }
    }

    observations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_tool_kind() {
        assert_eq!(classify_tool_kind("make"), ToolKind::BuildTool);
        assert_eq!(classify_tool_kind("cmake"), ToolKind::BuildTool);
        assert_eq!(classify_tool_kind("wasm-opt"), ToolKind::BuildTool);
        assert_eq!(classify_tool_kind("binaryen"), ToolKind::BuildTool);
        assert_eq!(classify_tool_kind("npm:oazapfts"), ToolKind::CodeGenerator);
        assert_eq!(classify_tool_kind("protoc"), ToolKind::CodeGenerator);
        assert_eq!(classify_tool_kind("opentofu"), ToolKind::DeveloperTool);
        assert_eq!(classify_tool_kind("terragrunt"), ToolKind::DeveloperTool);
    }
}

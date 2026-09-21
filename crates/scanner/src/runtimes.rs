use std::path::PathBuf;
use std::process::Command;
use unfuck_core::evidence::{Evidence, EvidenceSource};
use unfuck_core::ir::Runtime;
use unfuck_core::Confidence;

struct RuntimeProbe {
    name: &'static str,
    executable_candidates: &'static [&'static str],
    version_arg: &'static str,
    parse_version: fn(&str) -> Option<String>,
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

fn parse_python_version(output: &str) -> Option<String> {
    // Output: "Python 3.12.4"
    parse_first_semantic_version(output)
}

fn parse_node_version(output: &str) -> Option<String> {
    // Output: "v20.10.0"
    let trimmed = output.trim().trim_start_matches('v');
    parse_first_semantic_version(trimmed)
}

fn parse_bun_version(output: &str) -> Option<String> {
    // Output: "1.1.20"
    parse_first_semantic_version(output)
}

fn parse_rust_version(output: &str) -> Option<String> {
    // Output: "rustc 1.80.0 (...)"
    parse_first_semantic_version(output)
}

fn parse_go_version(output: &str) -> Option<String> {
    // Output: "go version go1.22.4 linux/amd64"
    parse_first_semantic_version(output)
}

fn parse_java_version(output: &str) -> Option<String> {
    // Output: "openjdk version \"21.0.3\" ..." or "java version \"1.8.0_...\""
    for line in output.lines() {
        if line.contains("version") {
            if let Some(start) = line.find('"') {
                if let Some(end) = line[start + 1..].find('"') {
                    return Some(line[start + 1..start + 1 + end].to_string());
                }
            }
        }
    }
    parse_first_semantic_version(output)
}

const RUNTIME_PROBES: &[RuntimeProbe] = &[
    RuntimeProbe {
        name: "python",
        executable_candidates: &["python3", "python"],
        version_arg: "--version",
        parse_version: parse_python_version,
    },
    RuntimeProbe {
        name: "node",
        executable_candidates: &["node", "nodejs"],
        version_arg: "--version",
        parse_version: parse_node_version,
    },
    RuntimeProbe {
        name: "bun",
        executable_candidates: &["bun"],
        version_arg: "--version",
        parse_version: parse_bun_version,
    },
    RuntimeProbe {
        name: "rust",
        executable_candidates: &["rustc"],
        version_arg: "--version",
        parse_version: parse_rust_version,
    },
    RuntimeProbe {
        name: "go",
        executable_candidates: &["go"],
        version_arg: "version",
        parse_version: parse_go_version,
    },
    RuntimeProbe {
        name: "java",
        executable_candidates: &["java"],
        version_arg: "-version",
        parse_version: parse_java_version,
    },
];

/// Resolve an executable binary by searching PATH.
fn resolve_in_path(binary: &str, path_entries: &[PathBuf]) -> Option<PathBuf> {
    for dir in path_entries {
        let candidate = dir.join(binary);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Scan machine runtimes deterministically.
pub fn scan_runtimes(path_entries: &[PathBuf]) -> Vec<Runtime> {
    let mut runtimes = Vec::new();

    for probe in RUNTIME_PROBES {
        for candidate_name in probe.executable_candidates {
            if let Some(executable_path) = resolve_in_path(candidate_name, path_entries) {
                // Execute controlled subprocess
                let output = Command::new(&executable_path)
                    .arg(probe.version_arg)
                    .output();

                match output {
                    Ok(out) => {
                        let stdout = String::from_utf8_lossy(&out.stdout);
                        let stderr = String::from_utf8_lossy(&out.stderr);
                        let combined = if stdout.trim().is_empty() {
                            stderr.to_string()
                        } else {
                            stdout.to_string()
                        };

                        if let Some(ver) = (probe.parse_version)(&combined) {
                            let evidence = Evidence::new(
                                EvidenceSource::ExecutableInspection {
                                    path: executable_path.clone(),
                                    version_string: combined.trim().to_string(),
                                    exit_code: out.status.code().unwrap_or(0),
                                },
                                Confidence::Confirmed,
                                format!(
                                    "Runtime '{}' discovered at {} with version {}",
                                    probe.name,
                                    executable_path.display(),
                                    ver
                                ),
                            );

                            runtimes.push(Runtime {
                                name: probe.name.to_string(),
                                version: ver,
                                executable_path,
                                evidence,
                            });
                            // Found runtime for this probe, break to avoid duplicates
                            break;
                        }
                    }
                    Err(_) => {
                        // Execution failed, continue to next candidate
                    }
                }
            }
        }
    }

    runtimes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_versions() {
        assert_eq!(
            parse_python_version("Python 3.12.4\n").as_deref(),
            Some("3.12.4")
        );
        assert_eq!(parse_node_version("v20.10.0\n").as_deref(), Some("20.10.0"));
        assert_eq!(parse_bun_version("1.1.20\n").as_deref(), Some("1.1.20"));
        assert_eq!(
            parse_rust_version("rustc 1.80.0 (051478957 2024-07-21)\n").as_deref(),
            Some("1.80.0")
        );
        assert_eq!(
            parse_go_version("go version go1.22.4 linux/amd64\n").as_deref(),
            Some("1.22.4")
        );
        assert_eq!(
            parse_java_version("openjdk version \"21.0.3\" 2024-04-16\n").as_deref(),
            Some("21.0.3")
        );
    }
}

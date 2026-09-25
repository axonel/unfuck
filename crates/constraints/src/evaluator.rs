use crate::model::{Constraint, ConstraintStatus, EvaluatedConstraint};
use crate::version::matches_version_constraint;
use std::path::Path;
use std::process::Command;
use unfuck_core::evidence::{Evidence, EvidenceSource};
use unfuck_core::ir::{
    MachineCapability, ProjectRequirement, RequirementKind, ServiceStatus, ToolKind, ToolScope,
};
use unfuck_core::{Confidence, VersionConstraint};

/// Convert a ProjectRequirement into a Constraint.
pub fn requirement_to_constraint(req: &ProjectRequirement) -> Option<Constraint> {
    match &req.kind {
        RequirementKind::Runtime { name, constraint } => Some(Constraint::RuntimeVersion {
            runtime: name.clone(),
            constraint: constraint.clone(),
        }),
        RequirementKind::PackageManager { name, constraint } => {
            Some(Constraint::PackageManagerVersion {
                name: name.clone(),
                constraint: constraint.clone(),
            })
        }
        RequirementKind::DeveloperTool {
            name,
            constraint,
            scope,
        } => Some(Constraint::ToolAvailable {
            name: name.clone(),
            kind: ToolKind::DeveloperTool,
            constraint: constraint.clone(),
            scope: *scope,
        }),
        RequirementKind::BuildTool {
            name,
            constraint,
            scope,
        } => Some(Constraint::ToolAvailable {
            name: name.clone(),
            kind: ToolKind::BuildTool,
            constraint: constraint.clone(),
            scope: *scope,
        }),
        RequirementKind::CodeGenerator {
            name,
            constraint,
            scope,
        } => Some(Constraint::ToolAvailable {
            name: name.clone(),
            kind: ToolKind::CodeGenerator,
            constraint: constraint.clone(),
            scope: *scope,
        }),
        RequirementKind::Port { port, .. } => Some(Constraint::PortAvailable { port: *port }),
        RequirementKind::Service { name, min_version } => Some(Constraint::ServiceRunning {
            service: name.clone(),
            min_version: min_version.clone(),
        }),
        RequirementKind::Os { name } => Some(Constraint::OsMatch {
            expected_os: name.clone(),
        }),
        RequirementKind::Arch { name } => Some(Constraint::ArchMatch {
            expected_arch: name.clone(),
        }),
        RequirementKind::Memory { min_bytes } => Some(Constraint::MemoryMin {
            min_bytes: *min_bytes,
        }),
        RequirementKind::EnvVar { name, required, .. } => Some(Constraint::EnvVarSet {
            key: name.clone(),
            required: *required,
        }),
        RequirementKind::Conflict {
            target, details, ..
        } => Some(Constraint::ConflictDetected {
            target: target.clone(),
            details: details.clone(),
        }),
        RequirementKind::Compiler {
            language,
            min_standard,
            constraint,
        } => Some(Constraint::CompilerAvailable {
            language: language.clone(),
            min_standard: min_standard.clone(),
            constraint: constraint.clone(),
        }),
        RequirementKind::LanguagePackage {
            language,
            package,
            constraint,
            scope,
        } => Some(Constraint::LanguagePackageAvailable {
            language: language.clone(),
            package: package.clone(),
            constraint: constraint.clone(),
            scope: *scope,
        }),
        RequirementKind::SystemLibrary {
            name,
            header,
            constraint,
            scope,
        } => Some(Constraint::SystemLibraryAvailable {
            name: name.clone(),
            header: header.clone(),
            constraint: constraint.clone(),
            scope: *scope,
        }),
    }
}

fn compiler_supports_standard(
    compiler_name: &str,
    lang: &str,
    standard: &str,
    tool_version: Option<&str>,
) -> (bool, Option<String>) {
    let std_lower = standard.to_lowercase();
    let lang_lower = lang.to_lowercase();

    // 1. Direct active capability probe (safe, read-only preprocessor check to /dev/null)
    let lang_flag = if lang_lower == "cpp" || lang_lower == "c++" {
        "c++"
    } else {
        "c"
    };

    let std_arg = format!("-std={}", std_lower);
    if let Ok(out) = Command::new(compiler_name)
        .args([
            &std_arg,
            "-E",
            "-x",
            lang_flag,
            "/dev/null",
            "-o",
            "/dev/null",
        ])
        .output()
    {
        if out.status.success() {
            return (
                true,
                Some(format!(
                    "Compiler '{}' capability probe verified support for -std={}",
                    compiler_name, standard
                )),
            );
        } else {
            let stderr = String::from_utf8_lossy(&out.stderr);
            if stderr.contains("unrecognized command-line option")
                || stderr.contains("invalid value")
                || stderr.contains("unknown argument")
                || stderr.contains("error: invalid")
            {
                return (
                    false,
                    Some(format!(
                        "Compiler '{}' does not support standard flag -std={}",
                        compiler_name, standard
                    )),
                );
            }
        }
    }

    // 2. Static version matrix fallback across standards
    if let Some(ver) = tool_version {
        let is_gcc = compiler_name.contains("gcc") || compiler_name.contains("g++");
        let is_clang = compiler_name.contains("clang");

        if lang_lower == "c" {
            let min_gcc = match std_lower.as_str() {
                "c99" | "gnu99" => Some("3.0.0"),
                "c11" | "gnu11" => Some("4.9.0"),
                "c17" | "gnu17" | "c18" | "gnu18" => Some("8.1.0"),
                "c23" | "gnu23" => Some("14.0.0"),
                _ => None,
            };
            let min_clang = match std_lower.as_str() {
                "c99" | "gnu99" => Some("1.0.0"),
                "c11" | "gnu11" => Some("3.1.0"),
                "c17" | "gnu17" | "c18" | "gnu18" => Some("6.0.0"),
                "c23" | "gnu23" => Some("18.0.0"),
                _ => None,
            };

            if is_gcc {
                if let Some(min_v) = min_gcc {
                    let c = VersionConstraint::parse(&format!("< {}", min_v));
                    if c.matches(ver) {
                        return (
                            false,
                            Some(format!(
                                "Compiler '{}' version {} is older than minimum version {} required for standard {}",
                                compiler_name, ver, min_v, standard
                            )),
                        );
                    }
                }
            } else if is_clang {
                if let Some(min_v) = min_clang {
                    let c = VersionConstraint::parse(&format!("< {}", min_v));
                    if c.matches(ver) {
                        return (
                            false,
                            Some(format!(
                                "Compiler '{}' version {} is older than minimum version {} required for standard {}",
                                compiler_name, ver, min_v, standard
                            )),
                        );
                    }
                }
            }
        } else if lang_lower == "cpp" || lang_lower == "c++" {
            let min_gcc = match std_lower.as_str() {
                "c++11" | "gnu++11" => Some("4.8.1"),
                "c++14" | "gnu++14" => Some("5.0.0"),
                "c++17" | "gnu++17" => Some("7.0.0"),
                "c++20" | "gnu++20" => Some("11.0.0"),
                "c++23" | "gnu++23" => Some("14.0.0"),
                _ => None,
            };
            let min_clang = match std_lower.as_str() {
                "c++11" | "gnu++11" => Some("3.3.0"),
                "c++14" | "gnu++14" => Some("3.4.0"),
                "c++17" | "gnu++17" => Some("5.0.0"),
                "c++20" | "gnu++20" => Some("10.0.0"),
                "c++23" | "gnu++23" => Some("17.0.0"),
                _ => None,
            };

            if is_gcc {
                if let Some(min_v) = min_gcc {
                    let c = VersionConstraint::parse(&format!("< {}", min_v));
                    if c.matches(ver) {
                        return (
                            false,
                            Some(format!(
                                "C++ compiler '{}' version {} is older than minimum version {} required for standard {}",
                                compiler_name, ver, min_v, standard
                            )),
                        );
                    }
                }
            } else if is_clang {
                if let Some(min_v) = min_clang {
                    let c = VersionConstraint::parse(&format!("< {}", min_v));
                    if c.matches(ver) {
                        return (
                            false,
                            Some(format!(
                                "C++ compiler '{}' version {} is older than minimum version {} required for standard {}",
                                compiler_name, ver, min_v, standard
                            )),
                        );
                    }
                }
            }
        }
    }

    (true, None)
}

/// Evaluates a single constraint against machine capabilities.
pub fn evaluate_constraint(
    constraint: &Constraint,
    machine: &MachineCapability,
    project_evidence: Option<Evidence>,
) -> EvaluatedConstraint {
    match constraint {
        Constraint::RuntimeVersion {
            runtime,
            constraint: req_constraint,
        } => {
            if let Some(rt) = machine.find_runtime(runtime) {
                if req_constraint.matches(&rt.version) {
                    EvaluatedConstraint {
                        constraint: constraint.clone(),
                        status: ConstraintStatus::Satisfied,
                        project_evidence,
                        machine_evidence: Some(rt.evidence.clone()),
                    }
                } else {
                    let reason = format!(
                        "Runtime '{}' version {} does not satisfy requirement {}",
                        runtime, rt.version, req_constraint
                    );
                    let root_cause_hint = format!("{}.version_mismatch", runtime);
                    EvaluatedConstraint {
                        constraint: constraint.clone(),
                        status: ConstraintStatus::Violated {
                            reason,
                            root_cause_hint,
                        },
                        project_evidence,
                        machine_evidence: Some(rt.evidence.clone()),
                    }
                }
            } else {
                let reason = format!("Runtime '{}' is not installed or not in PATH", runtime);
                let root_cause_hint = format!("{}.missing", runtime);
                EvaluatedConstraint {
                    constraint: constraint.clone(),
                    status: ConstraintStatus::Violated {
                        reason,
                        root_cause_hint,
                    },
                    project_evidence,
                    machine_evidence: None,
                }
            }
        }

        Constraint::PackageManagerVersion {
            name,
            constraint: req_constraint,
        } => {
            if let Some(pm) = machine.find_package_manager(name) {
                if let Some(req_c) = req_constraint {
                    if let Some(ref ver) = pm.version {
                        if req_c.matches(ver) {
                            EvaluatedConstraint {
                                constraint: constraint.clone(),
                                status: ConstraintStatus::Satisfied,
                                project_evidence,
                                machine_evidence: Some(pm.evidence.clone()),
                            }
                        } else {
                            let reason = format!(
                                "Package manager '{}' version {} does not satisfy requirement {}",
                                name, ver, req_c
                            );
                            let root_cause_hint = format!("{}.version_mismatch", name);
                            EvaluatedConstraint {
                                constraint: constraint.clone(),
                                status: ConstraintStatus::Violated {
                                    reason,
                                    root_cause_hint,
                                },
                                project_evidence,
                                machine_evidence: Some(pm.evidence.clone()),
                            }
                        }
                    } else {
                        EvaluatedConstraint {
                            constraint: constraint.clone(),
                            status: ConstraintStatus::Satisfied,
                            project_evidence,
                            machine_evidence: Some(pm.evidence.clone()),
                        }
                    }
                } else {
                    EvaluatedConstraint {
                        constraint: constraint.clone(),
                        status: ConstraintStatus::Satisfied,
                        project_evidence,
                        machine_evidence: Some(pm.evidence.clone()),
                    }
                }
            } else {
                let reason = format!("Package manager '{}' is not installed or not in PATH", name);
                let root_cause_hint = format!("{}.missing", name);
                EvaluatedConstraint {
                    constraint: constraint.clone(),
                    status: ConstraintStatus::Violated {
                        reason,
                        root_cause_hint,
                    },
                    project_evidence,
                    machine_evidence: None,
                }
            }
        }

        Constraint::ToolAvailable {
            name,
            kind,
            constraint: req_constraint,
            scope,
        } => {
            if let Some(tool) = machine.find_tool(name) {
                if let Some(req_c) = req_constraint {
                    if let Some(ref ver) = tool.version {
                        if req_c.matches(ver) {
                            EvaluatedConstraint {
                                constraint: constraint.clone(),
                                status: ConstraintStatus::Satisfied,
                                project_evidence,
                                machine_evidence: Some(tool.evidence.clone()),
                            }
                        } else {
                            let reason = format!(
                                "{} '{}' version {} does not satisfy requirement {}",
                                kind, name, ver, req_c
                            );
                            let root_cause_hint = format!("{}.version_mismatch", name);
                            EvaluatedConstraint {
                                constraint: constraint.clone(),
                                status: ConstraintStatus::Violated {
                                    reason,
                                    root_cause_hint,
                                },
                                project_evidence,
                                machine_evidence: Some(tool.evidence.clone()),
                            }
                        }
                    } else {
                        EvaluatedConstraint {
                            constraint: constraint.clone(),
                            status: ConstraintStatus::Satisfied,
                            project_evidence,
                            machine_evidence: Some(tool.evidence.clone()),
                        }
                    }
                } else {
                    EvaluatedConstraint {
                        constraint: constraint.clone(),
                        status: ConstraintStatus::Satisfied,
                        project_evidence,
                        machine_evidence: Some(tool.evidence.clone()),
                    }
                }
            } else {
                let reason = format!(
                    "{} '{}' is not installed or not in PATH (scope: {:?})",
                    kind, name, scope
                );
                let root_cause_hint = format!("{}.missing", name);
                EvaluatedConstraint {
                    constraint: constraint.clone(),
                    status: ConstraintStatus::Violated {
                        reason,
                        root_cause_hint,
                    },
                    project_evidence,
                    machine_evidence: None,
                }
            }
        }

        Constraint::PortAvailable { port } => {
            if let Some(occupied_info) = machine.is_port_occupied(*port) {
                let reason = format!(
                    "Required port {} is already in use by another process",
                    port
                );
                let root_cause_hint = format!("port:{}.occupied", port);
                EvaluatedConstraint {
                    constraint: constraint.clone(),
                    status: ConstraintStatus::Violated {
                        reason,
                        root_cause_hint,
                    },
                    project_evidence,
                    machine_evidence: Some(occupied_info.evidence.clone()),
                }
            } else {
                EvaluatedConstraint {
                    constraint: constraint.clone(),
                    status: ConstraintStatus::Satisfied,
                    project_evidence,
                    machine_evidence: None,
                }
            }
        }

        Constraint::ServiceRunning {
            service,
            min_version,
        } => {
            if let Some(srv) = machine.find_service(service) {
                if srv.status == ServiceStatus::Running {
                    if let (Some(req_ver), Some(actual_ver)) = (min_version, &srv.version) {
                        if matches_version_constraint(actual_ver, &format!(">={}", req_ver)) {
                            EvaluatedConstraint {
                                constraint: constraint.clone(),
                                status: ConstraintStatus::Satisfied,
                                project_evidence,
                                machine_evidence: Some(srv.evidence.clone()),
                            }
                        } else {
                            let reason = format!(
                                "Service '{}' version {} is older than required version {}",
                                service, actual_ver, req_ver
                            );
                            let root_cause_hint = format!("{}.version_incompatible", service);
                            EvaluatedConstraint {
                                constraint: constraint.clone(),
                                status: ConstraintStatus::Violated {
                                    reason,
                                    root_cause_hint,
                                },
                                project_evidence,
                                machine_evidence: Some(srv.evidence.clone()),
                            }
                        }
                    } else {
                        EvaluatedConstraint {
                            constraint: constraint.clone(),
                            status: ConstraintStatus::Satisfied,
                            project_evidence,
                            machine_evidence: Some(srv.evidence.clone()),
                        }
                    }
                } else {
                    let reason = format!(
                        "Service '{}' is present but currently stopped/inactive",
                        service
                    );
                    let root_cause_hint = format!("{}.stopped", service);
                    EvaluatedConstraint {
                        constraint: constraint.clone(),
                        status: ConstraintStatus::Violated {
                            reason,
                            root_cause_hint,
                        },
                        project_evidence,
                        machine_evidence: Some(srv.evidence.clone()),
                    }
                }
            } else {
                let reason = format!("Required service '{}' is not installed", service);
                let root_cause_hint = format!("{}.not_installed", service);
                EvaluatedConstraint {
                    constraint: constraint.clone(),
                    status: ConstraintStatus::Violated {
                        reason,
                        root_cause_hint,
                    },
                    project_evidence,
                    machine_evidence: None,
                }
            }
        }

        Constraint::OsMatch { expected_os } => {
            let matches = machine
                .os
                .to_lowercase()
                .contains(&expected_os.to_lowercase())
                || machine.os_family.eq_ignore_ascii_case(expected_os);
            if matches {
                EvaluatedConstraint {
                    constraint: constraint.clone(),
                    status: ConstraintStatus::Satisfied,
                    project_evidence,
                    machine_evidence: None,
                }
            } else {
                let reason = format!(
                    "Operating system mismatch: expected '{}', machine is '{}'",
                    expected_os, machine.os
                );
                let root_cause_hint = "os.mismatch".to_string();
                EvaluatedConstraint {
                    constraint: constraint.clone(),
                    status: ConstraintStatus::Violated {
                        reason,
                        root_cause_hint,
                    },
                    project_evidence,
                    machine_evidence: None,
                }
            }
        }

        Constraint::ArchMatch { expected_arch } => {
            if machine.arch.eq_ignore_ascii_case(expected_arch) {
                EvaluatedConstraint {
                    constraint: constraint.clone(),
                    status: ConstraintStatus::Satisfied,
                    project_evidence,
                    machine_evidence: None,
                }
            } else {
                let reason = format!(
                    "Architecture mismatch: expected '{}', machine is '{}'",
                    expected_arch, machine.arch
                );
                let root_cause_hint = "arch.mismatch".to_string();
                EvaluatedConstraint {
                    constraint: constraint.clone(),
                    status: ConstraintStatus::Violated {
                        reason,
                        root_cause_hint,
                    },
                    project_evidence,
                    machine_evidence: None,
                }
            }
        }

        Constraint::MemoryMin { min_bytes } => {
            if machine.total_memory_bytes >= *min_bytes {
                EvaluatedConstraint {
                    constraint: constraint.clone(),
                    status: ConstraintStatus::Satisfied,
                    project_evidence,
                    machine_evidence: None,
                }
            } else {
                let reason = format!(
                    "Insufficient memory: required {:.1} GB, machine has {:.1} GB",
                    *min_bytes as f64 / (1024.0 * 1024.0 * 1024.0),
                    machine.total_memory_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
                );
                let root_cause_hint = "memory.insufficient".to_string();
                EvaluatedConstraint {
                    constraint: constraint.clone(),
                    status: ConstraintStatus::Violated {
                        reason,
                        root_cause_hint,
                    },
                    project_evidence,
                    machine_evidence: None,
                }
            }
        }

        Constraint::EnvVarSet { key, required } => {
            if machine.env_vars.contains_key(key) {
                EvaluatedConstraint {
                    constraint: constraint.clone(),
                    status: ConstraintStatus::Satisfied,
                    project_evidence,
                    machine_evidence: None,
                }
            } else if *required {
                let reason = format!("Required environment variable '{}' is not set", key);
                let root_cause_hint = format!("env.{}.missing", key);
                EvaluatedConstraint {
                    constraint: constraint.clone(),
                    status: ConstraintStatus::Violated {
                        reason,
                        root_cause_hint,
                    },
                    project_evidence,
                    machine_evidence: None,
                }
            } else {
                EvaluatedConstraint {
                    constraint: constraint.clone(),
                    status: ConstraintStatus::Satisfied,
                    project_evidence,
                    machine_evidence: None,
                }
            }
        }

        Constraint::ConflictDetected { target, details } => {
            let reason = format!(
                "Contradictory configuration detected for '{}': {}",
                target, details
            );
            let root_cause_hint = format!("{}.configuration_conflict", target);
            EvaluatedConstraint {
                constraint: constraint.clone(),
                status: ConstraintStatus::Violated {
                    reason,
                    root_cause_hint,
                },
                project_evidence,
                machine_evidence: None,
            }
        }

        Constraint::ComposeConfigUnresolved {
            compose_file,
            project_name: _,
            service_name,
            missing_env_files,
            unresolved_vars,
            env_templates: _,
            directly_affected_services: _,
            transitively_blocked_services: _,
            bootstrap_suggestions: _,
        } => {
            let mut reasons = Vec::new();
            if !missing_env_files.is_empty() {
                let files: Vec<String> = missing_env_files
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect();
                reasons.push(format!(
                    "required env file(s) missing: {}",
                    files.join(", ")
                ));
            }
            if !unresolved_vars.is_empty() {
                reasons.push(format!(
                    "unresolved required variable(s): {}",
                    unresolved_vars.join(", ")
                ));
            }
            let svc_str = service_name
                .as_deref()
                .map(|s| format!(" for service '{}'", s))
                .unwrap_or_default();
            let reason = format!(
                "Docker Compose configuration in '{}'{} is unresolved: {}",
                compose_file.display(),
                svc_str,
                reasons.join("; ")
            );
            let root_cause_hint = service_name
                .as_deref()
                .map(|s| format!("compose.{}.config_unresolved", s))
                .unwrap_or_else(|| "compose.config_unresolved".to_string());
            EvaluatedConstraint {
                constraint: constraint.clone(),
                status: ConstraintStatus::Violated {
                    reason,
                    root_cause_hint,
                },
                project_evidence,
                machine_evidence: None,
            }
        }

        Constraint::ComposeServiceState {
            compose_file,
            service_name,
            container_name,
            expected_state,
            actual_state,
        } => {
            let satisfied = match (expected_state.as_str(), actual_state.as_str()) {
                ("running", "running") | ("running", "running (healthy)") => true,
                ("healthy", "running (healthy)") => true,
                _ => actual_state == expected_state,
            };
            if satisfied {
                EvaluatedConstraint {
                    constraint: constraint.clone(),
                    status: ConstraintStatus::Satisfied,
                    project_evidence,
                    machine_evidence: None,
                }
            } else {
                let c_str = container_name
                    .as_deref()
                    .map(|c| format!(" (container '{}')", c))
                    .unwrap_or_default();
                let reason = format!(
                    "Compose service '{}'{} defined in '{}' is in state '{}', expected '{}'",
                    service_name,
                    c_str,
                    compose_file.display(),
                    actual_state,
                    expected_state
                );
                let root_cause_hint = format!("compose.{}.state_mismatch", service_name);
                EvaluatedConstraint {
                    constraint: constraint.clone(),
                    status: ConstraintStatus::Violated {
                        reason,
                        root_cause_hint,
                    },
                    project_evidence,
                    machine_evidence: None,
                }
            }
        }

        Constraint::CompilerAvailable {
            language,
            min_standard,
            constraint: req_constraint,
        } => {
            let candidates: &[&str] = match language.to_lowercase().as_str() {
                "c" => &["gcc", "clang", "cc"],
                "cpp" | "c++" => &["g++", "clang++", "c++", "gcc", "clang"],
                "fortran" => &["gfortran", "flang"],
                "rust" => &["rustc"],
                _ => &[language.as_str()],
            };

            let mut found_tool = None;
            for cand in candidates {
                if let Some(tool) = machine.find_tool(cand) {
                    found_tool = Some(tool.clone());
                    break;
                }
            }

            if let Some(tool) = found_tool {
                let mut satisfied = true;
                let mut fail_reason = None;

                if let Some(req_c) = req_constraint {
                    if let Some(ref ver) = tool.version {
                        if !req_c.matches(ver) {
                            satisfied = false;
                            fail_reason = Some(format!(
                                "Compiler '{}' version {} does not satisfy requirement {}",
                                tool.name, ver, req_c
                            ));
                        }
                    }
                }

                if satisfied {
                    if let Some(ref std_name) = min_standard {
                        let (supported, detail) = compiler_supports_standard(
                            &tool.name,
                            language,
                            std_name,
                            tool.version.as_deref(),
                        );
                        if !supported {
                            satisfied = false;
                            fail_reason = detail;
                        }
                    }
                }

                if satisfied {
                    EvaluatedConstraint {
                        constraint: constraint.clone(),
                        status: ConstraintStatus::Satisfied,
                        project_evidence,
                        machine_evidence: Some(tool.evidence.clone()),
                    }
                } else {
                    let reason = fail_reason.unwrap_or_else(|| {
                        format!("Compiler '{}' does not satisfy requirements", tool.name)
                    });
                    let root_cause_hint = format!("{}.compiler_incompatible", language);
                    EvaluatedConstraint {
                        constraint: constraint.clone(),
                        status: ConstraintStatus::Violated {
                            reason,
                            root_cause_hint,
                        },
                        project_evidence,
                        machine_evidence: Some(tool.evidence.clone()),
                    }
                }
            } else {
                let reason = format!(
                    "No compiler found for language '{}' (checked: {})",
                    language,
                    candidates.join(", ")
                );
                let root_cause_hint = format!("{}.compiler_missing", language);
                EvaluatedConstraint {
                    constraint: constraint.clone(),
                    status: ConstraintStatus::Violated {
                        reason,
                        root_cause_hint,
                    },
                    project_evidence,
                    machine_evidence: None,
                }
            }
        }

        Constraint::LanguagePackageAvailable {
            language,
            package,
            constraint: _req_constraint,
            scope,
        } => {
            if matches!(scope, ToolScope::Optional | ToolScope::DeclaredButUnused) {
                EvaluatedConstraint {
                    constraint: constraint.clone(),
                    status: ConstraintStatus::Satisfied,
                    project_evidence,
                    machine_evidence: None,
                }
            } else if language == "python" {
                let check_cmd = Command::new("python3")
                    .args(["-c", &format!("import {}", package)])
                    .output();
                match check_cmd {
                    Ok(out) if out.status.success() => EvaluatedConstraint {
                        constraint: constraint.clone(),
                        status: ConstraintStatus::Satisfied,
                        project_evidence,
                        machine_evidence: None,
                    },
                    _ => {
                        let reason = format!(
                            "Python module '{}' is not installed in the active Python environment",
                            package
                        );
                        let root_cause_hint = format!("python.{}.missing", package);
                        EvaluatedConstraint {
                            constraint: constraint.clone(),
                            status: ConstraintStatus::Violated {
                                reason,
                                root_cause_hint,
                            },
                            project_evidence,
                            machine_evidence: None,
                        }
                    }
                }
            } else {
                EvaluatedConstraint {
                    constraint: constraint.clone(),
                    status: ConstraintStatus::Satisfied,
                    project_evidence,
                    machine_evidence: None,
                }
            }
        }

        Constraint::SystemLibraryAvailable {
            name,
            header,
            constraint: _req_constraint,
            scope,
        } => {
            if matches!(scope, ToolScope::Optional | ToolScope::DeclaredButUnused) {
                EvaluatedConstraint {
                    constraint: constraint.clone(),
                    status: ConstraintStatus::Satisfied,
                    project_evidence,
                    machine_evidence: None,
                }
            } else {
                let mut found_evidence = None;

                // 1. Check pkg-config metadata
                let pkg_names = if let Some(stripped) = name.strip_prefix("lib") {
                    vec![name.clone(), stripped.to_string()]
                } else {
                    vec![name.clone(), format!("lib{}", name)]
                };

                for pkg in &pkg_names {
                    if let Ok(out) = Command::new("pkg-config").args(["--exists", pkg]).output() {
                        if out.status.success() {
                            let mut detail = format!("pkg-config metadata exists for '{}'", pkg);
                            if let Ok(ver_out) = Command::new("pkg-config")
                                .args(["--modversion", pkg])
                                .output()
                            {
                                if ver_out.status.success() {
                                    let ver =
                                        String::from_utf8_lossy(&ver_out.stdout).trim().to_string();
                                    if !ver.is_empty() {
                                        detail = format!(
                                            "pkg-config metadata exists for '{}' (version: {})",
                                            pkg, ver
                                        );
                                    }
                                }
                            }
                            found_evidence = Some(Evidence::new(
                                EvidenceSource::DynamicProbe {
                                    target: format!("pkg-config {}", pkg),
                                    probe_type: "pkg-config".to_string(),
                                    outcome: detail.clone(),
                                },
                                Confidence::Confirmed,
                                detail,
                            ));
                            break;
                        }
                    }
                }

                // 2. Check standard linker-discoverable library paths
                if found_evidence.is_none() {
                    let lib_dirs = [
                        "/usr/lib",
                        "/usr/lib64",
                        "/usr/lib/x86_64-linux-gnu",
                        "/usr/lib/aarch64-linux-gnu",
                        "/lib",
                        "/lib64",
                        "/usr/local/lib",
                    ];
                    let mut patterns = Vec::new();
                    if name.starts_with("lib") {
                        patterns.push(format!("{}.so", name));
                        patterns.push(format!("{}.a", name));
                    } else {
                        patterns.push(format!("lib{}.so", name));
                        patterns.push(format!("lib{}.a", name));
                        patterns.push(format!("{}.so", name));
                    }

                    for dir in &lib_dirs {
                        let p = Path::new(dir);
                        for pat in &patterns {
                            let candidate = p.join(pat);
                            if candidate.exists() {
                                let detail = format!(
                                    "library binary discoverable by linker at '{}'",
                                    candidate.display()
                                );
                                found_evidence = Some(Evidence::new(
                                    EvidenceSource::DirectObservation {
                                        detail: detail.clone(),
                                    },
                                    Confidence::High,
                                    detail,
                                ));
                                break;
                            }
                        }
                        if found_evidence.is_some() {
                            break;
                        }
                    }
                }

                // 3. If header specified, verify header exists
                if let Some(ref hdr) = header {
                    let header_dirs = [
                        "/usr/include",
                        "/usr/local/include",
                        "/usr/include/x86_64-linux-gnu",
                        "/usr/include/aarch64-linux-gnu",
                    ];
                    let mut header_path = None;
                    for dir in &header_dirs {
                        let p = Path::new(dir).join(hdr);
                        if p.exists() {
                            header_path = Some(p);
                            break;
                        }
                    }

                    if let Some(hp) = header_path {
                        if let Some(ref mut ev) = found_evidence {
                            ev.description =
                                format!("{}, header exists at '{}'", ev.description, hp.display());
                        }
                    } else {
                        found_evidence = None;
                    }
                }

                if let Some(ev) = found_evidence {
                    EvaluatedConstraint {
                        constraint: constraint.clone(),
                        status: ConstraintStatus::Satisfied,
                        project_evidence,
                        machine_evidence: Some(ev),
                    }
                } else {
                    let header_clause = header
                        .as_deref()
                        .map(|h| format!(" (header '{}')", h))
                        .unwrap_or_default();
                    let reason = format!(
                        "System library '{}'{} is not discoverable via pkg-config or standard library paths",
                        name, header_clause
                    );
                    let root_cause_hint = format!("syslib.{}.missing", name);
                    EvaluatedConstraint {
                        constraint: constraint.clone(),
                        status: ConstraintStatus::Violated {
                            reason,
                            root_cause_hint,
                        },
                        project_evidence,
                        machine_evidence: None,
                    }
                }
            }
        }
    }
}

/// Convert a ProjectRequirement into a Constraint with optional project manifest context.
pub fn requirement_to_constraint_with_project(
    req: &ProjectRequirement,
    project: Option<&unfuck_core::ir::ProjectManifest>,
    machine: &MachineCapability,
) -> Option<Constraint> {
    if let Some(ref plat) = req.platform {
        if !machine.os.to_lowercase().contains(&plat.to_lowercase()) {
            return None;
        }
    }
    match &req.kind {
        RequirementKind::Service { name, min_version } => {
            if let Some(proj) = project {
                if let Some((compose_proj, compose_svc)) =
                    proj.find_compose_service_for_service(name)
                {
                    if !compose_proj.can_instantiate {
                        let bootstrap_suggestions = proj
                            .bootstrap_actions
                            .iter()
                            .map(|b| b.description.clone())
                            .collect();
                        return Some(Constraint::ComposeConfigUnresolved {
                            compose_file: compose_proj.file_path.clone(),
                            project_name: compose_proj.name.clone(),
                            service_name: None,
                            missing_env_files: compose_proj.missing_env_files.clone(),
                            unresolved_vars: compose_proj.unresolved_env_vars.clone(),
                            env_templates: compose_proj.env_templates.clone(),
                            directly_affected_services: compose_proj
                                .directly_affected_services
                                .clone(),
                            transitively_blocked_services: compose_proj
                                .transitively_blocked_services
                                .clone(),
                            bootstrap_suggestions,
                        });
                    }

                    let target_container = machine.find_container_for_compose_service(
                        compose_proj.name.as_deref(),
                        &compose_svc.name,
                        compose_svc.container_name.as_deref(),
                    );

                    let (expected_state, actual_state) = if let Some(container) = target_container {
                        let expected = if compose_svc.has_healthcheck {
                            "healthy".to_string()
                        } else {
                            "running".to_string()
                        };
                        let actual = container.status.to_string();
                        (expected, actual)
                    } else {
                        ("running".to_string(), "not-created".to_string())
                    };

                    return Some(Constraint::ComposeServiceState {
                        compose_file: compose_proj.file_path.clone(),
                        service_name: compose_svc.name.clone(),
                        container_name: compose_svc.container_name.clone(),
                        expected_state,
                        actual_state,
                    });
                }
            }

            Some(Constraint::ServiceRunning {
                service: name.clone(),
                min_version: min_version.clone(),
            })
        }
        _ => requirement_to_constraint(req),
    }
}

/// Evaluates all project requirements against machine capabilities with project manifest context.
pub fn evaluate_project(
    project: &unfuck_core::ir::ProjectManifest,
    machine: &MachineCapability,
) -> Vec<EvaluatedConstraint> {
    let mut results = Vec::new();
    for compose_proj in &project.compose_projects {
        if !compose_proj.can_instantiate {
            let bootstrap_suggestions = project
                .bootstrap_actions
                .iter()
                .map(|b| b.description.clone())
                .collect();
            let constraint = Constraint::ComposeConfigUnresolved {
                compose_file: compose_proj.file_path.clone(),
                project_name: compose_proj.name.clone(),
                service_name: None,
                missing_env_files: compose_proj.missing_env_files.clone(),
                unresolved_vars: compose_proj.unresolved_env_vars.clone(),
                env_templates: compose_proj.env_templates.clone(),
                directly_affected_services: compose_proj.directly_affected_services.clone(),
                transitively_blocked_services: compose_proj.transitively_blocked_services.clone(),
                bootstrap_suggestions,
            };
            if !results
                .iter()
                .any(|e: &EvaluatedConstraint| e.constraint == constraint)
            {
                let ev = Evidence::from_repo_file(
                    compose_proj.file_path.clone(),
                    None,
                    format!(
                        "Compose file {} cannot be instantiated",
                        compose_proj.file_path.display()
                    ),
                );
                let evaluated = evaluate_constraint(&constraint, machine, Some(ev));
                results.push(evaluated);
            }
        }
    }
    for req in &project.requirements {
        if let Some(constraint) =
            requirement_to_constraint_with_project(req, Some(project), machine)
        {
            if results
                .iter()
                .any(|e: &EvaluatedConstraint| e.constraint == constraint)
            {
                continue;
            }
            let evaluated = evaluate_constraint(&constraint, machine, Some(req.evidence.clone()));
            results.push(evaluated);
        }
    }
    results
}

/// Evaluates all project requirements against machine capabilities.
pub fn evaluate_all(
    requirements: &[ProjectRequirement],
    machine: &MachineCapability,
) -> Vec<EvaluatedConstraint> {
    let mut results = Vec::new();
    for req in requirements {
        if let Some(constraint) = requirement_to_constraint(req) {
            if results
                .iter()
                .any(|e: &EvaluatedConstraint| e.constraint == constraint)
            {
                continue;
            }
            let evaluated = evaluate_constraint(&constraint, machine, Some(req.evidence.clone()));
            results.push(evaluated);
        }
    }
    results
}

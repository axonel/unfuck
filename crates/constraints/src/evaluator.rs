use crate::model::{Constraint, ConstraintStatus, EvaluatedConstraint};
use crate::version::matches_version_constraint;
use unfuck_core::evidence::Evidence;
use unfuck_core::ir::{
    MachineCapability, ProjectRequirement, RequirementKind, ServiceStatus, ToolKind,
};

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
    }
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
    }
}

/// Convert a ProjectRequirement into a Constraint with optional project manifest context.
pub fn requirement_to_constraint_with_project(
    req: &ProjectRequirement,
    project: Option<&unfuck_core::ir::ProjectManifest>,
    machine: &MachineCapability,
) -> Option<Constraint> {
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

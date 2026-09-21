use serde::{Deserialize, Serialize};
use unfuck_constraints::model::{Constraint, ConstraintStatus, EvaluatedConstraint};
use unfuck_core::evidence::Evidence;
use unfuck_core::ir::EnvironmentModel;
use unfuck_core::Confidence;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PredictionCategory {
    RuntimeIncompatibility,
    PortCollision,
    MissingService,
    InsufficientResources,
    ConfigurationMissing,
    ConfigurationConflict,
    OsArchMismatch,
}

/// A structured failure prediction derived from deterministic constraint evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prediction {
    pub title: String,
    pub category: PredictionCategory,
    pub summary: String,
    pub confidence: Confidence,
    pub constraint: Constraint,
    pub affected_components: Vec<String>,
    pub project_evidence: Option<Evidence>,
    pub machine_evidence: Option<Evidence>,
}

/// Deterministically predicts environment and runtime failures before execution.
pub fn predict_failures(
    model: &EnvironmentModel,
    evaluated_constraints: &[EvaluatedConstraint],
) -> Vec<Prediction> {
    let mut predictions = Vec::new();

    for eval in evaluated_constraints {
        if let ConstraintStatus::Violated {
            reason,
            root_cause_hint: _,
        } = &eval.status
        {
            match &eval.constraint {
                Constraint::RuntimeVersion {
                    runtime,
                    constraint_str,
                } => {
                    let affected = if model.project.languages.iter().any(|l| l.contains(runtime)) {
                        vec![runtime.clone(), "build".to_string(), "startup".to_string()]
                    } else {
                        vec![runtime.clone(), "runtime".to_string()]
                    };

                    predictions.push(Prediction {
                        title: format!("{} runtime incompatibility predicted", runtime),
                        category: PredictionCategory::RuntimeIncompatibility,
                        summary: format!(
                            "Project expects {} {}, but {}. Application startup or build is predicted to fail.",
                            runtime, constraint_str, reason
                        ),
                        confidence: Confidence::High,
                        constraint: eval.constraint.clone(),
                        affected_components: affected,
                        project_evidence: eval.project_evidence.clone(),
                        machine_evidence: eval.machine_evidence.clone(),
                    });
                }

                Constraint::PortAvailable { port } => {
                    predictions.push(Prediction {
                        title: format!("Port {} collision predicted", port),
                        category: PredictionCategory::PortCollision,
                        summary: format!(
                            "Project expects port {} to be available, but it is currently occupied. Server startup will fail with EADDRINUSE.",
                            port
                        ),
                        confidence: Confidence::High,
                        constraint: eval.constraint.clone(),
                        affected_components: vec![format!("port:{}", port), "networking".to_string(), "server".to_string()],
                        project_evidence: eval.project_evidence.clone(),
                        machine_evidence: eval.machine_evidence.clone(),
                    });
                }

                Constraint::ServiceRunning {
                    service,
                    min_version,
                } => {
                    let version_str = min_version
                        .as_deref()
                        .map(|v| format!(" (version >= {})", v))
                        .unwrap_or_default();
                    predictions.push(Prediction {
                        title: format!("Required service '{}' failure predicted", service),
                        category: PredictionCategory::MissingService,
                        summary: format!(
                            "Project depends on service '{}{}', but it is not running or not installed. Connections will be refused.",
                            service, version_str
                        ),
                        confidence: Confidence::High,
                        constraint: eval.constraint.clone(),
                        affected_components: vec![service.clone(), "database/backend".to_string()],
                        project_evidence: eval.project_evidence.clone(),
                        machine_evidence: eval.machine_evidence.clone(),
                    });
                }

                Constraint::MemoryMin { min_bytes } => {
                    predictions.push(Prediction {
                        title: "Resource exhaustion (OOM) predicted".to_string(),
                        category: PredictionCategory::InsufficientResources,
                        summary: format!(
                            "Project requires at least {:.1} GB memory, but machine has less. Build or runtime may be terminated by OOM killer.",
                            *min_bytes as f64 / (1024.0 * 1024.0 * 1024.0)
                        ),
                        confidence: Confidence::Medium,
                        constraint: eval.constraint.clone(),
                        affected_components: vec!["system".to_string(), "build".to_string()],
                        project_evidence: eval.project_evidence.clone(),
                        machine_evidence: eval.machine_evidence.clone(),
                    });
                }

                Constraint::EnvVarSet { key, required } => {
                    if *required {
                        predictions.push(Prediction {
                            title: format!("Required environment variable '{}' missing", key),
                            category: PredictionCategory::ConfigurationMissing,
                            summary: format!(
                                "Project declares required environment variable '{}', but it is not set in the environment.",
                                key
                            ),
                            confidence: Confidence::High,
                            constraint: eval.constraint.clone(),
                            affected_components: vec!["configuration".to_string(), "startup".to_string()],
                            project_evidence: eval.project_evidence.clone(),
                            machine_evidence: None,
                        });
                    }
                }

                Constraint::OsMatch { expected_os } => {
                    predictions.push(Prediction {
                        title: format!("Operating system mismatch: expected {}", expected_os),
                        category: PredictionCategory::OsArchMismatch,
                        summary: format!(
                            "Project specifies operating system '{}', but host OS is '{}'.",
                            expected_os, model.machine.os
                        ),
                        confidence: Confidence::Confirmed,
                        constraint: eval.constraint.clone(),
                        affected_components: vec!["os".to_string()],
                        project_evidence: eval.project_evidence.clone(),
                        machine_evidence: None,
                    });
                }

                Constraint::ArchMatch { expected_arch } => {
                    predictions.push(Prediction {
                        title: format!("Architecture mismatch: expected {}", expected_arch),
                        category: PredictionCategory::OsArchMismatch,
                        summary: format!(
                            "Project specifies CPU architecture '{}', but host is '{}'.",
                            expected_arch, model.machine.arch
                        ),
                        confidence: Confidence::Confirmed,
                        constraint: eval.constraint.clone(),
                        affected_components: vec!["architecture".to_string()],
                        project_evidence: eval.project_evidence.clone(),
                        machine_evidence: None,
                    });
                }

                Constraint::ConflictDetected { target, details } => {
                    predictions.push(Prediction {
                        title: format!("Contradictory {} configuration detected", target),
                        category: PredictionCategory::ConfigurationConflict,
                        summary: format!(
                            "Project configuration contains conflicting {} requirements: {}.",
                            target, details
                        ),
                        confidence: Confidence::Confirmed,
                        constraint: eval.constraint.clone(),
                        affected_components: vec![
                            target.clone(),
                            "configuration".to_string(),
                            "build".to_string(),
                        ],
                        project_evidence: eval.project_evidence.clone(),
                        machine_evidence: None,
                    });
                }
            }
        }
    }

    let mut deduped: Vec<Prediction> = Vec::new();
    for p in predictions {
        if let Some(existing) = deduped.iter_mut().find(|e| e.constraint == p.constraint) {
            for comp in p.affected_components {
                if !existing.affected_components.contains(&comp) {
                    existing.affected_components.push(comp);
                }
            }
        } else {
            deduped.push(p);
        }
    }

    deduped
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use unfuck_core::ir::{MachineCapability, ProjectManifest};

    #[test]
    fn test_predict_runtime_failure() {
        let manifest = ProjectManifest {
            name: "app".to_string(),
            root_path: PathBuf::from("/test/app"),
            languages: vec!["python".to_string()],
            package_managers: vec![],
            requirements: vec![],
            declared_ports: vec![],
            env_vars: vec![],
            env_var_specs: vec![],
            components: vec![],
            docker_used: false,
            evidence: vec![],
        };

        let machine = MachineCapability {
            os: "Linux".to_string(),
            os_family: "linux".to_string(),
            arch: "x86_64".to_string(),
            cpu_count: 4,
            total_memory_bytes: 1024,
            available_memory_bytes: 512,
            runtimes: vec![],
            services: vec![],
            listening_ports: vec![],
            env_vars: HashMap::new(),
            path_entries: vec![],
            evidence: vec![],
        };

        let env_model = EnvironmentModel::new(manifest, machine);

        let eval = EvaluatedConstraint {
            constraint: Constraint::RuntimeVersion {
                runtime: "python".to_string(),
                constraint_str: ">= 3.11".to_string(),
            },
            status: ConstraintStatus::Violated {
                reason: "Runtime 'python' is not installed".to_string(),
                root_cause_hint: "python.missing".to_string(),
            },
            project_evidence: None,
            machine_evidence: None,
        };

        let predictions = predict_failures(&env_model, &[eval]);
        assert_eq!(predictions.len(), 1);
        assert_eq!(
            predictions[0].category,
            PredictionCategory::RuntimeIncompatibility
        );
        assert_eq!(predictions[0].confidence, Confidence::High);
    }
}

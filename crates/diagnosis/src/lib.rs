use serde::{Deserialize, Serialize};
use unfuck_constraints::model::Constraint;
use unfuck_core::evidence::Evidence;
use unfuck_core::Confidence;
use unfuck_graph::model::CausalTrace;
use unfuck_predictor::Prediction;

/// Structured root-cause diagnosis explaining why an environment failure will occur.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnosis {
    pub problem: String,
    pub root_cause: String,
    pub causal_chain: Vec<String>,
    pub violated_constraint: String,
    pub confidence: Confidence,
    pub affected_components: Vec<String>,
    pub project_evidence: Option<Evidence>,
    pub machine_evidence: Option<Evidence>,
}

/// Generates deterministic root-cause diagnoses from predictions and graph causal traces.
pub fn diagnose_all(predictions: &[Prediction], traces: &[CausalTrace]) -> Vec<Diagnosis> {
    let mut diagnoses = Vec::new();

    for pred in predictions {
        let matching_trace = traces.iter().find(|t| t.constraint == pred.constraint);

        let (root_cause, causal_chain) = match &pred.constraint {
            Constraint::RuntimeVersion {
                runtime,
                constraint,
            } => {
                let actual_state = matching_trace
                    .and_then(|t| t.machine_state.as_deref())
                    .unwrap_or("runtime missing or version incompatible");

                let chain = vec![
                    format!("Host machine state: {}", actual_state),
                    format!("Project specification: requires {} {}", runtime, constraint),
                    format!("Violated invariant: {}.version satisfies {}", runtime, constraint),
                    format!("Downstream impact: {} toolchain cannot initialize; build and runtime will fail", runtime),
                ];

                (
                    format!("{}.version satisfies {}", runtime, constraint),
                    chain,
                )
            }

            Constraint::PackageManagerVersion { name, constraint } => {
                let actual_state = matching_trace
                    .and_then(|t| t.machine_state.as_deref())
                    .unwrap_or("package manager missing or version incompatible");
                let constraint_desc = match constraint {
                    Some(c) => format!(" satisfying {}", c),
                    None => " installed".to_string(),
                };

                let chain = vec![
                    format!("Host machine state: {}", actual_state),
                    format!(
                        "Project specification: requires package manager {}{}",
                        name, constraint_desc
                    ),
                    format!(
                        "Violated invariant: package_manager.{}{}",
                        name, constraint_desc
                    ),
                    format!(
                        "Downstream impact: dependency installation via {} cannot proceed",
                        name
                    ),
                ];

                (
                    format!("package_manager.{}{}", name, constraint_desc),
                    chain,
                )
            }

            Constraint::ToolAvailable {
                name,
                kind,
                constraint,
                scope,
            } => {
                let actual_state = matching_trace
                    .and_then(|t| t.machine_state.as_deref())
                    .unwrap_or("tool missing or version incompatible");
                let constraint_desc = match constraint {
                    Some(c) => format!(" satisfying {}", c),
                    None => " installed".to_string(),
                };

                let chain = vec![
                    format!("Host machine state: {}", actual_state),
                    format!(
                        "Project specification: declares {} tool {}{} (scope: {:?})",
                        kind, name, constraint_desc, scope
                    ),
                    format!("Violated invariant: tool.{}{}", name, constraint_desc),
                    format!(
                        "Downstream impact: tasks or builds relying on {} will fail",
                        name
                    ),
                ];

                (format!("tool.{}{}", name, constraint_desc), chain)
            }

            Constraint::PortAvailable { port } => {
                let actual_state = matching_trace
                    .and_then(|t| t.machine_state.as_deref())
                    .unwrap_or("port occupied in kernel socket table");

                let chain = vec![
                    format!("Host network state: {}", actual_state),
                    format!("Project specification: requires port {} to be available", port),
                    format!("Violated invariant: port.{} must be free", port),
                    format!("Downstream impact: application binding to port {} will encounter EADDRINUSE collision", port),
                ];

                (format!("port:{}.free", port), chain)
            }

            Constraint::ServiceRunning {
                service,
                min_version,
            } => {
                let ver_clause = min_version
                    .as_deref()
                    .map(|v| format!(" >= {}", v))
                    .unwrap_or_default();
                let actual_state = matching_trace
                    .and_then(|t| t.machine_state.as_deref())
                    .unwrap_or("service stopped or inactive");

                let chain = vec![
                    format!("Host service state: {}", actual_state),
                    format!(
                        "Project specification: depends on active service {}{}",
                        service, ver_clause
                    ),
                    format!("Violated invariant: service.{}.status == RUNNING", service),
                    format!(
                        "Downstream impact: application connections to {} will be refused",
                        service
                    ),
                ];

                (format!("service.{}.running", service), chain)
            }

            Constraint::MemoryMin { min_bytes } => {
                let chain = vec![
                    "Host resource state: available memory is below required threshold".to_string(),
                    format!("Project specification: requires at least {:.1} GB memory", *min_bytes as f64 / (1024.0 * 1024.0 * 1024.0)),
                    "Violated invariant: machine.memory >= project.min_memory".to_string(),
                    "Downstream impact: high risk of out-of-memory termination during build or heavy execution".to_string(),
                ];

                ("memory.minimum_threshold".to_string(), chain)
            }

            Constraint::EnvVarSet { key, .. } => {
                let chain = vec![
                    format!("Host environment state: variable '{}' is unset", key),
                    format!("Project specification: requires '{}' in environment", key),
                    format!("Violated invariant: env.contains('{}')", key),
                    format!(
                        "Downstream impact: application configuration lookup for '{}' will fail",
                        key
                    ),
                ];

                (format!("env.{}.present", key), chain)
            }

            Constraint::OsMatch { expected_os } => {
                let chain = vec![
                    "Host OS differs from project expectations".to_string(),
                    format!("Project specification: requires OS '{}'", expected_os),
                    format!("Violated invariant: host.os == '{}'", expected_os),
                    "Downstream impact: platform-specific scripts or binaries will fail"
                        .to_string(),
                ];

                (format!("os.match({})", expected_os), chain)
            }

            Constraint::ArchMatch { expected_arch } => {
                let chain = vec![
                    "Host architecture differs from project expectations".to_string(),
                    format!(
                        "Project specification: requires architecture '{}'",
                        expected_arch
                    ),
                    format!("Violated invariant: host.arch == '{}'", expected_arch),
                    "Downstream impact: native compilation or prebuilt binary execution will fail"
                        .to_string(),
                ];

                (format!("arch.match({})", expected_arch), chain)
            }
            Constraint::ConflictDetected { target, details } => {
                let chain = vec![
                    format!("Configuration conflict detected: {}", details),
                    format!("Target: {}", target),
                    "Violated invariant: configuration sources must not specify conflicting requirements".to_string(),
                    "Downstream impact: unpredictable build or runtime failures due to toolchain or version disagreement".to_string(),
                ];

                (format!("conflict.{}", target), chain)
            }

            Constraint::ComposeConfigUnresolved {
                compose_file,
                project_name: _,
                service_name,
                missing_env_files,
                unresolved_vars,
            } => {
                let s_name = service_name.as_deref().unwrap_or("compose");
                let mut chain = Vec::new();
                chain.push(format!(
                    "Project specification: defines Compose service '{}' in '{}'",
                    s_name,
                    compose_file.display()
                ));
                if !missing_env_files.is_empty() {
                    let missing_str = missing_env_files
                        .iter()
                        .map(|p| p.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ");
                    chain.push(format!(
                        "Configuration defect: required environment file(s) missing: {}",
                        missing_str
                    ));
                }
                if !unresolved_vars.is_empty() {
                    chain.push(format!(
                        "Unresolved variable(s): {}",
                        unresolved_vars.join(", ")
                    ));
                }
                chain.push("Violated invariant: compose_config.is_resolvable()".to_string());
                chain.push(format!(
                    "Downstream impact: Docker Compose cannot instantiate the stack; service '{}' container cannot be started",
                    s_name
                ));

                let root_cause = if !missing_env_files.is_empty() {
                    format!("missing.env_file:{}", missing_env_files[0].display())
                } else {
                    format!("compose.{}.unresolved_vars", s_name)
                };
                (root_cause, chain)
            }

            Constraint::ComposeServiceState {
                compose_file,
                service_name,
                container_name,
                expected_state,
                actual_state,
            } => {
                let c_str = container_name
                    .as_deref()
                    .map(|c| format!(" (container '{}')", c))
                    .unwrap_or_default();
                let chain = vec![
                    format!(
                        "Project specification: defines Compose service '{}'{} in '{}'",
                        service_name,
                        c_str,
                        compose_file.display()
                    ),
                    format!("Host container state: {}", actual_state),
                    format!(
                        "Violated invariant: compose_service.{}.state == '{}'",
                        service_name, expected_state
                    ),
                    format!(
                        "Downstream impact: network connections to service '{}' will fail",
                        service_name
                    ),
                ];
                (format!("compose.{}.state", service_name), chain)
            }
        };

        let final_root_cause = matching_trace
            .and_then(|t| t.root_cause.clone())
            .unwrap_or(root_cause);

        let final_causal_chain = matching_trace
            .filter(|t| !t.causal_steps.is_empty())
            .map(|t| t.causal_steps.clone())
            .unwrap_or(causal_chain);

        let affected_components = if !pred.affected_components.is_empty() {
            pred.affected_components.clone()
        } else if let Some(trace) = matching_trace {
            trace.affected_components.clone()
        } else {
            Vec::new()
        };

        diagnoses.push(Diagnosis {
            problem: pred.title.clone(),
            root_cause: final_root_cause,
            causal_chain: final_causal_chain,
            violated_constraint: pred.constraint.to_string(),
            confidence: pred.confidence,
            affected_components,
            project_evidence: pred.project_evidence.clone(),
            machine_evidence: pred.machine_evidence.clone(),
        });
    }

    diagnoses
}

#[cfg(test)]
mod tests {
    use super::*;
    use unfuck_predictor::PredictionCategory;

    #[test]
    fn test_diagnosis_generation() {
        let pred = Prediction {
            title: "python runtime incompatibility predicted".to_string(),
            category: PredictionCategory::RuntimeIncompatibility,
            summary: "Python 3.10 is installed, >= 3.11 required".to_string(),
            confidence: Confidence::High,
            constraint: Constraint::RuntimeVersion {
                runtime: "python".to_string(),
                constraint: unfuck_core::version::VersionConstraint::parse(">= 3.11"),
            },
            affected_components: vec!["python".to_string(), "backend".to_string()],
            project_evidence: None,
            machine_evidence: None,
        };

        let diagnoses = diagnose_all(&[pred], &[]);
        assert_eq!(diagnoses.len(), 1);
        let diag = &diagnoses[0];
        assert_eq!(diag.confidence, Confidence::High);
        assert!(diag.root_cause.contains("python.version"));
        assert_eq!(diag.causal_chain.len(), 4);
    }
}

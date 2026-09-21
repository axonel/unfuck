use std::path::PathBuf;
use unfuck_constraints::evaluator::evaluate_all;
use unfuck_core::ir::{EnvironmentModel, PortInfo, PortState};
use unfuck_core::Confidence;
use unfuck_diagnosis::diagnose_all;
use unfuck_graph::EnvironmentGraph;
use unfuck_predictor::{predict_failures, PredictionCategory};
use unfuck_project::analyze_project;
use unfuck_scanner::scan_machine;
use unfuck_verifier::verify_environment;

fn fixtures_dir() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests")
        .join("fixtures")
}

#[test]
fn test_fixture_analysis_node() {
    let fixture_path = fixtures_dir().join("healthy-node-app");
    let manifest = analyze_project(&fixture_path).expect("analyze healthy-node-app");

    assert_eq!(manifest.name, "healthy-node-app");
    assert!(manifest
        .languages
        .contains(&"javascript/typescript".to_string()));
    let node_req = manifest.requirements.iter().find(|r| r.name == "node");
    assert!(node_req.is_some());
}

#[test]
fn test_fixture_analysis_python() {
    let fixture_path = fixtures_dir().join("healthy-python-app");
    let manifest = analyze_project(&fixture_path).expect("analyze healthy-python-app");

    assert_eq!(manifest.name, "healthy-python-app");
    assert!(manifest.languages.contains(&"python".to_string()));
    let py_req = manifest.requirements.iter().find(|r| r.name == "python");
    assert!(py_req.is_some());
}

#[test]
fn test_fixture_analysis_docker() {
    let fixture_path = fixtures_dir().join("docker-postgres-app");
    let manifest = analyze_project(&fixture_path).expect("analyze docker-postgres-app");

    assert!(manifest.docker_used);
    assert!(manifest.declared_ports.contains(&3000));
    assert!(manifest.declared_ports.contains(&5432));
    assert!(manifest.requirements.iter().any(|r| r.name == "docker"));
    assert!(manifest.requirements.iter().any(|r| r.name == "postgresql"));
}

#[test]
fn test_broken_node_version_prediction() {
    let fixture_path = fixtures_dir().join("broken-node-version");
    let manifest = analyze_project(&fixture_path).expect("analyze broken-node-version");
    let machine = scan_machine();

    let evaluated_constraints = evaluate_all(&manifest.requirements, &machine);
    let env_model = EnvironmentModel::new(manifest, machine);
    let graph = EnvironmentGraph::build(&env_model, &evaluated_constraints);
    let predictions = predict_failures(&env_model, &evaluated_constraints);
    let traces = graph.all_causal_traces();
    let diagnoses = diagnose_all(&predictions, &traces);

    // Because broken-node-version requires node >= 99.0.0, this MUST be predicted as a failure
    assert!(
        !predictions.is_empty(),
        "Should predict failure for node >= 99.0.0"
    );
    let node_pred = predictions
        .iter()
        .find(|p| p.category == PredictionCategory::RuntimeIncompatibility);
    assert!(node_pred.is_some());
    let pred = node_pred.unwrap();
    assert_eq!(pred.confidence, Confidence::High);

    // Verify diagnosis
    let node_diag = diagnoses.iter().find(|d| d.problem.contains("node"));
    assert!(node_diag.is_some());
    let diag = node_diag.unwrap();
    assert!(diag.root_cause.contains("node.version"));
    assert_eq!(diag.causal_chain.len(), 4);
}

#[test]
fn test_broken_python_version_prediction() {
    let fixture_path = fixtures_dir().join("broken-python-version");
    let manifest = analyze_project(&fixture_path).expect("analyze broken-python-version");
    let machine = scan_machine();

    let evaluated_constraints = evaluate_all(&manifest.requirements, &machine);
    let env_model = EnvironmentModel::new(manifest, machine);
    let graph = EnvironmentGraph::build(&env_model, &evaluated_constraints);
    let predictions = predict_failures(&env_model, &evaluated_constraints);
    let traces = graph.all_causal_traces();
    let diagnoses = diagnose_all(&predictions, &traces);

    // broken-python-version requires python >= 3.99.0
    assert!(
        !predictions.is_empty(),
        "Should predict failure for python >= 3.99.0"
    );
    let py_pred = predictions
        .iter()
        .find(|p| p.category == PredictionCategory::RuntimeIncompatibility);
    assert!(py_pred.is_some());
    assert_eq!(py_pred.unwrap().confidence, Confidence::High);

    let py_diag = diagnoses.iter().find(|d| d.problem.contains("python"));
    assert!(py_diag.is_some());
    assert!(py_diag.unwrap().root_cause.contains("python.version"));
}

#[test]
fn test_port_collision_prediction() {
    let fixture_path = fixtures_dir().join("docker-postgres-app");
    let manifest = analyze_project(&fixture_path).expect("analyze docker-postgres-app");

    // Create a mock machine where port 3000 is occupied
    let mut machine = scan_machine();
    machine.listening_ports.push(PortInfo {
        port: 3000,
        state: PortState::Occupied {
            pid: Some(1337),
            process_name: Some("rogue-web".to_string()),
        },
        evidence: unfuck_core::evidence::Evidence::new(
            unfuck_core::evidence::EvidenceSource::ProcessInspection {
                pid: 1337,
                name: "rogue-web".to_string(),
                cmdline: None,
            },
            Confidence::Confirmed,
            "Port 3000 occupied by rogue-web",
        ),
    });

    let evaluated_constraints = evaluate_all(&manifest.requirements, &machine);
    let env_model = EnvironmentModel::new(manifest, machine);
    let graph = EnvironmentGraph::build(&env_model, &evaluated_constraints);
    let predictions = predict_failures(&env_model, &evaluated_constraints);
    let traces = graph.all_causal_traces();
    let diagnoses = diagnose_all(&predictions, &traces);

    let port_pred = predictions
        .iter()
        .find(|p| p.category == PredictionCategory::PortCollision);
    assert!(port_pred.is_some(), "Port collision should be predicted");
    assert_eq!(port_pred.unwrap().confidence, Confidence::High);

    let port_diag = diagnoses.iter().find(|d| d.problem.contains("3000"));
    assert!(port_diag.is_some());
    assert!(port_diag.unwrap().root_cause.contains("port:3000.free"));
}

#[test]
fn test_read_only_verification_report() {
    let fixture_path = fixtures_dir().join("broken-node-version");
    let manifest = analyze_project(&fixture_path).expect("analyze broken-node-version");
    let machine = scan_machine();
    let evaluated_constraints = evaluate_all(&manifest.requirements, &machine);
    let env_model = EnvironmentModel::new(manifest, machine);

    let report = verify_environment(&env_model, &evaluated_constraints);
    assert!(!report.success);
    assert!(report.failed_checks >= 1);
}

#[test]
fn test_json_serialization_roundtrip() {
    let fixture_path = fixtures_dir().join("healthy-node-app");
    let manifest = analyze_project(&fixture_path).expect("analyze healthy-node-app");
    let machine = scan_machine();
    let evaluated_constraints = evaluate_all(&manifest.requirements, &machine);
    let env_model = EnvironmentModel::new(manifest.clone(), machine.clone());
    let predictions = predict_failures(&env_model, &evaluated_constraints);
    let graph = EnvironmentGraph::build(&env_model, &evaluated_constraints);
    let traces = graph.all_causal_traces();
    let diagnoses = diagnose_all(&predictions, &traces);
    let verification = verify_environment(&env_model, &evaluated_constraints);

    let report = unfuck::UnfuckReport {
        project: manifest,
        machine,
        evaluated_constraints,
        predictions,
        diagnoses,
        verification,
    };

    let json_str = serde_json::to_string_pretty(&report).expect("serialize report");
    assert!(json_str.contains("healthy-node-app"));

    // Verify it parses back as generic Value and retains keys
    let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("deserialize report");
    assert!(parsed.get("project").is_some());
    assert!(parsed.get("machine").is_some());
    assert!(parsed.get("predictions").is_some());
    assert!(parsed.get("diagnoses").is_some());
    assert!(parsed.get("verification").is_some());
}

#[test]
fn test_fixture_conflict_node_version() {
    let fixture_path = fixtures_dir().join("conflict-node-version");
    let manifest = analyze_project(&fixture_path).expect("analyze conflict-node-version");
    let machine = scan_machine();

    let evaluated_constraints = evaluate_all(&manifest.requirements, &machine);
    let env_model = EnvironmentModel::new(manifest, machine);
    let predictions = predict_failures(&env_model, &evaluated_constraints);

    let conflict_pred = predictions
        .iter()
        .find(|p| p.category == PredictionCategory::ConfigurationConflict);
    assert!(
        conflict_pred.is_some(),
        "Expected ConfigurationConflict prediction for node version mismatch between .nvmrc and package.json"
    );
    let pred = conflict_pred.unwrap();
    assert_eq!(pred.confidence, Confidence::Confirmed);
    assert!(pred
        .summary
        .contains("Contradictory node version requirements"));
}

#[test]
fn test_fixture_missing_env_app() {
    let fixture_path = fixtures_dir().join("missing-env-app");
    let manifest = analyze_project(&fixture_path).expect("analyze missing-env-app");
    let machine = scan_machine();

    let evaluated_constraints = evaluate_all(&manifest.requirements, &machine);
    let env_model = EnvironmentModel::new(manifest, machine);
    let predictions = predict_failures(&env_model, &evaluated_constraints);

    // API_SECRET_KEY is required and missing
    let secret_pred = predictions
        .iter()
        .find(|p| p.title.contains("API_SECRET_KEY"));
    assert!(
        secret_pred.is_some(),
        "Expected missing env prediction for API_SECRET_KEY"
    );

    // PORT has default 3000, so it should NOT be flagged as missing
    let port_pred = predictions.iter().find(|p| p.title.contains("PORT"));
    assert!(
        port_pred.is_none(),
        "PORT has a default in .env.example and should not be predicted as missing"
    );
}

#[test]
fn test_fixture_mise_pinned_tools() {
    let fixture_path = fixtures_dir().join("mise-pinned-tools");
    let manifest = analyze_project(&fixture_path).expect("analyze mise-pinned-tools");

    // Check package manager consolidation (pnpm from package.json engines + packageManager + mise.toml)
    let pnpm_reqs: Vec<_> = manifest
        .requirements
        .iter()
        .filter(|r| r.name == "pnpm")
        .collect();
    assert_eq!(
        pnpm_reqs.len(),
        1,
        "pnpm requirements must be consolidated into exactly one requirement"
    );
    let pnpm_req = pnpm_reqs[0];
    match &pnpm_req.kind {
        unfuck_core::ir::RequirementKind::PackageManager { name, constraint } => {
            assert_eq!(name, "pnpm");
            assert_eq!(
                constraint,
                &Some(unfuck_core::version::VersionConstraint::Exact(
                    "11.24.0".to_string()
                ))
            );
        }
        other => panic!("Expected PackageManager kind for pnpm, found {:?}", other),
    }
    assert!(
        !pnpm_req.additional_evidence.is_empty(),
        "Consolidated pnpm requirement must preserve additional evidence from package.json"
    );

    // Check exact pin on Java (must NOT be coerced to >=)
    let java_req = manifest
        .requirements
        .iter()
        .find(|r| r.name == "java")
        .expect("java requirement");
    match &java_req.kind {
        unfuck_core::ir::RequirementKind::Runtime { name, constraint } => {
            assert_eq!(name, "java");
            assert_eq!(
                constraint,
                &unfuck_core::version::VersionConstraint::Exact("21.0.2".to_string())
            );
        }
        other => panic!("Expected Runtime kind for java, found {:?}", other),
    }

    // Check classification and scopes
    let terragrunt = manifest
        .requirements
        .iter()
        .find(|r| r.name == "terragrunt")
        .expect("terragrunt");
    assert!(matches!(
        &terragrunt.kind,
        unfuck_core::ir::RequirementKind::DeveloperTool {
            scope: unfuck_core::ir::ToolScope::RequiredForTask,
            ..
        }
    ));

    let opentofu = manifest
        .requirements
        .iter()
        .find(|r| r.name == "opentofu")
        .expect("opentofu");
    assert!(matches!(
        &opentofu.kind,
        unfuck_core::ir::RequirementKind::DeveloperTool {
            scope: unfuck_core::ir::ToolScope::RequiredForTask,
            ..
        }
    ));

    let openapi = manifest
        .requirements
        .iter()
        .find(|r| r.name.contains("openapi-generator-cli"))
        .expect("openapi-generator-cli");
    assert!(matches!(
        &openapi.kind,
        unfuck_core::ir::RequirementKind::CodeGenerator {
            scope: unfuck_core::ir::ToolScope::RequiredForTask,
            ..
        }
    ));

    let oazapfts = manifest
        .requirements
        .iter()
        .find(|r| r.name.contains("oazapfts"))
        .expect("oazapfts");
    assert!(matches!(
        &oazapfts.kind,
        unfuck_core::ir::RequirementKind::CodeGenerator { .. }
    ));

    let extism = manifest
        .requirements
        .iter()
        .find(|r| r.name.contains("extism"))
        .expect("extism");
    assert!(matches!(
        &extism.kind,
        unfuck_core::ir::RequirementKind::DeveloperTool { .. }
    ));

    // Evaluate predictions against empty machine
    let machine = unfuck_core::ir::MachineCapability {
        os: "Linux".to_string(),
        os_family: "linux".to_string(),
        arch: "x86_64".to_string(),
        cpu_count: 8,
        total_memory_bytes: 16 * 1024 * 1024 * 1024,
        available_memory_bytes: 8 * 1024 * 1024 * 1024,
        runtimes: vec![],
        package_managers: vec![],
        tools: vec![],
        services: vec![],
        containers: vec![],
        listening_ports: vec![],
        env_vars: std::collections::HashMap::new(),
        path_entries: vec![],
        evidence: vec![],
    };

    let evaluated = evaluate_all(&manifest.requirements, &machine);
    let env_model = EnvironmentModel::new(manifest, machine);
    let predictions = predict_failures(&env_model, &evaluated);

    // Verify task tool prediction confidence is calibrated to Medium, not claiming application startup failure
    let tg_pred = predictions
        .iter()
        .find(|p| p.title.contains("terragrunt"))
        .expect("terragrunt prediction");
    assert_eq!(tg_pred.confidence, Confidence::Medium);
    assert!(!tg_pred.summary.contains("Application startup"));
}

#[test]
fn test_fixture_exact_runtime_pin() {
    let fixture_path = fixtures_dir().join("exact-runtime-pin");
    let manifest = analyze_project(&fixture_path).expect("analyze exact-runtime-pin");

    let java_req = manifest
        .requirements
        .iter()
        .find(|r| r.name == "java")
        .expect("java");
    assert_eq!(
        java_req.kind,
        unfuck_core::ir::RequirementKind::Runtime {
            name: "java".to_string(),
            constraint: unfuck_core::version::VersionConstraint::Exact("21.0.2".to_string()),
        }
    );

    // Simulate Fedora / RHEL machine with Java 26.0.2.1 installed
    let machine = unfuck_core::ir::MachineCapability {
        os: "Linux".to_string(),
        os_family: "linux".to_string(),
        arch: "x86_64".to_string(),
        cpu_count: 8,
        total_memory_bytes: 16 * 1024 * 1024 * 1024,
        available_memory_bytes: 8 * 1024 * 1024 * 1024,
        runtimes: vec![unfuck_core::ir::Runtime {
            name: "java".to_string(),
            version: "26.0.2.1".to_string(),
            executable_path: PathBuf::from("/usr/bin/java"),
            evidence: unfuck_core::evidence::Evidence::from_executable(
                PathBuf::from("/usr/bin/java"),
                "openjdk 26.0.2.1",
                "java -version",
            ),
        }],
        package_managers: vec![],
        tools: vec![],
        services: vec![],
        containers: vec![],
        listening_ports: vec![],
        env_vars: std::collections::HashMap::new(),
        path_entries: vec![],
        evidence: vec![],
    };

    let evaluated = evaluate_all(&manifest.requirements, &machine);
    assert_eq!(evaluated.len(), 1);
    assert!(
        evaluated[0].is_violated(),
        "Java 26.0.2.1 must NOT satisfy exact pin == 21.0.2"
    );
}

#[test]
fn test_fixture_duplicate_runtime_sources() {
    let fixture_path = fixtures_dir().join("duplicate-runtime-sources");
    let manifest = analyze_project(&fixture_path).expect("analyze duplicate-runtime-sources");

    let node_reqs: Vec<_> = manifest
        .requirements
        .iter()
        .filter(|r| r.name == "node")
        .collect();
    assert_eq!(
        node_reqs.len(),
        1,
        "Duplicate node requirements across package.json and mise.toml must be consolidated"
    );

    let node_req = node_reqs[0];
    assert_eq!(
        node_req.kind,
        unfuck_core::ir::RequirementKind::Runtime {
            name: "node".to_string(),
            constraint: unfuck_core::version::VersionConstraint::Exact("24.21.0".to_string()),
        }
    );
    assert!(
        !node_req.additional_evidence.is_empty(),
        "Consolidated requirement must preserve package.json evidence"
    );
}

#[test]
fn test_fixture_a_host_postgres_requirement() {
    let fixture_path = fixtures_dir().join("host-postgres-app");
    let manifest = analyze_project(&fixture_path).expect("analyze host-postgres-app");
    assert!(manifest.compose_projects.is_empty());
    assert!(manifest.requirements.iter().any(|r| r.name == "postgresql"));

    let machine = unfuck_core::ir::MachineCapability::default();
    let evaluated = unfuck_constraints::evaluator::evaluate_project(&manifest, &machine);
    let pg_eval = evaluated
        .iter()
        .find(|e| matches!(&e.constraint, unfuck_constraints::model::Constraint::ServiceRunning { service, .. } if service == "postgresql"))
        .expect("Host postgresql ServiceRunning constraint");
    assert!(pg_eval.is_violated());
}

#[test]
fn test_fixture_b_compose_postgres_healthy() {
    let fixture_path = fixtures_dir().join("compose-postgres-healthy");
    let manifest = analyze_project(&fixture_path).expect("analyze compose-postgres-healthy");
    assert_eq!(manifest.compose_projects.len(), 1);

    let mut machine = unfuck_core::ir::MachineCapability::default();
    machine
        .containers
        .push(unfuck_core::ir::ContainerObservation {
            id: "c123".to_string(),
            names: vec!["compose_healthy_postgres".to_string()],
            image: "postgres:16".to_string(),
            status: unfuck_core::ir::ContainerStatus::Running {
                healthy: Some(true),
            },
            ports: vec![],
            compose_project: Some("compose_healthy".to_string()),
            compose_service: Some("database".to_string()),
            labels: std::collections::HashMap::new(),
            evidence: unfuck_core::evidence::Evidence::from_repo_file(
                std::path::PathBuf::from("docker-compose.yml"),
                None,
                "Healthy test container",
            ),
        });

    let evaluated = unfuck_constraints::evaluator::evaluate_project(&manifest, &machine);
    let pg_eval = evaluated
        .iter()
        .find(|e| matches!(&e.constraint, unfuck_constraints::model::Constraint::ComposeServiceState { service_name, .. } if service_name == "database"))
        .expect("ComposeServiceState for database");
    assert!(
        pg_eval.is_satisfied(),
        "Healthy compose container must satisfy constraint"
    );
}

#[test]
fn test_fixture_c_compose_missing_env() {
    let fixture_path = fixtures_dir().join("compose-missing-env");
    let manifest = analyze_project(&fixture_path).expect("analyze compose-missing-env");
    assert_eq!(manifest.compose_projects.len(), 1);
    assert!(!manifest.compose_projects[0].can_instantiate);

    let machine = unfuck_core::ir::MachineCapability::default();
    let evaluated = unfuck_constraints::evaluator::evaluate_project(&manifest, &machine);
    let config_eval = evaluated
        .iter()
        .find(|e| {
            matches!(
                &e.constraint,
                unfuck_constraints::model::Constraint::ComposeConfigUnresolved { .. }
            )
        })
        .expect("ComposeConfigUnresolved constraint");
    assert!(config_eval.is_violated());

    let env_model = unfuck_core::ir::EnvironmentModel::new(manifest, machine);
    let predictions = unfuck_predictor::predict_failures(&env_model, &evaluated);
    let pred = predictions
        .iter()
        .find(|p| p.category == unfuck_predictor::PredictionCategory::ComposeConfigMissing)
        .expect("ComposeConfigMissing prediction");
    assert!(pred.summary.contains("docker/.env"));

    let graph = unfuck_graph::EnvironmentGraph::build(&env_model, &evaluated);
    let traces = graph.all_causal_traces();
    let diagnoses = unfuck_diagnosis::diagnose_all(&predictions, &traces);
    let diag = diagnoses
        .iter()
        .find(|d| d.root_cause.contains("missing.env_file"))
        .expect("missing env file diagnosis");
    assert!(diag.causal_chain.iter().any(|c| c.contains("docker/.env")));
}

#[test]
fn test_fixture_d_compose_resolved_env() {
    let fixture_path = fixtures_dir().join("compose-resolved-env");
    let env_file = fixture_path.join("docker").join(".env");
    std::fs::write(&env_file, "DB_PASSWORD=supersecret\n").expect("write .env for fixture d");

    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let _guard = Cleanup(env_file);

    let manifest = analyze_project(&fixture_path).expect("analyze compose-resolved-env");
    assert_eq!(manifest.compose_projects.len(), 1);
    assert!(
        manifest.compose_projects[0].can_instantiate,
        "Compose project must be instantiable when .env exists"
    );

    let machine = unfuck_core::ir::MachineCapability::default();
    let evaluated = unfuck_constraints::evaluator::evaluate_project(&manifest, &machine);
    assert!(
        !evaluated.iter().any(|e| matches!(
            &e.constraint,
            unfuck_constraints::model::Constraint::ComposeConfigUnresolved { .. }
        )),
        "ComposeConfigUnresolved must NOT be emitted when configuration is resolved"
    );
}

#[test]
fn test_fixture_e_unrelated_postgres_container() {
    let fixture_path = fixtures_dir().join("unrelated-postgres-container");
    let manifest = analyze_project(&fixture_path).expect("analyze unrelated-postgres-container");

    // Machine has an unrelated container for project "heym" named "heym-postgres"
    let mut machine = unfuck_core::ir::MachineCapability::default();
    machine
        .containers
        .push(unfuck_core::ir::ContainerObservation {
            id: "c999".to_string(),
            names: vec!["heym-postgres".to_string()],
            image: "postgres:16".to_string(),
            status: unfuck_core::ir::ContainerStatus::Running {
                healthy: Some(true),
            },
            ports: vec![],
            compose_project: Some("heym".to_string()),
            compose_service: Some("postgres".to_string()),
            labels: std::collections::HashMap::new(),
            evidence: unfuck_core::evidence::Evidence::from_repo_file(
                std::path::PathBuf::from("docker-compose.yml"),
                None,
                "Unrelated running container",
            ),
        });

    let evaluated = unfuck_constraints::evaluator::evaluate_project(&manifest, &machine);
    let pg_eval = evaluated
        .iter()
        .find(|e| {
            matches!(
                &e.constraint,
                unfuck_constraints::model::Constraint::ComposeServiceState { .. }
            )
        })
        .expect("ComposeServiceState constraint");

    if let unfuck_constraints::model::Constraint::ComposeServiceState { actual_state, .. } =
        &pg_eval.constraint
    {
        assert_eq!(
            actual_state, "not-created",
            "Unrelated heym-postgres container must NOT satisfy alpha_postgres"
        );
    } else {
        panic!("Expected ComposeServiceState");
    }
    assert!(pg_eval.is_violated());
}

#[test]
fn test_fixture_f_compose_stopped_container() {
    let fixture_path = fixtures_dir().join("compose-stopped-container");
    let manifest = analyze_project(&fixture_path).expect("analyze compose-stopped-container");

    // Machine has matching stopped container
    let mut machine = unfuck_core::ir::MachineCapability::default();
    machine
        .containers
        .push(unfuck_core::ir::ContainerObservation {
            id: "c888".to_string(),
            names: vec!["stopped_postgres".to_string()],
            image: "postgres:16".to_string(),
            status: unfuck_core::ir::ContainerStatus::Exited { exit_code: 0 },
            ports: vec![],
            compose_project: Some("stopped_proj".to_string()),
            compose_service: Some("database".to_string()),
            labels: std::collections::HashMap::new(),
            evidence: unfuck_core::evidence::Evidence::from_repo_file(
                std::path::PathBuf::from("docker-compose.yml"),
                None,
                "Stopped container",
            ),
        });

    let evaluated = unfuck_constraints::evaluator::evaluate_project(&manifest, &machine);
    let pg_eval = evaluated
        .iter()
        .find(|e| {
            matches!(
                &e.constraint,
                unfuck_constraints::model::Constraint::ComposeServiceState { .. }
            )
        })
        .expect("ComposeServiceState constraint");
    assert!(pg_eval.is_violated());

    let env_model = unfuck_core::ir::EnvironmentModel::new(manifest, machine);
    let predictions = unfuck_predictor::predict_failures(&env_model, &evaluated);
    let pred = predictions
        .iter()
        .find(|p| p.category == unfuck_predictor::PredictionCategory::ContainerStopped)
        .expect("ContainerStopped prediction");
    assert!(pred.summary.contains("exited (0)"));
}

#[test]
fn test_fixture_g_multi_component_java_attribution() {
    let fixture_path = fixtures_dir().join("multi-component-java-pin");
    let manifest = analyze_project(&fixture_path).expect("analyze multi-component-java-pin");

    assert_eq!(manifest.components.len(), 2);
    let web_comp = manifest
        .components
        .iter()
        .find(|c| c.name == "web")
        .expect("web");
    let mobile_comp = manifest
        .components
        .iter()
        .find(|c| c.name == "mobile")
        .expect("mobile");

    assert!(web_comp.languages.iter().any(|l| l.contains("javascript")));
    assert!(mobile_comp.requirements.iter().any(|r| r.name == "java"));

    let machine = unfuck_core::ir::MachineCapability::default();
    let evaluated = unfuck_constraints::evaluator::evaluate_project(&manifest, &machine);
    let env_model = unfuck_core::ir::EnvironmentModel::new(manifest, machine);

    let graph = unfuck_graph::EnvironmentGraph::build(&env_model, &evaluated);
    let traces = graph.all_causal_traces();
    let java_trace = traces
        .iter()
        .find(|t| matches!(&t.constraint, unfuck_constraints::model::Constraint::RuntimeVersion { runtime, .. } if runtime == "java"))
        .expect("Java trace");

    assert_eq!(
        java_trace.requirement.as_deref(),
        Some("mobile"),
        "Java requirement must be attributed to mobile component, NOT web"
    );
    assert!(
        java_trace.causal_steps[0].contains("mobile"),
        "Causal step must name mobile component"
    );
}

#[test]
fn test_compose_shared_missing_env_deduplication() {
    let fixture_path = fixtures_dir().join("compose-shared-missing-env");
    let manifest = analyze_project(&fixture_path).expect("analyze compose-shared-missing-env");

    assert_eq!(manifest.compose_projects.len(), 1);
    let cp = &manifest.compose_projects[0];
    assert_eq!(cp.services.len(), 2);

    let machine = unfuck_core::ir::MachineCapability::default();
    let evaluated = unfuck_constraints::evaluator::evaluate_project(&manifest, &machine);
    let env_model = unfuck_core::ir::EnvironmentModel::new(manifest, machine);
    let predictions = unfuck_predictor::predict_failures(&env_model, &evaluated);

    let graph = unfuck_graph::EnvironmentGraph::build(&env_model, &evaluated);
    let traces = graph.all_causal_traces();
    let diagnoses = unfuck_diagnosis::diagnose_all(&predictions, &traces);

    let compose_diags: Vec<_> = diagnoses
        .iter()
        .filter(|d| d.root_cause.contains("missing.env_file"))
        .collect();
    assert_eq!(
        compose_diags.len(),
        1,
        "Shared missing .env must produce exactly ONE deduplicated diagnosis"
    );

    let diag = compose_diags[0];
    assert_eq!(diag.problem, "Compose configuration unresolved");
    assert_eq!(diag.root_cause, "missing.env_file:docker/.env");
    assert_eq!(
        diag.affected_services,
        vec!["database".to_string(), "redis".to_string()]
    );
    assert_eq!(
        diag.configuration_template,
        Some(std::path::PathBuf::from("docker/example.env"))
    );

    assert!(diag
        .causal_chain
        .iter()
        .any(|c| c.contains("Compose file references docker/.env")));
    assert!(diag
        .causal_chain
        .iter()
        .any(|c| c.contains("docker/.env does not exist")));
    assert!(diag
        .causal_chain
        .iter()
        .any(|c| c.contains("Configuration template found: docker/example.env")));
    assert!(diag
        .causal_chain
        .iter()
        .any(|c| c.contains("Compose project cannot be instantiated")));
    assert!(diag
        .causal_chain
        .iter()
        .any(|c| c.contains("dependent services cannot be created: database, redis")));
}

#[test]
fn test_compose_env_template_detection() {
    let fixture_path = fixtures_dir().join("compose-shared-missing-env");
    let manifest = analyze_project(&fixture_path).expect("analyze compose-shared-missing-env");

    let cp = &manifest.compose_projects[0];
    assert_eq!(cp.env_templates.len(), 1);
    assert_eq!(
        cp.env_templates[0].missing_path,
        std::path::PathBuf::from("docker/.env")
    );
    assert_eq!(
        cp.env_templates[0].template_path,
        std::path::PathBuf::from("docker/example.env")
    );

    let template_evidence = manifest
        .evidence
        .iter()
        .find(|e| e.description.contains("Configuration template found"));
    assert!(
        template_evidence.is_some(),
        "Manifest evidence must record the discovered configuration template"
    );
    assert!(template_evidence
        .unwrap()
        .description
        .contains("docker/.env"));
}

#[test]
fn test_fixture_compose_project_blocker() {
    let fixture_path = fixtures_dir().join("compose-project-blocker");
    let manifest = analyze_project(&fixture_path).expect("analyze compose-project-blocker");

    assert_eq!(manifest.compose_projects.len(), 1);
    let cp = &manifest.compose_projects[0];
    assert!(!cp.can_instantiate);
    assert_eq!(
        cp.directly_affected_services,
        vec!["api".to_string(), "worker".to_string()]
    );
    assert_eq!(
        cp.transitively_blocked_services,
        vec!["frontend".to_string(), "metrics".to_string()]
    );

    assert!(
        manifest
            .bootstrap_actions
            .iter()
            .any(|b| b.description.contains("setup.sh copies")),
        "Bootstrap action from setup.sh must be recognized"
    );

    let machine = unfuck_core::ir::MachineCapability::default();
    let evaluated = unfuck_constraints::evaluator::evaluate_project(&manifest, &machine);
    let env_model = unfuck_core::ir::EnvironmentModel::new(manifest, machine);
    let predictions = unfuck_predictor::predict_failures(&env_model, &evaluated);
    let graph = unfuck_graph::EnvironmentGraph::build(&env_model, &evaluated);
    let traces = graph.all_causal_traces();
    let diagnoses = unfuck_diagnosis::diagnose_all(&predictions, &traces);

    let compose_diags: Vec<_> = diagnoses
        .iter()
        .filter(|d| d.problem == "Compose configuration unresolved")
        .collect();
    assert_eq!(
        compose_diags.len(),
        1,
        "Must produce exactly one project-level compose diagnosis"
    );
    let diag = compose_diags[0];
    assert_eq!(
        diag.directly_affected_services,
        vec!["api".to_string(), "worker".to_string()]
    );
    assert_eq!(
        diag.transitively_blocked_services,
        vec!["frontend".to_string(), "metrics".to_string()]
    );
    assert!(
        diag.bootstrap_suggestions
            .iter()
            .any(|s| s.contains("setup.sh copies")),
        "Diagnosis must include bootstrap action suggestion"
    );
}

#[test]
fn test_fixture_version_build_metadata() {
    let fixture_path = fixtures_dir().join("version-build-metadata");
    let manifest = analyze_project(&fixture_path).expect("analyze version-build-metadata");

    let pm_req = manifest
        .requirements
        .iter()
        .find(|r| r.name == "pnpm")
        .expect("pnpm requirement");

    match &pm_req.kind {
        unfuck_core::ir::RequirementKind::PackageManager { constraint, .. } => {
            let c = constraint.as_ref().expect("pnpm constraint");
            assert_eq!(c.to_string(), "==11.10.0");
            assert!(
                c.matches("11.10.0"),
                "Exact pin 11.10.0 must match host version 11.10.0"
            );
            assert!(
                !c.matches("11.24.0"),
                "Exact pin 11.10.0 must not match 11.24.0"
            );
        }
        _ => panic!("Expected PackageManager requirement"),
    }
}

#[test]
fn test_fixture_env_template_optional_vars() {
    let fixture_path = fixtures_dir().join("env-template-optional-vars");
    let manifest = analyze_project(&fixture_path).expect("analyze env-template-optional-vars");

    let secret_spec = manifest
        .env_var_specs
        .iter()
        .find(|s| s.name == "SECRET_KEY")
        .expect("SECRET_KEY spec");
    assert_eq!(
        secret_spec.category,
        unfuck_core::ir::EnvVarCategory::Required
    );

    let proxy_spec = manifest
        .env_var_specs
        .iter()
        .find(|s| s.name == "OPTIONAL_PROXY")
        .expect("OPTIONAL_PROXY spec");
    assert_eq!(
        proxy_spec.category,
        unfuck_core::ir::EnvVarCategory::IntentionallyEmpty
    );
    assert_eq!(proxy_spec.default_value.as_deref(), Some(""));

    let prefix_spec = manifest
        .env_var_specs
        .iter()
        .find(|s| s.name == "APP_PREFIX")
        .expect("APP_PREFIX spec");
    assert_eq!(
        prefix_spec.category,
        unfuck_core::ir::EnvVarCategory::IntentionallyEmpty
    );
    assert_eq!(prefix_spec.default_value.as_deref(), Some(""));

    let debug_spec = manifest
        .env_var_specs
        .iter()
        .find(|s| s.name == "DEBUG")
        .expect("DEBUG spec");
    assert_eq!(
        debug_spec.category,
        unfuck_core::ir::EnvVarCategory::OptionalWithDefault
    );
    assert_eq!(debug_spec.default_value.as_deref(), Some("false"));

    let req_env_count = manifest
        .requirements
        .iter()
        .filter(|r| {
            matches!(
                &r.kind,
                unfuck_core::ir::RequirementKind::EnvVar { required: true, .. }
            )
        })
        .count();
    assert_eq!(
        req_env_count, 1,
        "Only SECRET_KEY should be a required env var constraint"
    );
}

#[test]
fn test_fixture_bootstrap_copy_template() {
    let fixture_path = fixtures_dir().join("bootstrap-copy-template");
    let manifest = analyze_project(&fixture_path).expect("analyze bootstrap-copy-template");

    assert!(
        manifest.bootstrap_actions.iter().any(|b| b
            .description
            .contains("Makefile copies .env.example to .env")),
        "Bootstrap action from Makefile must be recognized"
    );
}

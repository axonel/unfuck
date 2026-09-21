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

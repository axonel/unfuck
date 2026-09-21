pub mod format;

use serde::Serialize;
use std::path::Path;
use unfuck_constraints::evaluator::evaluate_all;
use unfuck_constraints::model::EvaluatedConstraint;
use unfuck_core::ir::{EnvironmentModel, MachineCapability, ProjectManifest};
use unfuck_diagnosis::{diagnose_all, Diagnosis};
use unfuck_graph::EnvironmentGraph;
use unfuck_predictor::{predict_failures, Prediction};
use unfuck_project::analyze_project;
use unfuck_scanner::scan_machine;
use unfuck_verifier::{verify_environment, VerificationReport};

#[derive(Serialize)]
pub struct UnfuckReport {
    pub project: ProjectManifest,
    pub machine: MachineCapability,
    pub evaluated_constraints: Vec<EvaluatedConstraint>,
    pub predictions: Vec<Prediction>,
    pub diagnoses: Vec<Diagnosis>,
    pub verification: VerificationReport,
}

pub struct PipelineOutput {
    pub env_model: EnvironmentModel,
    pub evaluated_constraints: Vec<EvaluatedConstraint>,
    pub graph: EnvironmentGraph,
    pub predictions: Vec<Prediction>,
    pub diagnoses: Vec<Diagnosis>,
    pub verification: VerificationReport,
}

pub fn execute_pipeline(target_path: &Path) -> Result<PipelineOutput, unfuck_core::UnfuckError> {
    let project = analyze_project(target_path)?;
    let machine = scan_machine();
    let evaluated_constraints = evaluate_all(&project.requirements, &machine);
    let env_model = EnvironmentModel::new(project, machine);
    let graph = EnvironmentGraph::build(&env_model, &evaluated_constraints);
    let predictions = predict_failures(&env_model, &evaluated_constraints);
    let traces = graph.all_causal_traces();
    let diagnoses = diagnose_all(&predictions, &traces);
    let verification = verify_environment(&env_model, &evaluated_constraints);

    Ok(PipelineOutput {
        env_model,
        evaluated_constraints,
        graph,
        predictions,
        diagnoses,
        verification,
    })
}

use colored::*;
use unfuck_constraints::model::EvaluatedConstraint;
use unfuck_core::Confidence;
use unfuck_diagnosis::Diagnosis;
use unfuck_predictor::Prediction;
use unfuck_verifier::VerificationReport;

pub fn print_banner() {
    println!(
        "{}",
        "UNFUCK — Development Environment Engine".bold().cyan()
    );
    println!("{}", "──────────────────────────────────────────".dimmed());
}

pub fn print_human_summary(
    project_name: &str,
    project_path: &str,
    languages: &[String],
    package_managers: &[String],
    predictions: &[Prediction],
    evaluated_constraints: &[EvaluatedConstraint],
    verbose: bool,
) {
    print_banner();
    println!("Project:     {}", project_path.bold());
    println!("Name:        {}", project_name);
    if !languages.is_empty() {
        println!("Languages:   {}", languages.join(", "));
    }
    if !package_managers.is_empty() {
        println!("Package Mgr: {}", package_managers.join(", "));
    }
    println!();

    if predictions.is_empty() {
        println!("{}", "Environment: COMPATIBLE".bold().green());
        println!();
        println!(" {} Project requirements discovered", "✓".green());
        println!(" {} Runtime versions compatible", "✓".green());
        println!(" {} Required services available", "✓".green());
        println!(" {} Declared ports available", "✓".green());
        println!(" {} Configuration consistent", "✓".green());
        println!();
        println!("{}", "No known blockers.".green());
    } else {
        let violations_count = evaluated_constraints
            .iter()
            .filter(|c| c.is_violated())
            .count();
        println!(
            "{}",
            format!(
                "{} problems detected ({} predicted failures)",
                violations_count,
                predictions.len()
            )
            .bold()
            .red()
        );
        println!();

        for pred in predictions {
            let conf_tag = match pred.confidence {
                Confidence::Confirmed => "CONFIRMED".bold().on_red().white(),
                Confidence::High => "HIGH     ".bold().red(),
                Confidence::Medium => "MEDIUM   ".bold().yellow(),
                Confidence::Low => "LOW      ".dimmed(),
                Confidence::Unknown => "UNKNOWN  ".dimmed(),
            };

            println!("  {}  {}", conf_tag, pred.title.bold());
            println!("             {}", pred.summary.dimmed());

            if verbose {
                if let Some(ref p_ev) = pred.project_evidence {
                    println!("             project evidence: {}", p_ev.description.cyan());
                }
                if let Some(ref m_ev) = pred.machine_evidence {
                    println!(
                        "             machine evidence: {}",
                        m_ev.description.magenta()
                    );
                }
            }
        }

        println!();
        println!("{}", "Next steps:".bold());
        println!("  unfuck explain     Inspect root causes and causal dependency chains");
        println!("  unfuck verify      Run read-only environment verification checks");
    }
}

pub fn print_diagnoses(diagnoses: &[Diagnosis], verbose: bool) {
    print_banner();
    println!("{}", "Root-Cause Diagnosis & Causal Chains".bold());
    println!();

    if diagnoses.is_empty() {
        println!(
            "{}",
            "No environment failures diagnosed. All invariants hold.".green()
        );
        return;
    }

    for (idx, diag) in diagnoses.iter().enumerate() {
        println!("{}. {}", idx + 1, diag.problem.bold().red());
        println!(
            "   Root Cause:          {}",
            diag.root_cause.bold().yellow()
        );
        println!("   Violated Constraint: {}", diag.violated_constraint);
        println!("   Confidence:          {}", diag.confidence);
        println!(
            "   Affected Components: {}",
            diag.affected_components.join(", ")
        );
        println!();
        println!("   Causal Chain:");
        for (step_num, step) in diag.causal_chain.iter().enumerate() {
            if step_num == diag.causal_chain.len() - 1 {
                println!("     └─► {}", step.red());
            } else {
                println!("     ├─► {}", step);
            }
        }
        println!();

        if verbose {
            if let Some(ref p_ev) = diag.project_evidence {
                println!(
                    "   Project Evidence:    {} ({:?})",
                    p_ev.description, p_ev.source
                );
            }
            if let Some(ref m_ev) = diag.machine_evidence {
                println!(
                    "   Machine Evidence:    {} ({:?})",
                    m_ev.description, m_ev.source
                );
            }
            println!();
        }
    }
}

pub fn print_verification(report: &VerificationReport) {
    print_banner();
    println!("{}", "Read-Only Environment Verification".bold());
    println!();

    for check in &report.checks {
        let mark = if check.passed {
            "✓".green()
        } else {
            "✗".red()
        };
        let status = if check.passed {
            "PASSED".green()
        } else {
            "FAILED".bold().red()
        };

        println!(
            "  {} [{}] {:<25} {}",
            mark, status, check.name, check.message
        );
    }

    println!();
    println!(
        "Summary: {}/{} checks passed ({} failed)",
        report.passed_checks, report.total_checks, report.failed_checks
    );

    if report.success {
        println!("{}", "Environment verification PASSED.".bold().green());
    } else {
        println!("{}", "Environment verification FAILED.".bold().red());
    }
}

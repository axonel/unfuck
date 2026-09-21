use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;
use unfuck::format;
use unfuck::{execute_pipeline, UnfuckReport};
use unfuck_diagnosis::Diagnosis;
use unfuck_project::analyze_project;
use unfuck_scanner::scan_machine;

#[derive(Parser)]
#[command(
    name = "unfuck",
    author = "Axonel Team",
    version = "0.1.0",
    about = "Development-environment resolution engine",
    long_about = "UNFUCK models development environments as constraint systems, predicting failures before they happen and explaining root causes with structured evidence."
)]
pub struct Cli {
    /// Path to target project repository
    #[arg(default_value = ".")]
    pub path: PathBuf,

    /// Output results in structured JSON format
    #[arg(long, global = true)]
    pub json: bool,

    /// Verbose output with full evidence and provenance details
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Scan project and host machine without evaluating predictions
    Scan {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Predict runtime and environment failures before execution
    Predict {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
    /// Explain root causes and causal dependency chains
    Explain {
        #[arg(default_value = ".")]
        path: PathBuf,
        #[arg(long)]
        target: Option<String>,
    },
    /// Perform read-only verification of environment against project requirements
    Verify {
        #[arg(default_value = ".")]
        path: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Scan { path }) => match analyze_project(path) {
            Ok(proj) => {
                let mach = scan_machine();
                if cli.json {
                    let scan_json = serde_json::json!({
                        "project": proj,
                        "machine": mach,
                    });
                    println!("{}", serde_json::to_string_pretty(&scan_json).unwrap());
                } else {
                    format::print_banner();
                    println!("Project: {}", path.display());
                    println!("Languages: {:?}", proj.languages);
                    println!("Requirements: {}", proj.requirements.len());
                    println!("Machine OS: {}", mach.os);
                    println!("Machine Arch: {}", mach.arch);
                    println!("Discovered runtimes: {}", mach.runtimes.len());
                    for r in &mach.runtimes {
                        println!(
                            "  - {} {} ({})",
                            r.name,
                            r.version,
                            r.executable_path.display()
                        );
                    }
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("Error scanning project: {}", e);
                ExitCode::FAILURE
            }
        },

        Some(Commands::Predict { path }) => match execute_pipeline(path) {
            Ok(out) => {
                if cli.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&out.predictions).unwrap()
                    );
                } else {
                    format::print_banner();
                    println!("Predicted Failures: {}", out.predictions.len());
                    for pred in &out.predictions {
                        println!("- [{}] {}: {}", pred.confidence, pred.title, pred.summary);
                    }
                }
                if out.predictions.is_empty() {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(1)
                }
            }
            Err(e) => {
                eprintln!("Error running prediction: {}", e);
                ExitCode::FAILURE
            }
        },

        Some(Commands::Explain { path, target }) => match execute_pipeline(path) {
            Ok(out) => {
                let filtered: Vec<Diagnosis> = if let Some(t) = target {
                    out.diagnoses
                        .into_iter()
                        .filter(|d| {
                            d.affected_components.iter().any(|c| c.contains(t))
                                || d.problem.to_lowercase().contains(&t.to_lowercase())
                        })
                        .collect()
                } else {
                    out.diagnoses
                };

                if cli.json {
                    println!("{}", serde_json::to_string_pretty(&filtered).unwrap());
                } else {
                    format::print_diagnoses(&filtered, cli.verbose);
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("Error generating explanation: {}", e);
                ExitCode::FAILURE
            }
        },

        Some(Commands::Verify { path }) => match execute_pipeline(path) {
            Ok(out) => {
                if cli.json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&out.verification).unwrap()
                    );
                } else {
                    format::print_verification(&out.verification);
                }
                if out.verification.success {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(1)
                }
            }
            Err(e) => {
                eprintln!("Error executing verification: {}", e);
                ExitCode::FAILURE
            }
        },

        None => {
            // Default command: unfuck [PATH]
            match execute_pipeline(&cli.path) {
                Ok(out) => {
                    let has_failures = !out.predictions.is_empty();
                    if cli.json {
                        let report = UnfuckReport {
                            project: out.env_model.project,
                            machine: out.env_model.machine,
                            evaluated_constraints: out.evaluated_constraints,
                            predictions: out.predictions,
                            diagnoses: out.diagnoses,
                            verification: out.verification,
                        };
                        println!("{}", serde_json::to_string_pretty(&report).unwrap());
                    } else {
                        format::print_human_summary(
                            &out.env_model.project.name,
                            &cli.path.display().to_string(),
                            &out.env_model.project.languages,
                            &out.env_model.project.package_managers,
                            &out.predictions,
                            &out.evaluated_constraints,
                            cli.verbose,
                        );
                    }

                    if has_failures {
                        ExitCode::from(1)
                    } else {
                        ExitCode::SUCCESS
                    }
                }
                Err(e) => {
                    eprintln!("Error running UNFUCK: {}", e);
                    ExitCode::FAILURE
                }
            }
        }
    }
}

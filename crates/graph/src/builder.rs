use crate::model::{CausalTrace, EdgeData, NodeData};
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use unfuck_constraints::model::{Constraint, ConstraintStatus, EvaluatedConstraint};
use unfuck_core::evidence::Evidence;
use unfuck_core::ir::EnvironmentModel;

/// The environment graph connecting Project, Requirements, Machine capabilities, Constraints, and Evidence.
#[derive(Debug, Clone)]
pub struct EnvironmentGraph {
    pub graph: DiGraph<NodeData, EdgeData>,
    pub project_node: NodeIndex,
    pub machine_node: NodeIndex,
}

impl EnvironmentGraph {
    /// Construct the environment graph from an EnvironmentModel and evaluated constraints.
    pub fn build(model: &EnvironmentModel, evaluated_constraints: &[EvaluatedConstraint]) -> Self {
        let mut graph = DiGraph::new();

        // 1. Root Project node
        let project_node = graph.add_node(NodeData::Project {
            name: model.project.name.clone(),
            path: model.project.root_path.clone(),
        });

        // 2. Root Machine node
        let machine_node = graph.add_node(NodeData::Machine {
            os: model.machine.os.clone(),
            arch: model.machine.arch.clone(),
        });

        // 3. Machine capabilities (Runtimes, Services, Ports)
        let mut runtime_nodes = std::collections::HashMap::new();
        for rt in &model.machine.runtimes {
            let rt_node = graph.add_node(NodeData::Runtime {
                name: rt.name.clone(),
                version: rt.version.clone(),
                executable_path: rt.executable_path.clone(),
            });
            graph.add_edge(machine_node, rt_node, EdgeData::Provides);

            let ev_node = graph.add_node(NodeData::Evidence {
                description: rt.evidence.description.clone(),
                confidence: rt.evidence.confidence,
            });
            graph.add_edge(rt_node, ev_node, EdgeData::SupportedBy);
            runtime_nodes.insert(rt.name.to_lowercase(), (rt_node, rt.clone()));
        }

        let mut service_nodes = std::collections::HashMap::new();
        for srv in &model.machine.services {
            let srv_node = graph.add_node(NodeData::Service {
                name: srv.name.clone(),
                status: srv.status,
                version: srv.version.clone(),
            });
            graph.add_edge(machine_node, srv_node, EdgeData::Provides);

            let ev_node = graph.add_node(NodeData::Evidence {
                description: srv.evidence.description.clone(),
                confidence: srv.evidence.confidence,
            });
            graph.add_edge(srv_node, ev_node, EdgeData::SupportedBy);
            service_nodes.insert(srv.name.to_lowercase(), (srv_node, srv.clone()));
        }

        let mut port_nodes = std::collections::HashMap::new();
        for p in &model.machine.listening_ports {
            let p_node = graph.add_node(NodeData::Port {
                port: p.port,
                state: p.state.clone(),
            });
            graph.add_edge(machine_node, p_node, EdgeData::Provides);

            let ev_node = graph.add_node(NodeData::Evidence {
                description: p.evidence.description.clone(),
                confidence: p.evidence.confidence,
            });
            graph.add_edge(p_node, ev_node, EdgeData::SupportedBy);
            port_nodes.insert(p.port, (p_node, p.clone()));
        }

        // 4. Project Requirements and Constraints
        for eval in evaluated_constraints {
            let constraint_node = graph.add_node(NodeData::Constraint {
                constraint: eval.constraint.clone(),
                status: eval.status.clone(),
            });

            graph.add_edge(project_node, constraint_node, EdgeData::Requires);

            // Connect project evidence
            if let Some(ref p_ev) = eval.project_evidence {
                let ev_node = graph.add_node(NodeData::Evidence {
                    description: p_ev.description.clone(),
                    confidence: p_ev.confidence,
                });
                graph.add_edge(constraint_node, ev_node, EdgeData::SupportedBy);
            }

            // Connect machine capability and machine evidence
            match &eval.constraint {
                Constraint::RuntimeVersion { runtime, .. } => {
                    if let Some((rt_node, _)) = runtime_nodes.get(&runtime.to_lowercase()) {
                        let edge_type = if eval.is_violated() {
                            EdgeData::Violates
                        } else {
                            EdgeData::EvaluatedAs
                        };
                        graph.add_edge(*rt_node, constraint_node, edge_type);
                    }
                }
                Constraint::PortAvailable { port } => {
                    if let Some((p_node, _)) = port_nodes.get(port) {
                        let edge_type = if eval.is_violated() {
                            EdgeData::Violates
                        } else {
                            EdgeData::EvaluatedAs
                        };
                        graph.add_edge(*p_node, constraint_node, edge_type);
                    }
                }
                Constraint::ServiceRunning { service, .. } => {
                    if let Some((srv_node, _)) = service_nodes.get(&service.to_lowercase()) {
                        let edge_type = if eval.is_violated() {
                            EdgeData::Violates
                        } else {
                            EdgeData::EvaluatedAs
                        };
                        graph.add_edge(*srv_node, constraint_node, edge_type);
                    }
                }
                _ => {}
            }
        }

        Self {
            graph,
            project_node,
            machine_node,
        }
    }

    /// Find all constraint nodes that have been violated.
    pub fn find_violations(&self) -> Vec<NodeIndex> {
        let mut violations = Vec::new();
        for idx in self.graph.node_indices() {
            if let Some(NodeData::Constraint { status, .. }) = self.graph.node_weight(idx) {
                if matches!(status, ConstraintStatus::Violated { .. }) {
                    violations.push(idx);
                }
            }
        }
        violations
    }

    /// Trace the causal chain of a violation node back to project requirements and machine observations.
    pub fn trace_causal_chain(&self, violation_idx: NodeIndex) -> Option<CausalTrace> {
        let weight = self.graph.node_weight(violation_idx)?;
        let (constraint, status) = match weight {
            NodeData::Constraint { constraint, status } => (constraint.clone(), status.clone()),
            _ => return None,
        };

        let mut project_evidence: Option<Evidence> = None;
        let mut machine_evidence: Option<Evidence> = None;
        let mut machine_state: Option<String> = None;

        // Check outgoing edges from constraint node (SupportedBy -> Evidence)
        for edge in self
            .graph
            .edges_directed(violation_idx, Direction::Outgoing)
        {
            if *edge.weight() == EdgeData::SupportedBy {
                if let Some(NodeData::Evidence {
                    description,
                    confidence,
                }) = self.graph.node_weight(edge.target())
                {
                    project_evidence = Some(Evidence::new(
                        unfuck_core::evidence::EvidenceSource::DirectObservation {
                            detail: description.clone(),
                        },
                        *confidence,
                        description.clone(),
                    ));
                }
            }
        }

        // Check incoming edges to constraint node (e.g. from Runtime, Port, or Service)
        for edge in self
            .graph
            .edges_directed(violation_idx, Direction::Incoming)
        {
            match edge.weight() {
                EdgeData::Violates | EdgeData::EvaluatedAs => {
                    let source_idx = edge.source();
                    if let Some(src_weight) = self.graph.node_weight(source_idx) {
                        match src_weight {
                            NodeData::Runtime {
                                name,
                                version,
                                executable_path,
                            } => {
                                machine_state = Some(format!(
                                    "Runtime '{}' is installed at {} (version {})",
                                    name,
                                    executable_path.display(),
                                    version
                                ));
                            }
                            NodeData::Port { port, state } => {
                                machine_state = Some(format!("Port {} state is {:?}", port, state));
                            }
                            NodeData::Service {
                                name,
                                status,
                                version,
                            } => {
                                machine_state = Some(format!(
                                    "Service '{}' status is {:?} (version {:?})",
                                    name, status, version
                                ));
                            }
                            _ => {}
                        }

                        // Also find evidence on the source machine capability node
                        for src_edge in self.graph.edges_directed(source_idx, Direction::Outgoing) {
                            if *src_edge.weight() == EdgeData::SupportedBy {
                                if let Some(NodeData::Evidence {
                                    description,
                                    confidence,
                                }) = self.graph.node_weight(src_edge.target())
                                {
                                    machine_evidence = Some(Evidence::new(
                                        unfuck_core::evidence::EvidenceSource::DirectObservation {
                                            detail: description.clone(),
                                        },
                                        *confidence,
                                        description.clone(),
                                    ));
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        Some(CausalTrace {
            constraint,
            status,
            requirement: None,
            project_evidence,
            machine_state,
            machine_evidence,
        })
    }

    /// Retrieve causal traces for all violations in the environment.
    pub fn all_causal_traces(&self) -> Vec<CausalTrace> {
        self.find_violations()
            .into_iter()
            .filter_map(|idx| self.trace_causal_chain(idx))
            .collect()
    }
}

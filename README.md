# UNFUCK

> **UNFUCK is a development-environment resolution engine that models repositories and host machines as constraint-driven dependency graphs, predicts failures before they happen, determines root causes with traceable evidence, and verifies environment invariants.**

Core principle:
> **UNFUCK must be useful without an LLM.** Any LLM integration is optional and sits strictly above deterministic system intelligence.

---

## What UNFUCK Does Today (Phase 1)

Unlike superficial "doctor" commands that merely check `command -v <binary>`, UNFUCK:

1. **Discovers Project Invariants**: Parses `package.json`, `bun.lock`, `pyproject.toml`, `requirements.txt`, `Dockerfile`, `compose.yaml`, `.nvmrc`, `.python-version`, `.tool-versions`, `mise.toml`, and `.env.example` to extract typed runtime, service, port, and environment requirements.
2. **Inspects the Host Machine**: Reads kernel `/proc` interfaces (`/proc/net/tcp`, `/proc/net/tcp6`, `/proc/[pid]/fd`), OS metadata (`/etc/os-release`), hardware specs, system PATH, installed runtimes (Node, Bun, Python, Rust, Go, Java), and system services (Docker, PostgreSQL) with exact provenance.
3. **Builds an Environment IR & Graph**: Merges project requirements and machine observations into a strongly typed Intermediate Representation (IR) and dependency graph.
4. **Evaluates Constraints Data-Driven**: Evaluates version expressions, port availability, service presence, and OS/architecture compatibility through a unified constraint evaluator without ad-hoc `if` branches.
5. **Predicts Failures Deterministically**: Identifies runtime mismatches, port collisions, missing services, and configuration gaps before you run `npm start`, `python main.py`, or `docker compose up`.
6. **Explains Root Causes**: Traces causal chains back to the earliest known violated invariant and presents evidence with explicit confidence ratings (`CONFIRMED`, `HIGH`, `MEDIUM`, `LOW`).
7. **Performs Read-Only Verification**: Verifies your development environment against repository requirements without modifying system state.
8. **First-Class JSON API**: Every command supports `--json` for pipeline integration and machine consumption.

---

## Installation & Build

Requires a modern Rust toolchain (Rust 1.80+):

```bash
git clone https://github.com/axonel/unfuck.git
cd unfuck
cargo build --release
```

The executable will be located at `./target/release/unfuck`.

---

## Usage

### 1. Default Inspection (`unfuck [PATH]`)

Runs the full pipeline against a repository (defaulting to current directory):

```bash
unfuck .
```

#### Example: Healthy Environment

```text
UNFUCK — Development Environment Engine
──────────────────────────────────────────
Project:     .
Name:        my-project
Languages:   python

Environment: COMPATIBLE

 ✓ Project requirements discovered
 ✓ Runtime versions compatible
 ✓ Required services available
 ✓ Declared ports available
 ✓ Configuration consistent

No known blockers.
```

#### Example: Broken Environment

```text
UNFUCK — Development Environment Engine
──────────────────────────────────────────
Project:     tests/fixtures/broken-python-version
Name:        broken-python-version
Languages:   python

2 problems detected (2 predicted failures)

  HIGH       python runtime incompatibility predicted
             Project expects python >=3.99.0, but Runtime 'python' version 3.12.4 does not satisfy requirement >=3.99.0. Application startup or build is predicted to fail.
  HIGH       Required service 'postgresql' failure predicted
             Project depends on service 'postgresql', but it is not running or not installed. Connections will be refused.

Next steps:
  unfuck explain     Inspect root causes and causal dependency chains
  unfuck verify      Run read-only environment verification checks
```

---

### 2. Root-Cause Explanation (`unfuck explain [PATH]`)

Explains why the failure will occur, mapping the causal chain from host observation to application failure:

```bash
unfuck explain tests/fixtures/broken-python-version
```

```text
UNFUCK — Development Environment Engine
──────────────────────────────────────────
Root-Cause Diagnosis & Causal Chains

1. python runtime incompatibility predicted
   Root Cause:          python.version >= >=3.99.0
   Violated Constraint: Runtime 'python' must satisfy >=3.99.0
   Confidence:          HIGH
   Affected Components: python, build, startup

   Causal Chain:
     ├─► Host machine state: Runtime 'python' is installed at /usr/bin/python3 (version 3.12.4)
     ├─► Project specification: requires python >=3.99.0
     ├─► Violated invariant: python.version satisfies >=3.99.0
     └─► Downstream impact: python toolchain cannot initialize; build and runtime will fail

2. Required service 'postgresql' failure predicted
   Root Cause:          service.postgresql.running
   Violated Constraint: Service 'postgresql' must be running
   Confidence:          HIGH
   Affected Components: postgresql, database/backend

   Causal Chain:
     ├─► Host service state: Service 'postgresql' status is Stopped
     ├─► Project specification: depends on active service postgresql
     ├─► Violated invariant: service.postgresql.status == RUNNING
     └─► Downstream impact: application connections to postgresql will be refused
```

---

### 3. Read-Only Verification (`unfuck verify [PATH]`)

Runs non-destructive verification checks:

```bash
unfuck verify tests/fixtures/broken-python-version
```

```text
UNFUCK — Development Environment Engine
──────────────────────────────────────────
Read-Only Environment Verification

  ✓ [PASSED] project_discovery         Discovered 2 requirements and 0 declared ports across ["python"]
  ✗ [FAILED] runtime:python            Runtime 'python' version 3.12.4 does not satisfy requirement >=3.99.0
  ✗ [FAILED] service:postgresql        Service 'postgresql' is present but currently stopped/inactive

Summary: 1/3 checks passed (2 failed)
Environment verification FAILED.
```

---

### 4. Structured JSON Output (`--json`)

Every command supports `--json` for machine readability:

```bash
unfuck . --json
```

```json
{
  "project": {
    "name": "my-app",
    "root_path": "/path/to/my-app",
    "languages": ["python"],
    "package_managers": ["uv"],
    "requirements": [...],
    "declared_ports": [8000],
    "env_vars": ["DATABASE_URL"],
    "docker_used": false,
    "evidence": [...]
  },
  "machine": {
    "os": "Ubuntu 24.04 LTS",
    "arch": "x86_64",
    "cpu_count": 8,
    "runtimes": [...],
    "services": [...],
    "listening_ports": [...]
  },
  "evaluated_constraints": [...],
  "predictions": [...],
  "diagnoses": [...],
  "verification": {
    "success": false,
    "checks": [...],
    "total_checks": 3,
    "passed_checks": 1,
    "failed_checks": 2
  }
}
```

---

## Architecture

UNFUCK is structured as a modular Cargo workspace:

```text
crates/
    core/         # Environment IR, Evidence, Confidence, common types & errors
    scanner/      # Deterministic Linux machine inspection with provenance
    project/      # Repository signal discovery & parsing (Node/Bun, Python, Docker, etc.)
    constraints/  # Data-driven constraint evaluation (Version, Port, Arch, OS, Memory)
    graph/        # Environment graph connecting project, capabilities, constraints, evidence
    predictor/    # Deterministic failure prediction
    diagnosis/    # Root-cause causal explanation without LLMs
    verifier/     # Read-only verification engine
    cli/          # Command-line interface with human & JSON formatting
tests/
    fixtures/     # Representative test repositories (healthy and broken)
```

See [ARCHITECTURE.md](file:///home/roonakyadav/Projects/unfuck/ARCHITECTURE.md) and [docs/ENVIRONMENT_MODEL.md](file:///home/roonakyadav/Projects/unfuck/docs/ENVIRONMENT_MODEL.md) for deeper architectural details.

---

## License

Apache-2.0

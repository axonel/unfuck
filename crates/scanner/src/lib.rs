pub mod env;
pub mod network;
pub mod os;
pub mod runtimes;
pub mod services;

use unfuck_core::ir::MachineCapability;

/// Perform deterministic Linux machine inspection.
pub fn scan_machine() -> MachineCapability {
    let os_info = os::scan_os();
    let path_entries = env::parse_path_entries();
    let (env_vars, env_evidence) = env::scan_env_vars();
    let runtimes = runtimes::scan_runtimes(&path_entries);
    let listening_ports = network::scan_listening_ports();
    let services = services::scan_services(&path_entries, &listening_ports);

    let mut evidence = os_info.evidence;
    evidence.extend(env_evidence);

    MachineCapability {
        os: os_info.os,
        os_family: os_info.os_family,
        arch: os_info.arch,
        cpu_count: os_info.cpu_count,
        total_memory_bytes: os_info.total_memory_bytes,
        available_memory_bytes: os_info.available_memory_bytes,
        runtimes,
        services,
        listening_ports,
        env_vars,
        path_entries,
        evidence,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_machine_runs_successfully() {
        let machine = scan_machine();
        assert!(!machine.os.is_empty());
        assert!(!machine.arch.is_empty());
        assert!(machine.cpu_count > 0);
        assert!(machine.total_memory_bytes > 0);
        // We know at least rustc / cargo is on this machine
        let rust_runtime = machine.find_runtime("rust");
        assert!(rust_runtime.is_some(), "Rust runtime should be detected");
    }
}

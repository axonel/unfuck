use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use unfuck_core::evidence::{Evidence, EvidenceSource};
use unfuck_core::ir::{ProjectRequirement, RequirementKind, ToolScope};
use unfuck_core::Confidence;
use unfuck_core::VersionConstraint;

#[derive(Debug, Clone)]
pub struct CMakeDiscovery {
    pub is_cmake: bool,
    pub languages: Vec<String>,
    pub requirements: Vec<ProjectRequirement>,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Clone)]
pub struct CMakeCommand {
    pub name: String,
    pub args: Vec<String>,
    pub line_no: usize,
    pub platform: Option<String>,
    pub is_guarded_optional: bool,
}

fn strip_quotes(s: &str) -> &str {
    let trimmed = s.trim();
    if trimmed.len() >= 2
        && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\'')))
    {
        return &trimmed[1..trimmed.len() - 1];
    }
    trimmed
}

/// Tokenize an argument string from a CMake command invocation into discrete argument strings,
/// handling quotes and whitespace.
fn tokenize_args(arg_str: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut quote_char = '"';
    let mut chars = arg_str.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '\\' {
                if let Some(next_c) = chars.next() {
                    current.push(next_c);
                }
            } else if c == quote_char {
                in_quotes = false;
                tokens.push(current.clone());
                current.clear();
            } else {
                current.push(c);
            }
        } else if c == '"' || c == '\'' {
            in_quotes = true;
            quote_char = c;
        } else if c.is_whitespace() || c == ';' {
            if !current.is_empty() {
                tokens.push(current.clone());
                current.clear();
            }
        } else {
            current.push(c);
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}

/// Strip CMake comments outside quotes (# ... to end of line, or #[[ ... ]]).
fn strip_cmake_comments(content: &str) -> String {
    let mut result = String::with_capacity(content.len());
    let mut in_quotes = false;
    let mut chars = content.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '\\' {
                result.push(c);
                if let Some(next_c) = chars.next() {
                    result.push(next_c);
                }
            } else if c == '"' {
                in_quotes = false;
                result.push(c);
            } else {
                result.push(c);
            }
        } else if c == '"' {
            in_quotes = true;
            result.push(c);
        } else if c == '#' {
            // Check for bracket comment #[[ ... ]]
            if chars.peek() == Some(&'[') {
                chars.next();
                if chars.peek() == Some(&'[') {
                    chars.next();
                    // Consume until ]]
                    while let Some(bc) = chars.next() {
                        if bc == ']' && chars.peek() == Some(&']') {
                            chars.next();
                            break;
                        }
                    }
                    continue;
                } else {
                    result.push('#');
                    result.push('[');
                    continue;
                }
            }
            // Regular line comment: skip until newline
            for lc in chars.by_ref() {
                if lc == '\n' {
                    result.push('\n');
                    break;
                }
            }
        } else {
            result.push(c);
        }
    }

    result
}

#[derive(Debug, Clone)]
struct ConditionScope {
    platform: Option<String>,
    is_optional: bool,
}

/// Parse CMake content into a sequence of CMake commands with line numbers and condition contexts.
pub fn parse_cmake_commands(
    content: &str,
    known_options: &HashMap<String, bool>,
) -> Vec<CMakeCommand> {
    let clean_content = strip_cmake_comments(content);
    let mut commands = Vec::new();
    let mut condition_stack: Vec<ConditionScope> = Vec::new();

    let mut chars = clean_content.char_indices().peekable();
    let mut line_no = 1;

    while let Some(&(idx, c)) = chars.peek() {
        let _ = idx;
        if c == '\n' {
            line_no += 1;
            chars.next();
            continue;
        }

        if c.is_alphabetic() || c == '_' {
            // Start of command identifier
            let start_line = line_no;
            let mut name = String::new();
            while let Some(&(_, id_c)) = chars.peek() {
                if id_c.is_alphanumeric() || id_c == '_' {
                    name.push(id_c);
                    chars.next();
                } else {
                    break;
                }
            }

            // Skip whitespace up to '('
            let mut found_paren = false;
            while let Some(&(_, ws_c)) = chars.peek() {
                if ws_c == '(' {
                    found_paren = true;
                    chars.next();
                    break;
                } else if ws_c.is_whitespace() {
                    if ws_c == '\n' {
                        line_no += 1;
                    }
                    chars.next();
                } else {
                    break;
                }
            }

            if found_paren {
                let mut paren_depth = 1;
                let mut arg_str = String::new();
                let mut in_quote = false;

                while let Some(&(_, arg_c)) = chars.peek() {
                    chars.next();
                    if arg_c == '\n' {
                        line_no += 1;
                    }

                    if in_quote {
                        if arg_c == '\\' {
                            arg_str.push(arg_c);
                            if let Some(&(_, next_c)) = chars.peek() {
                                chars.next();
                                if next_c == '\n' {
                                    line_no += 1;
                                }
                                arg_str.push(next_c);
                            }
                        } else if arg_c == '"' {
                            in_quote = false;
                            arg_str.push(arg_c);
                        } else {
                            arg_str.push(arg_c);
                        }
                    } else if arg_c == '"' {
                        in_quote = true;
                        arg_str.push(arg_c);
                    } else if arg_c == '(' {
                        paren_depth += 1;
                        arg_str.push(arg_c);
                    } else if arg_c == ')' {
                        paren_depth -= 1;
                        if paren_depth == 0 {
                            break;
                        }
                        arg_str.push(arg_c);
                    } else {
                        arg_str.push(arg_c);
                    }
                }

                let tokens = tokenize_args(&arg_str);
                let cmd_lower = name.to_lowercase();

                // Manage condition stack
                if cmd_lower == "if" {
                    let (plat, opt) = eval_condition(&tokens, known_options);
                    condition_stack.push(ConditionScope {
                        platform: plat,
                        is_optional: opt,
                    });
                } else if cmd_lower == "elseif" {
                    if let Some(scope) = condition_stack.last_mut() {
                        let (plat, opt) = eval_condition(&tokens, known_options);
                        scope.platform = plat;
                        scope.is_optional = opt;
                    }
                } else if cmd_lower == "else" {
                    if let Some(scope) = condition_stack.last_mut() {
                        scope.platform = None;
                    }
                } else if cmd_lower == "endif" {
                    condition_stack.pop();
                }

                // Determine active platform and optionality from condition stack
                let active_platform = condition_stack
                    .iter()
                    .rev()
                    .find_map(|s| s.platform.clone());
                let is_guarded_optional = condition_stack.iter().any(|s| s.is_optional);

                commands.push(CMakeCommand {
                    name: cmd_lower,
                    args: tokens,
                    line_no: start_line,
                    platform: active_platform,
                    is_guarded_optional,
                });
            }
        } else {
            chars.next();
        }
    }

    commands
}

/// Evaluates condition tokens for platform guards and optionality based on option defaults.
fn eval_condition(
    tokens: &[String],
    known_options: &HashMap<String, bool>,
) -> (Option<String>, bool) {
    let joined = tokens.join(" ").to_uppercase();

    let mut platform = None;
    if joined.contains("WIN32") || joined.contains("MSVC") || joined.contains("MINGW") {
        if !joined.contains("NOT WIN32") {
            platform = Some("windows".to_string());
        }
    } else if joined.contains("APPLE") || joined.contains("DARWIN") {
        if !joined.contains("NOT APPLE") {
            platform = Some("darwin".to_string());
        }
    } else if joined.contains("LINUX")
        || (joined.contains("UNIX") && !joined.contains("APPLE"))
        || joined.contains("CMAKE_SYSTEM_NAME STREQUAL LINUX")
        || joined.contains("CMAKE_SYSTEM_NAME STREQUAL \"LINUX\"")
    {
        platform = Some("linux".to_string());
    } else if joined.contains("ANDROID") {
        platform = Some("android".to_string());
    }

    let mut is_optional = false;
    for token in tokens {
        if let Some(&is_enabled) = known_options.get(token) {
            if !is_enabled {
                is_optional = true;
                break;
            }
        }
    }

    (platform, is_optional)
}

/// Parse options from CMake files: `option(<VAR> "<help_text>" [value])`.
pub fn parse_cmake_options(content: &str) -> HashMap<String, bool> {
    let mut options = HashMap::new();
    let clean = strip_cmake_comments(content);

    // Simple pass to find option(...) calls
    for line in clean.lines() {
        let trimmed = line.trim();
        if trimmed.to_lowercase().starts_with("option(")
            || trimmed.to_lowercase().starts_with("option (")
        {
            if let Some(open) = trimmed.find('(') {
                if let Some(close) = trimmed.rfind(')') {
                    let inner = &trimmed[open + 1..close];
                    let tokens = tokenize_args(inner);
                    if let Some(var_name) = tokens.first() {
                        let default_val = tokens.get(2).map(|s| s.as_str()).unwrap_or("OFF");
                        let is_on = matches!(
                            default_val.to_uppercase().as_str(),
                            "ON" | "TRUE" | "1" | "YES"
                        );
                        options.insert(var_name.clone(), is_on);
                    }
                }
            }
        }
    }

    options
}

pub fn std_rank(lang: &str, std_str: &str) -> u32 {
    let lower = std_str.to_lowercase();
    if lang == "c" {
        match lower.as_str() {
            "90" | "c90" => 1,
            "99" | "c99" => 2,
            "11" | "c11" => 3,
            "17" | "c17" | "18" | "c18" => 4,
            "23" | "c23" => 5,
            _ => 0,
        }
    } else if lang == "cpp" {
        match lower.as_str() {
            "98" | "c++98" => 1,
            "11" | "c++11" => 2,
            "14" | "c++14" => 3,
            "17" | "c++17" => 4,
            "20" | "c++20" => 5,
            "23" | "c++23" => 6,
            _ => 0,
        }
    } else {
        0
    }
}

fn format_standard(lang: &str, raw: &str) -> String {
    let clean = strip_quotes(raw);
    let lower = clean.to_lowercase();
    if lang == "c" {
        if lower.starts_with('c') {
            lower
        } else {
            format!("c{}", lower)
        }
    } else if lang == "cpp" {
        if lower.starts_with("c++") {
            lower
        } else if let Some(stripped) = lower.strip_prefix("cxx") {
            format!("c++{}", stripped)
        } else {
            format!("c++{}", lower)
        }
    } else {
        clean.to_string()
    }
}

/// Analyze CMake project configurations (CMakeLists.txt and referenced subdirectories / .cmake files).
pub fn analyze_cmake(root: &Path) -> CMakeDiscovery {
    let mut is_cmake = false;
    let mut languages = Vec::new();
    let mut requirements = Vec::new();
    let mut evidence = Vec::new();

    let root_cmake = root.join("CMakeLists.txt");
    if !root_cmake.exists() {
        return CMakeDiscovery {
            is_cmake,
            languages,
            requirements,
            evidence,
        };
    }

    is_cmake = true;

    // Discover CMake files to inspect
    let mut cmake_files: Vec<PathBuf> = vec![PathBuf::from("CMakeLists.txt")];

    // Read root file once to check for immediate add_subdirectory calls
    if let Ok(root_content) = fs::read_to_string(&root_cmake) {
        let commands = parse_cmake_commands(&root_content, &HashMap::new());
        for cmd in &commands {
            if cmd.name == "add_subdirectory" {
                if let Some(sub) = cmd.args.first() {
                    let sub_clean = strip_quotes(sub);
                    let sub_cmakelists = root.join(sub_clean).join("CMakeLists.txt");
                    if sub_cmakelists.is_file() {
                        let rel = PathBuf::from(sub_clean).join("CMakeLists.txt");
                        if !cmake_files.contains(&rel) {
                            cmake_files.push(rel);
                        }
                    }
                }
            } else if cmd.name == "include" {
                if let Some(inc) = cmd.args.first() {
                    let inc_clean = strip_quotes(inc);
                    if inc_clean.ends_with(".cmake") {
                        let inc_path = root.join(inc_clean);
                        if inc_path.is_file() {
                            let rel = PathBuf::from(inc_clean);
                            if !cmake_files.contains(&rel) {
                                cmake_files.push(rel);
                            }
                        }
                    }
                }
            }
        }
    }

    // Also inspect immediate subdirectories containing CMakeLists.txt (bounded search)
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let file_name = entry.file_name();
                let dir_str = file_name.to_string_lossy();
                if dir_str.starts_with('.')
                    || dir_str == "build"
                    || dir_str == "target"
                    || dir_str == "node_modules"
                    || dir_str == "vendor"
                {
                    continue;
                }

                let sub_cm = path.join("CMakeLists.txt");
                if sub_cm.is_file() {
                    if let Ok(rel) = sub_cm.strip_prefix(root) {
                        let rel_pb = rel.to_path_buf();
                        if !cmake_files.contains(&rel_pb) {
                            cmake_files.push(rel_pb);
                        }
                    }
                }
            }
        }
    }

    // 1. Collect all project options across all discovered cmake files
    let mut known_options: HashMap<String, bool> = HashMap::new();
    for rel_path in &cmake_files {
        let full = root.join(rel_path);
        if let Ok(content) = fs::read_to_string(&full) {
            let opts = parse_cmake_options(&content);
            known_options.extend(opts);
        }
    }

    // 2. Track extracted requirements across files
    let mut min_cmake_version: Option<(String, PathBuf, usize)> = None;
    let mut project_languages: Vec<String> = Vec::new();
    let mut c_standard: Option<String> = None;
    let mut cpp_standard: Option<String> = None;

    // Track packages and system libraries
    type PackageKey = (String, Option<String>);
    type PackageEntry = (ToolScope, Evidence, Option<VersionConstraint>);
    let mut seen_packages: BTreeMap<PackageKey, PackageEntry> = BTreeMap::new();
    let mut seen_python_components: BTreeMap<String, (ToolScope, Evidence)> = BTreeMap::new();
    let mut python_runtime_req: Option<(Option<VersionConstraint>, ToolScope, Evidence)> = None;

    for rel_path in &cmake_files {
        let full_path = root.join(rel_path);
        let content = match fs::read_to_string(&full_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let commands = parse_cmake_commands(&content, &known_options);

        for cmd in &commands {
            match cmd.name.as_str() {
                "cmake_minimum_required" => {
                    let mut ver_token = None;
                    let mut iter = cmd.args.iter().peekable();
                    while let Some(arg) = iter.next() {
                        if arg.eq_ignore_ascii_case("VERSION") {
                            ver_token = iter.next().cloned();
                            break;
                        }
                    }
                    if let Some(raw_ver) = ver_token {
                        let clean_ver = strip_quotes(&raw_ver);
                        // If version range (e.g. 3.15...3.25), use the minimum version before ...
                        let min_ver = clean_ver.split("...").next().unwrap_or(clean_ver).trim();
                        if !min_ver.is_empty() && min_cmake_version.is_none() {
                            min_cmake_version =
                                Some((min_ver.to_string(), rel_path.clone(), cmd.line_no));
                        }
                    }
                }

                "project" => {
                    // project(<name> [VERSION <v>] [DESCRIPTION <d>] [HOMEPAGE_URL <u>] [LANGUAGES] [<languages>...])
                    let mut args_iter = cmd.args.iter().skip(1); // skip project name
                    let mut found_languages_kw = false;
                    let mut explicit_langs = Vec::new();

                    while let Some(arg) = args_iter.next() {
                        let upper = arg.to_uppercase();
                        if upper == "LANGUAGES" {
                            found_languages_kw = true;
                            for lang_token in args_iter.by_ref() {
                                let l_upper = lang_token.to_uppercase();
                                if matches!(
                                    l_upper.as_str(),
                                    "VERSION" | "DESCRIPTION" | "HOMEPAGE_URL"
                                ) {
                                    break;
                                }
                                explicit_langs.push(lang_token.clone());
                            }
                            break;
                        } else if matches!(
                            upper.as_str(),
                            "VERSION" | "DESCRIPTION" | "HOMEPAGE_URL"
                        ) {
                            // skip value argument
                            let _ = args_iter.next();
                        } else {
                            explicit_langs.push(arg.clone());
                        }
                    }

                    if found_languages_kw
                        && explicit_langs
                            .iter()
                            .any(|l| l.eq_ignore_ascii_case("NONE"))
                    {
                        // explicitly disabled
                    } else if explicit_langs.is_empty() {
                        // CMake default is C and CXX
                        if !project_languages.contains(&"c".to_string()) {
                            project_languages.push("c".to_string());
                        }
                        if !project_languages.contains(&"cpp".to_string()) {
                            project_languages.push("cpp".to_string());
                        }
                    } else {
                        for lang in explicit_langs {
                            let norm = normalize_language(&lang);
                            if !project_languages.contains(&norm) {
                                project_languages.push(norm);
                            }
                        }
                    }
                }

                "enable_language" => {
                    for arg in &cmd.args {
                        let norm = normalize_language(arg);
                        if !project_languages.contains(&norm) {
                            project_languages.push(norm);
                        }
                    }
                }

                "set" => {
                    if let Some(var) = cmd.args.first() {
                        let var_upper = var.to_uppercase();
                        if var_upper == "CMAKE_C_STANDARD" {
                            if let Some(val) = cmd.args.get(1) {
                                let formatted = format_standard("c", val);
                                if let Some(ref current) = c_standard {
                                    if std_rank("c", &formatted) > std_rank("c", current) {
                                        c_standard = Some(formatted);
                                    }
                                } else {
                                    c_standard = Some(formatted);
                                }
                            }
                        } else if var_upper == "CMAKE_CXX_STANDARD" {
                            if let Some(val) = cmd.args.get(1) {
                                let formatted = format_standard("cpp", val);
                                if let Some(ref current) = cpp_standard {
                                    if std_rank("cpp", &formatted) > std_rank("cpp", current) {
                                        cpp_standard = Some(formatted);
                                    }
                                } else {
                                    cpp_standard = Some(formatted);
                                }
                            }
                        }
                    }
                }

                "target_compile_features" => {
                    for arg in &cmd.args {
                        let lower = arg.to_lowercase();
                        if let Some(raw_std) = lower.strip_prefix("c_std_") {
                            let formatted = format_standard("c", raw_std);
                            if let Some(ref current) = c_standard {
                                if std_rank("c", &formatted) > std_rank("c", current) {
                                    c_standard = Some(formatted);
                                }
                            } else {
                                c_standard = Some(formatted);
                            }
                        } else if let Some(raw_std) = lower.strip_prefix("cxx_std_") {
                            let formatted = format_standard("cpp", raw_std);
                            if let Some(ref current) = cpp_standard {
                                if std_rank("cpp", &formatted) > std_rank("cpp", current) {
                                    cpp_standard = Some(formatted);
                                }
                            } else {
                                cpp_standard = Some(formatted);
                            }
                        }
                    }
                }

                "find_package" => {
                    if let Some(pkg_name) = cmd.args.first() {
                        let is_required =
                            cmd.args.iter().any(|a| a.eq_ignore_ascii_case("REQUIRED"))
                                && !cmd.is_guarded_optional;
                        let scope = if is_required {
                            ToolScope::RequiredForBuild
                        } else {
                            ToolScope::Optional
                        };

                        // Extract version constraint if provided
                        let mut ver_constraint = None;
                        for arg in cmd.args.iter().skip(1) {
                            let clean = strip_quotes(arg);
                            if clean
                                .chars()
                                .next()
                                .map(|c| c.is_ascii_digit())
                                .unwrap_or(false)
                            {
                                ver_constraint =
                                    Some(VersionConstraint::GreaterEqual(clean.to_string()));
                                break;
                            }
                        }

                        let pkg_lower = pkg_name.to_lowercase();

                        // Special handling for Python
                        if pkg_lower == "python" || pkg_lower == "python3" || pkg_lower == "python2"
                        {
                            let ev = Evidence::new(
                                EvidenceSource::BuildConfiguration {
                                    path: rel_path.clone(),
                                    line: Some(cmd.line_no),
                                    detail: Some(format!(
                                        "CMake find_package({}) declared (scope: {:?})",
                                        pkg_name, scope
                                    )),
                                },
                                Confidence::High,
                                format!(
                                    "Python runtime required by CMake build configuration ({:?})",
                                    scope
                                ),
                            );

                            let combined_constraint = ver_constraint.clone().unwrap_or_else(|| {
                                VersionConstraint::GreaterEqual(
                                    if pkg_lower == "python2" { "2.7" } else { "3.0" }.to_string(),
                                )
                            });

                            if let Some(existing) = &python_runtime_req {
                                if existing.1 == ToolScope::Optional
                                    && scope == ToolScope::RequiredForBuild
                                {
                                    python_runtime_req =
                                        Some((Some(combined_constraint), scope, ev.clone()));
                                }
                            } else {
                                python_runtime_req =
                                    Some((Some(combined_constraint), scope, ev.clone()));
                            }

                            // Extract Python components
                            let mut in_components = false;
                            for arg in &cmd.args[1..] {
                                let arg_upper = arg.to_uppercase();
                                if arg_upper == "COMPONENTS" || arg_upper == "OPTIONAL_COMPONENTS" {
                                    in_components = true;
                                    continue;
                                }
                                if in_components {
                                    if matches!(
                                        arg_upper.as_str(),
                                        "REQUIRED" | "EXACT" | "QUIET" | "MODULE" | "CONFIG"
                                    ) {
                                        in_components = false;
                                        continue;
                                    }
                                    let comp_clean = strip_quotes(arg);
                                    let comp_lower = comp_clean.to_lowercase();
                                    if comp_lower != "interpreter"
                                        && comp_lower != "compiler"
                                        && comp_lower != "development"
                                        && comp_lower != "main"
                                    {
                                        let comp_ev = Evidence::new(
                                            EvidenceSource::BuildConfiguration {
                                                path: rel_path.clone(),
                                                line: Some(cmd.line_no),
                                                detail: Some(format!(
                                                    "Python package '{}' required by CMake find_package({})",
                                                    comp_clean, pkg_name
                                                )),
                                            },
                                            Confidence::High,
                                            format!("Python package '{}' required by CMake build", comp_clean),
                                        );
                                        seen_python_components.insert(comp_lower, (scope, comp_ev));
                                    }
                                }
                            }
                        } else if pkg_lower == "pkgconfig" {
                            let ev = Evidence::new(
                                EvidenceSource::BuildConfiguration {
                                    path: rel_path.clone(),
                                    line: Some(cmd.line_no),
                                    detail: Some(format!("CMake find_package(PkgConfig) (scope: {:?})", scope)),
                                },
                                Confidence::High,
                                format!("Build tool 'pkg-config' declared via CMake find_package ({:?})", scope),
                            );
                            requirements.push(ProjectRequirement::new(
                                "pkg-config",
                                RequirementKind::BuildTool {
                                    name: "pkg-config".to_string(),
                                    constraint: None,
                                    scope,
                                },
                                ev.clone(),
                            ));
                            evidence.push(ev);
                        } else {
                            // General system library/package requirement
                            let ev = Evidence::new(
                                EvidenceSource::BuildConfiguration {
                                    path: rel_path.clone(),
                                    line: Some(cmd.line_no),
                                    detail: Some(format!(
                                        "CMake find_package({}) declared (scope: {:?})",
                                        pkg_name, scope
                                    )),
                                },
                                Confidence::High,
                                format!(
                                    "System library/package '{}' declared in CMake ({:?})",
                                    pkg_name, scope
                                ),
                            );

                            let key = (pkg_lower, cmd.platform.clone());
                            if let Some(existing) = seen_packages.get_mut(&key) {
                                if existing.0 == ToolScope::Optional
                                    && scope == ToolScope::RequiredForBuild
                                {
                                    *existing = (scope, ev, ver_constraint);
                                }
                            } else {
                                seen_packages.insert(key, (scope, ev, ver_constraint));
                            }
                        }
                    }
                }

                "find_library" if cmd.args.len() >= 2 => {
                    // find_library(<VAR> [NAMES] name1 [name2 ...] [REQUIRED])
                    let is_required = cmd.args.iter().any(|a| a.eq_ignore_ascii_case("REQUIRED"))
                        && !cmd.is_guarded_optional;
                    let scope = if is_required {
                        ToolScope::RequiredForBuild
                    } else {
                        // If find_library is called without explicit options, default to RequiredForBuild unless guarded
                        if cmd.is_guarded_optional {
                            ToolScope::Optional
                        } else {
                            ToolScope::RequiredForBuild
                        }
                    };

                    let mut lib_names = Vec::new();
                    let mut in_names = true;
                    for arg in cmd.args.iter().skip(1) {
                        let upper = arg.to_uppercase();
                        if upper == "NAMES" {
                            in_names = true;
                            continue;
                        }
                        if matches!(
                            upper.as_str(),
                            "PATHS"
                                | "HINTS"
                                | "PATH_SUFFIXES"
                                | "DOC"
                                | "NO_DEFAULT_PATH"
                                | "REQUIRED"
                        ) {
                            in_names = false;
                            continue;
                        }
                        if in_names {
                            let clean = strip_quotes(arg);
                            if !clean.is_empty() && !clean.starts_with('$') {
                                lib_names.push(clean.to_string());
                            }
                        }
                    }

                    if let Some(first_lib) = lib_names.first() {
                        let ev = Evidence::new(
                            EvidenceSource::BuildConfiguration {
                                path: rel_path.clone(),
                                line: Some(cmd.line_no),
                                detail: Some(format!(
                                    "CMake find_library({}) declared (scope: {:?})",
                                    first_lib, scope
                                )),
                            },
                            Confidence::High,
                            format!(
                                "System library '{}' declared in CMake find_library ({:?})",
                                first_lib, scope
                            ),
                        );

                        let key = (first_lib.to_lowercase(), cmd.platform.clone());
                        if let Some(existing) = seen_packages.get_mut(&key) {
                            if existing.0 == ToolScope::Optional
                                && scope == ToolScope::RequiredForBuild
                            {
                                *existing = (scope, ev, None);
                            }
                        } else {
                            seen_packages.insert(key, (scope, ev, None));
                        }
                    }
                }

                "find_program" if cmd.args.len() >= 2 => {
                    let is_required = cmd.args.iter().any(|a| a.eq_ignore_ascii_case("REQUIRED"))
                        && !cmd.is_guarded_optional;
                    let scope = if is_required {
                        ToolScope::RequiredForBuild
                    } else {
                        ToolScope::Optional
                    };

                    let prog_name = strip_quotes(&cmd.args[1]);
                    if !prog_name.is_empty() && !prog_name.starts_with('$') {
                        let ev = Evidence::new(
                            EvidenceSource::BuildConfiguration {
                                path: rel_path.clone(),
                                line: Some(cmd.line_no),
                                detail: Some(format!(
                                    "CMake find_program({}) declared (scope: {:?})",
                                    prog_name, scope
                                )),
                            },
                            Confidence::High,
                            format!(
                                "Tool '{}' declared in CMake find_program ({:?})",
                                prog_name, scope
                            ),
                        );
                        let mut req = ProjectRequirement::new(
                            prog_name.to_lowercase(),
                            RequirementKind::BuildTool {
                                name: prog_name.to_lowercase(),
                                constraint: None,
                                scope,
                            },
                            ev.clone(),
                        );
                        if let Some(ref p) = cmd.platform {
                            req = req.with_platform(p.clone());
                        }
                        requirements.push(req);
                        evidence.push(ev);
                    }
                }

                _ => {}
            }
        }
    }

    // 3. Assemble root CMake build tool requirement
    if let Some((ver, path, line)) = min_cmake_version {
        let ev = Evidence::new(
            EvidenceSource::BuildConfiguration {
                path,
                line: Some(line),
                detail: Some(format!("cmake_minimum_required declared: {}", ver)),
            },
            Confidence::High,
            format!("CMake build tool minimum version requirement: {}", ver),
        );
        requirements.push(ProjectRequirement::new(
            "cmake",
            RequirementKind::BuildTool {
                name: "cmake".to_string(),
                constraint: Some(VersionConstraint::GreaterEqual(ver)),
                scope: ToolScope::RequiredForBuild,
            },
            ev.clone(),
        ));
        evidence.push(ev);
    } else {
        // Fallback: CMakeLists.txt present without explicit minimum version
        let ev = Evidence::new(
            EvidenceSource::BuildConfiguration {
                path: PathBuf::from("CMakeLists.txt"),
                line: None,
                detail: Some("CMake build system detected via CMakeLists.txt".to_string()),
            },
            Confidence::High,
            "CMake build tool required to configure project",
        );
        requirements.push(ProjectRequirement::new(
            "cmake",
            RequirementKind::BuildTool {
                name: "cmake".to_string(),
                constraint: None,
                scope: ToolScope::RequiredForBuild,
            },
            ev.clone(),
        ));
        evidence.push(ev);
    }

    // 4. Assemble compiler requirements
    for lang in &project_languages {
        languages.push(lang.clone());
        let std_opt = if lang == "c" {
            c_standard.clone()
        } else if lang == "cpp" {
            cpp_standard.clone()
        } else {
            None
        };

        let ev = Evidence::new(
            EvidenceSource::BuildConfiguration {
                path: PathBuf::from("CMakeLists.txt"),
                line: None,
                detail: Some(format!(
                    "{} compiler required{}",
                    lang.to_uppercase(),
                    std_opt
                        .as_deref()
                        .map(|s| format!(" ({})", s))
                        .unwrap_or_default()
                )),
            },
            Confidence::High,
            format!(
                "{} compiler required for build{}",
                lang.to_uppercase(),
                std_opt
                    .as_deref()
                    .map(|s| format!(" with standard {}", s))
                    .unwrap_or_default()
            ),
        );

        requirements.push(ProjectRequirement::new(
            lang,
            RequirementKind::Compiler {
                language: lang.clone(),
                min_standard: std_opt,
                constraint: None,
            },
            ev.clone(),
        ));
        evidence.push(ev);
    }

    // 5. Assemble Python runtime and package requirements
    if let Some((constraint, _scope, ev)) = python_runtime_req {
        requirements.push(ProjectRequirement::new(
            "python",
            RequirementKind::Runtime {
                name: "python".to_string(),
                constraint: constraint
                    .unwrap_or_else(|| VersionConstraint::GreaterEqual("3.0".to_string())),
            },
            ev.clone(),
        ));
        evidence.push(ev);

        for (pkg_name, (scope, comp_ev)) in seen_python_components {
            requirements.push(ProjectRequirement::new(
                format!("python:{}", pkg_name),
                RequirementKind::LanguagePackage {
                    language: "python".to_string(),
                    package: pkg_name,
                    constraint: None,
                    scope,
                },
                comp_ev.clone(),
            ));
            evidence.push(comp_ev);
        }
    }

    // 6. Assemble packages and system libraries
    for ((pkg_name, platform), (scope, ev, constraint)) in seen_packages {
        let mut req = ProjectRequirement::new(
            pkg_name.clone(),
            RequirementKind::SystemLibrary {
                name: pkg_name,
                header: None,
                constraint,
                scope,
            },
            ev.clone(),
        );
        if let Some(p) = platform {
            req = req.with_platform(p);
        }
        requirements.push(req);
        evidence.push(ev);
    }

    languages.sort();
    languages.dedup();

    CMakeDiscovery {
        is_cmake,
        languages,
        requirements,
        evidence,
    }
}

fn normalize_language(raw: &str) -> String {
    let clean = strip_quotes(raw);
    let lower = clean.to_lowercase();
    match lower.as_str() {
        "c" => "c".to_string(),
        "cxx" | "cpp" | "c++" => "cpp".to_string(),
        "cuda" => "cuda".to_string(),
        "fortran" => "fortran".to_string(),
        "objc" => "objc".to_string(),
        "objcxx" => "objcxx".to_string(),
        "csharp" | "c#" => "csharp".to_string(),
        "swift" => "swift".to_string(),
        "asm" => "asm".to_string(),
        _ => lower,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_parse_cmake_version_and_compiler() {
        let dir = tempdir().unwrap();
        let cmake_content = r#"
cmake_minimum_required(VERSION 3.20.0)
project(my_test_proj LANGUAGES C CXX)
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)
"#;
        fs::write(dir.path().join("CMakeLists.txt"), cmake_content).unwrap();

        let disc = analyze_cmake(dir.path());
        assert!(disc.is_cmake);
        assert_eq!(disc.languages, vec!["c", "cpp"]);

        // Verify cmake requirement
        let cmake_req = disc
            .requirements
            .iter()
            .find(|r| r.name == "cmake")
            .expect("cmake requirement missing");
        match &cmake_req.kind {
            RequirementKind::BuildTool {
                constraint, scope, ..
            } => {
                assert_eq!(*scope, ToolScope::RequiredForBuild);
                assert!(constraint.is_some());
                assert!(constraint.as_ref().unwrap().matches("3.20.0"));
                assert!(!constraint.as_ref().unwrap().matches("3.19.0"));
            }
            _ => panic!("Expected BuildTool"),
        }

        // Verify C compiler with standard c11
        let c_req = disc
            .requirements
            .iter()
            .find(|r| r.name == "c")
            .expect("c requirement missing");
        match &c_req.kind {
            RequirementKind::Compiler {
                min_standard,
                language,
                ..
            } => {
                assert_eq!(language, "c");
                assert_eq!(min_standard.as_deref(), Some("c11"));
            }
            _ => panic!("Expected Compiler"),
        }

        // Verify C++ compiler with standard c++17
        let cpp_req = disc
            .requirements
            .iter()
            .find(|r| r.name == "cpp")
            .expect("cpp requirement missing");
        match &cpp_req.kind {
            RequirementKind::Compiler {
                min_standard,
                language,
                ..
            } => {
                assert_eq!(language, "cpp");
                assert_eq!(min_standard.as_deref(), Some("c++17"));
            }
            _ => panic!("Expected Compiler"),
        }
    }

    #[test]
    fn test_find_package_required_vs_optional() {
        let dir = tempdir().unwrap();
        let cmake_content = r#"
cmake_minimum_required(VERSION 3.10)
project(sample C)
find_package(OpenSSL REQUIRED)
find_package(ZLIB)
"#;
        fs::write(dir.path().join("CMakeLists.txt"), cmake_content).unwrap();

        let disc = analyze_cmake(dir.path());
        let openssl = disc
            .requirements
            .iter()
            .find(|r| r.name == "openssl")
            .expect("openssl missing");
        match &openssl.kind {
            RequirementKind::SystemLibrary { scope, .. } => {
                assert_eq!(*scope, ToolScope::RequiredForBuild);
            }
            _ => panic!("Expected SystemLibrary"),
        }

        let zlib = disc
            .requirements
            .iter()
            .find(|r| r.name == "zlib")
            .expect("zlib missing");
        match &zlib.kind {
            RequirementKind::SystemLibrary { scope, .. } => {
                assert_eq!(*scope, ToolScope::Optional);
            }
            _ => panic!("Expected SystemLibrary"),
        }
    }

    #[test]
    fn test_platform_guard_stack() {
        let dir = tempdir().unwrap();
        let cmake_content = r#"
cmake_minimum_required(VERSION 3.10)
project(sample C)
if(WIN32)
    find_package(WinSock REQUIRED)
endif()
"#;
        fs::write(dir.path().join("CMakeLists.txt"), cmake_content).unwrap();

        let disc = analyze_cmake(dir.path());
        let winsock = disc
            .requirements
            .iter()
            .find(|r| r.name == "winsock")
            .expect("winsock missing");
        assert_eq!(winsock.platform.as_deref(), Some("windows"));
    }

    #[test]
    fn test_option_scope_guard() {
        let dir = tempdir().unwrap();
        let cmake_content = r#"
cmake_minimum_required(VERSION 3.10)
project(sample C)
option(ENABLE_TESTS "Enable tests" OFF)
if(ENABLE_TESTS)
    find_package(GTest REQUIRED)
endif()
"#;
        fs::write(dir.path().join("CMakeLists.txt"), cmake_content).unwrap();

        let disc = analyze_cmake(dir.path());
        let gtest = disc
            .requirements
            .iter()
            .find(|r| r.name == "gtest")
            .expect("gtest missing");
        match &gtest.kind {
            RequirementKind::SystemLibrary { scope, .. } => {
                // Because ENABLE_TESTS defaults to OFF, guarded find_package should be Optional!
                assert_eq!(*scope, ToolScope::Optional);
            }
            _ => panic!("Expected SystemLibrary"),
        }
    }
}

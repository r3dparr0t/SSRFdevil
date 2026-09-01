use chrono::Local;
use serde_yaml;
use std::{fs, io::{self, Write}, path::Path};

use ssrfdevil::{
    engine::rule::{MatchConfig, RuleFile, RuleMeta, ScriptConfig, Severity},
    paths,
};

fn parse_severity(s: &str) -> Result<Severity, String> {
    match s.to_lowercase().as_str() {
        "informational" | "info" => Ok(Severity::Info),
        "low" => Ok(Severity::Low),
        "medium" => Ok(Severity::Medium),
        "high" => Ok(Severity::High),
        "critical" => Ok(Severity::Critical),
        _ => Err(format!("'{}' is not a valid severity", s)),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🛠️  SSRFdevil Rule Generator (v2 - Evidence-based)");
    println!("====================================================");

    // ----基本信息----
    print!("📛 Rule Name (e.g., 'IPv4 localhost bypass'): ");
    io::stdout().flush()?;
    let mut name = String::new();
    io::stdin().read_line(&mut name)?;
    let name = name.trim();

    print!("📝 Description: ");
    io::stdout().flush()?;
    let mut desc = String::new();
    io::stdin().read_line(&mut desc)?;
    let desc = desc.trim();

    print!("🏷️  Tags (comma separated, e.g., 'localhost,ipv4,bypass'): ");
    io::stdout().flush()?;
    let mut tags_input = String::new();
    io::stdin().read_line(&mut tags_input)?;
    let tags: Vec<String> = tags_input
        .trim()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    print!("⚙️  Severity (informational/low/medium/high/critical): ");
    io::stdout().flush()?;
    let mut severity_str = String::new();
    io::stdin().read_line(&mut severity_str)?;
    let severity = parse_severity(&severity_str.trim().to_lowercase())
        .unwrap_or_else(|e| {
            eprintln!("⚠️  {} – defaulting to 'medium'", e);
            Severity::Medium
        });

    print!("📈 Rank (higher is better, e.g., 60): ");
    io::stdout().flush()?;
    let mut rank_input = String::new();
    io::stdin().read_line(&mut rank_input)?;
    let rank: u32 = rank_input.trim().parse().unwrap_or(50);

    // ---- confidence ----
    println!("\n📊 Confidence (0-100) – how much do you trust this rule?");
    println!("   - 80-100: strong evidence (e.g., reading /etc/passwd)");
    println!("   - 60-79:  moderate (e.g., heuristic patterns)");
    println!("   - 0-59:   weak / generic bypass (default)");
    print!("Confidence [default 55]: ");
    io::stdout().flush()?;
    let mut conf_input = String::new();
    io::stdin().read_line(&mut conf_input)?;
    let confidence: u8 = conf_input.trim().parse().unwrap_or(55);

    // ---- success_indicator ----
    println!("\n✅ success_indicator (evidence that confirms success)");
    println!("   Format: literal:pattern  or  regex:pattern");
    println!("   Example: literal:root:x:0:0");
    println!("   Enter one per line, empty line to finish:");
    let mut success_indicators = Vec::new();
    loop {
        print!("  > ");
        io::stdout().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        let line = line.trim();
        if line.is_empty() { break; }
        success_indicators.push(line.to_string());
    }

    // ---- failure_indicator ----
    println!("\n❌ failure_indicator (evidence that confirms rejection)");
    println!("   Format: literal:Access Denied  or  regex:blocked|denied");
    println!("   Enter one per line, empty line to finish:");
    let mut failure_indicators = Vec::new();
    loop {
        print!("  > ");
        io::stdout().flush()?;
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        let line = line.trim();
        if line.is_empty() { break; }
        failure_indicators.push(line.to_string());
    }

    // ---- generate ID ----
    let id = name
        .to_lowercase()
        .replace(' ', "_")
        .replace(['.', '/', '\\'], "_");

    let today = Local::now().format("%Y-%m-%d").to_string();

    // ---- Lua script ----
    println!("\n📜 Enter Lua script source (type 'END' on a new line to finish):");
    let mut source_lines = Vec::new();
    let mut line = String::new();
    while io::stdin().read_line(&mut line)? > 0 {
        if line.trim() == "END" {
            break;
        }
        source_lines.push(line.clone());
        line.clear();
    }
    let source = source_lines.concat();

    // ---- build rule ----
    let rule = RuleFile {
        meta: RuleMeta {
            id: id.clone(),
            version: 1,
            name: name.to_string(),
            description: desc.to_string(),
            author: "SSRFdevil".to_string(),
            created: today.clone(),
            updated: today.clone(),
            rank,
            confidence,
            severity,
            tags,
            references: vec![],
            success_indicator: success_indicators,
            failure_indicator: failure_indicators,
        },
        r#match: MatchConfig {
            kinds: vec![],
            schemes: vec!["http".to_string(), "https".to_string()],
            required_tags: vec![],
            require_params: false,
            requires: vec![],
            supports: vec![],
        },
        script: ScriptConfig {
            language: "lua".to_string(),
            entry: "run_batch".to_string(),  // ← نام استاندارد
            source,
        },
    };

    // ---- save ----
    fs::create_dir_all(paths::RULES_DIR)?;
    let max_num = fs::read_dir(paths::RULES_DIR)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .filter_map(|e| {
            e.file_name()
                .to_str()
                .and_then(|s| s.split('_').next())
                .and_then(|num| num.parse::<u32>().ok())
        })
        .max()
        .unwrap_or(0);

    let next_num = max_num + 1;
    let filename = format!("{:02}_{}.yaml", next_num, id);
    let filepath = Path::new(paths::RULES_DIR).join(&filename);

    let yaml_str = serde_yaml::to_string(&rule)?;
    fs::write(&filepath, yaml_str)?;

    println!("\n✅ Rule created successfully!");
    println!("📁 File: {}", filepath.display());
    println!("🔢 Rule ID: {}", id);
    println!("📊 Confidence: {}", confidence);
    println!("✅ success_indicator: {} patterns", rule.meta.success_indicator.len());
    println!("❌ failure_indicator: {} patterns", rule.meta.failure_indicator.len());

    Ok(())
}

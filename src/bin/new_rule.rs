use chrono::Local;
use serde_yaml;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

use ssrfdevil::rule::{MatchConfig, RuleFile, RuleMeta, ScriptConfig};
use ssrfdevil::paths;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🛠️  SSRFdevil Rule Generator");
    println!("==============================");

    // ۱. گرفتن ورودی از کاربر
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
    let mut severity = String::new();
    io::stdin().read_line(&mut severity)?;
    let severity = severity.trim().to_lowercase();

    print!("📈 Rank (higher is better, e.g., 60): ");
    io::stdout().flush()?;
    let mut rank_input = String::new();
    io::stdin().read_line(&mut rank_input)?;
    let rank: u32 = rank_input.trim().parse().unwrap_or(50);

    // ۲. ساخت ID از نام
    let id = name
        .to_lowercase()
        .replace(' ', "_")
        .replace(['.', '/', '\\'], "_");

    // ۳. تاریخ امروز
    let today = Local::now().format("%Y-%m-%d").to_string();

    // ۴. جمع‌آوری کد Lua از کاربر (چند خطی)
    println!("📜 Enter Lua script source (type 'END' on a new line to finish):");
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

    // ۵. ساخت ساختار نهایی
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
            confidence: 90,
            severity,
            tags,
            references: vec![],
        },
        r#match: MatchConfig {
            schemes: vec!["http".to_string(), "https".to_string()],
            requires: vec!["hostname".to_string()],
            supports: vec!["ipv4".to_string()],
        },
        script: ScriptConfig {
            language: "lua".to_string(),
            entry: "bypass".to_string(),
            source,
        },
    };

    // ۶. شماره‌گذاری فایل (پیدا کردن آخرین شماره)
    fs::create_dir_all(paths::RULES_DIR)?;
    let max_num = fs::read_dir(rules_dir)?
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
    let filepath = Path::new(rules_dir).join(&filename);

    // ۷. ذخیره به YAML
    let yaml_str = serde_yaml::to_string(&rule)?;
    fs::write(&filepath, yaml_str)?;

    println!("\n✅ Rule created successfully!");
    println!("📁 File: {}", filepath.display());
    println!("🔢 Rule ID: {}", id);
    println!("💡 Next: Run `cargo run -- <target>` to test it!");

    Ok(())
}

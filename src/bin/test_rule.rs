use std::env;
use std::fs;
use serde::Deserialize;
use mlua::{Lua, Table};

#[derive(Debug, Deserialize)]
struct ScriptSection {
    entry: String,
    source: String,
}

#[derive(Debug, Deserialize)]
struct RuleYaml {
    script: ScriptSection,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("❌ Usage: cargo run --bin test_rule -- <PATH_TO_YAML>");
        println!("Example: cargo run --bin test_rule -- rules/08_decimal_ip.yaml");
        return Ok(());
    }

    let yaml_path = &args[1];
    let content = fs::read_to_string(yaml_path)?;
    let rule: RuleYaml = serde_yaml::from_str(&content)?;

    println!("📜 Testing Rule File: {}", yaml_path);

    let lua = Lua::new();

    // ۱. ساخت دیتای ساختگی (Target) دقیقاً مشابه ساختاری که از دیتابیس/خزنده میاد
    let targets_table = lua.create_table()?;
    let t1 = lua.create_table()?;
    t1.set("url", "http://example.com/api/fetch?file=test.txt&user=admin")?;
    t1.set("method", "GET")?;

    let params_table = lua.create_table()?;
    let p1 = lua.create_table()?;
    p1.set("name", "file")?;
    p1.set("value", "test.txt")?;
    p1.set("location", "Query")?;
    params_table.set(1, p1)?;

    let p2 = lua.create_table()?;
    p2.set("name", "user")?;
    p2.set("value", "admin")?;
    p2.set("location", "Query")?;
    params_table.set(2, p2)?;

    t1.set("params", params_table)?;
    targets_table.set(1, t1)?;

    // ۲. بارگذاری اسکریپت لوا
    lua.load(&rule.script.source).exec()?;

    // ۳. صدا زدن تابع ورود (entry)
    let entry_fn = if rule.script.entry.is_empty() { "run_batch" } else { &rule.script.entry };
    let func: mlua::Function = lua.globals().get(entry_fn)?;
    
    let results_table: Table = func.call(targets_table)?;

    println!("\n=== 🧪 Generated Payloads Output ===");
    for (i, pair) in results_table.sequence_values::<Table>().enumerate() {
        let res = pair?;
        let url: String = res.get("url")?;
        let method: String = res.get::<_, Option<String>>("method")?.unwrap_or("GET".into());
        
        println!("\n[Payload #{}]", i + 1);
        println!("  ├── Method: {}", method);
        println!("  ├── URL:    {}", url);
        
        if let Ok(headers) = res.get::<_, Table>("headers") {
            println!("  └── Headers:");
            for h in headers.pairs::<String, String>() {
                if let Ok((k, v)) = h {
                    println!("        {}: {}", k, v);
                }
            }
        }
    }

    Ok(())
}

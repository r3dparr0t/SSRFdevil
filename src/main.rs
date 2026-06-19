use std::process;
use url::Url;

// mod scanner;
mod rule_mgr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> { // خروجی تابع اصلاح شد
    // get the target URL as input.
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("😈 SSRFdevil Error: Missing target URL\rUsage: SSRFdevil <url>");
        process::exit(1);
    }

    let target_str = &args[1];

    // parse URL correction
    let target_url = match Url::parse(target_str) {
        Ok(url) => url,
        Err(e) => {
            eprintln!("❌ Invalid URL format '{}': {}", target_str, e);
            process::exit(1);
        }
    };

    println!("🚀 Launching SSRFdevil for: {}", target_url);
    
    // load rules to sled
    let db = sled::open("rules_db")?;
    println!("--- Step 1: Synthesizing Directory ---");
    rule_mgr::populate_rules_db(&db, "./rules")?;
    
    // println!("\n--- Step 2: Listing Indexed Rules ---");
    // RuleMgr::list_rules(&db);

    // ۴. تست انتخاب هوشمند و پیش‌فرض (Best Rule)
    println!("--- Step 2: Smart Selection ---");
    if let Some(best_rule) = rule_mgr::get_default_rule(&db) {
        println!("🔥 System Auto-Selected Best Rule:");
        println!("   Name: {}", best_rule.meta.name);
        println!("   Rank: {}", best_rule.meta.rank);
        println!("   Updated: {}", best_rule.meta.updated);
        println!("   Script Content:\n{}", best_rule.script.source);
    } else {
        println!("❌ No rules found in database.");
    }
    
    // running scanner
    /* if let Err(e) = scanner::run(target_url).await {
        eprintln!("💥 Scanner encountered an error: {}", e);
    } */

    Ok(()) // اضافه کردن پایان موفقیت‌آمیز تابع
}

use std::process;
use url::Url;
// mod scanner;
use ssrfdevil::{
	crawler::crawler::Crawler,
	console,
	paths,
	engine::{
		ua_engine,
		rule_engine,
		RequestEngine,
		EngineConfig
	}
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // خروجی تابع اصلاح شد
    // get the target URL as input.
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("[😈] SSRFdevil Error: Missing target URL\rUsage: SSRFdevil <url>");
        process::exit(1);
    }

    let target_str = &args[1];

    // parse URL correction
    let target_url = match Url::parse(target_str) {
        Ok(url) => url,
        Err(e) => {
            eprintln!("[❌] Invalid URL format '{}': {}", target_str, e);
            process::exit(1);
        }
    };

    println!("[🚀] Launching SSRFdevil for: {}", target_url);
    
    // load rules to sled
    let db = sled::open(paths::DB_PATH)?;
    println!("[!] Synthesizing rules Directory...");
    rule_engine::populate_rules_db(&db, paths::RULES_DIR)?;

    // ۴. تست انتخاب هوشمند و پیش‌فرض (Best Rule)
    println!("[!] Default Selection by bypass tag, change rule range by 'use ipv4' or 'use all' for example.");
    *rule_engine::SELECTED_RULES.write().unwrap() = rule_engine::search_rules(&db, "bypass");
    
    if !rule_engine::SELECTED_RULES.read().unwrap().is_empty() {
        println!("[🔥] System Auto-Selected bypass rules...");
        rule_engine::display_result_rules(&rule_engine::SELECTED_RULES.read().unwrap());
    } else {
        println!("[❌] No rules found in database.");
    }
	ua_engine::init();
	let mut settings = console::Settings::default();
	let engine = RequestEngine::new(EngineConfig::default());
	let mut crawler = Crawler::new(engine.clone());
	
	console::run_interactive_console(&db, target_str, &mut settings, &mut crawler, &engine).await;

	// running scanner
    /* if let Err(e) = scanner::run(target_url).await {
        eprintln!("💥 Scanner encountered an error: {}", e);
    } */

    Ok(()) // اضافه کردن پایان موفقیت‌آمیز تابع
}

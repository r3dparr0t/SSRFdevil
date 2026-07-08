use std::process;
use std::time::Duration;
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

// تابع اول: فقط پارس متنی و اصلاح ساختار URL
fn parse_url(target: &str) -> Url {
    let trimmed_target = target.trim();
    let sanitized_str = if trimmed_target.starts_with("http://") || trimmed_target.starts_with("https://") {
        trimmed_target.to_string()
    } else {
        format!("http://{}", trimmed_target)
    };

    match Url::parse(&sanitized_str) {
        Ok(url) => url,
        Err(e) => {
            eprintln!("[❌] Invalid URL format '{}': {}", target, e);
            process::exit(1);
        }
    }
}

// تابع دوم: فرستادن ریکوئست واقعی و سنجش زنده بودن هدف (ناهمگام)
async fn validate_target_alive(url: &Url) -> Result<(), reqwest::Error> {
    println!("[🔍] Checking if target is alive...");
    
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(4)) // ۴ ثانیه تایم‌اوت
        .build()?;

    match client.get(url.as_str()).send().await {
        Ok(response) => {
            println!("[✅] Target is alive! Status: {}", response.status());
            Ok(())
        }
        Err(_e) => {
            println!("[👋] Nice try but this url is not valid or alive, try again!");
            process::exit(1);
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // get the target URL as input.
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        println!("[😈] SSRFdevil Error: Missing target URL\rUsage: SSRFdevil <url>");
        process::exit(1);
    }

    // ۱. پارس کردن متنی آدرس
    let target_url = parse_url(&args[1]);

    // ۲. بررسی زنده بودن آدرس از طریق تابع مجزا (باید .await بشه)
    validate_target_alive(&target_url).await?;

    // ۳. ادامه برنامه در صورت زنده بودن هدف
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
	
	console::run_interactive_console(&db, target_url.as_str(), &mut settings, &mut crawler, &engine).await;

    Ok(())
}

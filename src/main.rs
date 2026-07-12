use std::{
    process,
    time::Duration,
    fs,
    sync::Arc
};
use url::Url;
use ssrfdevil::{
	crawler::crawler::{Crawler,CrawlerConfig},
	console,
	paths,
	engine::{
		ua_engine,
		rule_engine,
		RequestEngine,
		EngineConfig
	},
	config
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
// ورودی به `&mut Url` تغییر کرد تا بتوانی آدرس اصلی را درون تابع تغییر دهی
async fn validate_target_alive(url: &mut Url) -> Result<(), reqwest::Error> {
    println!("[🔍] Checking if target is alive...");
    
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(4))
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()?;

    // تست اول با آدرس فعلی
    if client.get(url.as_str()).send().await.is_ok() {
        println!("[✅] Target is alive!");
        return Ok(());
    }

    // اگر خط داد و پروتکل http بود، پروتکلِ خودِ آدرس اصلی را به https تغییر می‌دهیم
    if url.scheme() == "http" {
        println!("[🔄] HTTP failed, retrying with HTTPS...");
        if url.set_scheme("https").is_ok() {
            // حالا با آدرس آپدیت شده (https) تست می‌کنیم
            if client.get(url.as_str()).send().await.is_ok() {
                println!("[✅] Target is alive via HTTPS! URL updated.");
                return Ok(());
            }
        }
    }

    // اگر هیچ‌کدام جواب ندادند
    println!("[👋] Nice try but this url is not valid or alive, try again!");
    process::exit(1);
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
    let mut target_url = parse_url(&args[1]);

    // ۲. بررسی زنده بودن آدرس از طریق تابع مجزا (باید .await بشه)
    validate_target_alive(&mut target_url).await?;

    // ۳. ادامه برنامه در صورت زنده بودن هدف
    println!("[🚀] Launching SSRFdevil for: {}", target_url);
    // remove old target_db
    let _ = fs::remove_dir_all(paths::TARGETS_DB).unwrap_or(());
    // load rules to sled
    let db = sled::open(paths::RULES_DB)?;
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

	config::init_global_settings();
    // init user profile engine.
	ua_engine::init();
    let engine_config = EngineConfig::default();
    let mut engine = RequestEngine::new(engine_config);

    // new crawler
    let crawler_config = CrawlerConfig {
        seed_urls: vec![target_url.clone()],
        max_depth: 3,                         // هر عمقی خواستی
        max_concurrent_requests: 10,          // تعداد هم‌زمانی
        allowed_domains: vec![],             // فقط دامنهٔ seed
    };

    let crawler = Arc::new(Crawler::new(engine.clone(), crawler_config));
    console::run_interactive_console(&db, target_url.as_str(), crawler, &mut engine).await;
    
	Ok(())
}

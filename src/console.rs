// src/console.rs
use std::{
    io::{self, Write},
    time::Duration,
    sync::Arc,
};

use sled::Db;
use crate::{
    lua_engine::executor,
    engine::{
        rule::RuleFile,
        ua_engine,
        rule_engine,
        RequestEngine,
        RedirectPolicy
    },
    crawler::crawler::Crawler,
    config::UaProfile
};

// وارد کردن تمام پیش‌نیازهای تعاملی از terminal_menu
use terminal_menu::{menu, button, label, scroll, run, mut_menu, back_button};

fn shell_prompt(selected: &[RuleFile], extrashell: &str) -> String {
    match selected.len() {
        0 => format!("ssrfdevil {}> ", extrashell),
        1 => format!("ssrfdevil ({}) {}> ", selected[0].meta.id, extrashell),
        n => format!("ssrfdevil (batch: {} rules) {}> ", n, extrashell),
    }
}

fn parse_command(input: &str) -> (&str, &str) {
    let mut parts = input.trim().splitn(2, ' ');
    (
        parts.next().unwrap_or(""),
        parts.next().unwrap_or(""),
    )
}

fn prompt(prompt: impl AsRef<str>) -> String {
    print!("{}", prompt.as_ref());
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();

    input.trim().to_owned()
}

fn prompt_i32(prompt_text: &str) -> Option<i32> {
    prompt(prompt_text).parse().ok()
}

// منوی تغییر پویا و تعاملی پروتکل User Agent
fn run_ua_headers_menu() {
    loop {
        let (current_profile, headers_count) = {
            let settings = crate::config::APP_SETTINGS.get().unwrap().read().unwrap();
            (settings.ua_profile.clone(), crate::engine::header_engine::get_custom_headers_len())
        };

        // ترفند هوشمندانه: گزینه فعال فعلی را به عنوان اولین آیتم در لیست قرار می‌دهیم تا پیش‌فرض شود
        let ua_options = match current_profile {
            UaProfile::Conservative => vec!["Conservative", "Balanced", "Full"],
            UaProfile::Balanced => vec!["Balanced", "Conservative", "Full"],
            UaProfile::Full => vec!["Full", "Conservative", "Balanced"],
        };

        // ساخت ساختار منوی تعاملی با terminal-menu
        let ua_menu = menu(vec![
            label("📝 [Menu 1] User-Agent & Custom Headers"),
            label("-----------------------------------------"),
            
            // گزینه انتخاب پروفایل به صورت لیست چرخشی
            scroll("    UA Profile      ", ua_options),
                
            label(format!("    Custom Headers  : {} loaded", headers_count)),
            button("📂 [Set/Edit Custom Headers]"),
            label("-----------------------------------------"),
            back_button("⬅️  [Back]")
        ]);

        run(&ua_menu);

        let mm = mut_menu(&ua_menu);
        
        // اگر کاربر گزینه بازگشت را زد، از لوپ خارج شو
        if mm.selected_item_name() == "⬅️  [Back]" {
            break;
        }

        // اعمال تغییرات انجام شده توسط کاربر روی ساختار تنظیمات اصلی
        if mm.selected_item_name() == "    UA Profile      " {
            let selected_val = mm.selection_value("    UA Profile      "); // اصلاح شد: استفاده از selection_value
            let mut settings = crate::config::APP_SETTINGS.get().unwrap().write().unwrap();
            match selected_val {
                "Conservative" => settings.ua_profile = UaProfile::Conservative,
                "Balanced" => settings.ua_profile = UaProfile::Balanced,
                "Full" => settings.ua_profile = UaProfile::Full,
                _ => {}
            }
            drop(settings);
            ua_engine::init();
        }

        if mm.selected_item_name() == "📂 [Set/Edit Custom Headers]" {
            println!("\nEnter header (Format 'Key: Value') or empty line to finish:");
            crate::engine::header_engine::clear_custom_headers();
            let mut added = 0;
            loop {
                let h = prompt("Header > ");
                if h.is_empty() { break; }
                match h.split_once(':') {
                    Some((k, v)) => {
                        match crate::engine::header_engine::add_custom_header(k.trim(), v.trim()) {
                            Ok(()) => added += 1,
                            Err(e) => println!("[!] Invalid header, skipped: {}", e),
                        }
                    }
                    None => println!("[!] Expected 'Key: Value' format, skipped."),
                }
            }
            println!("[+] {} custom header(s) updated.", added);
            prompt("\nPress Enter to return to menu...");
        }
    }
}

// منوی تعاملی پیکربندی اتصالات موتور
fn run_request_engine_menu(engine: &mut RequestEngine) {
    loop {
        let (threads, runtime, delay_min, delay_max) = {
            let settings = crate::config::APP_SETTINGS.get().unwrap().read().unwrap();
            (
                settings.threads,
                settings.max_runtime,
                settings.delay_min,
                settings.delay_max,
            )
        };
        let num = if let RedirectPolicy::Limited(v) = engine.config.redirects { v as u64 } else { 0 };

        let req_menu = menu(vec![
            label("⚡ [Menu 2] Request & Concurrency Settings"),
            label("-----------------------------------------"),
            button(format!("    Workers (Threads)     : {}", threads)),
            button(format!("    Max Runtime Limit     : {}s", if runtime == 0 { "Unlimited".to_string() } else { runtime.to_string() })),
            button(format!("    Request Timeout       : {}s", engine.config.timeout.as_secs())),
            button(format!("    Jitter Delay Range    : {}ms - {}ms", delay_min, delay_max)),
            button(format!("    Request Redirects     : {} times", num)),
            label("-----------------------------------------"),
            back_button("⬅️  [Back]")
        ]);

        run(&req_menu);

        let mm = mut_menu(&req_menu);
        let selected = mm.selected_item_name();

        if selected == "⬅️  [Back]" {
            break;
        }

        match selected {
            s if s.starts_with("    Workers") => {
                if let Some(t) = prompt_i32("Enter worker count > ") {
                    crate::config::APP_SETTINGS.get().unwrap().write().unwrap().threads = t;
                }
            }
            s if s.starts_with("    Max Runtime") => {
                if let Some(r) = prompt_i32("Enter max runtime in seconds (0 for infinite) > ") {
                    crate::config::APP_SETTINGS.get().unwrap().write().unwrap().max_runtime = r as u64;
                }
            }
            s if s.starts_with("    Request Timeout") => {
                if let Some(t) = prompt_i32("Enter timeout (seconds) > ") {
                    engine.config.timeout = Duration::from_secs(t.try_into().unwrap());
                }
            }
            s if s.starts_with("    Jitter Delay") => {
                if let Some(min) = prompt_i32("Min Delay (ms) > ") {
                    if let Some(max) = prompt_i32("Max Delay (ms) > ") {
                        let mut settings = crate::config::APP_SETTINGS.get().unwrap().write().unwrap();
                        settings.delay_min = min as u64;
                        settings.delay_max = max as u64;
                    }
                }
            }
            s if s.starts_with("    Request Redirects") => {
                if let Some(r) = prompt_i32("Enter retry count > ") {
                    engine.config.redirects = RedirectPolicy::Limited(r as usize);
                }
            }
            _ => {}
        }
    }
}

// منوی پیکربندی پیشرفته خزنده و وضعیت پروکسی
async fn run_crawler_advanced_menu(engine: &mut RequestEngine) {
    loop {
        // خواندن وضعیت‌های فعلی از تنظیمات در ابتدای هر تکرار لوپ
        let (rate, depth, targets, save) = {
            let settings = crate::config::APP_SETTINGS.get().unwrap().read().unwrap();
            (
                settings.crawler_rate_limit,
                settings.crawler_max_depth,
                settings.crawler_max_targets,
                settings.crawler_save_state,
            )
        };
        let proxies_len = crate::engine::proxy_engine::get_proxies_len();

        // چینش آرایه‌ها به شکلی که وضعیت فعلی سیستم همیشه آیتم اول (پیش‌فرض) منو باشد
        let proxy_options = if engine.config.proxy { vec!["ON", "OFF"] } else { vec!["OFF", "ON"] };
        let save_options = if save { vec!["Enabled", "Disabled"] } else { vec!["Disabled", "Enabled"] };

        let crawl_menu = menu(vec![
            label("🔍 [Menu 3] Crawler Core & Proxy Configuration"),
            label("-----------------------------------------"),
            button(format!("📂  Load Proxy List       : {} loaded", proxies_len)),
            scroll("🔄  Use Proxy             ", proxy_options),
            button(format!("⚡  Rate Limit (Global)   : {} req/sec", if rate == 0 { "Unlimited".to_string() } else { rate.to_string() })),
            button(format!("🕸️  Max Crawl Depth       : {}", depth)),
            button(format!("🎯  Max Target KillSwitch : {}", if targets == 0 { "Unlimited".to_string() } else { targets.to_string() })),
            scroll("💾  Save/Resume State     ", save_options),
            label("-----------------------------------------"),
            back_button("⬅️  [Back]")
        ]);

        run(&crawl_menu);

        let mm = mut_menu(&crawl_menu);
        let selected = mm.selected_item_name();

        if selected == "⬅️  [Back]" {
            break;
        }

        if selected.starts_with("📂  Load Proxy") {
            let path = prompt("Enter path to proxy list file > ");
            if !path.is_empty() {
                crate::engine::proxy_engine::load_proxies_from_file(&path, &engine.config).await;
                println!("[+] {} proxy client(s) ready.", crate::engine::proxy_engine::get_proxies_len());
                prompt("\nPress Enter to continue...");
            }
        } else if selected.starts_with("🔄  Use Proxy") {
            let selected_val = mm.selection_value("🔄  Use Proxy             ");
            if selected_val == "ON" && proxies_len == 0 {
                println!("\n[!] Proxy list is empty. Load a proxy list first!");
                engine.config.proxy = false;
                std::thread::sleep(Duration::from_millis(1500));
            } else {
                engine.config.proxy = selected_val == "ON";
            }
        } else if selected.starts_with("⚡  Rate Limit") {
            if let Some(r) = prompt_i32("Enter rate limit (req/s, 0 for unlimited) > ") {
                crate::config::APP_SETTINGS.get().unwrap().write().unwrap().crawler_rate_limit = r as usize;
            }
        } else if selected.starts_with("🕸️  Max Crawl") {
            if let Some(d) = prompt_i32("Enter max depth > ") {
                crate::config::APP_SETTINGS.get().unwrap().write().unwrap().crawler_max_depth = d as usize;
            }
        } else if selected.starts_with("🎯  Max Target") {
            if let Some(t) = prompt_i32("Enter max targets cap (0 for unlimited) > ") {
                crate::config::APP_SETTINGS.get().unwrap().write().unwrap().crawler_max_targets = t as usize;
            }
        } else if selected.starts_with("💾  Save/Resume") {
            let selected_val = mm.selection_value("💾  Save/Resume State     ");
            let mut settings = crate::config::APP_SETTINGS.get().unwrap().write().unwrap();
            settings.crawler_save_state = selected_val == "Enabled";
            // مطمئن می‌شویم که تغییر بلافاصله ذخیره و اعمال شده است
            drop(settings); 
        }
    }
}

// منوی اصلی تنظیمات برای هدایت به بخش‌های مختلف
async fn run_settings_menu(engine: &mut RequestEngine) {
    loop {
        let settings_menu = menu(vec![
            label("🔧  SSRFdevil Core Settings"),
            label("========================================="),
            button("👤 [1] User-Agent & Custom Headers Menu"),
            button("🚀 [2] Request Engine Settings (Threads/Delays)"),
            button("🦎 [3] Advanced Crawler & Proxy Settings"),
            label("========================================="),
            back_button("⬅️  [Back]")
        ]);

        run(&settings_menu);

        let mm = mut_menu(&settings_menu);
        match mm.selected_item_name() {
            "👤 [1] User-Agent & Custom Headers Menu" => run_ua_headers_menu(),
            "🚀 [2] Request Engine Settings (Threads/Delays)" => run_request_engine_menu(engine),
            "🦎 [3] Advanced Crawler & Proxy Settings" => run_crawler_advanced_menu(engine).await,
            _ => break,
        }
    }
}

pub async fn run_interactive_console(
    db: &Db,
    target_url: &str,
    crawler: Arc<Crawler>,
    engine: &mut RequestEngine,
) {
    let mut selected_rules: Vec<RuleFile> = rule_engine::SELECTED_RULES.read().unwrap().clone();
    let mut last_results: Vec<RuleFile> = Vec::new();

    println!("\nSSRFdevil Interactive Console\nJust type 'run' and enjoy or 'help' for commands.\n");
    loop {
        let input = prompt(&shell_prompt(&selected_rules, ""));
        if input.is_empty() { continue; }
        let (cmd, arg) = parse_command(&input);

        match cmd {
            "help" | "?" => print_help(),
            "settings" => {
                run_settings_menu(engine).await; 
            }
            "search" => {
                last_results = rule_engine::search_rules(db, arg);
                rule_engine::display_result_rules(&last_results);
                println!("[i] {} matching rule(s).", last_results.len());
            }
            "list" | "ls" => {
                last_results = rule_engine::search_rules(db, "");
                rule_engine::display_result_rules(&last_results);
                println!("[i] {} total rule(s).", last_results.len());
            }
            "use" => {
                if arg.is_empty() {
                    println!("Usage: use <index|rule_id|tag|all>");
                    continue;
                }
                if arg == "all" {
                    selected_rules = rule_engine::search_rules(db, "");
                    println!("[+] Loaded ALL {} rules.", selected_rules.len());
                } else if let Some(rules) = select_rule(db, arg, &last_results) {
                    selected_rules = rules;
                    println!("[+] Selected {} rule(s).", selected_rules.len());
                    rule_engine::display_result_rules(&selected_rules);
                } else {
                    println!("[!] Numeric selection requires an active search result or an ID.\nRun 'list' or 'search' first.");
                }
                *rule_engine::SELECTED_RULES.write().unwrap() = selected_rules.clone();
            }
            "crawl" => {
                println!("[*] Crawling {}...", target_url);
                crawler.run().await;
                let targets = crawler.targets().await;
                if targets.is_empty() {
                    println!("[!] No SSRF-prone targets found.");
                } else {
                    println!("[+] Found {} target(s).", targets.len());
                }
            }
            "run" | "scan" => {
                if selected_rules.is_empty() {
                    println!("[!] No rule(s) selected. Use 'use <id|idx|tag|all>' first.");
                    continue;
                }
            
                let crawled_targets = crawler.targets().await;
                if crawled_targets.is_empty() {
                    println!("[*] Meh, seems like you forgot I can crawl too...\n[*] Give me a sec.");
                    crawler.run().await;
                    
                    if crawler.targets().await.is_empty() {
                        println!("[!] Still nothing. Too clean or too stubborn.");
                        continue;
                    }
                }
            
                let targets = crawler.targets().await;
                println!("[+] Got {} target(s). Matching selected rules with targets...", targets.len());
                
                // 🔥 کلون کردن برای انتقال مالکیت به closure
                let rules_for_task = selected_rules.clone();
            
                let payloads = match tokio::task::spawn_blocking(move || {
                    executor::process_all_batches_single_pass(&targets, &rules_for_task)
                }).await {
                    Ok(Ok(p)) => p,
                    Ok(Err(e)) => {
                        println!("[!] Executor error: {}", e);
                        Vec::new()
                    }
                    Err(e) => {
                        println!("[!] Task panic: {}", e);
                        Vec::new()
                    }
                };
                
                println!("[+] Batch processing done in ONE pass. Generated {} payloads.", payloads.len());
            }
            "info" | "show" => {
                if arg.is_empty() {
                    if selected_rules.is_empty() { println!("[!] No rule active."); }
                    for r in &selected_rules { rule_engine::show_rule_details(r); }
                } else if let Some(rules) = select_rule(db, arg, &last_results) {
                    for r in &rules { rule_engine::show_rule_details(r); }
                }
            }
            "back" | "b" => {
                selected_rules.clear();
                rule_engine::SELECTED_RULES.write().unwrap().clear();
                println!("[+] Batch queue cleared.");
            }
            "exit" | "quit" => {
                println!("Goodbye.");
                break;
            }
            _ => println!("[!] Unknown command."),
        }
    }
}

fn select_rule(db: &Db, input: &str, last_results: &[RuleFile]) -> Option<Vec<RuleFile>> {
    if let Ok(idx) = input.parse::<usize>() {
        if last_results.is_empty() { return None; }
        return last_results.get(idx).cloned().map(|r| vec![r]);
    }

    if let Some(rule) = rule_engine::get_rule_by_id(db, input) {
        return Some(vec![rule]);
    }

    let results = rule_engine::search_rules(db, input);
    if results.is_empty() { None } else { Some(results) }
}

fn print_help() {
    println!(
        "\nCommands:
        search <text>        Search database rules
        use <idx|id|all>     Select a single rule, or 'all|tag' for Batch Scanning
        list /ls             Show all loaded rules
        run /scan            Execute selected rule(s) over crawled targets
        crawl                Trigger deep target auditing
        info /show <idx|id>  Inspect specific rule parameters
        back /b              Clear active rule/batch queue
        settings             Toggle UA profiles & Batch Modes (Auto/Step)
        exit /quit           Terminate active terminal\n"
    );
}

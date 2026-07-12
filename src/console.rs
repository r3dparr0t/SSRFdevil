use std::{
    io::{self, Write},
    time::Duration
};

use sled::Db;
use crate::{
    rule::RuleFile,
    executor,
    engine::{
        ua_engine,
        rule_engine,
        RequestEngine,
        RedirectPolicy
    },
    crawler::crawler::Crawler,
    config::{Settings, UaProfile} // دریافت مستقیم از ماژول کانفیگ مرکزی
};
use std::sync::Arc;

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

fn select_ua_profile(settings: &mut Settings) {
    let current = &settings.ua_profile;
    println!("\nUser-Agent Profile:");
    println!("        {}[1] conservative    weight >= 70", if *current == UaProfile::Conservative { "* " } else { "  " });
    println!("        {}[2] balanced        weight >= 30", if *current == UaProfile::Balanced { "* " } else { "  " });
    println!("        {}[3] full            all agents", if *current == UaProfile::Full { "* " } else { "  " });

    let input = prompt("\nSelect [1-3] > ");
    match input.trim() {
        "1" => { settings.ua_profile = UaProfile::Conservative; println!("[+] Profile set to Conservative."); }
        "2" => { settings.ua_profile = UaProfile::Balanced; println!("[+] Profile set to Balanced."); }
        "3" => { settings.ua_profile = UaProfile::Full; println!("[+] Profile set to Full."); }
        _ => println!("[!] Invalid option."),
    }
}

fn run_ua_headers_menu() {
    loop {
        let (ua_label, headers_count) = {
            let settings = crate::config::APP_SETTINGS.get().unwrap().read().unwrap();
            (settings.ua_profile.label().to_string(), settings.custom_headers.len())
        };

        println!("\n📝 [Menu 1] User-Agent & Custom Headers");
        println!("-----------------------------------------");
        println!("    [1] UA Profile      : {}", ua_label);
        println!("    [2] Custom Headers  : {} loaded", headers_count);
        println!("-----------------------------------------");
        println!("Select option or 'back' > ");

        let selected_rules = rule_engine::SELECTED_RULES.read().unwrap();
        let input = prompt(&shell_prompt(&selected_rules, "[settings->identity]"));

        match input.trim() {
            "1" => {
                {
                    let mut settings = crate::config::APP_SETTINGS.get().unwrap().write().unwrap();
                    select_ua_profile(&mut settings);
                }
                ua_engine::init();
            }
            "2" => {
                println!("Enter header (Format 'Key: Value') or empty line to finish:");
                let mut new_headers = std::collections::HashMap::new();
                loop {
                    let h = prompt("Header > ");
                    if h.is_empty() { break; }
                    if let Some((k, v)) = h.split_once(':') {
                        new_headers.insert(k.trim().to_string(), v.trim().to_string());
                    }
                }
                let mut settings = crate::config::APP_SETTINGS.get().unwrap().write().unwrap();
                settings.custom_headers = new_headers;
                println!("[+] Custom headers updated.");
            }
            "b" | "back" => break,
            _ => println!("[!] Invalid choice."),
        }
    }
}

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

        println!("\n⚡ [Menu 2] Request & Concurrency Settings");
        println!("-----------------------------------------");
        println!("    [1] Workers (Threads)     : {}", threads);
        println!("    [2] Max Runtime Limit     : {}s", if runtime == 0 { "Unlimited".to_string() } else { runtime.to_string() });
        println!("    [3] Request Timeout       : {}s", engine.config.timeout.as_secs());
        println!("    [4] Jitter Delay Range    : {}ms - {}ms", delay_min, delay_max);
        let num = if let RedirectPolicy::Limited(v) = engine.config.redirects { v as u64 } else { 0 };
        println!("    [5] Request redirects     : {} times", num);
        println!("-----------------------------------------");
        println!("Select option or 'back' > ");

        let selected_rules = rule_engine::SELECTED_RULES.read().unwrap();
        let input = prompt(&shell_prompt(&selected_rules, "[settings->engine]"));

        match input.trim() {
            "1" => {
                if let Some(t) = prompt_i32("Enter worker count > ") {
                    crate::config::APP_SETTINGS.get().unwrap().write().unwrap().threads = t;
                }
            }
            "2" => {
                if let Some(r) = prompt_i32("Enter max runtime in seconds (0 for infinite) > ") {
                    crate::config::APP_SETTINGS.get().unwrap().write().unwrap().max_runtime = r as u64;
                }
            }
            "3" => {
                if let Some(t) = prompt_i32("Enter timeout (seconds) > ") {
                    engine.config.timeout = Duration::from_secs(t.try_into().unwrap());
                }
            }
            "4" => {
                if let Some(min) = prompt_i32("Min Delay (ms) > ") {
                    if let Some(max) = prompt_i32("Max Delay (ms) > ") {
                        let mut settings = crate::config::APP_SETTINGS.get().unwrap().write().unwrap();
                        settings.delay_min = min as u64;
                        settings.delay_max = max as u64;
                    }
                }
            }
            "5" => {
                if let Some(r) = prompt_i32("Enter retry count > ") {
                    engine.config.redirects = RedirectPolicy::Limited(r as usize);
                }
            }
            "b" | "back" => break,
            _ => println!("[!] Invalid choice."),
        }
    }
}

fn run_crawler_advanced_menu() {
    loop {
        let (proxies_len, rotation, rate, depth, targets, save) = {
            let settings = crate::config::APP_SETTINGS.get().unwrap().read().unwrap();
            (
                settings.crawler_proxies.len(),
                settings.crawler_proxy_rotation,
                settings.crawler_rate_limit,
                settings.crawler_max_depth,
                settings.crawler_max_targets,
                settings.crawler_save_state,
            )
        };

        println!("\n🔍 [Menu 3] Crawler Core & Proxy Configuration");
        println!("-----------------------------------------");
        println!("    [1] Proxy List            : {} loaded", proxies_len);
        println!("    [2] Proxy Rotation        : {}", if rotation { "ON 🔄" } else { "OFF 🛑" });
        println!("    [3] Rate Limit (Global)   : {} req/sec", if rate == 0 { "Unlimited".to_string() } else { rate.to_string() });
        println!("    [4] Max Crawl Depth       : {}", depth);
        println!("    [5] Max Target KillSwitch : {}", if targets == 0 { "Unlimited".to_string() } else { targets.to_string() });
        println!("    [6] Save/Resume State     : {}", if save { "Enabled ✅" } else { "Disabled ❌" });
        println!("-----------------------------------------");
        println!("Select option or 'back' > ");

        let selected_rules = rule_engine::SELECTED_RULES.read().unwrap();
        let input = prompt(&shell_prompt(&selected_rules, "[settings->crawler]"));

        match input.trim() {
            "1" => {
                let path = prompt("Enter path to proxy list file > ");
                if !path.is_empty() {
                    if let Ok(content) = std::fs::read_to_string(&path) {
                        let list: Vec<String> = content.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
                        crate::config::APP_SETTINGS.get().unwrap().write().unwrap().crawler_proxies = list;
                    }
                }
            }
            "2" => {
                let mut settings = crate::config::APP_SETTINGS.get().unwrap().write().unwrap();
                settings.crawler_proxy_rotation = !settings.crawler_proxy_rotation;
            }
            "3" => {
                if let Some(r) = prompt_i32("Enter rate limit (req/s, 0 for unlimited) > ") {
                    crate::config::APP_SETTINGS.get().unwrap().write().unwrap().crawler_rate_limit = r as usize;
                }
            }
            "4" => {
                if let Some(d) = prompt_i32("Enter max depth > ") {
                    crate::config::APP_SETTINGS.get().unwrap().write().unwrap().crawler_max_depth = d as usize;
                }
            }
            "5" => {
                if let Some(t) = prompt_i32("Enter max targets cap (0 for unlimited) > ") {
                    crate::config::APP_SETTINGS.get().unwrap().write().unwrap().crawler_max_targets = t as usize;
                }
            }
            "6" => {
                let mut settings = crate::config::APP_SETTINGS.get().unwrap().write().unwrap();
                settings.crawler_save_state = !settings.crawler_save_state;
            }
            "b" | "back" => break,
            _ => println!("[!] Invalid choice."),
        }
    }
}

fn run_settings_menu(engine: &mut RequestEngine,) {
    loop {
        println!("\n⚙️  SSRFdevil Core Settings");
        println!("=========================================");
        println!("    [1] User-Agent & Custom Headers Menu --->");
        println!("    [2] Request Engine Settings (Threads/Delays) --->");
        println!("    [3] Advanced Crawler & Proxy Settings --->");
        println!("=========================================");
        println!("Type menu number to enter, or 'back' to return.");

        let selected_rules = rule_engine::SELECTED_RULES.read().unwrap();
        let input = prompt(&shell_prompt(&selected_rules, "[settings]"));

        match input.trim() {
            "1" => run_ua_headers_menu(),
            "2" => run_request_engine_menu(engine),
            "3" => run_crawler_advanced_menu(),
            "b" | "back" | "quit" | "exit" => break,
            _ => println!("[!] Unknown option."),
        }
    }
}

pub async fn run_interactive_console(
    db: &Db,
    target_url: &str,
    crawler: Arc<Crawler>,      // <-- Arc مستقیم
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
                run_settings_menu(engine); 
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
                    /*for r in &selected_rules {
                        println!("    → {} ({})", r.meta.name, r.meta.id);
                    }*/
                    rule_engine::display_result_rules(&selected_rules);
                } else {
                println!("[!] Numeric selection requires an active search result. or maybe you used Invalid key.\nSo use 'search <text>' or simply just 'list' first.");
                }
                *rule_engine::SELECTED_RULES.write().unwrap() = selected_rules.clone();
            }
            "crawl" => {
                println!("[*] Crawling {}...", target_url);
                crawler.run().await;                          // <-- مستقیماً روی Arc صدا می‌شه
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

                if crawler.targets().await.is_empty() {
                    println!("[*] Meh, seems like you forgot I can crawl too...\n[*] Give me a sec.");
                    crawler.run().await;
                    
                    if crawler.targets().await.is_empty() {
                        println!("[!] Still nothing. Too clean or too stubborn.");
                        continue;
                    }
                }
                //println!("[+] Got {} target(s). Now we're talking.", crawler.targets().len());
                println!("[+] Got {} target(s). Now we're talking.", crawler.targets().await.len());
                                                                                           
                let mut aborted = false;
                for (idx, rule) in selected_rules.iter().enumerate() {
                    println!("\n🚀 [{}/{}] Running: {} ({})", idx + 1, selected_rules.len(), rule.meta.name, rule.meta.id);
                    
                    let script_source = rule.script.source.clone();
                    let entry_point = rule.script.entry.clone();
                    let t_url = target_url.to_string();

                    // تغییر اصلی: تبدیل نوع خطا به استرینگ درون کلوژر برای پاس دادن امن بین تردها
                    let res = tokio::task::spawn_blocking(move || {
                        executor::execute_lua_bypass(&script_source, &entry_point, &t_url)
                            .map_err(|e| e.to_string())
                    }).await;

                    match res {
                        Ok(Ok(payload)) => {
                            println!("    [+] Generated URL: {}", payload.url);
                            match executor::run_payload(engine, payload).await {
                                Ok(resp) => println!("    [+] Response: {} ({} bytes)", resp.status, resp.body.len()),
                                Err(e) => println!("    ❌ Request Error: {}", e),
                            }
                        }
                        Ok(Err(lua_err)) => println!("    ❌ Lua Error: {}", lua_err),
                        Err(join_err) => println!("    ❌ Task Execution Panic: {}", join_err),
                    }

                    // چک کردن هندلینگ گام‌به‌گام (Interactive Step)
                        if selected_rules.len() > 1 && idx < selected_rules.len() - 1 {
                        let next = prompt("\nssrfdevil [batch-pause] > Press Enter for next rule, or type 'q' to abort: " );
                            if next == "q" {
                                aborted = true;
                                break;
                            }
                        }
                }
                if !aborted { println!("\n[+] Batch scan execution completed."); }
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

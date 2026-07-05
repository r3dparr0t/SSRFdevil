use std::io::{self, Write};
use sled::Db;
use crate::{
    rule::RuleFile,
    executor,
    engine::{ua_engine, rule_engine},
    crawler::crawler::Crawler
};
use url::Url;

#[derive(Debug, Clone, PartialEq)]
pub enum UaProfile {
    Conservative, 
    Balanced,     
    Full,         
}

impl UaProfile {
    pub fn min_weight(&self) -> u32 {
        match self {
            UaProfile::Conservative => 70,
            UaProfile::Balanced => 30,
            UaProfile::Full => 0,
        }
    }

    pub fn label(&self) -> &str {
        match self {
            UaProfile::Conservative => "conservative (weight >= 70)",
            UaProfile::Balanced => "balanced     (weight >= 30)",
            UaProfile::Full => "full         (all agents)",
        }
    }
}

pub struct Settings {
    pub ua_profile: UaProfile,
    pub timeout: i32,
    pub threads: i32,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            ua_profile: UaProfile::Balanced,
            timeout: 5,
            threads: 10,
        }
    }
}

fn run_settings_menu(settings: &mut Settings) {
	let stdin = io::stdin();
    loop {
        println!("\nCurrent Settings:");
        println!("        [1] User-Agent Profile    {}", settings.ua_profile.label());
        println!("        [2] Timeout               {}s", settings.timeout);
        println!("        [3] Threads               {}", settings.threads);
        println!("\nType setting number to change, or 'back' to return.");

        // نمایش پرامپت پویا متناسب با رول‌های فعال در بخش تنظیمات
        let selected_rules = rule_engine::SELECTED_RULES.read().unwrap();
        match selected_rules.len() {
            0 => print!("ssrfdevil [settings] > "),
            1 => print!("ssrfdevil ({}) [settings] > ", selected_rules[0].meta.id),
            n => print!("ssrfdevil (batch: {} rules) [settings] > ", n),
        }
        io::stdout().flush().unwrap();
        let mut input = String::new();
        if stdin.read_line(&mut input).is_err() { break; }

        match input.trim() {
            "1" => select_ua_profile(settings),
            "2" => {
                print!("Enter new timeout (seconds) > ");
                io::stdout().flush().unwrap();
                let mut t_input = String::new();
                if io::stdin().read_line(&mut t_input).is_ok() {
                    if let Ok(t) = t_input.trim().parse::<i32>() {
                        settings.timeout = t;
                        println!("[+] Timeout updated to {}s.", t);
                    } else {
                        println!("[!] Invalid number.");
                    }
                }
            }
            "3" => {
                print!("Enter new thread count > ");
                io::stdout().flush().unwrap();
                let mut th_input = String::new();
                if io::stdin().read_line(&mut th_input).is_ok() {
                    if let Ok(th) = th_input.trim().parse::<i32>() {
                        settings.threads = th;
                        println!("[+] Threads updated to {}.", th);
                    } else {
                        println!("[!] Invalid number.");
                    }
                }
            }
            "back" | "quit" | "exit" => break,
            _ => println!("[!] Unknown option."),
        }
    }
}

fn select_ua_profile(settings: &mut Settings) {
    let current = &settings.ua_profile;
    println!("\nUser-Agent Profile:");
    println!("        {}[1] conservative    weight >= 70", if *current == UaProfile::Conservative { "* " } else { "  " });
    println!("        {}[2] balanced        weight >= 30", if *current == UaProfile::Balanced { "* " } else { "  " });
    println!("        {}[3] full            all agents", if *current == UaProfile::Full { "* " } else { "  " });

    print!("\nSelect [1-3] > ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    match input.trim() {
        "1" => { settings.ua_profile = UaProfile::Conservative; println!("[+] Profile set to Conservative."); }
        "2" => { settings.ua_profile = UaProfile::Balanced; println!("[+] Profile set to Balanced."); }
        "3" => { settings.ua_profile = UaProfile::Full; println!("[+] Profile set to Full."); }
        _ => println!("[!] Invalid option."),
    }
}

pub async fn run_interactive_console(
    db: &Db,
    target_url: &str,
    settings: &mut Settings,
    crawler: &mut Crawler,
) {
    let stdin = io::stdin();
    let mut selected_rules: Vec<RuleFile> = rule_engine::SELECTED_RULES.read().unwrap().clone();
    let mut last_results: Vec<RuleFile> = Vec::new();

    println!("\nSSRFdevil Interactive Console\nJust type 'run' and enjoy or 'help' for commands.\n");

    loop {
        // پرامپت پویا بر اساس تعداد رول‌های فعال
        match selected_rules.len() {
            0 => print!("ssrfdevil > "),
            1 => print!("ssrfdevil ({}) > ", selected_rules[0].meta.id),
            n => print!("ssrfdevil (batch: {} rules) > ", n),
        }
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if stdin.read_line(&mut input).is_err() { break; }
        let input = input.trim();
        if input.is_empty() { continue; }

        let parts: Vec<&str> = input.splitn(2, ' ').collect();
        let cmd = parts[0];
        let arg = parts.get(1).copied().unwrap_or("");

        match cmd {
            "help" | "?" => print_help(),
            "settings" => {
                run_settings_menu(settings); 
                ua_engine::init();
            }
            "search" => {
                last_results = rule_engine::search_rules(db, arg);
                rule_engine::display_result_rules(&last_results);
                println!("[i] {} matching rule(s).", last_results.len());
            }
            "list" => {
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
                println!("[!] Rule not found. Search something FIRST!");
                }
                *rule_engine::SELECTED_RULES.write().unwrap() = selected_rules.clone();
            }
            "crawl" => {
                println!("[*] Crawling {}...", target_url);
                if let Ok(base) = Url::parse(target_url) {
                    crawler.crawl(&base).await;
                    if crawler.targets().is_empty() {
                        println!("[!] No SSRF-prone targets found.");
                    } else {
                        println!("[+] Found {} target(s).", crawler.targets().len());
                    }
                }
            }
            "run" | "scan" => {
                if selected_rules.is_empty() {
                    println!("[!] No rule(s) selected. Use 'use <id|all>' first.");
                    continue;
                }

                if crawler.targets().is_empty() {
                    println!("[*] Meh, seems like you forgot I can crawl too...\n[*] Give me a sec.");
                    if let Ok(base) = Url::parse(target_url) {
                        crawler.crawl(&base).await;
                    }
                    if crawler.targets().is_empty() {
                        println!("[!] Still nothing. Too clean or too stubborn.");
                        continue;
                    }
                    println!("[+] Got {} target(s). Now we're talking.", crawler.targets().len());
                }

                    
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
                            println!("    [*] Dispatching payload to target pipeline...");
                        }
                        Ok(Err(lua_err)) => println!("    ❌ Lua Error: {}", lua_err),
                        Err(join_err) => println!("    ❌ Task Execution Panic: {}", join_err),
                    }

                    // چک کردن هندلینگ گام‌به‌گام (Interactive Step)
                    if !rule_engine::SELECTED_RULES.read().unwrap().len() > 1 && idx < selected_rules.len() - 1 {
                        print!("\nssrfdevil [batch-pause] > Press Enter for next rule, or type 'q' to abort: ");
                        io::stdout().flush().unwrap();
                        let mut proceed = String::new();
                        if io::stdin().read_line(&mut proceed).is_ok() {
                            if proceed.trim() == "q" {
                                aborted = true;
                                println!("[!] Batch scanning aborted by user.");
                                break;
                            }
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
            "back" => {
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
        url                  Change target base URL
        search <text>        Search database rules
        use <idx|id|all>     Select a single rule, or 'all' for Batch Scanning
        list                 Show all loaded rules
        run /scan            Execute selected rule(s) over crawled targets
        crawl                Trigger deep target auditing
        info /show <idx|id>  Inspect specific rule parameters
        back                 Clear active rule/batch queue
        settings             Toggle UA profiles & Batch Modes (Auto/Step)
        exit /quit           Terminate active terminal\n"
    );
}

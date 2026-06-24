use std::io::{self, Write};
use sled::Db;
use crate::{
    rule::RuleFile,
    rule_mgr,
    executor
};

// ---------------------------------------------------
// بخش تنظیمات (Settings)
// ---------------------------------------------------

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

// اصلاح پرامپت منوی تنظیمات برای هماهنگی با Rule انتخاب شده
fn run_settings_menu(settings: &mut Settings, current_rule: &Option<RuleFile>) {
    let stdin = io::stdin();

    loop {
        println!("\nCurrent Settings:");
        println!("        [1] User-Agent Profile    {}", settings.ua_profile.label());
        println!("        [2] Timeout               {}s", settings.timeout);
        println!("        [3] Threads               {}", settings.threads);
        println!("\nType setting number to change, or 'back' to return.");

        // ساخت پرامپت شیک و داینامیک مد نظر تو
        match current_rule {
            Some(rule) => print!("ssrfdevil ({}) [settings] > ", rule.meta.id),
            None => print!("ssrfdevil [settings] > "),
        }
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if stdin.read_line(&mut input).is_err() {
            break;
        }

        match input.trim() {
            "1" => select_ua_profile(settings),
            "back" | "quit" | "exit" => break,
            _ => println!("[!] Unknown option."),
        }
    }
}

fn select_ua_profile(settings: &mut Settings) {
    let current = &settings.ua_profile;

    println!("\nUser-Agent Profile:");
    println!("        {}[1] conservative    weight >= 70  (desktop + modern Android only)", if *current == UaProfile::Conservative { "* " } else { "  " });
    println!("        {}[2] balanced        weight >= 30  (recommended)", if *current == UaProfile::Balanced { "* " } else { "  " });
    println!("        {}[3] full            all agents", if *current == UaProfile::Full { "* " } else { "  " });

    print!("\nSelect [1-3] > ");
    io::stdout().flush().unwrap();

    let stdin = io::stdin();
    let mut input = String::new();
    if stdin.read_line(&mut input).is_err() {
        return;
    }

    match input.trim() {
        "1" => { settings.ua_profile = UaProfile::Conservative; println!("[+] Profile set to Conservative."); }
        "2" => { settings.ua_profile = UaProfile::Balanced; println!("[+] Profile set to Balanced."); }
        "3" => { settings.ua_profile = UaProfile::Full; println!("[+] Profile set to Full."); }
        _ => println!("[!] Invalid option."),
    }
}


pub fn run_interactive_console(
    db: &Db, 
    initial_rule: Option<RuleFile>, 
    target_url: &str,
    settings: &mut Settings
) {
    let stdin = io::stdin();
    let mut current_rule = initial_rule;
    let mut last_results: Vec<RuleFile> = Vec::new();

    println!("\nSSRFdevil Interactive Console\nJust type 'run' and enjoy or 'help' for commands.\n");

    loop {
        match &current_rule {
            Some(rule) => print!("ssrfdevil ({}) > ", rule.meta.id),
            None => print!("ssrfdevil > "),
        }
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if stdin.read_line(&mut input).is_err() {
            break;
        }

        let input = input.trim();
        if input.is_empty() { continue; }

        let parts: Vec<&str> = input.splitn(2, ' ').collect();
        let cmd = parts[0];
        let arg = parts.get(1).copied().unwrap_or("");

        match cmd {
            "help" | "?" => print_help(),
            "settings" => {
                run_settings_menu(settings, &current_rule); 
                executor::init_ua_list(settings.ua_profile.min_weight());
                println!("[*] User-Agent profile reloaded based on new settings.");
            }
            "search" => {
                last_results = rule_mgr::search_rules(db, arg);
                rule_mgr::display_result_rules(&last_results);
                println!("[i] {} matching rule(s).", last_results.len());
            }
            "list" => {
                last_results = rule_mgr::search_rules(db, "");
                rule_mgr::display_result_rules(&last_results);
                println!("[i] {} total rule(s).", last_results.len());
            }
            "use" => {
                if arg.is_empty() {
                    println!("Usage: use <index|rule_id>");
                    continue;
                }
                if let Some(rule) = select_rule(db, arg, &last_results) {
                    println!("[+] Selected: {}", rule.meta.name);
                    current_rule = Some(rule);
                } else {
                    println!("[!] Rule not found.");
                }
            }
            "run" | "scan" => {
                match &current_rule {
                    Some(rule) => {
                        println!("[*] Executing Lua bypass script: {} ...", rule.meta.name);
                        match executor::execute_lua_bypass(
                            &rule.script.source,
                            &rule.script.entry,
                            &target_url
                        ) {
                            Ok(mut payload) => {
                                println!("[+] Lua Output -> Generated URL: {}", payload.url);
                                if payload.method != "GET" {
                                    println!("[+] Lua Output -> Method: {}", payload.method);
                                }

                            println!("[*] Ready to dispatch request to scanner module...");
                            }
                            Err(e) => println!("❌ Lua Execution Error: {}", e),
                        }
                    }
                    None => println!("[!] No rule selected. Use 'use <id>' first."),
                }
            }
            "info" => {
                if arg.is_empty() {
                    show_current_rule(&current_rule);
                } else if let Some(rule) = select_rule(db, arg, &last_results) {
                    rule_mgr::show_rule_details(&rule);
                } else {
                    println!("[!] Rule not found.");
                }
            }
            "back" => {
                current_rule = None;
                println!("[+] Rule deselected.");
            }
            "exit" | "quit" => {
                println!("Goodbye.");
                break;
            }
            _ => println!("[!] Unknown command."),
        }
    }
}

fn select_rule(db: &Db, input: &str, last_results: &[RuleFile]) -> Option<RuleFile> {
    if let Ok(idx) = input.parse::<usize>() {
        if last_results.is_empty() {
            println!("[i] Run 'search' or 'list' first to use index selection.");
            return None;
        }
        return last_results.get(idx).cloned();
    }
    rule_mgr::get_rule_by_id(db, input)
}

fn show_current_rule(current_rule: &Option<RuleFile>) {
    match current_rule {
        Some(rule) => rule_mgr::show_rule_details(rule),
        None => println!("[!] No rule selected."),
    }
}

fn print_help() {
    println!(
        "\nCommands:
        search <text>        Search rules by text
        use <index|id>       Select a rule by id or index
        list                 Show all rules
        run / scan           Start attack
        info <index|id>      Show details of current rule or given id
        back                 Deselect current rule
        settings             Adjust global settings (UA profile, etc)
        help / ?             Show this help
        exit / quit          Quit the console\n"
    );
}

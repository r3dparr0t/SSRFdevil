use std::io::{self, Write};
use sled::Db;

use ssrfdevil::{
	rule::RuleFile,
	rule_mgr,
	executor};

pub fn run_interactive_console(db: &Db, initial_rule: Option<RuleFile>, target_url: &str) {
    let stdin = io::stdin();

    let mut current_rule = initial_rule;
    let mut last_results: Vec<RuleFile> = Vec::new();

    println!("\nSSRFdevil Interactive Console\nJust type 'run' and enjoy or 'help' for commands.\n");

    loop {
        match &current_rule {
            Some(rule) => {
                print!("ssrfdevil ({}) > ", rule.meta.id);
            }
            None => {
                print!("ssrfdevil > ");
            }
        }

        io::stdout().flush().unwrap();

        let mut input = String::new();

        if stdin.read_line(&mut input).is_err() {
            break;
        }

        let input = input.trim();

        if input.is_empty() {
            continue;
        }

        let parts: Vec<&str> = input.splitn(2, ' ').collect();

        let cmd = parts[0];
        let arg = parts.get(1).copied().unwrap_or("");

        match cmd {
            "help" | "?" => {
                print_help();
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

                let selected = select_rule(db, arg, &last_results);

                match selected {
                    Some(rule) => {
                        println!("[+] Selected: {}", rule.meta.name);

                        current_rule = Some(rule);
                    }

                    None => {
                        println!("[!] Rule not found.");
                    }
                }
            }
            "run" | "scan" => {
            	match &current_rule {
            		Some(rule) => {
            			println!("[*] Executing Lua bypass script: {} ...", rule.meta.name);
                                
                        // صدا زدن مفسر لوآ با فیلدهای جدید یمل تو
                        match executor::execute_lua_bypass(
                        	&rule.script.source,
                            &rule.script.entry,
                            &target_url) {
                            	Ok(generated_url) => {
                                	println!("[+] Lua Output -> Generated URL: {}", generated_url);
                                	println!("[*] Ready to dispatch request to scanner module...");
                                    // اینجا بعداً خروجی را می‌فرستیم برای scanner::run(generated_url)
                                }
                                Err(e) => {
                                    println!("❌ Lua Execution Error: {}", e);
                                }
                            }
                         }
                         None => {
                            println!("[!] No rule selected. Use 'use <id>' first or type 'run' with default.");
                         }
                    }
            }
            "info" => {
                if arg.is_empty() {
                    show_current_rule(&current_rule);
                    continue;
                }

                let selected = select_rule(db, arg, &last_results);

                match selected {
                    Some(rule) => {
                        rule_mgr::show_rule_details(&rule);
                    }

                    None => {
                        println!("[!] Rule not found.");
                    }
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

            _ => {
                println!("[!] Unknown command.");
            }
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
        Some(rule) => {
            rule_mgr::show_rule_details(rule);
        }

        None => {
            println!("[!] No rule selected.");
        }
    }
}

fn print_help() {
    println!(
        "\nCommands:
        search <text>        Search rules by text
        use <index|id>       Select a rule by id or index
        list                 Show all rules
        run / scanner        Start attack.
        info <index|id>      Show details of current rule or given id
        back                 Deselect current rule
        help / ?             Show this help
        exit / quit          Quit the console\n"
    );
}

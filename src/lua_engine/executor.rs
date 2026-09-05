use mlua::{Lua, Table, HookTriggers}; 
use std::{
    collections::HashMap,
    error::Error,
    fs::OpenOptions,
    io::Write,
    time::{Duration, Instant},
};
use crate::{
    engine::rule::{RuleFile, Severity},
    crawler::crawler_config::Target,
    lua_engine::matcher
};

#[derive(Debug, Clone)]
pub struct LuaPayload {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub action: String,
    pub rule_id: String,
    pub severity: Severity,
    pub confidence: u8,
    pub correlation_id: Option<String>,
}

// حداکثر زمانی که یک رول اجازه دارد داخل لوا اجرا شود. اگر رد شود، اجرا با خطا قطع می‌شود
// نه کل برنامه؛ فقط همین رول skip می‌شود. جلوی حلقه‌ی بی‌پایان یک اسکریپت خراب/مخرب را می‌گیرد.
const LUA_RULE_TIMEOUT: Duration = Duration::from_secs(5);

/// نکته: این تابع دیگر Result برنمی‌گرداند. شکست یک رول = رد شدن از همان رول، نه سقوط کل pass.
/// هر خطا (سینتکس لوا، entry function غایب، فیلد ناقص در نتیجه) داخل هر رول لاگ و skip می‌شود.
pub fn process_all_batches_single_pass(
    targets: &[Target],
    rules: &[RuleFile],
) -> Vec<LuaPayload> {
    let batches = matcher::create_batches(targets, rules);

    if batches.is_empty() {
        println!("[!] No target matched the criteria for selected rules.");
        return Vec::new();
    }
    println!("[+] Created {} matched batch task(s). Executing...", batches.len());

    execute_lua_master_batch(&batches)
}

fn execute_lua_master_batch(batches: &[matcher::BatchTask]) -> Vec<LuaPayload> {
    let mut all_payloads = Vec::new();
    let mut failed_rules = 0usize;

    for task in batches {
        println!("\n🚀 Executing Rule: {} ({}) over {} matched target(s)",
                 task.rule.meta.name, task.rule.meta.id, task.targets.len());

        match run_single_rule(task) {
            Ok(payloads) => {
                for payload in &payloads {
                    log_payload_to_file(payload);
                }
                println!("    [+] Rule '{}' produced {} payload(s).", task.rule.meta.id, payloads.len());
                all_payloads.extend(payloads);
            }
            Err(e) => {
                failed_rules += 1;
                eprintln!("    ❌ Rule '{}' failed and was skipped: {}", task.rule.meta.id, e);
                continue;
            }
        }
    }

    println!(
        "\n    [+] Generated total {} payload(s) from Lua. ({} rule(s) skipped due to errors)",
        all_payloads.len(), failed_rules
    );
    all_payloads
}

/// یک رول را در یک VM لوای *تازه و ایزوله* اجرا می‌کند.
/// دلیل ساخت Lua::new() برای هر رول (به‌جای یک VM مشترک برای کل pass):
/// globals/functionهای یک اسکریپت نباید در اسکریپت رول بعدی نشت کنند.
fn run_single_rule(task: &matcher::BatchTask) -> Result<Vec<LuaPayload>, Box<dyn Error + Send + Sync>> {
    let lua = Lua::new();

    // --- Timeout Hook ---
    let start = Instant::now();
    let triggers = HookTriggers::default().every_nth_instruction(1000);  // تغییر این خط
    
    lua.set_hook(triggers, move |_, _| {
        if start.elapsed() > LUA_RULE_TIMEOUT {
            Err(mlua::Error::RuntimeError(format!(
                "rule execution exceeded {}s timeout",
                LUA_RULE_TIMEOUT.as_secs()
            )))
        } else {
            Ok(())
        }
    });

    // ==========================================
    // تزریق OOB به Lua
    // ==========================================
    let rule_id_for_lua = task.rule.meta.id.clone();

    // متغیر oob_base
    if let Some(base) = crate::engine::oob_engine::get_base_url() {
        lua.globals().set("oob_base", base)?;
    } else {
        lua.globals().set("oob_base", mlua::Value::Nil)?;
    }

    // تابع oob_token()
    let oob_token_fn = lua.create_function(move |_, ()| {
        match crate::engine::oob_engine::generate_token(&rule_id_for_lua) {
            Some(token) => Ok(token),
            None => Ok(String::new()),
        }
    })?;
    lua.globals().set("oob_token", oob_token_fn)?;

    // ==========================================
    // ساخت جدول targets
    // ==========================================
    let targets_table = lua.create_table()?;
    for (i, target) in task.targets.iter().enumerate() {
        let t_table = lua.create_table()?;
        t_table.set("url", target.url.as_str())?;
        t_table.set("method", target.method.as_str())?;

        let params_table = lua.create_table()?;
        for (j, param) in target.params.iter().enumerate() {
            let p_table = lua.create_table()?;
            p_table.set("name", param.name.as_str())?;
            p_table.set("value", param.value.as_deref().unwrap_or(""))?;
            p_table.set("location", format!("{:?}", param.location))?;
            params_table.set(j + 1, p_table)?;
        }
        t_table.set("params", params_table)?;
        targets_table.set(i + 1, t_table)?;
    }

    // لود اسکریپت
    lua.load(&task.rule.script.source).exec()?;

    let entry_fn = if task.rule.script.entry.is_empty() {
        "run_batch"
    } else {
        &task.rule.script.entry
    };

    let func: mlua::Function = lua
        .globals()
        .get(entry_fn)
        .map_err(|e| format!("entry function '{}' not found: {}", entry_fn, e))?;

    let results_table: Table = func.call(targets_table)?;

    // ==========================================
    // پارس نتایج
    // ==========================================
    let mut payloads = Vec::new();

    for pair in results_table.sequence_values::<Table>() {
        let res = match pair {
            Ok(r) => r,
            Err(e) => {
                eprintln!("    ⚠️  Skipping malformed Lua result row: {}", e);
                continue;
            }
        };

        let url: String = match res.get("url") {
            Ok(u) => u,
            Err(e) => {
                eprintln!("    ⚠️  Skipping result with missing/invalid 'url': {}", e);
                continue;
            }
        };

        let mut headers_map = HashMap::new();
        if let Ok(headers_table) = res.get::<_, Table>("headers") {
            for h_pair in headers_table.pairs::<String, String>() {
                if let Ok((k, v)) = h_pair {
                    headers_map.insert(k, v);
                }
            }
        }

        let method = res
            .get::<_, Option<String>>("method")
            .ok()
            .flatten()
            .unwrap_or_else(|| "GET".to_string());

        let body = res.get::<_, Option<String>>("body").ok().flatten();
        let action = res
            .get::<_, Option<String>>("action")
            .ok()
            .flatten()
            .unwrap_or_else(|| "scan".to_string());

        // گرفتن oob_token از نتیجه رول
        let correlation_id: Option<String> = res
            .get::<_, Option<String>>("oob_token")
            .ok()
            .flatten()
            .filter(|s| !s.is_empty());

        payloads.push(LuaPayload {
            url,
            method,
            headers: headers_map,
            body,
            action,
            rule_id: task.rule.meta.id.clone(),
            severity: task.rule.meta.severity.clone(),
            confidence: task.rule.meta.confidence,
            correlation_id,
        });
    }

    Ok(payloads)
}
fn log_payload_to_file(payload: &LuaPayload) {
    std::fs::create_dir_all(crate::paths::CRAWL_LOG_DIR).ok();
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(crate::paths::PAYLOAD_LOG)
    {
        let _ = writeln!(
            file,
            "[{}] RULE: {} | METHOD: {} | URL: {} | HEADERS: {:?}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            payload.rule_id,
            payload.method,
            payload.url,
            payload.headers
        );
    }
}

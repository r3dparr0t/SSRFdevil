use mlua::{Lua, Table};
use url::Url;
use std::{
    collections::HashMap,
    error::Error,
    fs::OpenOptions,
    io::Write,
};
use reqwest::{Method, header::{HeaderMap, HeaderName, HeaderValue}};
use crate::{
    engine::{
        rule::RuleFile,
        request_engine::RequestEngine,
        request::RequestData,
        response::ResponseData,
    },
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
}

// -----------------------------------------------
// Executing HTTP Payload Part          
// -----------------------------------------------

pub async fn run_payload(
    engine: &RequestEngine,
    payload: LuaPayload,
) -> Result<ResponseData, Box<dyn Error + Send + Sync>> {
    let url = Url::parse(&payload.url)?;
    let method = Method::from_bytes(payload.method.as_bytes())?;

    let mut headers = HeaderMap::new();
    for (k, v) in &payload.headers {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            headers.insert(name, value);
        }
    }

    let body = payload.body.map(|b| b.into_bytes());
    let req = RequestData { method, url, headers, body };
    Ok(engine.send(req).await?)
}

pub fn process_all_batches_single_pass(
    targets: &[Target],
    rules: &[RuleFile],
) -> Result<Vec<LuaPayload>, Box<dyn Error + Send + Sync>> {
    let batches = matcher::create_batches(targets, rules);
    
    if batches.is_empty() {
        println!("[!] No target matched the criteria for selected rules.");
        return Ok(Vec::new());
    }
    println!("[+] Created {} matched batch task(s). Executing...", batches.len());
    
    execute_lua_master_batch(&batches)
}

fn execute_lua_master_batch(
    batches: &[matcher::BatchTask],
) -> Result<Vec<LuaPayload>, Box<dyn Error + Send + Sync>> {
    let lua = Lua::new();
    let mut all_payloads = Vec::new(); // ۱. تعریف لیست کل پی‌لودها

    for task in batches {
        println!("\n🚀 Executing Rule: {} ({}) over {} matched target(s)", 
                 task.rule.meta.name, task.rule.meta.id, task.targets.len());

        // ۲. ساخت Table مربوط به Targetهای این Batch برای پاس دادن به لوا
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

        // ۳. بارگذاری و اجرای اسکریپت لوا مربوط به این رول
        lua.load(&task.rule.script.source).exec()?;
            
        // ۴. استخراج تابع entry (پیش‌فرض run_batch)
        let entry_fn = if task.rule.script.entry.is_empty() { 
            "run_batch" 
        } else { 
            &task.rule.script.entry 
        };
        let func: mlua::Function = lua.globals().get(entry_fn)?;

        // ۵. اجرای واقعی تابع لوا با پاس دادن targets_table
        let results_table: Table = func.call(targets_table)?;

        // ۶. پیمایش روی نتایج خروجی لوا
        for pair in results_table.sequence_values::<Table>() {
            let res = pair?;
            
            // استخراج هدرها از Lua Table به HashMap
            let mut headers_map = HashMap::new();
            if let Ok(headers_table) = res.get::<_, Table>("headers") {
                for h_pair in headers_table.pairs::<String, String>() {
                    if let Ok((k, v)) = h_pair {
                        headers_map.insert(k, v);
                    }
                }
            }
            
            let payload = LuaPayload {
                url: res.get("url")?,
                method: res.get::<_, Option<String>>("method")?.unwrap_or_else(|| "GET".to_string()),
                headers: headers_map,
                body: res.get::<_, Option<String>>("body")?,
                action: res.get::<_, Option<String>>("action")?.unwrap_or_else(|| "scan".to_string()),
            };

            // 📝 ذخیره پی‌لودهای تولیدشده داخل فایل data/logs/payload.log
            log_payload_to_file(&payload, &task.rule.meta.id);

            all_payloads.push(payload);
        }
    }

    println!("\n    [+] Generated total {} payload(s) from Lua.", all_payloads.len());
    Ok(all_payloads)
}

fn log_payload_to_file(payload: &LuaPayload, rule_id: &str) {
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
            rule_id,
            payload.method,
            payload.url,
            payload.headers
        );
    }
}

/*                        
                            
// ۳. ارسال درخواست‌ها به ریکوئست اینجین و چاپ خروجی متنی
for payload in payloads {
    println!("    [->] Sending Request: {} [{}]", payload.url, payload.method);
    match executor::run_payload(engine, payload).await {
    Ok(resp) => println!("        [+] Response: Status {} ({} bytes)", resp.status, resp.body.len()),
    Err(e) => println!("        ❌ Request Error: {}", e),
    }
}
Ok(Err(lua_err)) => println!("    ❌ Lua Error: {}", lua_err),
    Err(join_err) => println!("    ❌ Task Execution Panic: {}", join_err),
            
println!("\n[+] Batch scan execution completed.");*/

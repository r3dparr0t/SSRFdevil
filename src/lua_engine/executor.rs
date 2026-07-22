use mlua::{Lua, Table};
use url::Url;
use std::{
 	collections::HashMap,
 	error::Error
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
    lua_engine::matcher};
    
#[derive(Debug, Clone)]
pub struct LuaPayload {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub action: String,
}

// ---------------------------------------------------
// executing lua code part
// ---------------------------------------------------


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

/* pub fn execute_lua_bypass_batch(
    script_source: &str,
    entry_fn: &str,
    targets: &[&Target],
) -> Result<Vec<LuaPayload>, Box<dyn Error>> {
    let lua = Lua::new();

    // ۱. ساخت آرایه‌ای از تارگت‌ها برای پاس دادن به لوا
    let targets_table = lua.create_table()?;
    for (i, target) in targets.iter().enumerate() {
        let t_table = lua.create_table()?;
        t_table.set("url", target.url.as_str())?;
        t_table.set("method", target.method.as_str())?;
        
        // اضافه کردن پارامترهای تارگت به Table
        let params_table = lua.create_table()?;
        for (j, param) in target.params.iter().enumerate() {
            let p_table = lua.create_table()?;
            p_table.set("name", param.name.as_str())?;
            p_table.set("value", param.value.as_deref().unwrap_or(""))?;
            p_table.set("location", format!("{:?}", param.location))?; // Query, Form, Header...
            params_table.set(j + 1, p_table)?;
        }
        t_table.set("params", params_table)?;
        
        // اضافه کردن سایر متادیتای لازم...
        targets_table.set(i + 1, t_table)?; // در لوا نمایه از ۱ شروع می‌شود
    }

    let ctx = lua.create_table()?;
    ctx.set("targets", targets_table)?;
    //ctx.set("user_agent", ua_engine::next())?;

    // ۲. لود و اجرای یک‌باره اسکریپت
    lua.load(script_source).exec()?;
    let func: mlua::Function = lua.globals().get(entry_fn)?;
    
    // ۳. دریافت خروجی به صورت یک Table از Payloadها
    let results_table: Table = func.call(ctx)?;
    let mut payloads = Vec::new();

    for pair in results_table.sequence_values::<Table>() {
        let res = pair?;
        let payload = LuaPayload {
            url: res.get::<_, String>("url")?,
            method: res.get::<_, Option<String>>("method")?.unwrap_or_else(|| "GET".to_string()),
            headers: HashMap::new(), // استخراج هدرها از table
            body: res.get::<_, Option<String>>("body")?,
            action: res.get::<_, Option<String>>("action")?.unwrap_or_else(|| "execute".to_string()),
        };
        payloads.push(payload);
    }

    Ok(payloads)
}
*/

pub fn process_all_batches_single_pass(
    targets: &[Target],
    rules: &[RuleFile],
) -> Result<Vec<LuaPayload>, Box<dyn Error + Send + Sync>> {
    // ۱. استخراج دسته‌ها از Matcher
    let batches = matcher::create_batches(targets, rules);
    
    if batches.is_empty() {
        println!("[!] No target matched the criteria for selected rules.");
        return Ok(Vec::new());
    }
    println!("[+] Created {} matched batch task(s). Executing...", batches.len());
    // ۲. اجرای واقعی لوا: فقط و فقط ۱ بار فراخوانی برای کل مجموعه
    execute_lua_master_batch(&batches)
}

fn execute_lua_master_batch(
    batches: &[matcher::BatchTask],
) -> Result<Vec<LuaPayload>, Box<dyn Error + Send + Sync>> {
    let lua = Lua::new();
    let master_table = lua.create_table()?;

    // تبدیل تمام BatchTaskها به یک Table واحد در لوا
    for (i, task) in batches.iter().enumerate() {
        let batch_item = lua.create_table()?;
        batch_item.set("rule_id", task.rule.meta.id.as_str())?;
        println!("\n🚀 Executing Rule: {} ({}) over {} matched target(s)", task.rule.meta.name, task.rule.meta.id, task.targets.len());
                        
        let targets_table = lua.create_table()?;
        for (i, target) in task.targets.iter().enumerate() {
            let t_table = lua.create_table()?;
            t_table.set("url", target.url.as_str())?;
            t_table.set("method", target.method.as_str())?;
            // اضافه کردن پارامترهای تارگت به Table
            let params_table = lua.create_table()?;
            for (j, param) in target.params.iter().enumerate() {
                let p_table = lua.create_table()?;
                p_table.set("name", param.name.as_str())?;
                p_table.set("value", param.value.as_deref().unwrap_or(""))?;
                p_table.set("location", format!("{:?}", param.location))?; // Query, Form, Header...
                params_table.set(j + 1, p_table)?;
            }
            t_table.set("params", params_table)?;
        
            // اضافه کردن سایر متادیتای لازم...
            targets_table.set(i + 1, t_table)?; // در لوا نمایه از ۱ شروع می‌}
        }
        
        batch_item.set("targets", targets_table)?;
        master_table.set(i + 1, batch_item)?;
    }

    let ctx = lua.create_table()?;
    ctx.set("batches", master_table)?;
    // ctx.set("user_agent", ua_engine::next())?;

    // 🔥 اجرا فقط ۱ بار در کل این فرایند:
    // فرض بر این است که یک master runner کد لوا را لود می‌کند
    let func: mlua::Function = lua.globals().get("run_master_batch")?;
    let results_table: Table = func.call(ctx)?;

    let mut payloads = Vec::new();
    for pair in results_table.sequence_values::<Table>() {
        let res = pair?;
        payloads.push(LuaPayload {
            url: res.get("url")?,
            method: res.get::<_, Option<String>>("method")?.unwrap_or_else(|| "GET".to_string()),
            headers: HashMap::new(),
            body: res.get("body")?,
            action: res.get::<_, Option<String>>("action")?.unwrap_or_else(|| "execute".to_string()),
        });
    }
    println!("    [+] Generated {} payload(s) from Lua.", payloads.len());
    Ok(payloads)
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

use mlua::{Lua, Table};
use std::collections::HashMap;
use std::error::Error;
use url::Url;

#[derive(Debug, Clone)]
pub struct LuaPayload {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub action: String,
}

pub fn execute_lua_bypass(
    script_source: &str,
    entry_fn: &str,
    target_url: &str,
) -> Result<LuaPayload, Box<dyn Error>> {
    let lua = Lua::new();
    let parsed_url = Url::parse(target_url)?;
    let hostname = parsed_url.host_str().unwrap_or("").to_string();
    let port = parsed_url.port().unwrap_or(match parsed_url.scheme() {
        "https" => 443,
        _ => 80,
    });

    let ctx = lua.create_table()?;
    ctx.set("target", target_url)?;
    ctx.set("hostname", hostname)?;
    ctx.set("port", port)?;

    let log_func = lua.create_function(|_, message: String| {
        println!("[Lua Log]: {}", message);
        Ok(())
    })?;
    ctx.set("log", log_func)?;

    lua.load(script_source).exec()?;
    let func: mlua::Function = lua.globals().get(entry_fn)?;
    let result: Table = func.call(ctx)?;

    let mut payload = LuaPayload {
        url: String::new(),
        method: "GET".to_string(),
        headers: HashMap::new(),
        body: None,
        action: "execute".to_string(),
    };

    payload.url = result.get::<_, String>("url")?;
    if let Ok(method) = result.get::<_, String>("method") {
        payload.method = method.to_uppercase();
    }
    if let Ok(headers_table) = result.get::<_, Table>("headers") {
        for pair in headers_table.pairs::<String, String>() {
            let (k, v) = pair?;
            payload.headers.insert(k, v);
        }
    }
    if let Ok(body) = result.get::<_, String>("body") {
        payload.body = Some(body);
    }
    if let Ok(action) = result.get::<_, String>("action") {
        payload.action = action;
    }

    Ok(payload)
}

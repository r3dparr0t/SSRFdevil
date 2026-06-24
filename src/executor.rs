use mlua::{Lua, Table};
use std::{
    collections::HashMap,
    error::Error,
    fs,
    sync::RwLock
};
use url::Url;
use rand::distr::{Distribution, weighted::WeightedIndex};
use crate::paths;

#[derive(Debug, Clone)]
pub struct LuaPayload {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub action: String,
}

// ---------------------------------------------------
// بخش بارگذاری و انتخاب یوزرایجنت وزنی
// ---------------------------------------------------

pub type UaEntry = (u32, String);

pub fn load_user_agents(min_weight: u32) -> Vec<UaEntry> {
    let content = match fs::read_to_string(paths::UA_FILE) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("[!] Warning: Could not read {}! Using safe fallback.", paths::UA_FILE);
            return vec![(100, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36".to_string())];
        }
    };

    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() { return None; }
            if let Some((weight_str, ua)) = line.split_once('|') {
                if let Ok(weight) = weight_str.parse::<u32>() {
                    if weight >= min_weight {
                        return Some((weight, ua.to_string()));
                    }
                }
            }
            None
        })
        .collect()
}

fn get_weighted_ua(ua_list: &[UaEntry]) -> String {
    if ua_list.is_empty() {
        return "Mozilla/5.0 (compatible; SSRFdevil/1.0)".to_string();
    }
    let weights: Vec<u32> = ua_list.iter().map(|(w, _)| *w).collect();
    if let Ok(dist) = WeightedIndex::new(weights) {
        let mut rng = rand::rng(); 
        let index = dist.sample(&mut rng);
        ua_list[index].1.clone()
    } else {
        "Mozilla/5.0 (compatible; SSRFdevil/1.0)".to_string()
    }
}

// ---------------------------------------------------
// executing lua code part
// ---------------------------------------------------
static UA_LIST: RwLock<Vec<UaEntry>> = RwLock::new(Vec::new());

pub fn init_ua_list(min_weight: u32) {
    let list = load_user_agents(min_weight);
    *UA_LIST.write().unwrap() = list;
}

pub fn execute_lua_bypass(
    script_source: &str,
    entry_fn: &str,
    target_url: &str,
) -> Result<LuaPayload, Box<dyn Error>> {

    let random_ua = {
        let list = UA_LIST.read().unwrap();
        get_weighted_ua(&list)
    };
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
	let path = parsed_url.path().to_string();
	let scheme = parsed_url.scheme().to_string();

	ctx.set("path", path)?;
	ctx.set("scheme", scheme)?;
	ctx.set("user_agent", random_ua)?;
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

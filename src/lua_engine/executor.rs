use mlua::{Lua, Table};
use url::Url;
use std::{
 	collections::HashMap,
 	error::Error
};
use reqwest::{Method, header::{HeaderMap, HeaderName, HeaderValue}};
use crate::engine::{
    ua_engine,
    request_engine::RequestEngine,
    request::RequestData,
    response::ResponseData,
};

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
	let path = parsed_url.path().to_string();
	let scheme = parsed_url.scheme().to_string();

    let ctx = lua.create_table()?;
    ctx.set("target", target_url)?;
    ctx.set("hostname", hostname)?;
    ctx.set("port", port)?;
	ctx.set("path", path)?;
	ctx.set("scheme", scheme)?;
	ctx.set("user_agent", ua_engine::next())?;
	
    let log_func = lua.create_function(|_, message: String| {
        println!("[Lua Log]: {}", message);
        Ok(())
    })?;
    ctx.set("log", log_func)?;
    // finally run the rule lua code
    lua.load(script_source).exec()?;
    let func: mlua::Function = lua.globals().get(entry_fn)?;
    let result: Table = func.call(ctx)?;

    let mut payload = LuaPayload {
        url: result.get::<_, String>("url")?,
        method: "GET".to_string(), // as default
        headers: HashMap::new(),
        body: None,
        action: "execute".to_string(),
    };


    if let Ok(method) = result.get::<_, String>("method") {
        payload.method = method.to_uppercase();
    }
    //ua_engine::init();

    // set the default ua
    payload.headers.insert("User-Agent".to_string(), ua_engine::next());
    // reset as lua script may change the defaults
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

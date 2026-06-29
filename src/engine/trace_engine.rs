
// engine/trace_engine.rs
use crate::engine::request::RequestData;
use crate::engine::response::ResponseData;

pub fn before(req: &RequestData) {
    println!("[TRACE] 🛫 Sending {} to {}", req.method, req.url);
}

pub fn after(resp: &ResponseData) {
    println!("[TRACE] 🛬 Received Status: {}", resp.status);
}

pub fn error<E>(url: &str,err: E,)
where
    E: std::fmt::Display,
{
    eprintln!("[TRACE] ❌ {} -> {}", url, err);
}

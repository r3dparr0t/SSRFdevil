// engine/response.rs
use reqwest::header::HeaderMap;

pub struct ResponseData {
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

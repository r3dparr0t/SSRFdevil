// src/engine/delay_engine.rs
use std::time::Duration;
use rand::distr::{Distribution, Uniform}; // در رند جدید برای رنج تصادفی به این نیاز داریم

pub async fn wait() {
    // ایجاد یک تاخیر تصادفی بین ۵۰۰ تا ۱۵۰۰ میلی‌ثانیه با ساختار جدید rand
    let mut rng = rand::rng();
    let die = Uniform::new(500, 1500).unwrap();
    let jitter = die.sample(&mut rng);
    
    tokio::time::sleep(Duration::from_millis(jitter)).await;
}

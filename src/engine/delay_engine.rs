// src/engine/delay_engine.rs
use std::time::Duration;
use rand::distr::{Distribution, Uniform};

pub async fn wait() {
    let jitter = {
        let mut rng = rand::rng();
        Uniform::new(500, 1500).unwrap().sample(&mut rng)
    }; // اینجا rng دراپ می‌شه و دیگه زنده نیست

    tokio::time::sleep(Duration::from_millis(jitter)).await;
}

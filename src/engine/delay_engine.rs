// src/engine/delay_engine.rs
use std::time::Duration;
use rand::distr::{Distribution, Uniform};

pub async fn wait() {
    // خواندن رنج دیلی از کانفیگ مرکزی به صورت زنده
    let (min, max) = {
        let settings = crate::config::APP_SETTINGS.get().unwrap().read().unwrap();
        (settings.delay_min, settings.delay_max)
    };

    if min >= max {
        tokio::time::sleep(Duration::from_millis(min)).await;
        return;
    }

    let jitter = {
        let mut rng = rand::rng();
        Uniform::new(min, max).unwrap().sample(&mut rng)
    }; 

    tokio::time::sleep(Duration::from_millis(jitter)).await;
}

